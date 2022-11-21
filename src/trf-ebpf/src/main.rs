#![no_std]
#![no_main]

use core::{mem};
use memoffset::offset_of;
use aya_bpf::{
    maps::{HashMap, PerfEventArray},
    bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, xdp, map},
    programs::{TcContext, XdpContext},
};
use aya_log_ebpf::info;
use trf_common::{EventLog};

// for loops requisite:
use unroll::unroll_for_loops;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;
use bindings::{ethhdr, iphdr, tcphdr};

/** Logger Offset:
 * Since most Log4j loggers will receive input from some
 * HTTP header field (or any other protocol for that matter),
 * by knowing the packet offset where this input resides we
 * are able to provide an extra layer of sanitization.
 * Although obsfucated payloads is still an issue.
**/
#[no_mangle]
static LOGGER_N_SIZE: u32 = 13;
#[no_mangle]
static LOGGER_N_OFFSET: u8 = 76;
#[no_mangle]
static LOGGER_P_OFFSET: u8 = 91; // 76 + LOGGER_N_SIZE + 2 (': ')

// JNDI binding
const JNDI: [u8; 6] = [36, 123, 106, 110, 100, 105];
const LDAP: [u8; 5] = [58, 108, 100, 97, 112];

// HTTP bindings *1
const HTTP_RES: [u8; 4] = [72, 84, 84, 80];                 // HTTP/1.1 XXX
const HTTP_GET: [u8; 3] = [71, 69, 84];                     // GET XXX
// ----

/**
 * Notes:
 *  Current ingress/egress config is relative to docker0 interface.
 *  (if control flow is needed to be switched check comments)-
**/
// tcp probe tracepoint --> /sys/kernel/debug/tracing/events/tcp/tcp_probe

const IPPROTO_TCP: u8 = 6; // 0x0006
const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
const TCP_DATA: usize = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12; // +12 (TCP header opts)

#[no_mangle]
static MODE: u8 = 1;    
// mode: 1 - drop+block explicit http conns sent after jndi trigger (server log - curl)
// mode: 2 - drop+block unexpected tcp conns after ...

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<EventLog> = PerfEventArray::<EventLog>::with_max_entries(1024, 0);

#[map(name = "RTX")]
static mut RTX: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map(name = "WHLIST")]
static mut WHLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map(name = "LOOKUPS")]
static mut LOOKUPS: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

#[inline(always)]
unsafe fn is_verified(key: u32) -> bool {
    let val = WHLIST.get(&key);
    if val.is_some() {
        return true;
    }
    false
}

#[inline(always)]
unsafe fn is_blocked(key: u32) -> bool {
    let val = BLOCKLIST.get(&key);
    if val.is_some() {
        return true;
    }
    false
}

#[inline(always)]
unsafe fn block_addr(key: u32) {
    match BLOCKLIST.insert(&key, &1, 0) {
        Ok(_) => {},
        Err(_) => {},
    }
}

// Update RTX
#[inline(always)]
unsafe fn update_RTX(key: u32) -> Option<u32> {
    let val = RTX.get(&key);
    if val.is_some() {
        let mut count: u32 = *val.expect("failed to unwrap RTX count");
        count += 1;
        match RTX.insert(&key, &count, 0) {
            Ok(_) => return Some(count),
            Err(_) => return None,
        }
    }

    match RTX.insert(&key, &1, 0) {
        Ok(_) => return Some(1),
        Err(_) => return None,
    }
}

// Update LOOKUPS
#[inline(always)]
unsafe fn update_LOOKUPS(key: u32, add: bool) -> Option<u32> {
    let val = LOOKUPS.get(&key);
    if val.is_some() {
        let mut count: u32 = *val.expect("failed to unwrap LOOKUPS count");
        if add {
            count += 1;
        } else if count > 0 {
            count -= 1;
        }
        match LOOKUPS.insert(&key, &count, 0) {
            Ok(_) => return Some(count),
            Err(_) => return None,
        }
    }

    match LOOKUPS.insert(&key, &1, 0) {
        Ok(_) => return Some(1),
        Err(_) => return None,
    }
}

// INGRESS

#[xdp(name="intrf")]
pub fn intrf(ctx: XdpContext) -> u32 {
    match try_intrf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// ptr_at function to access packet data (byte - u8)
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}


// TODO: get dport (block LDAP ports --> confidence levels)
/*
                    Note: Pointer arithemtic isn't allowed while scanning.
                        733: (07) r2 += -67
                        R2 pointer arithmetic on pkt_end prohibited
                        verification time 13989 usec
                        stack depth 32
                        processed 793 insns (limit 1000000) max_states_per_insn 1 total_states 20 peak_states 20 mark_read 7

                    ex:
                    let mut j = 1;
                    for i in 1..HTTP_GET.len() {
                        byte = unsafe { *ptr_at(&ctx, TCP_DATA + i)? };
                        if byte == HTTP_GET[i] {
                            j += 1;
                            // todo: err handling
                        }
                    }
                    if j == HTTP_GET.len() { 
                        info!(&ctx, "\tHTTP GET: payload_size: {}", payload_size);
                    }
*/
fn try_intrf(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be(unsafe {
        *ptr_at(&ctx, offset_of!(ethhdr, h_proto))?
    });

    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS)
    }

    let mut elvls = [0u32;2usize];
    let mut ctxdrop: u32 = 0;
    let ip_proto = u8::from_be(unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))?
    });
    let saddr = u32::from_be(unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))?
    });
    let daddr = u32::from_be(unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))?
    });
    let scount = unsafe { update_RTX(saddr).expect("Error updating RTX") }; // baseline
    let dcount = unsafe { update_RTX(daddr).expect("Error updating RTX") };

    if dcount < scount && ip_proto == IPPROTO_TCP {
        if MODE == 2 {  // Block unexpected outbound TCP
            ctxdrop = 1;
            unsafe { block_addr(daddr) };
        } else if MODE == 1 {   // Filter HTTP: Specific to the JNDI Exploit (which leverages JNDI lookups using HTTP)
            let payload_size = ((ctx.data_end() - ctx.data()) - (TCP_DATA)) as usize;
            if payload_size >= 100 {
                let fbyte: u8 = unsafe { *ptr_at(&ctx, TCP_DATA)? };

                if fbyte == HTTP_GET[0] {
                    // ---
                    // elvls[0] = 1;
                    // ---
                    let i = HTTP_GET.len() - 1;
                    let lbyte: u8 = unsafe { *ptr_at(&ctx, TCP_DATA + i)? };
                    if lbyte == HTTP_GET[i] {
                        info!(&ctx, "\tHTTP GET: payload_size: {}", payload_size);
                        match unsafe { LOOKUPS.get(&saddr) } {
                            None => {
                                // block all unexpected GET requests
                            },
                            Some(_) => { // Triggered jndi lookup
                                // Drop packet + block addr
                                ctxdrop = 1;
                                unsafe { 
                                    block_addr(daddr);
                                    let r = update_LOOKUPS(saddr, false).unwrap();
                                    if r == 0 {
                                        LOOKUPS.remove(&saddr).expect("rm lookup");
                                    }
                                };
                            },
                        };
                    }
                } else if fbyte == HTTP_RES[0] {
                    let i = HTTP_RES.len() - 1;
                    let lbyte: u8 = unsafe { *ptr_at(&ctx, TCP_DATA + i)? };
                    if lbyte == HTTP_RES[i] {
                        info!(&ctx, "\tHTTP RESP: payload_size: {}", payload_size);
                    }
                }
            }
        }
    } else if unsafe { is_blocked(daddr) } {
        ctxdrop = 1;
    }
    
    //override
    if unsafe { is_verified(daddr) } {
        ctxdrop = 0;
        info!(&ctx, "\tDestination address whlisted");
    }

    let event = EventLog {
        etype: 0,
        saddr: saddr,
        daddr: daddr,
        edrop: ctxdrop,
        elvls: elvls,
    };

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }
    if ctxdrop == 1 {
        return Ok(xdp_action::XDP_DROP);
    }
    Ok(xdp_action::XDP_PASS)
}
/* Inverse Logic
    unsafe {
        update_RTX(saddr).expect("Error updating RTX");
        update_RTX(daddr).expect("Error updating RTX");
        if is_blocked(saddr) {
            ctxdrop = 1;
        }
    }; 
*/

// --- EGRESS

#[classifier(name="egtrf")]
pub fn egtrf(ctx: TcContext) -> i32 {
    match try_egtrf(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

//  Inspect for ${jndi:ldap, if so block request
//  Inspect for ${jndi, is so block unexpected GET requests / LDAP (port) requests
// offset = 0 --> G(ET) ; offset = 76 --> X(-API) (len=13) ;
#[inline(always)]
#[unroll_for_loops]
fn lookup_hdr(ctx: &TcContext, mut byte: u8, nxbyteidx: usize) -> Option<usize> { // TODO: Pass nxbyte instead of nxbyteindex
    // [88,45,65,112,105,45,86,101,114,115,105,111,110];
    let header_seq = core::include!("../../http-parser/src/header-dec-seq"); // len < LOGGER_N_SIZE
    let sz: usize = LOGGER_N_SIZE as usize;

    for i in 0..sz {
        if byte == header_seq[i] {
            if i == sz - 1 {
                return Some(3)
            } else {
                let j = i + 1;
                if j < sz {
                    byte = ctx.load::<u8>(TCP_DATA + (LOGGER_N_OFFSET as usize) + nxbyteidx).expect("valid header byte");
                    if byte == header_seq[j] {
                        return Some((i + (sz - j) + 3) as usize) // +2 --> ': ' ; +1 --> payload offset
                    }
                }
            }
        }
    }
    return None
}


/** Left hand side offet: 
  * Incremented for each byte not considered, since our logger offset will be
  * relative to the beginning of the header name field.
 **/
#[inline(always)]
#[unroll_for_loops]
unsafe fn bef_dpi(ctx: &TcContext) -> u32 {
    let mut lookup = 0;

    match ctx.load::<u8>(TCP_DATA) {
        Err(_) => {},
        Ok(mut byte) => {
            let mut i: usize = 0;
            if byte == HTTP_GET[i] {
                for i in 1..HTTP_GET.len() {
                    byte = ctx.load::<u8>(TCP_DATA + i).expect("valid GET byte");
                    if byte != HTTP_GET[i] {
                        return lookup;
                    }
                } // found GET request
            }

            let mut lhsoffset = 0;
            i = LOGGER_N_OFFSET as usize;
            for j in 0..(LOGGER_N_SIZE as usize + 1) / 2 { // 13 - 'X-Api-Version' Length ; https://stackoverflow.com/a/72442854
                byte = ctx.load::<u8>(TCP_DATA + i + j).expect("valid header byte");
                
                match lookup_hdr(ctx, byte, j+1) {
                    None => lhsoffset += 1,
                    Some(mut logger_off) => {
                        logger_off += lhsoffset;
                        byte = ctx.load::<u8>(TCP_DATA + i + logger_off).expect("valid X-Api-Version byte");            
                        let mut l = 0;
                        if byte == JNDI[l] {
                            for l in 1..JNDI.len() {
                                byte = ctx.load::<u8>(TCP_DATA + i + logger_off + l).expect("valid X-Api-Version byte");
                                if byte != JNDI[l] {
                                    return lookup;
                                }
                            } // found JNDI lookup 
                            lookup = 1;
                        
                            l = JNDI.len();
                            for m in 0..LDAP.len() {
                                byte = ctx.load::<u8>(TCP_DATA + i + logger_off + l + m).expect("valid X-Api-Version byte");
                                if byte != LDAP[m] {
                                    return lookup;
                                }
                            } // found '${jndi:ldap' pattern
                            // Testing!
                            // lookup = 2;
                        }
                    }
                }
            }
        },
    }

    lookup as u32
}

fn try_egtrf(ctx: TcContext) -> Result<i32, i64> {
    let h_proto = u16::from_be(
        ctx.load(offset_of!(ethhdr, h_proto))
            .map_err(|_| TC_ACT_PIPE)?,
    );

    if h_proto != ETH_P_IP {
        return Ok(TC_ACT_PIPE);
    }

    let mut elvls = [0u32;2usize];
    let mut ctxdrop = 0;
    let ip_proto = u8::from_be(
        ctx.load(ETH_HDR_LEN + offset_of!(iphdr, protocol))
            .map_err(|_| TC_ACT_PIPE)?,
    );
    let saddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))?);
    let daddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?);

    if unsafe { is_blocked(saddr)} {
        ctxdrop = 1;
    } else if ip_proto == IPPROTO_TCP {
        let einfo = unsafe { bef_dpi(&ctx) };
        match einfo {
            1 => {
                elvls[0] = 1;
                unsafe { update_LOOKUPS(daddr, true).expect("new lookup"); };
            },
            2 => ctxdrop = 1,
            _ => {},
        };
    }

    let event = EventLog {
        etype: 1,
        saddr: saddr,
        daddr: daddr,
        edrop: ctxdrop,
        elvls: elvls,
    };

    unsafe {
        update_RTX(saddr).expect("Error updating RTX");
        update_RTX(daddr).expect("Error updating RTX");
        EVENTS.output(&ctx, &event, 0);
    }
    
    if ctxdrop == 1 {
        return Ok(TC_ACT_SHOT);
    }
    Ok(TC_ACT_PIPE)
}

// ---

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}