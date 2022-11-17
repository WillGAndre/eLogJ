#![no_std]
#![no_main]

use core::{mem, assert_eq};
use memoffset::offset_of;
use aya_bpf::{
    maps::{HashMap, PerfEventArray},
    bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, xdp, map},
    programs::{TcContext, XdpContext},
};
use aya_log_ebpf::info;
use trf_common::EventLog;

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
static LOGGER_N_SIZE: usize;
#[no_mangle]
static LOGGER_N_SEQ: [u8; usize];
#[no_mangle]
static LOGGER_N_OFFSET: usize;
#[no_mangle]
static LOGGER_OFFSET: usize;

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
static mut LOOKUPS: HashMap<u32, usize> = HashMap::with_max_entries(1, 0);

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
// TODO: Change Option to Result + Refactor
#[inline(always)]
unsafe fn update_RTX(key: u32) -> Option<u32> {
    let val = RTX.get(&key);
    if val.is_some() {
        let mut count: u32 = *val.expect("failed to unwrap value");
        count += 1;
        match RTX.insert(&key, &count, 0) {
            Ok(_) => {},
            Err(_) => return None,
        }
        return Some(count)
    }

    match RTX.insert(&key, &1, 0) {
        Ok(_) => {},
        Err(_) => return None,
    }
    Some(1)
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

fn try_intrf(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be(unsafe {
        *ptr_at(&ctx, offset_of!(ethhdr, h_proto))?
    });

    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS)
    }

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
        if MODE == 2 {  // Block TCP
            ctxdrop = 1;
            unsafe { block_addr(daddr) };
        } else if MODE == 1 {   // Filter HTTP: Specific to the JNDI Exploit (which leverages JNDI lookups using HTTP)
            let payload_size = ((ctx.data_end() - ctx.data()) - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12)) as usize;
            if payload_size >= 100 {
                let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12;
                let byte: u8 = unsafe {
                    *ptr_at(&ctx, payload_offset)?
                };

                // TODO: Check viablility of assert_eq (on failure, they will panic)
                // todo: get dport, if LDAP block
                if byte == HTTP_GET[0] {
                    assert_eq!(unsafe { *ptr_at::<u8>(&ctx, payload_offset + 1)? }, HTTP_GET[1]);
                    assert_eq!(unsafe { *ptr_at::<u8>(&ctx, payload_offset + 2)? }, HTTP_GET[2]);
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
                                LOOKUPS.insert(&saddr, &0, 0).expect("ended lookup");
                            };
                        },
                    };
                } else if byte == HTTP_RES[0] {
                    assert_eq!(unsafe { *ptr_at::<u8>(&ctx, payload_offset + 1)? }, HTTP_RES[1]);
                    assert_eq!(unsafe { *ptr_at::<u8>(&ctx, payload_offset + 2)? }, HTTP_RES[2]);
                    assert_eq!(unsafe { *ptr_at::<u8>(&ctx, payload_offset + 3)? }, HTTP_RES[3]);
                    info!(&ctx, "\tHTTP RESP: payload_size: {}", payload_size);
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
        einfo: 0,
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
    let header_seq: [u8; 13] = [88,45,65,112,195,45,86,101,114,115,105,111,110];

    for i in 0..13 {
        if byte == header_seq[i] {
            if i == 12 {
                return Some(3)
            } else {
                let j = i + 1;
                if j < 13 {
                    byte = ctx.load::<u8>(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12 + 76 + nxbyteidx).expect("valid header byte");
                    if byte == header_seq[j] {
                        return Some((i + (13 - j) + 3) as usize) // +2 --> ': ' ; +1 --> payload offset
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

    match ctx.load::<u8>(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12) {
        Err(_) => {},
        Ok(mut byte) => {
            let mut i: usize = 0;
            if byte == HTTP_GET[i] {
                for i in 1..HTTP_GET.len() {
                    byte = ctx.load::<u8>(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12 + i).expect("valid GET byte");
                    if byte != HTTP_GET[i] {
                        return lookup;
                    }
                } // found GET request
            }

            let mut lhsoffset = 0;
            i = 76;
            for j in 0..7 { // 13 - 'X-Api-Version' Length
                byte = ctx.load::<u8>(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12 + i + j).expect("valid header byte");
                
                match lookup_hdr(ctx, byte, j+1) {
                    None => lhsoffset += 1,
                    Some(mut logger_off) => {
                        logger_off += lhsoffset;
                        byte = ctx.load::<u8>(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12 + i + logger_off).expect("valid X-Api-Version byte");            
                        let mut l = 0;
                        if byte == JNDI[l] {
                            for l in 1..JNDI.len() {
                                byte = ctx.load::<u8>(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12 + i + logger_off + l).expect("valid X-Api-Version byte");
                                if byte != JNDI[l] {
                                    return lookup;
                                }
                            } // found JNDI lookup 
                            lookup = 1;
                        
                            l = JNDI.len();
                            for m in 0..LDAP.len() {
                                byte = ctx.load::<u8>(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12 + i + logger_off + l + m).expect("valid X-Api-Version byte");
                                if byte != LDAP[m] {
                                    //return byte as u32;
                                    return lookup;
                                }
                            }
                            lookup = 2;
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

    let mut einfo = 0;
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
        einfo = unsafe { bef_dpi(&ctx) /*inspect_data(&ctx)*/ };
        match einfo {
            1 => unsafe { LOOKUPS.insert(&daddr, &1, 0).expect("new lookup"); },
            2 => ctxdrop = 1,
            _ => {},
        };
    }

    let event = EventLog {
        etype: 1,
        saddr: saddr,
        daddr: daddr,
        edrop: ctxdrop,
        einfo: einfo,
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


// ---

    // if MODE == 1 {
    //     if dcount < scount && ip_proto == IPPROTO_TCP {
    //         // Find HTTP: Specific to the JNDI Exploit (which leverages JNDI lookups using HTTP)
    //         let payload_size = ((ctx.data_end() - ctx.data()) - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12)) as usize;
    //         if payload_size >= 100 {
    //             let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12;
    //             let byte: u8 = unsafe {
    //                 *ptr_at(&ctx, payload_offset)?
    //             };

    //             if byte == HTTP_GET[0] {
    //                 assert_eq!(unsafe { *ptr_at::<u8>(&ctx, payload_offset + 1)? }, HTTP_GET[1]);
    //                 assert_eq!(unsafe { *ptr_at::<u8>(&ctx, payload_offset + 2)? }, HTTP_GET[2]);
    //                 info!(&ctx, "HTTP GET: payload_size: {}", payload_size);
                    
    //                 // Drop packet + block addr
    //                 ctxdrop = 1;
    //                 unsafe { block_addr(daddr) };
    //                 // ----
    //             } else if byte == HTTP_RES[0] {
    //                 assert_eq!(unsafe { *ptr_at::<u8>(&ctx, payload_offset + 1)? }, HTTP_RES[1]);
    //                 assert_eq!(unsafe { *ptr_at::<u8>(&ctx, payload_offset + 2)? }, HTTP_RES[2]);
    //                 assert_eq!(unsafe { *ptr_at::<u8>(&ctx, payload_offset + 3)? }, HTTP_RES[3]);
    //                 info!(&ctx, "HTTP RESP: payload_size: {}", payload_size);
    //             }
    //         }
    //     } else if unsafe { is_blocked(daddr) } {
    //         ctxdrop = 1;
    //     }
    // } else if MODE == 2 {
    //     if dcount == 1 && ip_proto == IPPROTO_TCP {
    //         // ldap ports: 389, 1389
    //         let sport = u16::from_be(unsafe {
    //             *ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source))?
    //         });
    //         let dport = u16::from_be(unsafe {
    //             *ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))?
    //         });

    //         let payload_size = ((ctx.data_end() - ctx.data()) - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12)) as usize;
    //         let payload_byte: u8 = unsafe {
    //             *ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12)?
    //         };

    //         info!(&ctx, "unexpected tcp packet {} --> {} ; payload_size: {} ; 1st byte: {}", sport, dport, payload_size, payload_byte);
    //         ctxdrop = 1;
    //         unsafe { block_addr(daddr) };
    //     } else if unsafe { is_blocked(daddr) } {
    //         ctxdrop = 1;
    //     }
    // }