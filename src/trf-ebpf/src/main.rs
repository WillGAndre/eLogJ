#![no_std]
#![no_main]

use core::{mem};
use memoffset::offset_of;
use aya_bpf::{
    maps::{HashMap, PerfEventArray},
    cty::{c_int, c_uint},
    bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, xdp, map, lsm},
    programs::{TcContext, XdpContext, LsmContext},
};
use aya_log_ebpf::info;
use trf_common::{EventLog};

// unrolls for loops 
use unroll::unroll_for_loops;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;
use bindings::{ethhdr, iphdr, tcphdr, bpf_attr, bpf_attr__bindgen_ty_13, bpf_cmd};

/** Logger Offset:
 * Since our Log4j logger example receives input from some
 * HTTP header field (or any other protocol for that matter),
 * by knowing the packet offset where this input resides we
 * are able to provide an extra layer of sanitization.
 * Although obsfucated payloads is still an issue.
 * 
 * 0 => Logger entry name size
 * 1 => Logger name offset (start)
 *
 *  Note about Rule set:
 * I tried several implementations of the current `const RULE_SET`:
 *      1 - Receiving the rule set dynamically as a cli argument
 *          (loading it from userspace to kernelspace).
 *      2 - Storing logger information including the rule set in
 *          a separate eBPF map (big perf hit).
 * 
 *  Current pro/con:
 * Logger-info is stored in files due to easy accessibility from
 * userspace and kernelspace. Content from the files is read once.
**/
const LOGGER_INFO: [usize; 2] = core::include!("../../logger-info/src/header-offset");
const HEADER_SEQ: [u8; LOGGER_INFO[0]] = core::include!("../../logger-info/src/header-dec-seq"); // [88,45,65,112,105,45,86,101,114,115,105,111,110];
const RULE_SET: [u32; 4usize] = core::include!("../../logger-info/src/rule-set");
/*
    0: Block TCP (1) / Block HTTP (2)                           ---> NOTE: OUTBOUND TRAFFIC ONLY
    1: Block LDAP ports (todo)                                        (Future work: custom ports)
    3: Block JNDI lookup (1) / Block JNDI request (2)
    4: Block JNDI:LDAP lookup (1) / Block JNDI:LDAP request (2)

    ex1: [1, 0, 0, 2]
    ex2: [0, 0, 1, 1]
*/

// Payload bindings
const JNDI: [u8; 6] = [36, 123, 106, 110, 100, 105];        // ${jndi
const LDAP: [u8; 5] = [58, 108, 100, 97, 112];              // :ldap
// HTTP bindings
const HTTP_RES: [u8; 4] = [72, 84, 84, 80];                 // HTTP/1.1 XXX
const HTTP_GET: [u8; 3] = [71, 69, 84];                     // GET XXX

const IPPROTO_TCP: u8 = 6; // 0x0006
const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
const TCP_DATA: usize = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12; // +12 (TCP header opts)

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

// Update RTX w/ internal counter, returns count.
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

/** (eBPF map) LOOKUPS:
 * Single key/value hashmap used to update an 
 * internal counter that indicates the number
 * of lookups. Counter is inc/decremented
 * accordingly (as well as removed) so that
 * state integrity may be sanitized/maintained. (future work -> ebpf LSM)
**/
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

/** (XDP) Ingress traffic:
 * Looks for unexpected packets (packets that haven't been registered
 * from egress TC traffic, aka source address from a packet sent to our logger).
 *
 * Rule sets (indexes 0 and 1) filter outbound traffic. 
 * If destination address is whlisted' rule sets are overrided.
 * 
**/
fn try_intrf(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be(unsafe {
        *ptr_at(&ctx, offset_of!(ethhdr, h_proto))?
    });

    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS)
    }

    let mut elvls = [(0, 0) ; 2usize];
    let mut ctxdrop = 0;
    let mut ctxoveride = 0;
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
        let data_size = ((ctx.data_end() - ctx.data()) - (TCP_DATA)) as usize;

        if data_size >= 100 {
            let fbyte: u8 = unsafe { *ptr_at(&ctx, TCP_DATA)? };
            if fbyte == HTTP_GET[0] {
                let i = HTTP_GET.len() - 1;
                let lbyte: u8 = unsafe { *ptr_at(&ctx, TCP_DATA + i)? };
                if lbyte == HTTP_GET[i] {
                    match unsafe { LOOKUPS.get(&saddr) } {
                        None => {
                            // unexpected GET requests (not triggered by lookup)
                        },
                        Some(_) => {
                            unsafe {
                                // JNDI / JNDI:LDAP lookup blocked
                                if RULE_SET[2] == 1 || RULE_SET[3] == 1 {
                                    block_addr(daddr);
                                }
                                let r = update_LOOKUPS(saddr, false).unwrap();
                                if r == 0 {
                                    LOOKUPS.remove(&saddr).expect("rm lookup");
                                }
                            };
                        },
                    };
                    elvls[0] = (2, 1);
                }
            } else if fbyte == HTTP_RES[0] {
                let i = HTTP_RES.len() - 1;
                let lbyte: u8 = unsafe { *ptr_at(&ctx, TCP_DATA + i)? };
                if lbyte == HTTP_RES[i] {
                    // info!(&ctx, "\tHTTP RESP: data_size: {}", data_size);
                    elvls[0] = (2, 2);
                }
            }
        } else {
            elvls[0] = (1, 0);
        }

        // RULE SET (idx=0): if 1 --> block TCP ; if 2 --> block HTTP
        if RULE_SET[0] != 0 && RULE_SET[0] == elvls[0].0 {
            ctxdrop = 1;
        }
    }
    
    if unsafe { is_blocked(daddr) } {
        ctxdrop = 1;
    }

    //override
    if unsafe { is_verified(daddr) } {
        ctxdrop = 0;
        ctxoveride = 1;
        info!(&ctx, "\tDestination address whlisted");
    }

    let event = EventLog {
        etype: 0,
        saddr: saddr,
        daddr: daddr,
        edrop: ctxdrop,
        eovrd: ctxoveride,
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
    // let header_seq = core::include!("../../http-parser/src/header-dec-seq");
    let sz: usize = LOGGER_INFO[0] as usize;

    for i in 0..sz {
        if byte == HEADER_SEQ[i] {
            if i == sz - 1 {
                return Some(3)
            } else {
                let j = i + 1;
                if j < sz {
                    byte = ctx.load::<u8>(TCP_DATA + (LOGGER_INFO[1] as usize) + nxbyteidx).expect("valid header byte");
                    if byte == HEADER_SEQ[j] {
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
            i = LOGGER_INFO[1] as usize;
            for j in 0..(LOGGER_INFO[0] as usize + 1) / 2 { // 13 - 'X-Api-Version' Length ; https://stackoverflow.com/a/72442854
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

    let mut elvls = [(0, 0) ; 2usize];
    let mut ctxdrop = 0;
    let mut ctxoveride = 0;
    let ip_proto = u8::from_be(
        ctx.load(ETH_HDR_LEN + offset_of!(iphdr, protocol))
            .map_err(|_| TC_ACT_PIPE)?,
    );
    let saddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))?);
    let daddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?);

    if unsafe { is_blocked(saddr)} {
        ctxdrop = 1;
    } else if ip_proto == IPPROTO_TCP {
        let einfo = unsafe { bef_dpi(&ctx) as usize };

        if einfo != 0 {
            elvls[einfo - 1] = (1, 0);                  // Future work: Using bef_dpi get ip address inside payload (as u32)
            if RULE_SET[2] == 1 || RULE_SET[3] == 1 {
                unsafe { update_LOOKUPS(daddr, true).expect("new lookup"); };
            } else if RULE_SET[2] == 2 || RULE_SET[3] == 2 {
                ctxdrop = 1;
            }
        }
        // (?) todo    
        //     if RULE_SET[einfo + 1] == 1 {
        //         unsafe { update_LOOKUPS(daddr, true).expect("new lookup"); };
        //     } else if RULE_SET[einfo + 1] == 2 {
        //         ctxdrop = 1;
        //     }
    }

    //override
    if unsafe { is_verified(saddr) } {
        ctxdrop = 0;
        ctxoveride = 1;
        info!(&ctx, "\tSource address whlisted");
    }

    let event = EventLog {
        etype: 1,
        saddr: saddr,
        daddr: daddr,
        edrop: ctxdrop,
        eovrd: ctxoveride,
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

// --- LSM
#[lsm(name="bpflsm")]
pub fn bpflsm(ctx: LsmContext) -> i32 {
    match unsafe { try_bpflsm(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// TODO: Transfer eMON logic
//Block eBPF program loads (after eLogJ init)
//Block lookup/updates for whlist map
//Block bpf map delete syscalls to eBPF maps
//Supply "state" tracing
unsafe fn try_bpflsm(ctx: LsmContext) -> Result<i32, i32> {    
    let cmd: c_int = ctx.arg(0);
    let attr: *const bpf_attr = ctx.arg(1);
    let size: c_uint = ctx.arg(2);

    // Query file descriptor 
    let query_fd: bpf_attr__bindgen_ty_13 = attr.task_fd_query;

    if cmd == bpf_cmd.BPF_MAP_LOOKUP_ELEM {

    } else if cmd == bpf_cmd.BPF_MAP_UPDATE_ELEM {

    } else if cmd == bpf_cmd.BPF_MAP_DELETE_ELEM {

    }


    // info!(&ctx, "cmd: {}", cmd);
    Ok(0)
}

// ---

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}