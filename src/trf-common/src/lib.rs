#![no_std]

/** EventLog
 * etype --> Type of event:
 *              0 => Outbound traffic (XDP)
 *              1 => Inbound traffic  (TC)
 *
 * eroute --> [source addres , destination address]
 * eaction --> [ctxdrop , ctxoverride]
 * elvls --> Depends on etype:
 *              0 => [ TCP Traffic (y/n) , HTTP GET (1) or HTTP Resp (2) , LDAP Resp (y/n) ]
 *              1 => [ `${` regex match (y/n) , `${jndi` regex match (y/n) , `:ldap` regex match (y/n) ]
 *                                                                                      |
 *                                                                              assumed that `${jndi` was also found
**/

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventLog {
    pub etype: u32,
    pub eroute: [u32;2usize],
    pub eaction: [u32;2usize],
    pub elvls: [u32;3usize],
}
// Distinct struct fields may induce padding issues (that why we use the same type - u32)

#[cfg(feature = "user")]
unsafe impl aya::Pod for EventLog {}
// Pod trait allows EventLog to be converted to/from a byte-slice