#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventLog {
    pub etype: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub edrop: u32,

    // temp
    pub einfo: u32,
}
// Distinct struct fields may induce padding issues (that why we use the same type - u32)

#[cfg(feature = "user")]
unsafe impl aya::Pod for EventLog {}
// Pod trait allows EventLog to be converted to/from a byte-slice