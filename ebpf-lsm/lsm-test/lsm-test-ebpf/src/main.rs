#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::{bpf_attr, bpf_cmd};
use aya_bpf::{
    cty::{c_int, c_uint},
    macros::lsm,
    programs::LsmContext,
};
use aya_log_ebpf::info;

#[lsm(name="bpf")]
pub fn bpf(ctx: LsmContext) -> i32 {
    match unsafe { try_bpf(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_bpf(ctx: LsmContext) -> Result<i32, i32> {
    info!(&ctx, "lsm hook bpf called");
    
    let cmd: c_int = ctx.arg(0);
    let attr: *const bpf_attr = ctx.arg(1);
    let size: c_uint = ctx.arg(2);

    info!(&ctx, "cmd: {}", cmd);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
