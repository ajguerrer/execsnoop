#![no_std]
#![no_main]

use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[tracepoint]
pub fn execsnoop(ctx: TracePointContext) -> u32 {
    match try_execsnoop(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_execsnoop(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint sys_enter_execve called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
