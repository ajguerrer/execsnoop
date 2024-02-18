#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use core::{cmp::min, ptr::read_volatile, slice::from_raw_parts};

use aya_bpf::{
    bindings::BPF_NOEXIST,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_probe_read_kernel, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    BpfContext,
};
use execsnoop_common::{Event, DEFAULT_MAX_ARGS, TOTAL_MAX_ARGS, UID_ALL};
use vmlinux::{task_struct, trace_event_raw_sys_enter, trace_event_raw_sys_exit};

#[no_mangle]
static INCLUDE_FAILED: bool = false;

#[no_mangle]
static TARG_UID: u32 = UID_ALL;

#[no_mangle]
static MAX_ARGS: u32 = DEFAULT_MAX_ARGS;

// https://github.com/iovisor/bcc/blob/master/libbpf-tools/execsnoop.bpf.c#L23
const MAX_ENTRIES: u32 = 10240;
#[map]
pub static mut EXECS: HashMap<i32, Event> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
pub static mut EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[tracepoint]
pub fn execsnoop_enter(ctx: TracePointContext) -> u32 {
    // safety: ...Let's just give in. Here be dragons.
    match unsafe { try_execsnoop_enter(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[tracepoint]
pub fn execsnoop_exit(ctx: TracePointContext) -> u32 {
    // safety: Yup, dragons be here too.
    match unsafe { try_execsnoop_exit(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

unsafe fn try_execsnoop_enter(ctx: TracePointContext) -> Result<(), i64> {
    let uid = bpf_get_current_uid_gid() as u32;
    let targ_uid = read_volatile(&TARG_UID);
    if targ_uid != UID_ALL && uid != targ_uid {
        return Ok(());
    }

    let pid = bpf_get_current_pid_tgid() as i32;
    EXECS.insert(&pid, &Event::EMPTY, BPF_NOEXIST as u64)?;
    let event = &mut *EXECS.get_ptr_mut(&pid).ok_or(-1)?;
    event.pid = pid;

    event.uid = uid;

    let current_task = &*(bpf_get_current_task() as *const task_struct);
    let parent = &*bpf_probe_read_kernel(&current_task.parent)?;
    event.ppid = bpf_probe_read_kernel(&parent.tgid)? as i32;

    let enter_ctx = &*(ctx.as_ptr() as *const trace_event_raw_sys_enter);
    bpf_probe_read_user_str_bytes(enter_ctx.args[0] as *const u8, &mut event.args[0])?;
    event.args_count += 1;

    let max_args = min(read_volatile(&MAX_ARGS), TOTAL_MAX_ARGS) as usize;
    let args = from_raw_parts(enter_ctx.args[1] as *const *const u8, max_args);
    for (dest, src) in event.args.iter_mut().zip(args).skip(1) {
        match bpf_probe_read_user(src as *const _) {
            Ok(argp) => bpf_probe_read_user_str_bytes(argp, dest)?,
            // process has no more args to read
            Err(_) => return Ok(()),
        };
        event.args_count += 1;
    }

    Ok(())
}

unsafe fn try_execsnoop_exit(ctx: TracePointContext) -> Result<(), i64> {
    let uid = bpf_get_current_uid_gid() as u32;
    let targ_uid = read_volatile(&TARG_UID);
    if targ_uid != UID_ALL && uid != targ_uid {
        return Ok(());
    }

    let pid = bpf_get_current_pid_tgid() as i32;
    let event = &mut *EXECS.get_ptr_mut(&pid).ok_or(-1)?;

    event.comm = bpf_get_current_comm()?;

    let exit_ctx = &*(ctx.as_ptr() as *const trace_event_raw_sys_exit);
    event.retval = exit_ctx.ret as i32;

    if read_volatile(&INCLUDE_FAILED) || event.retval >= 0 {
        EVENTS.output(&ctx, event, 0);
    }

    EXECS.remove(&pid)?;

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
