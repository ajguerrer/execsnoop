use anyhow::{bail, Context};
use aya::{include_bytes_aligned, programs::TracePoint, Bpf, BpfLoader};
use clap::Parser;
use execsnoop_common::bool::Bool;

use crate::args::Args;

pub fn init() -> Result<(Args, Bpf), anyhow::Error> {
    let args = Args::parse();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        bail!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let data = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/execsnoop");
    #[cfg(not(debug_assertions))]
    let data = include_bytes_aligned!("../../target/bpfel-unknown-none/release/execsnoop");

    let mut bpf = BpfLoader::new()
        .set_global("INCLUDE_FAILED", &Bool(args.fails), true)
        .set_global("TARG_UID", &args.uid, true)
        .set_global("MAX_ARGS", &args.max_args, true)
        .load(data)?;

    let program: &mut TracePoint = bpf
        .program_mut("execsnoop_enter")
        .context("find execsnoop_enter")?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let program: &mut TracePoint = bpf
        .program_mut("execsnoop_exit")
        .context("find execsnoop_exit")?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_exit_execve")?;

    Ok((args, bpf))
}
