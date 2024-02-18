use std::{sync::OnceLock, time::Instant};

use execsnoop_common::Event;
use time::{macros::format_description, OffsetDateTime, UtcOffset};

use crate::args::Args;

pub fn print_header(args: &Args) {
    if args.time {
        print!("{:8} ", "TIME")
    }

    if args.timestamp {
        print!("{:8} ", "TIME(s)")
    }

    if args.print_uid {
        print!("{:6} ", "UID")
    }

    println!("{:16} {:6} {:6} {:3} ARGS", "PCOMM", "PID", "PPID", "RET")
}

pub fn print_event(args: &Args, event: &Event) {
    let comm = event.comm();
    if let Some(name) = &args.name {
        if !comm.contains(name) {
            return;
        }
    }

    if args.time {
        static OFFSET: OnceLock<UtcOffset> = OnceLock::new();
        let offset = OFFSET.get_or_init(|| UtcOffset::current_local_offset().unwrap());
        let time = OffsetDateTime::now_utc().to_offset(*offset);
        let time = time
            .time()
            .format(format_description!("[hour]:[minute]:[second]"))
            .unwrap();
        print!("{:8} ", time)
    }

    if args.timestamp {
        static START: OnceLock<Instant> = OnceLock::new();
        let start = START.get_or_init(Instant::now);
        print!("{:8.3} ", start.elapsed().as_secs_f64())
    }

    if args.print_uid {
        print!("{:6} ", event.uid)
    }

    println!(
        "{:16} {:6} {:6} {:3} {}",
        comm,
        event.pid,
        event.ppid,
        event.retval,
        event.args().collect::<Vec<_>>().join(" "),
    )
}
