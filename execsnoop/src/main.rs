pub(crate) mod args;
pub(crate) mod init;
pub(crate) mod print;

use std::mem::size_of;

use anyhow::Context;
use args::Args;
use aya::{
    maps::{
        perf::{AsyncPerfEventArrayBuffer, PerfBufferError},
        AsyncPerfEventArray, MapData,
    },
    util::online_cpus,
};
use execsnoop_common::Event;
use print::{print_event, print_header};
use tokio::{signal, task::spawn};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    let (args, mut bpf) = init::init()?;

    print_header(&args);

    let mut events = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").context("find EVENTS")?)?;
    for cpu_id in online_cpus()? {
        let buf = events.open(cpu_id, None)?;
        let args = args.clone();
        spawn(async move { read_event_loop(cpu_id, args, buf).await });
    }
    signal::ctrl_c().await?;

    Ok(())
}

async fn read_event_loop(
    cpu_id: u32,
    args: Args,
    mut buf: AsyncPerfEventArrayBuffer<MapData>,
) -> Result<(), PerfBufferError> {
    let mut data = [bytes::BytesMut::with_capacity(size_of::<Event>())];
    loop {
        let events = buf.read_events(&mut data).await?;
        for event in &data[..events.read] {
            let event = unsafe { &*(event.as_ptr() as *const Event) };
            print_event(&args, event);
        }

        if events.lost > 0 {
            println!("lost {} events on CPI #{}", events.lost, cpu_id);
        }
    }
}
