#![allow(non_snake_case, non_upper_case_globals)]
use std::borrow::Cow;

use aya::{maps::perf::AsyncPerfEventArray, programs::TracePoint};
use bytes::BytesMut;
use log::{debug, warn};
use pinchy_common::{syscalls::SYS_ppoll, SyscallEvent};
use tokio::{
    signal,
    sync::mpsc::{channel, Sender},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Expect first argument to be the PID to monitor
    let pid: u32 = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Please provide a PID as the first argument"))?
        .parse()
        .map_err(|_| anyhow::anyhow!("PID must be a valid u32"))?;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/pinchy"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    // Set the PIDs we want to trace...
    let mut pid_filter: aya::maps::HashMap<_, u32, u8> = ebpf
        .map_mut("PID_FILTER")
        .ok_or_else(|| anyhow::anyhow!("PID_FILTER map not found"))?
        .try_into()?;
    pid_filter.insert(pid, 0, 0)?;

    let program: &mut TracePoint = ebpf.program_mut("pinchy").unwrap().try_into()?;
    program.load()?;
    program.attach("raw_syscalls", "sys_enter")?;

    let program: &mut TracePoint = ebpf.program_mut("pinchy_exit").unwrap().try_into()?;
    program.load()?;
    program.attach("raw_syscalls", "sys_exit")?;

    let (tx, mut rx) = channel(128);
    spawn_event_readers(&mut ebpf, tx).await?;
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event.syscall_nr {
                SYS_ppoll => {
                    let data = unsafe { event.data.ppoll };

                    let return_meaning = match event.return_value {
                        0 => Cow::Borrowed("Timeout (0)"),
                        -1 => Cow::Borrowed("Error (-1)"),
                        _ => Cow::Owned(format!("{} fds ready", event.return_value)),
                    };

                    println!(
                        "[{}] ppoll(fds: {:?}, nfds = {}) = {}",
                        event.tid,
                        &data.fds[..data.nfds as usize],
                        data.nfds,
                        return_meaning
                    );
                }
                _ => println!("[{}] unknown syscall {}", event.tid, event.syscall_nr),
            }
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

pub async fn spawn_event_readers(
    ebpf: &mut aya::Ebpf,
    tx: Sender<SyscallEvent>,
) -> anyhow::Result<()> {
    let mut events = AsyncPerfEventArray::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("EVENTS map not found"))?,
    )?;
    let cpus = aya::util::online_cpus().map_err(|e| anyhow::anyhow!("online_cpus: {:?}", e))?;
    for cpu_id in cpus {
        let mut bufs = vec![BytesMut::with_capacity(4096)];
        let mut buf_events = events.open(cpu_id, None)?;
        let tx = tx.clone();
        tokio::spawn(async move {
            loop {
                match buf_events.read_events(&mut bufs).await {
                    Ok(evts) => {
                        for i in 0..evts.read {
                            let event = &bufs[i];
                            let syscall_event: SyscallEvent =
                                unsafe { std::ptr::read_unaligned(event.as_ptr() as *const _) };
                            let _ = tx.send(syscall_event).await;
                        }
                    }
                    Err(e) => {
                        eprintln!("PerfEventArray read error: {e}");
                        break;
                    }
                }
            }
        });
    }
    Ok(())
}
