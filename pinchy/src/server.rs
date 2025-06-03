#![allow(non_snake_case, non_upper_case_globals)]
use std::{
    collections::HashMap,
    io::{pipe, PipeWriter},
    os::fd::FromRawFd,
    sync::Arc,
};

use anyhow::anyhow;
use aya::{maps::perf::AsyncPerfEventArray, programs::TracePoint};
use bytes::BytesMut;
use log::{debug, warn};
use pinchy_common::SyscallEvent;
use tokio::{
    io::unix::AsyncFd,
    signal,
    sync::{
        mpsc::{channel, Sender},
        Mutex,
    },
};
use zbus::zvariant::Fd;

mod events;
mod util;

type SharedEbpf = Arc<Mutex<aya::Ebpf>>;
type PipeMap = Arc<Mutex<HashMap<u32, Vec<AsyncFd<PipeWriter>>>>>;

struct PinchyDBus {
    ebpf: SharedEbpf,
    pipe_map: PipeMap,
}

#[zbus::interface(name = "org.pinchy.Service")]
impl PinchyDBus {
    async fn trace_pid(&mut self, pid: u32) -> zbus::fdo::Result<Fd> {
        let (read, write) = match pipe() {
            Ok(pair) => pair,
            Err(e) => return Err(zbus::fdo::Error::Failed(e.to_string())),
        };

        add_pid_trace(&self.ebpf, &mut self.pipe_map, pid, write)
            .await
            .map_err(|e| {
                zbus::fdo::Error::Failed(format!(
                    "Adding PID {} for tracing: {}",
                    pid,
                    e.to_string()
                ))
            })?;

        Ok(Fd::from(std::os::fd::OwnedFd::from(read)))
    }
}

async fn add_pid_trace(
    ebpf: &SharedEbpf,
    pipe_map: &PipeMap,
    pid: u32,
    fd: PipeWriter,
) -> anyhow::Result<()> {
    pipe_map
        .lock()
        .await
        .entry(pid)
        .or_default()
        .push(AsyncFd::new(fd).expect("Wrapping in AsyncFd"));

    let mut ebpf = ebpf.lock().await;
    let mut pid_filter: aya::maps::HashMap<_, u32, u8> = ebpf
        .map_mut("PID_FILTER")
        .ok_or_else(|| anyhow::anyhow!("PID_FILTER map not found"))?
        .try_into()?;
    pid_filter.insert(pid, 0, 0)?;
    Ok(())
}

// Removal from the pipe map is handled separately
async fn remove_pid_trace(ebpf: &SharedEbpf, pid: u32) -> anyhow::Result<()> {
    let mut ebpf = ebpf.lock().await;
    let mut pid_filter: aya::maps::HashMap<_, u32, u8> = ebpf
        .map_mut("PID_FILTER")
        .expect("PID_FILTER map not found")
        .try_into()
        .expect("Map conversion failed");
    pid_filter.remove(&pid).map_err(|e| anyhow!(e))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Expect first argument to be the PID to monitor
    let pid = if let Some(first) = std::env::args().nth(1) {
        Some(
            first
                .parse::<u32>()
                .map_err(|_| anyhow::anyhow!("PID must be a valid u32"))?,
        )
    } else {
        None
    };

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

    let program: &mut TracePoint = ebpf.program_mut("pinchy").unwrap().try_into()?;
    program.load()?;
    program.attach("raw_syscalls", "sys_enter")?;

    let program: &mut TracePoint = ebpf.program_mut("pinchy_exit").unwrap().try_into()?;
    program.load()?;
    program.attach("raw_syscalls", "sys_exit")?;

    // Wrap our ebpf object in a way that it can be shared with the various areas of the
    // code that need it.
    let ebpf = Arc::new(Mutex::new(ebpf));

    // The pipes we want to send data to
    let pipe_map = Arc::new(Mutex::new(HashMap::new()));

    let (tx, mut rx) = channel(128);
    spawn_event_readers(&ebpf, tx).await?;
    let tebpf = ebpf.clone();
    let tpipe_map = pipe_map.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            events::handle_event(event, tebpf.clone(), tpipe_map.clone()).await;
        }
    });

    // If we did get a PID as argument, monitor and print that to our own stdout.
    if let Some(pid) = pid {
        add_pid_trace(&ebpf, &pipe_map, pid, unsafe { PipeWriter::from_raw_fd(1) }).await?;
    }

    // Start D-Bus service on system bus
    let dbus = PinchyDBus { ebpf, pipe_map };
    let conn = zbus::Connection::system().await?;
    conn.object_server().at("/org/pinchy/Service", dbus).await?;
    conn.request_name("org.pinchy.Service").await?;
    println!("Pinchy D-Bus service started on system bus");

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

pub async fn spawn_event_readers(
    ebpf: &SharedEbpf,
    tx: Sender<SyscallEvent>,
) -> anyhow::Result<()> {
    let mut events = AsyncPerfEventArray::try_from(
        ebpf.lock()
            .await
            .take_map("EVENTS")
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
