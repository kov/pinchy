#![allow(non_snake_case, non_upper_case_globals)]
use std::{
    collections::HashMap,
    io::{self, pipe, PipeWriter, Write as _},
    os::fd::{AsRawFd as _, FromRawFd, OwnedFd},
    sync::Arc,
};

use anyhow::anyhow;
use aya::{maps::perf::AsyncPerfEventArray, programs::TracePoint};
use bytes::BytesMut;
use log::{debug, trace, warn};
use pinchy_common::SyscallEvent;
use tokio::{
    io::unix::AsyncFd,
    signal,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
};
use zbus::{fdo::DBusProxy, message::Header, names::BusName, zvariant::Fd};

mod events;
mod util;

type SharedEbpf = Arc<Mutex<aya::Ebpf>>;
type PipeMap = Arc<Mutex<HashMap<u32, Vec<AsyncFd<PipeWriter>>>>>;

pub fn open_pidfd(pid: libc::pid_t) -> io::Result<OwnedFd> {
    let raw_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw_fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: We just obtained the fd, and it's valid
        Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as i32) })
    }
}

pub fn uid_from_pidfd(fd: &OwnedFd) -> io::Result<u32> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let ret = unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let stat = unsafe { stat.assume_init() };

    Ok(stat.st_uid)
}

pub fn uid_from_pid(pid: u32) -> io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    let proc_path = format!("/proc/{}", pid);
    let meta = std::fs::metadata(proc_path)?;
    Ok(meta.uid())
}

async fn validate_same_user_or_root(
    header: &Header<'_>,
    conn: &zbus::Connection,
    pid: u32,
) -> io::Result<Option<OwnedFd>> {
    trace!("validate_same_user_or_root for PID {}", pid as libc::pid_t);

    // Use a pidfd to ensure we know what process we are talking about.
    let pidfd = open_pidfd(pid as libc::pid_t)?;

    // User who owns the PID.
    let pid_uid = uid_from_pid(pid)?;

    // Check that the pidfd is still valid after reading the uid from /proc/<pid> to ensure the
    // PID hasn't been changed from under us between opening the fd and checking the user id.
    let fd = pidfd.as_raw_fd();
    let pidfd_still_valid = tokio::task::spawn_blocking(move || {
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
    .await
    .unwrap_or_else(|e| {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Join error: {e}"),
        ))
    });
    pidfd_still_valid?;

    trace!("pidfd {} has uid {}", pidfd.as_raw_fd(), pid_uid);

    // User making the tracing request.
    let caller = header.sender().unwrap();
    let bus_name: BusName = caller.as_str().try_into().unwrap();
    let dbus_proxy = DBusProxy::new(conn)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let caller_uid = dbus_proxy
        .get_connection_unix_user(bus_name)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    trace!("dbus request came from uid {caller_uid}");

    if caller_uid == pid_uid || caller_uid == 0 {
        Ok(Some(pidfd))
    } else {
        Ok(None)
    }
}

struct PinchyDBus {
    ebpf: SharedEbpf,
    pipe_map: PipeMap,
}

#[zbus::interface(name = "org.pinchy.Service")]
impl PinchyDBus {
    async fn trace_pid(
        &mut self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        pid: u32,
    ) -> zbus::fdo::Result<Fd> {
        let Some(pidfd) = validate_same_user_or_root(&header, conn, pid)
            .await
            .map_err(|e| zbus::fdo::Error::AuthFailed(e.to_string()))?
        else {
            return Err(zbus::fdo::Error::AuthFailed("Not authorized".to_string()));
        };

        let (read, write) = match pipe() {
            Ok(pair) => pair,
            Err(e) => return Err(zbus::fdo::Error::Failed(e.to_string())),
        };

        let async_pidfd = AsyncFd::new(pidfd).map_err(|e| {
            zbus::fdo::Error::Failed(format!("Failed to wrap pidfd in AsyncFd: {e}"))
        })?;

        add_pid_trace(&self.ebpf, &mut self.pipe_map, pid, write)
            .await
            .map_err(|e| {
                zbus::fdo::Error::Failed(format!("Adding PID {} for tracing: {e}", pid))
            })?;

        // Make sure we stop tracing and drop the state if the PID exits.
        let ebpf = self.ebpf.clone();
        let pipe_map = self.pipe_map.clone();
        tokio::spawn(async move {
            // Wait for the process to exit
            let _ = async_pidfd.readable().await;

            // Remove from eBPF and pipe map
            if let Err(e) = remove_pid_trace(&ebpf, pid).await {
                eprintln!("Failed to remove PID from eBPF: {e}");
            }
            pipe_map.lock().await.remove(&pid);
        });

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

    // Aya considers trying to remove an item that is not in the map an error. This can happen
    // if the pipe is closed by the client, which may cause all the writers for that PID to be
    // removed, which triggers a call to remove_pid_trace() - see events::handle_event().
    if let Ok(_) = pid_filter.get(&pid, 0) {
        match pid_filter.remove(&pid) {
            Ok(_) => Ok(()),
            Err(e) => {
                use aya::maps::MapError;
                match &e {
                    MapError::KeyNotFound | MapError::ElementNotFound => Ok(()),
                    _ => Err(anyhow!(e)),
                }
            }
        }
    } else {
        Ok(())
    }
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

    // The following lines start the basic structure of tasks that handle events. Readers are spawned
    // for each of the per-CPU buffers send events to the main handler channel, spawned on this function.
    // There is also a writer task - handler output is put on its own queue and it can take its time
    // sending it out to the various subscribers.
    let (tx, mut rx) = channel(128);
    spawn_event_readers(&ebpf, tx).await?;

    let (write_tx, write_rx) = channel(128);
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let output = events::handle_event(&event).await;
            if let Err(e) = write_tx.send((output, event.pid)).await {
                eprintln!("FATAL: failed to send output to writer channel: {e}");
                return;
            }
        }
    });

    spawn_event_writer(ebpf.clone(), pipe_map.clone(), write_rx).await;

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

pub async fn spawn_event_writer(
    ebpf: SharedEbpf,
    pipe_map: PipeMap,
    mut rx: Receiver<(String, u32)>,
) {
    tokio::spawn(async move {
        while let Some((output, pid)) = rx.recv().await {
            let mut map = pipe_map.lock().await;
            match map.get_mut(&pid) {
                Some(writers) => {
                    let mut keep = Vec::with_capacity(writers.len());

                    for w in writers.iter_mut() {
                        if let Err(_err) = w
                            .writable_mut()
                            .await
                            .unwrap()
                            .get_inner_mut()
                            .write_all(output.as_bytes())
                        {
                            keep.push(false);
                        } else {
                            keep.push(true);
                        }
                    }

                    // Remove any writers that had errors.
                    let mut keep_iter = keep.iter();
                    writers.retain(|_| *keep_iter.next().unwrap());

                    if writers.is_empty() {
                        if let Err(e) = remove_pid_trace(&ebpf, pid).await {
                            log::error!(
                                "Failed to remove PID {} from eBPF filter map: {}",
                                pid,
                                e.to_string()
                            );
                        }
                        log::trace!("No more writers for PID {}", pid);
                    }
                }
                None => {
                    eprintln!("Unexpected: do not have writers for PID, but still monitoring it...")
                }
            }
        }
    });
}
