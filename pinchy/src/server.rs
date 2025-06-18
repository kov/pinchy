// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#![allow(non_snake_case, non_upper_case_globals)]
use std::{
    collections::HashMap,
    convert::TryFrom,
    fs::File,
    io::{self, pipe, BufRead, BufReader, PipeWriter},
    os::fd::{AsRawFd as _, FromRawFd, OwnedFd},
    sync::Arc,
    time::Instant,
};

use anyhow::anyhow;
use aya::{
    maps::{ring_buf::RingBuf, Array, ProgramArray},
    programs::TracePoint,
    Ebpf,
};
use log::{debug, trace, warn};
use nix::unistd::{setgid, setuid, User};
use pinchy_common::{
    syscalls::{
        syscall_name_from_nr, SYS_close, SYS_epoll_pwait, SYS_execve, SYS_fstat, SYS_futex,
        SYS_getdents64, SYS_ioctl, SYS_lseek, SYS_mmap, SYS_munmap, SYS_openat, SYS_ppoll,
        SYS_read, SYS_sched_yield, SYS_write, ALL_SYSCALLS,
    },
    SyscallEvent,
};
use tokio::{
    io::{unix::AsyncFd, AsyncWriteExt},
    signal,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex, Notify, RwLock,
    },
    time::{sleep, Duration},
};
use zbus::{fdo::DBusProxy, message::Header, names::BusName, zvariant::Fd};

type SharedEbpf = Arc<Mutex<aya::Ebpf>>;
type PipeMap = Arc<Mutex<HashMap<u32, Vec<(tokio::io::BufWriter<tokio::fs::File>, Vec<i64>)>>>>;

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
        syscalls: Vec<i64>,
    ) -> zbus::fdo::Result<Fd> {
        let Some(pidfd) = validate_same_user_or_root(&header, conn, pid)
            .await
            .map_err(|e| zbus::fdo::Error::AuthFailed(e.to_string()))?
        else {
            return Err(zbus::fdo::Error::AccessDenied("Not authorized".to_string()));
        };

        let (read, write) = match pipe() {
            Ok(pair) => pair,
            Err(e) => return Err(zbus::fdo::Error::Failed(e.to_string())),
        };

        let async_pidfd = AsyncFd::new(pidfd).map_err(|e| {
            zbus::fdo::Error::Failed(format!("Failed to wrap pidfd in AsyncFd: {e}"))
        })?;

        add_pid_trace(&self.ebpf, &mut self.pipe_map, pid, write, syscalls)
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

            // Give eBPF a small window for sending out the final events
            sleep(Duration::from_millis(10)).await;

            // Remove from eBPF and pipe map
            trace!("PID {pid} exited, removing from map");
            if let Err(e) = remove_pid_trace(&ebpf, pid).await {
                eprintln!("Failed to remove PID from eBPF: {e}");
            }

            // Flush writers before dropping them, so all data is received by the client.
            if let Some(writers) = pipe_map.lock().await.remove(&pid) {
                for (mut w, _) in writers {
                    let _ = w.flush().await;
                }
            };

            resubscribe_syscalls(&ebpf, &pipe_map).await;
        });

        Ok(Fd::from(std::os::fd::OwnedFd::from(read)))
    }
}

async fn add_pid_trace(
    ebpf: &SharedEbpf,
    pipe_map: &PipeMap,
    pid: u32,
    fd: PipeWriter,
    syscalls: Vec<i64>,
) -> anyhow::Result<()> {
    // WISH: could we have impl From<OwnedFd> for BufWriter pls ;D
    let writer = tokio::io::BufWriter::new(tokio::fs::File::from(std::fs::File::from(
        OwnedFd::from(fd),
    )));

    pipe_map
        .lock()
        .await
        .entry(pid)
        .or_default()
        .push((writer, syscalls));

    {
        let mut ebpf = ebpf.lock().await;
        let mut pid_filter: aya::maps::HashMap<_, u32, u8> = ebpf
            .map_mut("PID_FILTER")
            .ok_or_else(|| anyhow::anyhow!("PID_FILTER map not found"))?
            .try_into()?;
        pid_filter.insert(pid, 0, 0)?;
    }

    resubscribe_syscalls(ebpf, pipe_map).await;

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

async fn resubscribe_syscalls(ebpf: &SharedEbpf, pipe_map: &PipeMap) {
    let mut bitmap = [0u8; 64];

    pipe_map.lock().await.iter().for_each(|(_, writers)| {
        for (_, syscalls) in writers.iter() {
            for &syscall_nr in syscalls.iter() {
                bitmap[(syscall_nr / 8) as usize] |= 1 << (syscall_nr % 8);
            }
        }
    });

    let mut ebpf = ebpf.lock().await;
    let mut map: aya::maps::Array<_, u8> =
        Array::try_from(ebpf.map_mut("SYSCALL_FILTER").unwrap()).unwrap();

    for (i, byte) in bitmap.iter().enumerate() {
        map.set(i as u32, byte, 0).unwrap();
    }
}

const IDLE_AFTER_SECONDS: u64 = 15;
fn spawn_auto_quit_task(ebpf: SharedEbpf, pipe_map: PipeMap, idle_since: Arc<RwLock<Instant>>) {
    tokio::spawn(async move {
        let idle_timeout = Duration::from_secs(5);

        loop {
            if idle_since.read().await.elapsed().as_secs() >= IDLE_AFTER_SECONDS {
                // Hold the lock while notifying waiters, so we are less likely to accept a new
                // connection while quitting.
                let map = pipe_map.lock().await;
                if map.is_empty() {
                    println!("Pinchy has been idle for a while, shutting down");
                    unsafe { libc::kill(std::process::id() as i32, libc::SIGINT) };
                    return;
                }
            } else {
                // We're busy, let's try reaping any dangling writers caused by our clients
                // goind away.
                let mut pids_to_remove = vec![];
                {
                    let mut map = pipe_map.lock().await;
                    trace!("Writers map size before reaping: {}", map.len());
                    println!("Currently serving: {}", map.len());
                    for (&pid, writers) in map.iter_mut() {
                        let mut keep = Vec::with_capacity(writers.len());
                        for (w, _) in writers.iter_mut() {
                            let should_keep = w.flush().await.is_ok();
                            keep.push(should_keep);
                        }

                        // Remove any writers that had errors / closed pipes. FIXME: share code with
                        // event writer task.
                        let mut keep_iter = keep.iter();
                        writers.retain(|_| *keep_iter.next().unwrap());

                        trace!("Writers left for PID {}: {}", pid, writers.len());
                        if writers.is_empty() {
                            pids_to_remove.push(pid);
                        }
                    }

                    // Remove PID from the map here, it gets removed from the trace below.
                    for &pid in &pids_to_remove {
                        map.remove(&pid);
                    }
                }

                for pid in pids_to_remove {
                    if let Err(err) = remove_pid_trace(&ebpf, pid).await {
                        eprintln!("Failed to remove PID {pid} from trace: {err}")
                    };
                }

                resubscribe_syscalls(&ebpf, &pipe_map).await;
                trace!(
                    "Writers map size after reaping: {}",
                    pipe_map.lock().await.len()
                );

                // Not idle, check again soon
                sleep(idle_timeout).await;
            }
        }
    });
}

fn parse_uid_min() -> u32 {
    let file = File::open("/etc/login.defs");
    if let Ok(file) = file {
        for line in BufReader::new(file).lines().flatten() {
            let line = line.trim();
            if line.starts_with("#") || line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            if let (Some(key), Some(val)) = (parts.next(), parts.next()) {
                if key == "UID_MIN" {
                    if let Ok(uid_min) = val.parse::<u32>() {
                        return uid_min;
                    }
                }
            }
        }
    }
    1000 // fallback default
}

fn drop_privileges() -> anyhow::Result<()> {
    let uid_min = parse_uid_min();
    let mut uid = None;
    let mut gid = None;

    if let Ok(Some(user)) = User::from_name("pinchy") {
        if user.uid.as_raw() < uid_min {
            uid = Some(user.uid);
            gid = Some(user.gid);
        }
    }

    if uid.is_none() {
        if let Ok(Some(user)) = User::from_name("nobody") {
            uid = Some(user.uid);
            gid = Some(user.gid);
        }
    }

    let (uid, gid) = match (uid, gid) {
        (Some(uid), Some(gid)) => (uid, gid),
        _ => return Err(anyhow!("No suitable user found for privilege drop")),
    };

    setgid(gid)?;
    setuid(uid)?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_default_env()
        .filter(None, log::LevelFilter::Warn)
        .init();

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

    // Attach execve entry tracepoint for argument capture. This is necessary specifically
    // for execve, as the process gets replaced when it is completed, erasing the data we
    // need, so we need to capture it beforehand.
    let program: &mut TracePoint = ebpf
        .program_mut("syscall_enter_execve")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    load_tailcalls(&mut ebpf)?;

    // Wrap our ebpf object in a way that it can be shared with the various areas of the
    // code that need it.
    let ebpf = Arc::new(Mutex::new(ebpf));

    // The pipes we want to send data to
    let pipe_map = Arc::new(Mutex::new(HashMap::new()));

    let shutdown = Arc::new(Notify::new());

    // The following lines start the basic structure of tasks that handle events. Readers are spawned
    // for each of the per-CPU buffers send events to the main handler channel, spawned on this function.
    // There is also a writer task - handler output is put on its own queue and it can take its time
    // sending it out to the various subscribers.
    let (tx, rx) = channel(128);
    let idle_since = Arc::new(RwLock::new(Instant::now()));
    spawn_event_readers(&ebpf, tx, shutdown.clone(), idle_since.clone()).await?;

    spawn_event_writer(ebpf.clone(), pipe_map.clone(), rx).await;

    spawn_auto_quit_task(ebpf.clone(), pipe_map.clone(), idle_since);

    // Start D-Bus service
    let dbus = PinchyDBus { ebpf, pipe_map };

    // We allow requesting usage of the session bus, mostly for the tests.
    let (conn, bus_type) = match std::env::var("PINCHYD_USE_SESSION_BUS") {
        Ok(value) if value == "true" => (zbus::Connection::session().await?, "session"),
        _ => (zbus::Connection::system().await?, "system"),
    };

    conn.object_server().at("/org/pinchy/Service", dbus).await?;
    conn.request_name("org.pinchy.Service").await?;
    println!("Pinchy D-Bus service started on {bus_type} bus");

    // Drop privileges. At this point we have created maps, loaded programs, opened
    // event buffers and obtained our well-known D-Bus name, so we can diminish and
    // go into the West.
    drop_privileges()?;

    let ctrl_c = signal::ctrl_c();

    println!("Waiting for Ctrl-C...");
    tokio::select! {
        result = ctrl_c => {
            eprintln!("Ctrl-C received...");
            conn.close().await?;
            result?;
        },
        _ = shutdown.notified() => conn.close().await?,
    };

    shutdown.notify_waiters();

    println!("Exiting...");

    Ok(())
}

fn load_tailcalls(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut prog_array = ProgramArray::try_from(
        ebpf.take_map("SYSCALL_TAILCALLS")
            .ok_or_else(|| anyhow::anyhow!("SYSCALL_TAILCALLS map not found"))?,
    )?;

    // Track which syscalls have explicit handlers
    let mut explicitly_supported = std::collections::HashSet::new();

    let prog: &mut TracePoint = ebpf
        .program_mut("syscall_exit_trivial")
        .unwrap()
        .try_into()?;
    prog.load()?;

    // Use the same tail call handler for trivial syscalls.
    const TRIVIAL_SYSCALLS: &[i64] = &[SYS_close, SYS_lseek, SYS_sched_yield];
    for &syscall_nr in TRIVIAL_SYSCALLS {
        prog_array.set(syscall_nr as u32, prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
    }

    for (prog_name, syscall_nr) in [
        ("syscall_exit_epoll_pwait", SYS_epoll_pwait),
        ("syscall_exit_ppoll", SYS_ppoll),
        ("syscall_exit_read", SYS_read),
        ("syscall_exit_write", SYS_write),
        ("syscall_exit_openat", SYS_openat),
        ("syscall_exit_fstat", SYS_fstat),
        ("syscall_exit_getdents64", SYS_getdents64),
        ("syscall_exit_futex", SYS_futex),
        ("syscall_exit_ioctl", SYS_ioctl),
        ("syscall_exit_execve", SYS_execve),
        ("syscall_exit_mmap", SYS_mmap),
        ("syscall_exit_munmap", SYS_munmap),
    ] {
        let prog: &mut TracePoint = ebpf.program_mut(prog_name).unwrap().try_into()?;
        prog.load()?;
        prog_array.set(syscall_nr as u32, prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
        trace!("registered program for {}", syscall_nr);
    }

    // Load the generic handler for all other syscalls
    let generic_prog: &mut TracePoint = ebpf
        .program_mut("syscall_exit_generic")
        .unwrap()
        .try_into()?;
    generic_prog.load()?;

    // Register generic handler for all other syscalls
    for &syscall_nr in ALL_SYSCALLS {
        if syscall_nr >= 0 && syscall_nr < 512 && !explicitly_supported.contains(&syscall_nr) {
            prog_array.set(syscall_nr as u32, generic_prog.fd()?, 0)?;
            if let Some(name) = syscall_name_from_nr(syscall_nr) {
                trace!(
                    "registered generic handler for syscall {} ({})",
                    syscall_nr,
                    name
                );
            }
        }
    }

    Ok(())
}

pub async fn spawn_event_readers(
    ebpf: &SharedEbpf,
    tx: Sender<SyscallEvent>,
    shutdown: Arc<Notify>,
    idle_since: Arc<RwLock<Instant>>,
) -> anyhow::Result<()> {
    let ring = RingBuf::try_from(
        ebpf.lock()
            .await
            .take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("EVENTS map not found"))?,
    )?;
    let mut async_ring = AsyncFd::new(ring)?;
    let tx = tx.clone();
    let shutdown = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    trace!("[ringbuf reader] Shutdown requested, stopping...");
                    return;
                }
                result = async_ring.readable_mut() => {
                    match result {
                        Ok(mut guard) => {
                            // Bump the idle timer.
                            *idle_since.write().await = Instant::now();

                            let ring = guard.get_inner_mut();
                            while let Some(item) = ring.next() {
                                let event = &*item;
                                if event.len() == std::mem::size_of::<SyscallEvent>() {
                                    let syscall_event: SyscallEvent = unsafe { std::ptr::read_unaligned(event.as_ptr() as *const _) };
                                    let _ = tx.send(syscall_event).await;
                                }
                            }
                            guard.clear_ready();
                        }
                        Err(e) => {
                            eprintln!("RingBuf read error: {e}");
                            return;
                        }
                    }
                }
            }
        }
    });
    Ok(())
}

pub async fn spawn_event_writer(
    ebpf: SharedEbpf,
    pipe_map: PipeMap,
    mut rx: Receiver<SyscallEvent>,
) {
    tokio::spawn(async move {
        let mut events_buf = Vec::with_capacity(128);
        loop {
            let received = rx.recv_many(&mut events_buf, 128).await;
            if received == 0 {
                break;
            }

            let mut map = pipe_map.lock().await;

            let mut pids_to_remove = vec![];
            let mut writer_removed = false;
            for i in 0..received {
                let event = &mut events_buf[i];
                match map.get_mut(&event.pid) {
                    Some(writers) => {
                        let mut keep = Vec::with_capacity(writers.len());

                        for (w, syscalls_to_trace) in writers.iter_mut() {
                            if !syscalls_to_trace.contains(&event.syscall_nr) {
                                keep.push(true);
                                continue;
                            }
                            let event_bytes: &[u8] = unsafe {
                                std::slice::from_raw_parts(
                                    event as *const SyscallEvent as *const u8,
                                    size_of::<SyscallEvent>(),
                                )
                            };
                            if let Err(_err) = w.write_all(event_bytes).await {
                                keep.push(false);
                                writer_removed = true;
                            } else {
                                keep.push(true);
                            }
                        }

                        // Remove any writers that had errors.
                        let mut keep_iter = keep.iter();
                        writers.retain(|_| *keep_iter.next().unwrap());

                        // Release the map as early as we can, it will be locked again by
                        // the helpers called below.
                        if writers.is_empty() {
                            pids_to_remove.push(event.pid);
                        }
                    }
                    None => {
                        eprintln!(
                            "Unexpected: do not have writers for PID, but still monitoring it..."
                        );
                        if let Err(e) = remove_pid_trace(&ebpf, event.pid).await {
                            log::error!(
                                "Failed to remove PID {} from eBPF filter map: {}",
                                event.pid,
                                e.to_string()
                            );
                        }
                        log::trace!("No more writers for PID {}", event.pid);
                    }
                }
            }

            events_buf.clear();

            for &pid in &pids_to_remove {
                map.remove(&pid);
            }

            drop(map);

            for &pid in &pids_to_remove {
                if let Err(err) = remove_pid_trace(&ebpf, pid).await {
                    eprintln!("Failed to remove PID {pid} from trace: {err}")
                };
            }

            if writer_removed || !pids_to_remove.is_empty() {
                resubscribe_syscalls(&ebpf, &pipe_map).await;
            }
        }
    });
}
