// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#![allow(non_snake_case, non_upper_case_globals)]
use std::{
    convert::TryFrom,
    fs::File,
    io::{self, pipe, BufRead, BufReader},
    os::fd::{AsRawFd as _, FromRawFd, OwnedFd},
    sync::Arc,
    time::Instant,
};

use anyhow::{anyhow, Context};
use aya::{maps::ProgramArray, programs::TracePoint, Ebpf};
use log::{debug, trace, warn};
use nix::unistd::{setgid, setuid, User};
use pinchy_common::syscalls::{
    syscall_name_from_nr, SYS_brk, SYS_close, SYS_epoll_pwait, SYS_execve, SYS_faccessat,
    SYS_fcntl, SYS_fstat, SYS_futex, SYS_getdents64, SYS_getrandom, SYS_ioctl, SYS_lseek, SYS_mmap,
    SYS_mprotect, SYS_munmap, SYS_newfstatat, SYS_openat, SYS_ppoll, SYS_prlimit64, SYS_read,
    SYS_rseq, SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_sched_yield, SYS_set_robust_list,
    SYS_set_tid_address, SYS_statfs, SYS_uname, SYS_write, ALL_SYSCALLS,
};
use tokio::{
    signal,
    sync::RwLock,
    time::{sleep, Duration},
};
use zbus::{fdo::DBusProxy, message::Header, names::BusName, zvariant::Fd};

use crate::tracing::{EventDispatch, SharedEventDispatch};

mod tracing;

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
    let proc_path = format!("/proc/{pid}");
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
    .unwrap_or_else(|e| Err(io::Error::other(format!("Join error: {e}"))));
    pidfd_still_valid?;

    trace!("pidfd {} has uid {}", pidfd.as_raw_fd(), pid_uid);

    // User making the tracing request.
    let caller = header.sender().unwrap();
    let bus_name: BusName = caller.as_str().try_into().unwrap();
    let dbus_proxy = DBusProxy::new(conn).await.map_err(io::Error::other)?;
    let caller_uid = dbus_proxy
        .get_connection_unix_user(bus_name)
        .await
        .map_err(io::Error::other)?;

    trace!("dbus request came from uid {caller_uid}");

    if caller_uid == pid_uid || caller_uid == 0 {
        Ok(Some(pidfd))
    } else {
        Ok(None)
    }
}

struct PinchyDBus {
    dispatch: SharedEventDispatch,
}

#[zbus::interface(name = "org.pinchy.Service")]
impl PinchyDBus {
    async fn trace_pid(
        &mut self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        pid: u32,
        syscalls: Vec<i64>,
    ) -> zbus::fdo::Result<Fd<'_>> {
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

        let writer = tokio::io::BufWriter::new(tokio::fs::File::from(std::fs::File::from(
            OwnedFd::from(write),
        )));

        let _client_id = self
            .dispatch
            .write()
            .await
            .register_client(pid, writer, syscalls, Some(pidfd))
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(Fd::from(std::os::fd::OwnedFd::from(read)))
    }
}

const IDLE_AFTER_SECONDS: u64 = 15;
fn spawn_auto_quit_task(dispatch: SharedEventDispatch, idle_since: Arc<RwLock<Instant>>) {
    tokio::spawn(async move {
        let idle_timeout = Duration::from_secs(5);

        loop {
            if idle_since.read().await.elapsed().as_secs() >= IDLE_AFTER_SECONDS {
                let pid_count = dispatch.read().await.active_pid_count();
                if pid_count == 0 {
                    println!("Pinchy has been idle for a while, shutting down");
                    unsafe { libc::kill(std::process::id() as i32, libc::SIGINT) };
                    return;
                }
            }

            let pid_count = dispatch.read().await.active_pid_count();
            println!("Currently serving: {pid_count}");
            sleep(idle_timeout).await;
        }
    });
}

fn parse_uid_min() -> u32 {
    let file = File::open("/etc/login.defs");
    if let Ok(file) = file {
        for line in BufReader::new(file).lines() {
            let line = line.expect("Failed to read from /etc/login.defs");
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

    // Keeps track of how long since we handled an event; used to decide when to
    // automatically quit.
    let idle_since = Arc::new(RwLock::new(Instant::now()));

    // The core event dispatch
    let dispatch = EventDispatch::spawn(ebpf, idle_since.clone()).await?;

    spawn_auto_quit_task(dispatch.clone(), idle_since);

    // Start D-Bus service
    let dbus = PinchyDBus { dispatch };

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
    };

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
    prog.load()
        .with_context(|| "trying to load syscall_exit_trivial:".to_string())?;

    // Use the same tail call handler for trivial syscalls.
    const TRIVIAL_SYSCALLS: &[i64] = &[
        SYS_close,
        SYS_lseek,
        SYS_sched_yield,
        SYS_brk,
        SYS_mprotect,
        SYS_getrandom,
        SYS_set_robust_list,
        SYS_set_tid_address,
        SYS_rt_sigprocmask,
        SYS_rt_sigaction,
    ];
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
        ("syscall_exit_newfstatat", SYS_newfstatat),
        ("syscall_exit_getdents64", SYS_getdents64),
        ("syscall_exit_futex", SYS_futex),
        ("syscall_exit_ioctl", SYS_ioctl),
        ("syscall_exit_fcntl", SYS_fcntl),
        ("syscall_exit_execve", SYS_execve),
        ("syscall_exit_mmap", SYS_mmap),
        ("syscall_exit_munmap", SYS_munmap),
        ("syscall_exit_statfs", SYS_statfs),
        ("syscall_exit_prlimit64", SYS_prlimit64),
        ("syscall_exit_rseq", SYS_rseq),
        ("syscall_exit_faccessat", SYS_faccessat),
        ("syscall_exit_uname", SYS_uname),
    ] {
        let prog: &mut TracePoint = ebpf
            .program_mut(prog_name)
            .with_context(|| format!("getting eBPF program {prog_name}"))?
            .try_into()?;
        prog.load()
            .with_context(|| format!("trying to load {prog_name} into eBPF"))?;
        prog_array.set(syscall_nr as u32, prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
        trace!("registered program for {syscall_nr}");
    }

    // Load the generic handler for all other syscalls
    let generic_prog: &mut TracePoint = ebpf
        .program_mut("syscall_exit_generic")
        .with_context(|| "getting syscall_exit_generic".to_string())?
        .try_into()?;
    generic_prog
        .load()
        .with_context(|| "trying to load syscall_exit_generic into eBPF".to_string())?;

    // Register generic handler for all other syscalls
    for &syscall_nr in ALL_SYSCALLS {
        if (0..512).contains(&syscall_nr) && !explicitly_supported.contains(&syscall_nr) {
            prog_array.set(syscall_nr as u32, generic_prog.fd()?, 0)?;
            if let Some(name) = syscall_name_from_nr(syscall_nr) {
                trace!("registered generic handler for syscall {syscall_nr} ({name})");
            }
        }
    }

    Ok(())
}
