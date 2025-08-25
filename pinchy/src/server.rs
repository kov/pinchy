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
use pinchy_common::syscalls::{self, syscall_name_from_nr};
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
    env_logger::init();

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

    // Keep track of how long it takes to load the eBPF programs.
    let now = Instant::now();

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

    // Attach execveat entry tracepoint for argument capture. This is necessary specifically
    // for execveat, as the process gets replaced when it is completed, erasing the data we
    // need, so we need to capture it beforehand.
    let program: &mut TracePoint = ebpf
        .program_mut("syscall_enter_execveat")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execveat")?;

    load_tailcalls(&mut ebpf)?;

    println!("Loaded eBPF programs in {:?}", now.elapsed());

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
        syscalls::SYS_close,
        syscalls::SYS_dup3,
        syscalls::SYS_fcntl,
        syscalls::SYS_lseek,
        syscalls::SYS_sched_yield,
        syscalls::SYS_getpid,
        syscalls::SYS_gettid,
        syscalls::SYS_getuid,
        syscalls::SYS_geteuid,
        syscalls::SYS_getgid,
        syscalls::SYS_getegid,
        syscalls::SYS_getppid,
        syscalls::SYS_brk,
        syscalls::SYS_mprotect,
        syscalls::SYS_getrandom,
        syscalls::SYS_set_robust_list,
        syscalls::SYS_set_tid_address,
        syscalls::SYS_rt_sigaction,
        syscalls::SYS_rt_sigqueueinfo,
        syscalls::SYS_rt_tgsigqueueinfo,
        syscalls::SYS_fchdir,
        syscalls::SYS_exit_group,
        syscalls::SYS_rt_sigreturn,
        syscalls::SYS_dup,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_dup2,
        syscalls::SYS_sync,
        syscalls::SYS_setsid,
        syscalls::SYS_setuid,
        syscalls::SYS_setgid,
        syscalls::SYS_close_range,
        syscalls::SYS_getpgid,
        syscalls::SYS_getsid,
        syscalls::SYS_setpgid,
        syscalls::SYS_umask,
        syscalls::SYS_vhangup,
        syscalls::SYS_ioprio_get,
        syscalls::SYS_ioprio_set,
        syscalls::SYS_setregid,
        syscalls::SYS_setresgid,
        syscalls::SYS_setresuid,
        syscalls::SYS_setreuid,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_alarm,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_pause,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_getpgrp,
        syscalls::SYS_personality,
        syscalls::SYS_getpriority,
        syscalls::SYS_setpriority,
        syscalls::SYS_tkill,
        syscalls::SYS_tgkill,
        syscalls::SYS_kill,
        syscalls::SYS_exit,
        syscalls::SYS_sched_getscheduler,
        syscalls::SYS_setfsuid,
        syscalls::SYS_setfsgid,
        syscalls::SYS_sched_get_priority_max,
        syscalls::SYS_sched_get_priority_min,
        syscalls::SYS_socket,
        syscalls::SYS_listen,
        syscalls::SYS_shutdown,
        syscalls::SYS_fsync,
        syscalls::SYS_fsmount,
        syscalls::SYS_fdatasync,
        syscalls::SYS_ftruncate,
        syscalls::SYS_fchmod,
        syscalls::SYS_fchown,
        syscalls::SYS_flock,
        syscalls::SYS_truncate,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_epoll_create,
        syscalls::SYS_epoll_create1,
        syscalls::SYS_pidfd_open,
        syscalls::SYS_pidfd_getfd,
        syscalls::SYS_process_mrelease,
        syscalls::SYS_mlock,
        syscalls::SYS_mlock2,
        syscalls::SYS_mlockall,
        syscalls::SYS_membarrier,
        syscalls::SYS_mremap,
        syscalls::SYS_msync,
        syscalls::SYS_munlock,
        syscalls::SYS_munlockall,
        syscalls::SYS_readahead,
        syscalls::SYS_setns,
        syscalls::SYS_unshare,
        syscalls::SYS_memfd_secret,
        syscalls::SYS_userfaultfd,
        syscalls::SYS_pkey_alloc,
        syscalls::SYS_pkey_free,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_eventfd,
        syscalls::SYS_eventfd2,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_inotify_init,
        syscalls::SYS_inotify_init1,
        syscalls::SYS_inotify_rm_watch,
        syscalls::SYS_timer_delete,
        syscalls::SYS_timer_getoverrun,
    ];
    for &syscall_nr in TRIVIAL_SYSCALLS {
        prog_array.set(syscall_nr as u32, prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
    }

    for (prog_name, syscall_nr) in [
        ("syscall_exit_execve", syscalls::SYS_execve),
        ("syscall_exit_rseq", syscalls::SYS_rseq),
        (
            "syscall_exit_sched_setscheduler",
            syscalls::SYS_sched_setscheduler,
        ),
    ] {
        let prog: &mut aya::programs::TracePoint = ebpf
            .program_mut(prog_name)
            .context("missing tailcall")?
            .try_into()?;
        prog.load()
            .with_context(|| format!("trying to load {prog_name} into eBPF"))?;
        prog_array.set(syscall_nr as u32, prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
    }

    // Network syscalls - all handled by the unified network handler
    const NETWORK_SYSCALLS: &[i64] = &[
        syscalls::SYS_recvmsg,
        syscalls::SYS_sendmsg,
        syscalls::SYS_accept,
        syscalls::SYS_accept4,
        syscalls::SYS_recvfrom,
        syscalls::SYS_sendto,
        syscalls::SYS_bind,
        syscalls::SYS_connect,
        syscalls::SYS_socketpair,
        syscalls::SYS_getsockname,
        syscalls::SYS_getpeername,
        syscalls::SYS_setsockopt,
        syscalls::SYS_getsockopt,
        syscalls::SYS_recvmmsg,
        syscalls::SYS_sendmmsg,
    ];
    let network_prog: &mut aya::programs::TracePoint = ebpf
        .program_mut("syscall_exit_network")
        .context("missing network handler")?
        .try_into()?;
    network_prog
        .load()
        .context("trying to load syscall_exit_network into eBPF")?;
    for &syscall_nr in NETWORK_SYSCALLS {
        prog_array.set(syscall_nr as u32, network_prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
    }

    // Filesystem syscalls - all handled by the unified filesystem handler
    const FILESYSTEM_SYSCALLS: &[i64] = &[
        syscalls::SYS_fstat,
        syscalls::SYS_newfstatat,
        syscalls::SYS_getdents64,
        syscalls::SYS_statfs,
        syscalls::SYS_fstatfs,
        syscalls::SYS_fsopen,
        syscalls::SYS_fsconfig,
        syscalls::SYS_fspick,
        syscalls::SYS_statx,
        syscalls::SYS_faccessat,
        syscalls::SYS_fallocate,
        syscalls::SYS_readlinkat,
        syscalls::SYS_getcwd,
        syscalls::SYS_chdir,
        syscalls::SYS_mkdirat,
        syscalls::SYS_flistxattr,
        syscalls::SYS_listxattr,
        syscalls::SYS_llistxattr,
        syscalls::SYS_setxattr,
        syscalls::SYS_lsetxattr,
        syscalls::SYS_fsetxattr,
        syscalls::SYS_getxattr,
        syscalls::SYS_lgetxattr,
        syscalls::SYS_fgetxattr,
        syscalls::SYS_removexattr,
        syscalls::SYS_lremovexattr,
        syscalls::SYS_fremovexattr,
        syscalls::SYS_fchmodat,
        syscalls::SYS_fchownat,
        syscalls::SYS_renameat,
        syscalls::SYS_renameat2,
        syscalls::SYS_unlinkat,
        syscalls::SYS_symlinkat,
        syscalls::SYS_linkat,
        syscalls::SYS_acct,
        syscalls::SYS_mknodat,
        syscalls::SYS_pivot_root,
        syscalls::SYS_chroot,
        syscalls::SYS_open_tree,
        syscalls::SYS_mount,
        syscalls::SYS_umount2,
        syscalls::SYS_mount_setattr,
        syscalls::SYS_move_mount,
        syscalls::SYS_swapon,
        syscalls::SYS_swapoff,
        syscalls::SYS_inotify_add_watch,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_chown,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_lchown,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_rename,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_rmdir,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_unlink,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_symlink,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_link,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_mknod,
        syscalls::SYS_truncate,
    ];
    let filesystem_prog: &mut aya::programs::TracePoint = ebpf
        .program_mut("syscall_exit_filesystem")
        .context("missing filesystem handler")?
        .try_into()?;
    filesystem_prog
        .load()
        .context("trying to load syscall_exit_filesystem into eBPF")?;
    for &syscall_nr in FILESYSTEM_SYSCALLS {
        prog_array.set(syscall_nr as u32, filesystem_prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
    }

    // Basic I/O syscalls - all handled by the unified basic_io handler
    const BASIC_IO_SYSCALLS: &[i64] = &[
        syscalls::SYS_openat,
        syscalls::SYS_openat2,
        syscalls::SYS_read,
        syscalls::SYS_write,
        syscalls::SYS_pread64,
        syscalls::SYS_pwrite64,
        syscalls::SYS_readv,
        syscalls::SYS_writev,
        syscalls::SYS_preadv,
        syscalls::SYS_pwritev,
        syscalls::SYS_preadv2,
        syscalls::SYS_pwritev2,
        syscalls::SYS_epoll_pwait,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_epoll_wait,
        syscalls::SYS_epoll_pwait2,
        syscalls::SYS_epoll_ctl,
        syscalls::SYS_ppoll,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_poll,
        syscalls::SYS_pselect6,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_select,
        syscalls::SYS_pipe2,
        syscalls::SYS_splice,
        syscalls::SYS_tee,
        syscalls::SYS_vmsplice,
    ];
    let basic_io_prog: &mut aya::programs::TracePoint = ebpf
        .program_mut("syscall_exit_basic_io")
        .context("missing basic_io handler")?
        .try_into()?;
    basic_io_prog
        .load()
        .context("trying to load syscall_exit_basic_io into eBPF")?;
    for &syscall_nr in BASIC_IO_SYSCALLS {
        prog_array.set(syscall_nr as u32, basic_io_prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
    }

    // Memory syscalls - all handled by the unified memory handler
    const MEMORY_SYSCALLS: &[i64] = &[
        syscalls::SYS_mmap,
        syscalls::SYS_munmap,
        syscalls::SYS_madvise,
        syscalls::SYS_process_madvise,
        syscalls::SYS_process_vm_readv,
        syscalls::SYS_process_vm_writev,
    ];
    let memory_prog: &mut aya::programs::TracePoint = ebpf
        .program_mut("syscall_exit_memory")
        .context("missing memory handler")?
        .try_into()?;
    memory_prog
        .load()
        .context("trying to load syscall_exit_memory into eBPF")?;
    for &syscall_nr in MEMORY_SYSCALLS {
        prog_array.set(syscall_nr as u32, memory_prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
    }

    // System syscalls - all handled by the unified system handler
    const SYSTEM_SYSCALLS: &[i64] = &[
        syscalls::SYS_reboot,
        syscalls::SYS_uname,
        syscalls::SYS_ioctl,
        syscalls::SYS_gettimeofday,
        syscalls::SYS_settimeofday,
        syscalls::SYS_sysinfo,
        syscalls::SYS_times,
        syscalls::SYS_nanosleep,
        syscalls::SYS_clock_nanosleep,
        syscalls::SYS_getcpu,
        syscalls::SYS_capget,
        syscalls::SYS_capset,
        syscalls::SYS_setrlimit,
        syscalls::SYS_getrlimit,
        syscalls::SYS_init_module,
        syscalls::SYS_finit_module,
        syscalls::SYS_delete_module,
        syscalls::SYS_sethostname,
        syscalls::SYS_setdomainname,
    ];
    let system_prog: &mut aya::programs::TracePoint = ebpf
        .program_mut("syscall_exit_system")
        .context("missing system handler")?
        .try_into()?;
    system_prog
        .load()
        .context("trying to load syscall_exit_system into eBPF")?;
    for &syscall_nr in SYSTEM_SYSCALLS {
        prog_array.set(syscall_nr as u32, system_prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
    }

    // IPC syscalls - all handled by the unified IPC handler
    const IPC_SYSCALLS: &[i64] = &[
        syscalls::SYS_shmget,
        syscalls::SYS_shmat,
        syscalls::SYS_shmdt,
        syscalls::SYS_shmctl,
        syscalls::SYS_msgget,
        syscalls::SYS_msgsnd,
        syscalls::SYS_msgrcv,
        syscalls::SYS_msgctl,
        syscalls::SYS_semget,
        syscalls::SYS_semop,
        syscalls::SYS_semctl,
    ];
    let ipc_prog: &mut aya::programs::TracePoint = ebpf
        .program_mut("syscall_exit_ipc")
        .context("missing IPC handler")?
        .try_into()?;
    ipc_prog
        .load()
        .context("trying to load syscall_exit_ipc into eBPF")?;
    for &syscall_nr in IPC_SYSCALLS {
        prog_array.set(syscall_nr as u32, ipc_prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
    }

    // Sync syscalls - all handled by the unified sync handler
    const SYNC_SYSCALLS: &[i64] = &[
        syscalls::SYS_futex,
        syscalls::SYS_futex_waitv,
        syscalls::SYS_get_robust_list,
    ];
    let sync_prog: &mut aya::programs::TracePoint = ebpf
        .program_mut("syscall_exit_sync")
        .context("missing sync handler")?
        .try_into()?;
    sync_prog
        .load()
        .context("trying to load syscall_exit_sync into eBPF")?;
    for &syscall_nr in SYNC_SYSCALLS {
        prog_array.set(syscall_nr as u32, sync_prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
    }

    // Time syscalls - all handled by the unified time handler
    const TIME_SYSCALLS: &[i64] = &[
        syscalls::SYS_adjtimex,
        syscalls::SYS_clock_adjtime,
        syscalls::SYS_clock_getres,
        syscalls::SYS_clock_gettime,
        syscalls::SYS_clock_settime,
        syscalls::SYS_timer_create,
        syscalls::SYS_timer_gettime,
        syscalls::SYS_timer_settime,
    ];
    let time_prog: &mut aya::programs::TracePoint = ebpf
        .program_mut("syscall_exit_time")
        .context("missing time handler")?
        .try_into()?;
    time_prog
        .load()
        .context("trying to load syscall_exit_time into eBPF")?;
    for &syscall_nr in TIME_SYSCALLS {
        prog_array.set(syscall_nr as u32, time_prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
    }

    // Process syscalls - all handled by the unified process handler
    const PROCESS_SYSCALLS: &[i64] = &[
        syscalls::SYS_wait4,
        syscalls::SYS_waitid,
        syscalls::SYS_getrusage,
        syscalls::SYS_clone3,
        syscalls::SYS_clone,
        syscalls::SYS_pidfd_send_signal,
        syscalls::SYS_prlimit64,
    ];
    let process_prog: &mut aya::programs::TracePoint = ebpf
        .program_mut("syscall_exit_process")
        .context("missing process handler")?
        .try_into()?;
    process_prog
        .load()
        .context("trying to load syscall_exit_process into eBPF")?;
    for &syscall_nr in PROCESS_SYSCALLS {
        prog_array.set(syscall_nr as u32, process_prog.fd()?, 0)?;
        explicitly_supported.insert(syscall_nr);
    }

    for (prog_name, syscall_nr) in [
        (
            "syscall_exit_sched_getaffinity",
            syscalls::SYS_sched_getaffinity,
        ),
        (
            "syscall_exit_sched_setaffinity",
            syscalls::SYS_sched_setaffinity,
        ),
        ("syscall_exit_sched_getparam", syscalls::SYS_sched_getparam),
        ("syscall_exit_sched_setparam", syscalls::SYS_sched_setparam),
        (
            "syscall_exit_sched_rr_get_interval",
            syscalls::SYS_sched_rr_get_interval,
        ),
        ("syscall_exit_sched_getattr", syscalls::SYS_sched_getattr),
        ("syscall_exit_sched_setattr", syscalls::SYS_sched_setattr),
        ("syscall_exit_sigaltstack", syscalls::SYS_sigaltstack),
        ("syscall_exit_rt_sigprocmask", syscalls::SYS_rt_sigprocmask),
        ("syscall_exit_rt_sigpending", syscalls::SYS_rt_sigpending),
        ("syscall_exit_rt_sigsuspend", syscalls::SYS_rt_sigsuspend),
        (
            "syscall_exit_rt_sigtimedwait",
            syscalls::SYS_rt_sigtimedwait,
        ),
        #[cfg(target_arch = "x86_64")]
        ("syscall_exit_signalfd", syscalls::SYS_signalfd),
        ("syscall_exit_signalfd4", syscalls::SYS_signalfd4),
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

        // FIXME: this is a hack to keep the change small for adding support for this syscall, but we will likely
        // move to a different model with shared tracepoints for groups of syscalls in the future.
        if syscall_nr == syscalls::SYS_execve {
            prog_array.set(syscalls::SYS_execveat as u32, prog.fd()?, 0)?;
            explicitly_supported.insert(syscalls::SYS_execveat);
        }
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
    for &syscall_nr in syscalls::ALL_SYSCALLS {
        if (0..512).contains(&syscall_nr) && !explicitly_supported.contains(&syscall_nr) {
            prog_array.set(syscall_nr as u32, generic_prog.fd()?, 0)?;
            if let Some(name) = syscall_name_from_nr(syscall_nr) {
                trace!("registered generic handler for syscall {syscall_nr} ({name})");
            }
        }
    }

    Ok(())
}
