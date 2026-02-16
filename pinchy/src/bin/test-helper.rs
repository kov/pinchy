mod syslog_constants {
    pub const SYSLOG_ACTION_READ_ALL: i32 = 3;
    pub const SYSLOG_ACTION_CLEAR: i32 = 5;
    pub const SYSLOG_ACTION_CONSOLE_OFF: i32 = 6;
    pub const SYSLOG_ACTION_CONSOLE_ON: i32 = 7;
    pub const SYSLOG_ACTION_CONSOLE_LEVEL: i32 = 8;
    pub const SYSLOG_ACTION_SIZE_UNREAD: i32 = 9;
    pub const SYSLOG_ACTION_SIZE_BUFFER: i32 = 10;
}

use std::{
    env::{current_dir, set_current_dir},
    ffi::{c_void, CString},
    fs,
    path::PathBuf,
};

use anyhow::bail;
use pinchy_common::{syscalls, DATA_READ_SIZE};

/// Returns the workspace root by walking up from the crate root.
fn find_workspace_root(mut dir: PathBuf) -> PathBuf {
    loop {
        let candidate = dir.join("Cargo.toml");
        if candidate.exists() {
            // Check if this Cargo.toml is a workspace root
            if fs::read_to_string(&candidate)
                .map(|s| s.contains("[workspace]"))
                .unwrap_or(false)
            {
                return dir;
            }
        }
        if !dir.pop() {
            panic!("Workspace root not found!");
        }
    }
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct IoUringProbeOp {
    op: u8,
    resv: u8,
    flags: u16,
    resv2: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct IoUringProbe<const N: usize> {
    last_op: u8,
    ops_len: u8,
    resv: u16,
    resv2: [u32; 3],
    ops: [IoUringProbeOp; N],
}

impl<const N: usize> Default for IoUringProbe<N> {
    fn default() -> Self {
        IoUringProbe {
            last_op: 0,
            ops_len: 0,
            resv: 0,
            resv2: [0; 3],
            ops: [IoUringProbeOp::default(); N],
        }
    }
}

fn main() -> anyhow::Result<()> {
    // Start from the crate's root
    let workspace_root = find_workspace_root(current_dir()?);

    // Change to workspace root if not already there
    let cwd = current_dir()?;
    if cwd != workspace_root {
        set_current_dir(&workspace_root)?;
    }

    fs::exists("pinchy/tests/GPLv2").expect("probably not on the correct cwd");

    let mut args = std::env::args();

    // Ignore the binary name
    let _ = args.next();

    // Call the workload for the test provided as argument
    if let Some(name) = args.next() {
        match name.as_str() {
            "pinchy_reads" => pinchy_reads(),
            "benchmark_trace_loop" => benchmark_trace_loop(),
            "benchmark_basic_io_wave1" => benchmark_basic_io_wave1(),
            "benchmark_basic_io_wave2" => benchmark_basic_io_wave2(),
            "benchmark_filesystem_wave1" => benchmark_filesystem_wave1(),
            "benchmark_filesystem_wave2" => benchmark_filesystem_wave2(),
            "rt_sig" => rt_sig(),
            "rt_sigaction_realtime" => rt_sigaction_realtime(),
            "rt_sigaction_standard" => rt_sigaction_standard(),
            "fcntl_test" => fcntl_test(),
            "fchdir_test" => fchdir_test(),
            "network_test" => network_test(),
            "accept_test" => accept_test(),
            "socket_lifecycle_test" => socket_lifecycle_test(),
            "recvfrom_test" => recvfrom_test(),
            "identity_syscalls" => identity_syscalls(),
            "madvise_test" => madvise_test(),
            "mlock_test" => mlock_test(),
            "file_descriptor_test" => file_descriptor_test(),
            "session_process_test" => session_process_test(),
            "uid_gid_test" => uid_gid_test(),
            "process_identity_test" => process_identity_test(),
            "system_operations_test" => system_operations_test(),
            "ioprio_test" => ioprio_test(),
            "scheduler_test" => scheduler_test(),
            "pread_pwrite_test" => pread_pwrite_test(),
            "readv_writev_test" => readv_writev_test(),
            "pselect6_test" => pselect6_test(),
            "filesystem_sync_test" => filesystem_sync_test(),
            "filesystem_syscalls_test" => filesystem_syscalls_test(),
            "epoll_test" => epoll_test(),
            "eventfd_test" => eventfd_test(),
            "timer_test" => timer_test(),
            "timerfd_test" => timerfd_test(),
            "itimer_test" => itimer_test(),
            "syslog_test" => syslog_test(),
            "ptrace_test" => ptrace_test(),
            "seccomp_test" => seccomp_test(),
            "quotactl_test" => quotactl_test(),
            "execveat_test" => execveat_test(),
            "pipe_operations_test" => pipe_operations_test(),
            "io_multiplexing_test" => io_multiplexing_test(),
            "io_uring_test" => io_uring_test(),
            "xattr_test" => xattr_test(),
            "sysv_ipc_test" => sysv_ipc_test(),
            "posix_mq_test" => posix_mq_test(),
            "socketpair_sendmmsg_test" => socketpair_sendmmsg_test(),
            "system_info_test" => system_info_test(),
            "prctl_test" => prctl_test(),
            "mmap_test" => mmap_test(),
            "memfd_test" => memfd_test(),
            "ioctl_test" => ioctl_test(),
            "filesystem_links_test" => filesystem_links_test(),
            "statfs_test" => statfs_test(),
            "socket_introspection_test" => socket_introspection_test(),
            "aio_test" => aio_test(),
            "landlock_test" => landlock_test(),
            "mempolicy_test" => mempolicy_test(),
            "key_management_test" => key_management_test(),
            "perf_event_test" => perf_event_test(),
            "bpf_test" => bpf_test(),
            "fanotify_test" => fanotify_test(),
            "file_handles_test" => file_handles_test(),
            name => bail!("Unknown test name: {name}"),
        }
    } else {
        bail!("Need a test name as the first argument, nothing provided.")
    }
}

fn filesystem_syscalls_test() -> anyhow::Result<()> {
    use std::{
        fs::{self, File},
        os::unix::io::AsRawFd,
        path::Path,
    };

    // Use the GPLv2 file and its directory as test targets
    let gpl_path = Path::new("pinchy/tests/GPLv2");
    let gpl_cpath =
        CString::new(gpl_path.as_os_str().as_encoded_bytes()).expect("Converting path to CString");
    let dir_path = gpl_path.parent().expect("should have parent directory");

    // --- getdents64 ---
    let dir = fs::File::open(dir_path)?;
    let dir_fd = dir.as_raw_fd();
    let mut buf = vec![0u8; 4096];
    let nread = unsafe { libc::syscall(libc::SYS_getdents64, dir_fd, buf.as_mut_ptr(), buf.len()) };
    assert!(nread > 0, "getdents64 should return > 0");

    // --- fstat ---
    let file = File::open(gpl_path)?;
    let fd = file.as_raw_fd();
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::fstat(fd, &mut stat) };
    assert_eq!(res, 0, "fstat should succeed");
    assert!(stat.st_size > 0, "GPLv2 file should not be empty");

    // --- newfstatat ---
    let mut stat2: pinchy_common::kernel_types::Stat = unsafe { std::mem::zeroed() };
    let res = unsafe {
        libc::syscall(
            libc::SYS_newfstatat,
            libc::AT_FDCWD,
            gpl_cpath.as_ptr(),
            &mut stat2,
            0,
        )
    };
    assert_eq!(res, 0, "newfstatat should succeed");
    assert_eq!(stat2.st_size, stat.st_size, "sizes should match");

    // --- faccessat ---
    let res = unsafe {
        libc::syscall(
            libc::SYS_faccessat,
            libc::AT_FDCWD,
            gpl_cpath.as_ptr(),
            libc::R_OK,
            0,
        )
    };
    assert_eq!(res, 0, "faccessat should succeed for readable file");

    // Call faccessat2 for the same readable file. This syscall is supported on
    // recent kernels and is handled the same way in the eBPF code; we exercise
    // the success case and an error case to validate formatting for both.
    let _ = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            libc::AT_FDCWD,
            gpl_cpath.as_ptr(),
            libc::R_OK,
            0,
        )
    };

    // Error case: faccessat2 on a non-existent path (should fail)
    let _ = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            libc::AT_FDCWD,
            c"pinchy/tests/non-existent-file".as_ptr(),
            libc::R_OK,
            0,
        )
    };
    // We don't assert a specific result here since failure is acceptable and
    // we're primarily testing tracing/formatting of the syscall arguments.

    Ok(())
}

fn mempolicy_test() -> anyhow::Result<()> {
    use pinchy_common::syscalls;
    unsafe {
        let page_size = 4096;

        // Allocate a test buffer using mmap
        let addr = libc::mmap(
            std::ptr::null_mut(),
            page_size * 2,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );

        if addr == libc::MAP_FAILED {
            bail!("mmap failed: {}", std::io::Error::last_os_error());
        }

        // Test set_mempolicy with MPOL_DEFAULT and NULL nodemask
        // This simply resets the policy to default
        let _result = libc::syscall(
            syscalls::SYS_set_mempolicy,
            0, // MPOL_DEFAULT
            std::ptr::null::<u64>(),
            0, // maxnode
        );

        // Test mbind on the allocated region
        // Use MPOL_BIND with nodemask pointing to node 0
        let mut nodemask: u64 = 0x1; // Node 0
        let result = libc::syscall(
            syscalls::SYS_mbind,
            addr as u64,
            page_size,
            1, // MPOL_BIND
            &mut nodemask as *mut u64,
            1, // maxnode = 1 (one u64)
            0, // flags
        );

        if result != 0 {
            // On single-node systems, mbind might fail with EINVAL
            // This is expected behavior - we're just testing that we can trace it
        }

        // Test get_mempolicy to read the policy
        let mut mode_out: u32 = 0;
        let mut nodemask_out: u64 = 0;
        let result = libc::syscall(
            syscalls::SYS_get_mempolicy,
            &mut mode_out as *mut u32,
            &mut nodemask_out as *mut u64,
            64, // maxnode
            addr as u64,
            1, // MPOL_F_ADDR
        );

        if result != 0 {
            // May fail on some systems, but we're testing the tracing
        }

        // Test mincore on the mmap'd region to check page residency
        let mut vec_buf = vec![0u8; (page_size * 2).div_ceil(4096)];
        let result = libc::syscall(
            syscalls::SYS_mincore,
            addr as u64,
            page_size * 2,
            vec_buf.as_mut_ptr(),
        );

        if result != 0 {
            bail!("mincore failed: {}", std::io::Error::last_os_error());
        }

        // Test migrate_pages - attempt to migrate from node 0 to node 0 (no-op)
        let old_nodes: u64 = 0x1; // Node 0
        let new_nodes: u64 = 0x1; // Node 0
        let _result = libc::syscall(
            syscalls::SYS_migrate_pages,
            libc::getpid(),
            64, // maxnode
            &old_nodes as *const u64,
            &new_nodes as *const u64,
        );

        // Test move_pages - attempt to move a page
        let pages = [addr as u64];
        let nodes = [0i32]; // Target node
        let mut status = vec![0i32];
        let _result = libc::syscall(
            syscalls::SYS_move_pages,
            libc::getpid(),
            1, // count
            pages.as_ptr(),
            nodes.as_ptr(),
            status.as_mut_ptr(),
            0, // flags
        );

        // Clean up
        libc::munmap(addr, page_size * 2);
    }

    Ok(())
}

fn statfs_test() -> anyhow::Result<()> {
    use std::{fs::File, os::unix::io::AsRawFd, path::Path};

    // Test both statfs (with path) and fstatfs (with file descriptor)
    let gpl_path = Path::new("pinchy/tests/GPLv2");
    let gpl_cpath =
        CString::new(gpl_path.as_os_str().as_encoded_bytes()).expect("Converting path to CString");

    // --- statfs: Get filesystem stats for a path ---
    let mut statfs_buf: libc::statfs = unsafe { std::mem::zeroed() };
    let statfs_result = unsafe {
        libc::syscall(
            libc::SYS_statfs,
            gpl_cpath.as_ptr(),
            &mut statfs_buf as *mut _,
        )
    };
    // statfs should succeed for existing path
    assert_eq!(statfs_result, 0, "statfs should succeed");

    // --- statfs error case: non-existent path ---
    let mut statfs_buf_err: libc::statfs = unsafe { std::mem::zeroed() };
    let _ = unsafe {
        libc::syscall(
            libc::SYS_statfs,
            c"/non/existent/path".as_ptr(),
            &mut statfs_buf_err as *mut _,
        )
    };
    // We expect this to fail but don't assert - we're testing tracing

    // --- fstatfs: Get filesystem stats for a file descriptor ---
    let file = File::open(gpl_path)?;
    let fd = file.as_raw_fd();
    let mut fstatfs_buf: libc::statfs = unsafe { std::mem::zeroed() };
    let fstatfs_result =
        unsafe { libc::syscall(libc::SYS_fstatfs, fd, &mut fstatfs_buf as *mut _) };
    assert_eq!(fstatfs_result, 0, "fstatfs should succeed");

    // Verify that both calls give similar filesystem information
    assert_eq!(
        statfs_buf.f_type, fstatfs_buf.f_type,
        "filesystem types should match"
    );
    assert_eq!(
        statfs_buf.f_bsize, fstatfs_buf.f_bsize,
        "block sizes should match"
    );

    Ok(())
}

fn pinchy_reads() -> anyhow::Result<()> {
    unsafe {
        // Test openat first
        let fd = libc::openat(
            libc::AT_FDCWD,
            c"pinchy/tests/GPLv2".as_ptr(),
            libc::O_RDONLY,
        );

        let mut buf: Vec<u8> = Vec::with_capacity(1024);

        // This read should not have any elipsing in the output.
        let count = libc::read(fd, buf.as_mut_ptr() as *mut c_void, DATA_READ_SIZE);
        assert_eq!(count, DATA_READ_SIZE as isize);

        // This read should elipsize.
        let count = libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.capacity());
        assert_eq!(count, buf.capacity() as isize);

        libc::lseek(fd, 0, libc::SEEK_END);

        // This read should produce EOF.
        let count = libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.capacity());
        assert_eq!(count, 0);

        libc::close(fd);

        // Test openat2 with RESOLVE_* flags (successful case)
        use pinchy_common::kernel_types::OpenHow;

        let how = OpenHow {
            flags: libc::O_RDONLY as u64,
            mode: 0,
            resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS,
        };

        let fd2 = libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c"pinchy/tests/GPLv2".as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        ) as i32;

        if fd2 >= 0 {
            libc::close(fd2);
        }

        // Test openat2 with no resolve flags (should succeed)
        let how_simple = OpenHow {
            flags: libc::O_RDONLY as u64,
            mode: 0,
            resolve: 0, // No resolve flags
        };

        let fd3 = libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c"pinchy/tests/GPLv2".as_ptr(),
            &how_simple as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        ) as i32;

        if fd3 >= 0 {
            libc::close(fd3);
        }

        // Test openat2 error case - non-existent file
        let how_error = OpenHow {
            flags: libc::O_RDONLY as u64,
            mode: 0,
            resolve: libc::RESOLVE_NO_SYMLINKS,
        };

        let fd_error = libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c"pinchy/tests/non-existent-file".as_ptr(),
            &how_error as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        ) as i32;

        // This should fail, but we still trace the error
        if fd_error >= 0 {
            libc::close(fd_error);
        }
    }
    Ok(())
}

fn benchmark_trace_loop() -> anyhow::Result<()> {
    let loops = std::env::var("PINCHY_BENCH_LOOPS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(250);

    if loops == 0 {
        return Ok(());
    }

    let mut buf = [0u8; DATA_READ_SIZE];

    unsafe {
        for _ in 0..loops {
            let fd = libc::openat(
                libc::AT_FDCWD,
                c"pinchy/tests/GPLv2".as_ptr(),
                libc::O_RDONLY,
            );

            if fd < 0 {
                bail!("openat failed: {}", std::io::Error::last_os_error());
            }

            let count = libc::read(fd, buf.as_mut_ptr() as *mut c_void, DATA_READ_SIZE);
            assert_eq!(count, DATA_READ_SIZE as isize);

            let seek_result = libc::lseek(fd, 0, libc::SEEK_SET);
            assert_eq!(seek_result, 0);

            let close_result = libc::close(fd);
            assert_eq!(close_result, 0);
        }
    }

    Ok(())
}

fn benchmark_basic_io_wave1() -> anyhow::Result<()> {
    let loops = std::env::var("PINCHY_BENCH_LOOPS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(250);

    if loops == 0 {
        return Ok(());
    }

    let write_buf = [0x41u8; DATA_READ_SIZE];
    let mut read_buf = [0u8; DATA_READ_SIZE];
    let mut readv_buf_a = [0u8; 32];
    let mut readv_buf_b = [0u8; 32];
    let mut readv2_buf_a = [0u8; 32];
    let mut readv2_buf_b = [0u8; 32];

    let writev_data_a = b"basic-io-wave1-a";
    let writev_data_b = b"basic-io-wave1-b";

    unsafe {
        for _ in 0..loops {
            let fd = libc::openat(
                libc::AT_FDCWD,
                c"/tmp/benchmark_basic_io_wave1".as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            );

            if fd < 0 {
                bail!("openat failed: {}", std::io::Error::last_os_error());
            }

            let write_ret = libc::write(fd, write_buf.as_ptr() as *const c_void, write_buf.len());
            assert_eq!(write_ret, write_buf.len() as isize);

            let pwrite_ret = libc::pwrite64(fd, write_buf.as_ptr() as *const c_void, 16, 8);
            assert_eq!(pwrite_ret, 16);

            let pread_ret =
                libc::pread64(fd, read_buf.as_mut_ptr() as *mut c_void, read_buf.len(), 0);
            assert_eq!(pread_ret, read_buf.len() as isize);

            let write_iov = [
                libc::iovec {
                    iov_base: writev_data_a.as_ptr() as *mut c_void,
                    iov_len: writev_data_a.len(),
                },
                libc::iovec {
                    iov_base: writev_data_b.as_ptr() as *mut c_void,
                    iov_len: writev_data_b.len(),
                },
            ];

            let writev_ret = libc::writev(fd, write_iov.as_ptr(), write_iov.len() as i32);
            assert_eq!(
                writev_ret,
                (writev_data_a.len() + writev_data_b.len()) as isize
            );

            let lseek_ret = libc::lseek(fd, 0, libc::SEEK_SET);
            assert_eq!(lseek_ret, 0);

            let read_iov = [
                libc::iovec {
                    iov_base: readv_buf_a.as_mut_ptr() as *mut c_void,
                    iov_len: readv_buf_a.len(),
                },
                libc::iovec {
                    iov_base: readv_buf_b.as_mut_ptr() as *mut c_void,
                    iov_len: readv_buf_b.len(),
                },
            ];

            let readv_ret = libc::readv(fd, read_iov.as_ptr(), read_iov.len() as i32);
            assert_eq!(readv_ret, (readv_buf_a.len() + readv_buf_b.len()) as isize);

            let preadv_ret = libc::preadv(fd, read_iov.as_ptr(), read_iov.len() as i32, 0);
            assert_eq!(preadv_ret, (readv_buf_a.len() + readv_buf_b.len()) as isize);

            let pwritev_ret = libc::pwritev(fd, write_iov.as_ptr(), write_iov.len() as i32, 8);
            assert_eq!(
                pwritev_ret,
                (writev_data_a.len() + writev_data_b.len()) as isize
            );

            let read_iov2 = [
                libc::iovec {
                    iov_base: readv2_buf_a.as_mut_ptr() as *mut c_void,
                    iov_len: readv2_buf_a.len(),
                },
                libc::iovec {
                    iov_base: readv2_buf_b.as_mut_ptr() as *mut c_void,
                    iov_len: readv2_buf_b.len(),
                },
            ];

            let preadv2_ret = libc::preadv2(fd, read_iov2.as_ptr(), read_iov2.len() as i32, 0, 0);
            assert_eq!(
                preadv2_ret,
                (readv2_buf_a.len() + readv2_buf_b.len()) as isize
            );

            let pwritev2_ret =
                libc::pwritev2(fd, write_iov.as_ptr(), write_iov.len() as i32, 12, 0);
            assert_eq!(
                pwritev2_ret,
                (writev_data_a.len() + writev_data_b.len()) as isize
            );

            let close_ret = libc::close(fd);
            assert_eq!(close_ret, 0);
        }

        let _ = libc::unlink(c"/tmp/benchmark_basic_io_wave1".as_ptr());
    }

    Ok(())
}

fn benchmark_basic_io_wave2() -> anyhow::Result<()> {
    let loops = std::env::var("PINCHY_BENCH_LOOPS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(250);

    if loops == 0 {
        return Ok(());
    }

    let how = pinchy_common::kernel_types::OpenHow {
        flags: (libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC) as u64,
        mode: 0o644,
        resolve: 0,
    };

    let write_data = b"basic-io-wave2-pipe-data";
    let vmsplice_data = b"basic-io-wave2-vmsplice";

    unsafe {
        for _ in 0..loops {
            let fd = libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                c"/tmp/benchmark_basic_io_wave2".as_ptr(),
                &how as *const pinchy_common::kernel_types::OpenHow,
                std::mem::size_of::<pinchy_common::kernel_types::OpenHow>(),
            ) as i32;

            if fd < 0 {
                bail!("openat2 failed: {}", std::io::Error::last_os_error());
            }

            let mut pipe1 = [0i32; 2];
            let mut pipe2 = [0i32; 2];
            let mut pipe3 = [0i32; 2];
            let mut pipe4 = [0i32; 2];

            if libc::syscall(libc::SYS_pipe2, pipe1.as_mut_ptr(), 0) != 0 {
                bail!("pipe2 #1 failed: {}", std::io::Error::last_os_error());
            }

            if libc::syscall(libc::SYS_pipe2, pipe2.as_mut_ptr(), libc::O_NONBLOCK) != 0 {
                bail!("pipe2 #2 failed: {}", std::io::Error::last_os_error());
            }

            if libc::syscall(libc::SYS_pipe2, pipe3.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
                bail!("pipe2 #3 failed: {}", std::io::Error::last_os_error());
            }

            if libc::syscall(
                libc::SYS_pipe2,
                pipe4.as_mut_ptr(),
                libc::O_NONBLOCK | libc::O_CLOEXEC,
            ) != 0
            {
                bail!("pipe2 #4 failed: {}", std::io::Error::last_os_error());
            }

            let epfd = libc::epoll_create1(libc::EPOLL_CLOEXEC);
            if epfd < 0 {
                bail!("epoll_create1 failed: {}", std::io::Error::last_os_error());
            }

            let mut event = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: pipe2[0] as u64,
            };

            let epoll_ctl_ret = libc::syscall(
                libc::SYS_epoll_ctl,
                epfd,
                libc::EPOLL_CTL_ADD,
                pipe2[0],
                &mut event as *mut libc::epoll_event,
            );

            if epoll_ctl_ret != 0 {
                bail!("epoll_ctl failed: {}", std::io::Error::last_os_error());
            }

            let write_ret = libc::write(
                pipe1[1],
                write_data.as_ptr() as *const c_void,
                write_data.len(),
            );
            if write_ret != write_data.len() as isize {
                bail!("write to pipe failed");
            }

            let splice_ret = libc::syscall(
                libc::SYS_splice,
                pipe1[0],
                std::ptr::null_mut::<libc::loff_t>(),
                pipe2[1],
                std::ptr::null_mut::<libc::loff_t>(),
                write_data.len(),
                libc::SPLICE_F_MOVE,
            );
            if splice_ret < 0 {
                bail!("splice failed: {}", std::io::Error::last_os_error());
            }

            let tee_ret = libc::syscall(
                libc::SYS_tee,
                pipe2[0],
                pipe3[1],
                write_data.len(),
                libc::SPLICE_F_NONBLOCK,
            );
            if tee_ret < 0 {
                bail!("tee failed: {}", std::io::Error::last_os_error());
            }

            let iov = libc::iovec {
                iov_base: vmsplice_data.as_ptr() as *mut libc::c_void,
                iov_len: vmsplice_data.len(),
            };
            let vmsplice_ret = libc::syscall(
                libc::SYS_vmsplice,
                pipe4[1],
                &iov as *const libc::iovec,
                1,
                libc::SPLICE_F_GIFT,
            );
            if vmsplice_ret < 0 {
                bail!("vmsplice failed: {}", std::io::Error::last_os_error());
            }

            let mut pollfd = libc::pollfd {
                fd: pipe3[0],
                events: libc::POLLIN,
                revents: 0,
            };
            let ppoll_timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ppoll_ret = libc::ppoll(&mut pollfd, 1, &ppoll_timeout, std::ptr::null());
            if ppoll_ret < 0 {
                bail!("ppoll failed: {}", std::io::Error::last_os_error());
            }

            let mut pselect_readfds: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut pselect_readfds);
            libc::FD_SET(pipe3[0], &mut pselect_readfds);
            let pselect_timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let pselect_ret = libc::syscall(
                libc::SYS_pselect6,
                pipe3[0] + 1,
                &mut pselect_readfds as *mut libc::fd_set,
                std::ptr::null_mut::<libc::fd_set>(),
                std::ptr::null_mut::<libc::fd_set>(),
                &pselect_timeout as *const libc::timespec,
                std::ptr::null::<libc::c_void>(),
            );
            if pselect_ret < 0 {
                bail!("pselect6 failed: {}", std::io::Error::last_os_error());
            }

            let mut epoll_events = [libc::epoll_event { events: 0, u64: 0 }; 4];
            let epoll_pwait_ret = libc::syscall(
                libc::SYS_epoll_pwait,
                epfd,
                epoll_events.as_mut_ptr(),
                4,
                0,
                std::ptr::null::<libc::sigset_t>(),
                std::mem::size_of::<libc::sigset_t>(),
            );
            if epoll_pwait_ret < 0 {
                bail!("epoll_pwait failed: {}", std::io::Error::last_os_error());
            }

            let epoll_pwait2_timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let epoll_pwait2_ret = libc::syscall(
                libc::SYS_epoll_pwait2,
                epfd,
                epoll_events.as_mut_ptr(),
                4,
                &epoll_pwait2_timeout as *const libc::timespec,
                std::ptr::null::<libc::sigset_t>(),
                std::mem::size_of::<libc::sigset_t>(),
            );
            if epoll_pwait2_ret < 0 {
                bail!("epoll_pwait2 failed: {}", std::io::Error::last_os_error());
            }

            #[cfg(target_arch = "x86_64")]
            {
                let mut pollfd_x86 = libc::pollfd {
                    fd: pipe3[0],
                    events: libc::POLLIN,
                    revents: 0,
                };
                let poll_ret = libc::poll(&mut pollfd_x86, 1, 0);
                if poll_ret < 0 {
                    bail!("poll failed: {}", std::io::Error::last_os_error());
                }

                let mut select_readfds: libc::fd_set = std::mem::zeroed();
                libc::FD_ZERO(&mut select_readfds);
                libc::FD_SET(pipe3[0], &mut select_readfds);
                let mut select_timeout = libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                };
                let select_ret = libc::syscall(
                    libc::SYS_select,
                    pipe3[0] + 1,
                    &mut select_readfds as *mut libc::fd_set,
                    std::ptr::null_mut::<libc::fd_set>(),
                    std::ptr::null_mut::<libc::fd_set>(),
                    &mut select_timeout as *mut libc::timeval,
                );
                if select_ret < 0 {
                    bail!("select failed: {}", std::io::Error::last_os_error());
                }

                let mut offset = 0i64;
                let sendfile_ret = libc::syscall(
                    libc::SYS_sendfile,
                    pipe2[1],
                    fd,
                    &mut offset as *mut i64,
                    16usize,
                );
                if sendfile_ret < 0 {
                    bail!("sendfile failed: {}", std::io::Error::last_os_error());
                }
            }

            libc::close(epfd);
            libc::close(fd);
            libc::close(pipe1[0]);
            libc::close(pipe1[1]);
            libc::close(pipe2[0]);
            libc::close(pipe2[1]);
            libc::close(pipe3[0]);
            libc::close(pipe3[1]);
            libc::close(pipe4[0]);
            libc::close(pipe4[1]);
        }

        let _ = libc::unlink(c"/tmp/benchmark_basic_io_wave2".as_ptr());
    }

    Ok(())
}

fn benchmark_filesystem_wave1() -> anyhow::Result<()> {
    let loops = std::env::var("PINCHY_BENCH_LOOPS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(250);

    if loops == 0 {
        return Ok(());
    }

    let file_path = c"/tmp/benchmark_filesystem_wave1_file";
    let link_path = c"/tmp/benchmark_filesystem_wave1_link";
    let statfs_path = c"/tmp";
    let mut readlink_buf = [0u8; DATA_READ_SIZE];
    let mut stat = pinchy_common::kernel_types::Stat::default();

    unsafe {
        for _ in 0..loops {
            let fd = libc::openat(
                libc::AT_FDCWD,
                file_path.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            );

            if fd < 0 {
                bail!("openat failed: {}", std::io::Error::last_os_error());
            }

            let mut fstat_buf: libc::stat = std::mem::zeroed();
            if libc::fstat(fd, &mut fstat_buf) != 0 {
                bail!("fstat failed: {}", std::io::Error::last_os_error());
            }

            if libc::syscall(
                libc::SYS_newfstatat,
                libc::AT_FDCWD,
                file_path.as_ptr(),
                &mut stat as *mut pinchy_common::kernel_types::Stat,
                0,
            ) != 0
            {
                bail!("newfstatat failed: {}", std::io::Error::last_os_error());
            }

            if libc::syscall(
                libc::SYS_faccessat,
                libc::AT_FDCWD,
                file_path.as_ptr(),
                libc::R_OK,
                0,
            ) != 0
            {
                bail!("faccessat failed: {}", std::io::Error::last_os_error());
            }

            let _ = libc::syscall(
                libc::SYS_faccessat2,
                libc::AT_FDCWD,
                file_path.as_ptr(),
                libc::R_OK,
                0,
            );

            let _ = libc::unlink(link_path.as_ptr());
            if libc::symlink(file_path.as_ptr(), link_path.as_ptr()) != 0 {
                bail!("symlink failed: {}", std::io::Error::last_os_error());
            }

            let readlink_res = libc::syscall(
                libc::SYS_readlinkat,
                libc::AT_FDCWD,
                link_path.as_ptr(),
                readlink_buf.as_mut_ptr(),
                readlink_buf.len(),
            );
            if readlink_res < 0 {
                bail!("readlinkat failed: {}", std::io::Error::last_os_error());
            }

            let mut statfs_buf: libc::statfs = std::mem::zeroed();
            if libc::syscall(
                libc::SYS_statfs,
                statfs_path.as_ptr(),
                &mut statfs_buf as *mut _,
            ) != 0
            {
                bail!("statfs failed: {}", std::io::Error::last_os_error());
            }

            let mut fstatfs_buf: libc::statfs = std::mem::zeroed();
            if libc::syscall(libc::SYS_fstatfs, fd, &mut fstatfs_buf as *mut _) != 0 {
                bail!("fstatfs failed: {}", std::io::Error::last_os_error());
            }

            if libc::close(fd) != 0 {
                bail!("close failed: {}", std::io::Error::last_os_error());
            }
        }

        let _ = libc::unlink(link_path.as_ptr());
        let _ = libc::unlink(file_path.as_ptr());
    }

    Ok(())
}

fn benchmark_filesystem_wave2() -> anyhow::Result<()> {
    fn is_expected_xattr_errno(errno: i32) -> bool {
        matches!(
            errno,
            libc::ENODATA
                | libc::EOPNOTSUPP
                | libc::EPERM
                | libc::EACCES
                | libc::EINVAL
                | libc::ENOENT
                | libc::ERANGE
        )
    }

    fn check_xattr_result(operation: &str, result: libc::c_long) -> anyhow::Result<()> {
        if result >= 0 {
            return Ok(());
        }

        let error = std::io::Error::last_os_error();
        let errno = error.raw_os_error().unwrap_or_default();

        if is_expected_xattr_errno(errno) {
            return Ok(());
        }

        bail!("{operation} failed: {error}");
    }

    let loops = std::env::var("PINCHY_BENCH_LOOPS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(250);

    if loops == 0 {
        return Ok(());
    }

    let file_path = c"/tmp/benchmark_filesystem_wave2_file";
    let link_path = c"/tmp/benchmark_filesystem_wave2_link";
    let xattr_name = c"user.pinchy_wave2";
    let value = b"pinchy-wave2-value";
    let mut value_buf = [0u8; DATA_READ_SIZE];
    let mut list_buf = [0u8; DATA_READ_SIZE];

    unsafe {
        for _ in 0..loops {
            let fd = libc::openat(
                libc::AT_FDCWD,
                file_path.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            );

            if fd < 0 {
                bail!("openat failed: {}", std::io::Error::last_os_error());
            }

            let _ = libc::unlink(link_path.as_ptr());

            if libc::symlink(file_path.as_ptr(), link_path.as_ptr()) != 0 {
                bail!("symlink failed: {}", std::io::Error::last_os_error());
            }

            check_xattr_result(
                "setxattr",
                libc::syscall(
                    libc::SYS_setxattr,
                    file_path.as_ptr(),
                    xattr_name.as_ptr(),
                    value.as_ptr(),
                    value.len(),
                    0,
                ),
            )?;

            check_xattr_result(
                "lsetxattr",
                libc::syscall(
                    libc::SYS_lsetxattr,
                    link_path.as_ptr(),
                    xattr_name.as_ptr(),
                    value.as_ptr(),
                    value.len(),
                    0,
                ),
            )?;

            check_xattr_result(
                "fsetxattr",
                libc::syscall(
                    libc::SYS_fsetxattr,
                    fd,
                    xattr_name.as_ptr(),
                    value.as_ptr(),
                    value.len(),
                    0,
                ),
            )?;

            check_xattr_result(
                "getxattr",
                libc::syscall(
                    libc::SYS_getxattr,
                    file_path.as_ptr(),
                    xattr_name.as_ptr(),
                    value_buf.as_mut_ptr(),
                    value_buf.len(),
                ),
            )?;

            check_xattr_result(
                "lgetxattr",
                libc::syscall(
                    libc::SYS_lgetxattr,
                    link_path.as_ptr(),
                    xattr_name.as_ptr(),
                    value_buf.as_mut_ptr(),
                    value_buf.len(),
                ),
            )?;

            check_xattr_result(
                "fgetxattr",
                libc::syscall(
                    libc::SYS_fgetxattr,
                    fd,
                    xattr_name.as_ptr(),
                    value_buf.as_mut_ptr(),
                    value_buf.len(),
                ),
            )?;

            check_xattr_result(
                "listxattr",
                libc::syscall(
                    libc::SYS_listxattr,
                    file_path.as_ptr(),
                    list_buf.as_mut_ptr(),
                    list_buf.len(),
                ),
            )?;

            check_xattr_result(
                "llistxattr",
                libc::syscall(
                    libc::SYS_llistxattr,
                    link_path.as_ptr(),
                    list_buf.as_mut_ptr(),
                    list_buf.len(),
                ),
            )?;

            check_xattr_result(
                "flistxattr",
                libc::syscall(
                    libc::SYS_flistxattr,
                    fd,
                    list_buf.as_mut_ptr(),
                    list_buf.len(),
                ),
            )?;

            check_xattr_result(
                "removexattr",
                libc::syscall(
                    libc::SYS_removexattr,
                    file_path.as_ptr(),
                    xattr_name.as_ptr(),
                ),
            )?;

            check_xattr_result(
                "lremovexattr",
                libc::syscall(
                    libc::SYS_lremovexattr,
                    link_path.as_ptr(),
                    xattr_name.as_ptr(),
                ),
            )?;

            check_xattr_result(
                "fremovexattr",
                libc::syscall(libc::SYS_fremovexattr, fd, xattr_name.as_ptr()),
            )?;

            if libc::close(fd) != 0 {
                bail!("close failed: {}", std::io::Error::last_os_error());
            }
        }

        let _ = libc::unlink(link_path.as_ptr());
        let _ = libc::unlink(file_path.as_ptr());
    }

    Ok(())
}

fn rt_sig() -> anyhow::Result<()> {
    unsafe {
        let mut old_set: libc::sigset_t = std::mem::zeroed();
        let mut new_set: libc::sigset_t = std::mem::zeroed();

        // Initialize the new signal set and add SIGUSR1 to it
        libc::sigemptyset(&mut new_set);
        libc::sigaddset(&mut new_set, libc::SIGUSR1);

        // Block SIGUSR1 using SIG_BLOCK
        let result = libc::sigprocmask(libc::SIG_BLOCK, &new_set, &mut old_set);
        assert_eq!(result, 0, "Failed to block SIGUSR1");

        // Get current signal mask using SIG_SETMASK with NULL set
        let mut current_set: libc::sigset_t = std::mem::zeroed();
        let result = libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut current_set);
        assert_eq!(result, 0, "Failed to get current signal mask");

        // Verify SIGUSR1 is in the current mask
        let is_blocked = libc::sigismember(&current_set, libc::SIGUSR1);
        assert_eq!(is_blocked, 1, "SIGUSR1 should be blocked");

        // Unblock SIGUSR1 using SIG_UNBLOCK
        let result = libc::sigprocmask(libc::SIG_UNBLOCK, &new_set, std::ptr::null_mut());
        assert_eq!(result, 0, "Failed to unblock SIGUSR1");

        // Restore the original signal mask
        let result = libc::sigprocmask(libc::SIG_SETMASK, &old_set, std::ptr::null_mut());
        assert_eq!(result, 0, "Failed to restore original signal mask");
    }
    Ok(())
}

fn rt_sigaction_realtime() -> anyhow::Result<()> {
    unsafe {
        // Test rt_sigaction with a real-time signal (SIGRT1 = SIGRTMIN + 1)
        let sigrt1 = libc::SIGRTMIN() + 1;

        let mut old_action: libc::sigaction = std::mem::zeroed();
        let mut new_action: libc::sigaction = std::mem::zeroed();

        // Set up a simple signal handler (we'll use SIG_IGN for simplicity)
        new_action.sa_sigaction = libc::SIG_IGN;
        new_action.sa_flags = 0;
        libc::sigemptyset(&mut new_action.sa_mask);

        // Install the signal handler for SIGRT1
        let result = libc::sigaction(sigrt1, &new_action, &mut old_action);
        assert_eq!(result, 0, "Failed to install signal handler for SIGRT1");

        // Get the current signal handler (this will trigger another rt_sigaction call)
        let mut current_action: libc::sigaction = std::mem::zeroed();
        let result = libc::sigaction(sigrt1, std::ptr::null(), &mut current_action);
        assert_eq!(result, 0, "Failed to get current signal handler for SIGRT1");

        // Verify the handler was set correctly
        assert_eq!(current_action.sa_sigaction, libc::SIG_IGN);

        // Restore the original signal handler
        let result = libc::sigaction(sigrt1, &old_action, std::ptr::null_mut());
        assert_eq!(
            result, 0,
            "Failed to restore original signal handler for SIGRT1"
        );
    }
    Ok(())
}

fn rt_sigaction_standard() -> anyhow::Result<()> {
    unsafe {
        // Test rt_sigaction with a standard signal (SIGUSR1)
        let sigusr1 = libc::SIGUSR1;

        let mut old_action: libc::sigaction = std::mem::zeroed();
        let mut new_action: libc::sigaction = std::mem::zeroed();

        // Set up a simple signal handler (we'll use SIG_IGN for simplicity)
        new_action.sa_sigaction = libc::SIG_IGN;
        new_action.sa_flags = 0;
        libc::sigemptyset(&mut new_action.sa_mask);

        // Install the signal handler for SIGUSR1
        let result = libc::sigaction(sigusr1, &new_action, &mut old_action);
        assert_eq!(result, 0, "Failed to install signal handler for SIGUSR1");

        // Get the current signal handler (this will trigger another rt_sigaction call)
        let mut current_action: libc::sigaction = std::mem::zeroed();
        let result = libc::sigaction(sigusr1, std::ptr::null(), &mut current_action);
        assert_eq!(
            result, 0,
            "Failed to get current signal handler for SIGUSR1"
        );

        // Verify the handler was set correctly
        assert_eq!(current_action.sa_sigaction, libc::SIG_IGN);

        // Restore the original signal handler
        let result = libc::sigaction(sigusr1, &old_action, std::ptr::null_mut());
        assert_eq!(
            result, 0,
            "Failed to restore original signal handler for SIGUSR1"
        );
    }
    Ok(())
}

fn fchdir_test() -> anyhow::Result<()> {
    use std::{fs::File, os::unix::io::AsRawFd};

    // Open the current directory
    let file = File::open(".")?;
    let fd = file.as_raw_fd();

    // Call fchdir on the directory fd
    let ret = unsafe { libc::fchdir(fd) };
    assert_eq!(ret, 0, "fchdir failed");

    Ok(())
}

fn fcntl_test() -> anyhow::Result<()> {
    unsafe {
        // Open a file to test fcntl on
        let fd = libc::openat(
            libc::AT_FDCWD,
            c"pinchy/tests/GPLv2".as_ptr(),
            libc::O_RDONLY,
        );
        if fd < 0 {
            bail!("Failed to open test file");
        }

        // Test F_GETFL - get file status flags
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            bail!("Failed to get file flags");
        }

        // Test F_GETFD - get file descriptor flags
        let fd_flags = libc::fcntl(fd, libc::F_GETFD);
        if fd_flags < 0 {
            bail!("Failed to get fd flags");
        }

        // Test F_SETFD - set close-on-exec flag
        let result = libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        if result < 0 {
            bail!("Failed to set fd flags");
        }

        // Test F_DUPFD - duplicate file descriptor
        let new_fd = libc::fcntl(fd, libc::F_DUPFD, 10);
        if new_fd < 0 {
            bail!("Failed to duplicate fd");
        }

        // Test F_DUPFD_CLOEXEC - duplicate with close-on-exec
        let new_fd2 = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 20);
        if new_fd2 < 0 {
            bail!("Failed to duplicate fd with cloexec");
        }

        // Clean up
        libc::close(new_fd2);
        libc::close(new_fd);
        libc::close(fd);
    }

    Ok(())
}

fn socket_introspection_test() -> anyhow::Result<()> {
    unsafe {
        let server_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);

        if server_fd < 0 {
            bail!("socket() failed: {}", std::io::Error::last_os_error());
        }

        let mut server_addr: libc::sockaddr_in = std::mem::zeroed();
        server_addr.sin_family = libc::AF_INET as u16;
        server_addr.sin_port = 0;
        server_addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();

        let bind_result = libc::bind(
            server_fd,
            &server_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );

        if bind_result < 0 {
            bail!("bind() failed: {}", std::io::Error::last_os_error());
        }

        let listen_result = libc::listen(server_fd, 1);

        if listen_result < 0 {
            bail!("listen() failed: {}", std::io::Error::last_os_error());
        }

        let mut bound_addr: libc::sockaddr_in = std::mem::zeroed();
        let mut bound_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let server_getsockname = libc::getsockname(
            server_fd,
            &mut bound_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut bound_len,
        );

        if server_getsockname < 0 {
            bail!(
                "server getsockname() failed: {}",
                std::io::Error::last_os_error()
            );
        }

        assert!(bound_len >= std::mem::size_of::<libc::sockaddr_in>() as u32);

        let client_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);

        if client_fd < 0 {
            bail!(
                "client socket() failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let connect_result = libc::connect(
            client_fd,
            &bound_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );

        if connect_result < 0 {
            bail!("connect() failed: {}", std::io::Error::last_os_error());
        }

        let mut accepted_addr: libc::sockaddr_in = std::mem::zeroed();
        let mut accepted_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let accepted_fd = libc::accept(
            server_fd,
            &mut accepted_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut accepted_len,
        );

        if accepted_fd < 0 {
            bail!("accept() failed: {}", std::io::Error::last_os_error());
        }

        let mut local_addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut local_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let getsockname_result = libc::getsockname(
            client_fd,
            &mut local_addr as *mut libc::sockaddr_storage as *mut libc::sockaddr,
            &mut local_len,
        );

        if getsockname_result < 0 {
            bail!(
                "client getsockname() failed: {}",
                std::io::Error::last_os_error()
            );
        }

        assert!(local_len > 0);

        let mut peer_addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut peer_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let getpeername_result = libc::getpeername(
            client_fd,
            &mut peer_addr as *mut libc::sockaddr_storage as *mut libc::sockaddr,
            &mut peer_len,
        );

        if getpeername_result < 0 {
            bail!(
                "client getpeername() failed: {}",
                std::io::Error::last_os_error()
            );
        }

        assert!(peer_len > 0);

        let option_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);

        if option_fd < 0 {
            bail!(
                "socket() for setsockopt failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let value: libc::c_int = 1;
        let value_ptr = &value as *const libc::c_int as *const libc::c_void;
        let value_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let reuseaddr_result = libc::setsockopt(
            option_fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            value_ptr,
            value_len,
        );

        if reuseaddr_result < 0 {
            bail!(
                "setsockopt(SO_REUSEADDR) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let mut reuseaddr_value = 0;
        let mut reuseaddr_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let reuseaddr_get_result = libc::getsockopt(
            option_fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &mut reuseaddr_value as *mut libc::c_int as *mut libc::c_void,
            &mut reuseaddr_len,
        );

        if reuseaddr_get_result < 0 {
            bail!(
                "getsockopt(SO_REUSEADDR) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        assert_eq!(reuseaddr_value, 1);

        let keepalive_result = libc::setsockopt(
            client_fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            value_ptr,
            value_len,
        );

        if keepalive_result < 0 {
            bail!(
                "setsockopt(SO_KEEPALIVE) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let mut keepalive_value = 0;
        let mut keepalive_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let keepalive_get_result = libc::getsockopt(
            client_fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &mut keepalive_value as *mut libc::c_int as *mut libc::c_void,
            &mut keepalive_len,
        );

        if keepalive_get_result < 0 {
            bail!(
                "getsockopt(SO_KEEPALIVE) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        assert_eq!(keepalive_value, 1);

        let nodelay_result = libc::setsockopt(
            client_fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            value_ptr,
            value_len,
        );

        if nodelay_result < 0 {
            bail!(
                "setsockopt(TCP_NODELAY) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let mut nodelay_value = 0;
        let mut nodelay_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let nodelay_get_result = libc::getsockopt(
            client_fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &mut nodelay_value as *mut libc::c_int as *mut libc::c_void,
            &mut nodelay_len,
        );

        if nodelay_get_result < 0 {
            bail!(
                "getsockopt(TCP_NODELAY) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        assert_eq!(nodelay_value, 1);

        let close_option = libc::close(option_fd);

        if close_option < 0 {
            bail!(
                "close(option_fd) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let udp_fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);

        if udp_fd < 0 {
            bail!("UDP socket() failed: {}", std::io::Error::last_os_error());
        }

        let mut dest_addr: libc::sockaddr_in = std::mem::zeroed();
        dest_addr.sin_family = libc::AF_INET as u16;
        dest_addr.sin_port = u16::to_be(9);
        dest_addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
        let message = b"socket introspection";
        let sendto_result = libc::sendto(
            udp_fd,
            message.as_ptr() as *const libc::c_void,
            message.len(),
            0,
            &dest_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );

        if sendto_result < 0 {
            bail!("sendto failed: {}", std::io::Error::last_os_error());
        }

        let close_udp = libc::close(udp_fd);

        if close_udp < 0 {
            bail!("close(udp_fd) failed: {}", std::io::Error::last_os_error());
        }

        let close_client = libc::close(client_fd);

        if close_client < 0 {
            bail!(
                "close(client_fd) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let close_accepted = libc::close(accepted_fd);

        if close_accepted < 0 {
            bail!(
                "close(accepted_fd) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let close_server = libc::close(server_fd);

        if close_server < 0 {
            bail!(
                "close(server_fd) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    Ok(())
}

fn network_test() -> anyhow::Result<()> {
    use std::{
        net::{TcpListener, TcpStream},
        os::unix::io::AsRawFd,
    };

    // Create a TCP listener on localhost
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    // Connect to ourselves - this is simpler than threading
    let client = TcpStream::connect(addr)?;

    // Accept the connection we just made - this generates accept4
    let (server, _client_addr) = listener.accept()?;

    // Get raw file descriptors for direct syscall usage
    let client_fd = client.as_raw_fd();
    let server_fd = server.as_raw_fd();

    // Send some test data using sendmsg syscall directly
    let test_message = b"Hello, network test!";
    unsafe {
        let mut iov = libc::iovec {
            iov_base: test_message.as_ptr() as *mut libc::c_void,
            iov_len: test_message.len(),
        };

        let msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let bytes_sent = libc::sendmsg(client_fd, &msg, 0);
        if bytes_sent < 0 {
            bail!("sendmsg failed");
        }
    }

    // Receive the data using recvmsg syscall directly
    let mut buffer = [0u8; 1024];
    unsafe {
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: buffer.len(),
        };

        let msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let bytes_received = libc::recvmsg(
            server_fd,
            &msg as *const libc::msghdr as *mut libc::msghdr,
            0,
        );
        if bytes_received < 0 {
            bail!("recvmsg failed");
        }

        // Verify we got the expected data
        assert_eq!(&buffer[..bytes_received as usize], test_message);
    }

    Ok(())
}

fn recvfrom_test() -> anyhow::Result<()> {
    use std::{net::UdpSocket, os::unix::io::AsRawFd};

    // Create UDP sockets for testing recvfrom
    let server_socket = UdpSocket::bind("127.0.0.1:0")?;
    let server_addr = server_socket.local_addr()?;

    let client_socket = UdpSocket::bind("127.0.0.1:0")?;

    // Get raw file descriptor for direct syscall usage
    let server_fd = server_socket.as_raw_fd();

    // Send test data from client to server using standard library (will generate some syscalls)
    let test_message = b"UDP recvfrom test!";
    client_socket.send_to(test_message, server_addr)?;

    // Use recvfrom syscall directly to receive data
    let mut buffer = [0u8; 1024];
    unsafe {
        let mut src_addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let bytes_received = libc::recvfrom(
            server_fd,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
            0, // flags
            &mut src_addr as *mut libc::sockaddr_storage as *mut libc::sockaddr,
            &mut addr_len,
        );

        if bytes_received < 0 {
            bail!("recvfrom failed: {}", std::io::Error::last_os_error());
        }

        // Verify we got the expected data
        assert_eq!(&buffer[..bytes_received as usize], test_message);

        // Also test recvfrom without source address (NULL parameters)
        client_socket.send_to(b"second message", server_addr)?;

        let bytes_received2 = libc::recvfrom(
            server_fd,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
            0,                    // flags
            std::ptr::null_mut(), // NULL src_addr
            std::ptr::null_mut(), // NULL addr_len
        );

        if bytes_received2 < 0 {
            bail!(
                "second recvfrom failed: {}",
                std::io::Error::last_os_error()
            );
        }

        assert_eq!(&buffer[..bytes_received2 as usize], b"second message");
    }

    Ok(())
}

fn accept_test() -> anyhow::Result<()> {
    unsafe {
        // Create a socket for listening
        let server_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if server_fd < 0 {
            bail!("socket() failed");
        }

        // Create sockaddr_in for binding
        let mut server_addr: libc::sockaddr_in = std::mem::zeroed();
        server_addr.sin_family = libc::AF_INET as u16;
        server_addr.sin_port = 0u16.to_be(); // Let the OS choose port
        server_addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be(); // 127.0.0.1

        let server_addr_ptr = &server_addr as *const libc::sockaddr_in as *const libc::sockaddr;

        // Bind the socket
        let bind_result = libc::bind(
            server_fd,
            server_addr_ptr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        if bind_result < 0 {
            bail!("bind() failed");
        }

        // Listen on the socket
        let listen_result = libc::listen(server_fd, 1);
        if listen_result < 0 {
            bail!("listen() failed");
        }

        // Get the actual port that was assigned
        let mut actual_addr: libc::sockaddr_in = std::mem::zeroed();
        let mut addr_len = std::mem::size_of::<libc::sockaddr_in>() as u32;
        let getsockname_result = libc::getsockname(
            server_fd,
            &mut actual_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut addr_len,
        );
        if getsockname_result < 0 {
            bail!("getsockname() failed");
        }

        // Create a client socket to connect to the server
        let client_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if client_fd < 0 {
            bail!("client socket() failed");
        }

        // Connect the client to the server
        let connect_result = libc::connect(
            client_fd,
            &actual_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        if connect_result < 0 {
            bail!("connect() failed");
        }

        // Use the accept() syscall (not accept4) to accept the connection
        let mut client_addr: libc::sockaddr_in = std::mem::zeroed();
        let mut client_addr_len = std::mem::size_of::<libc::sockaddr_in>() as u32;

        let accepted_fd = libc::accept(
            server_fd,
            &mut client_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut client_addr_len,
        );
        if accepted_fd < 0 {
            bail!("accept() failed");
        }

        // Clean up
        libc::close(accepted_fd);
        libc::close(client_fd);
        libc::close(server_fd);
    }

    Ok(())
}

fn identity_syscalls() -> anyhow::Result<()> {
    unsafe {
        // Call all identity-related syscalls
        let _pid = libc::getpid();
        let _tid = libc::gettid();
        let _uid = libc::getuid();
        let _euid = libc::geteuid();
        let _gid = libc::getgid();
        let _egid = libc::getegid();
        let _ppid = libc::getppid();
    }

    Ok(())
}

fn madvise_test() -> anyhow::Result<()> {
    unsafe {
        // Allocate a page of memory using mmap
        let page_size = 4096;
        let addr = libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );

        if addr == libc::MAP_FAILED {
            bail!("mmap failed: {}", std::io::Error::last_os_error());
        }

        // Test different madvise advice values

        // MADV_WILLNEED - tell kernel we will need these pages soon
        let result = libc::madvise(addr, page_size, libc::MADV_WILLNEED);
        if result != 0 {
            bail!(
                "madvise WILLNEED failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // MADV_DONTNEED - tell kernel we don't need these pages
        let result = libc::madvise(addr, page_size, libc::MADV_DONTNEED);
        if result != 0 {
            bail!(
                "madvise DONTNEED failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // MADV_NORMAL - reset to normal behavior
        let result = libc::madvise(addr, page_size, libc::MADV_NORMAL);
        if result != 0 {
            bail!("madvise NORMAL failed: {}", std::io::Error::last_os_error());
        }

        // Test with an invalid address (should fail)
        let result = libc::madvise(std::ptr::null_mut(), page_size, libc::MADV_WILLNEED);
        assert_eq!(result, -1, "madvise with NULL address should fail");

        // Clean up
        let result = libc::munmap(addr, page_size);
        if result != 0 {
            bail!("munmap failed: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn mlock_test() -> anyhow::Result<()> {
    unsafe {
        // Allocate a page of memory using mmap
        let page_size = 4096;
        let addr = libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );

        if addr == libc::MAP_FAILED {
            bail!("mmap failed: {}", std::io::Error::last_os_error());
        }

        // Lock the memory page
        let result = libc::mlock(addr, page_size);
        if result != 0 {
            bail!("mlock failed: {}", std::io::Error::last_os_error());
        }

        // Unlock all locked memory using munlockall
        let result = libc::munlockall();
        if result != 0 {
            bail!("munlockall failed: {}", std::io::Error::last_os_error());
        }

        // Clean up
        let result = libc::munmap(addr, page_size);
        if result != 0 {
            bail!("munmap failed: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn file_descriptor_test() -> anyhow::Result<()> {
    unsafe {
        // Open a file to get a file descriptor
        let fd = libc::openat(
            libc::AT_FDCWD,
            c"pinchy/tests/GPLv2".as_ptr(),
            libc::O_RDONLY,
        );
        if fd < 0 {
            bail!("Failed to open file: {}", std::io::Error::last_os_error());
        }

        // Test dup - duplicate the file descriptor
        let dup_fd = libc::dup(fd);
        if dup_fd < 0 {
            bail!("dup failed: {}", std::io::Error::last_os_error());
        }

        // Test dup2 - duplicate to a specific file descriptor
        #[cfg(target_arch = "x86_64")]
        let dup2_fd = libc::dup2(fd, 10);

        #[cfg(target_arch = "x86_64")]
        if dup2_fd < 0 {
            bail!("dup2 failed: {}", std::io::Error::last_os_error());
        }

        // Test dup3 - duplicate with flags
        let dup3_fd = libc::dup3(fd, 11, 0);
        if dup3_fd < 0 {
            bail!("dup3 failed: {}", std::io::Error::last_os_error());
        }

        // Test close_range - close a range of file descriptors
        // We'll close from dup_fd to dup_fd (just one fd)
        let result = libc::syscall(libc::SYS_close_range, dup_fd, dup_fd, 0);
        if result != 0 {
            // close_range might not be available on all systems, so we'll just close manually
            libc::close(dup_fd);
        }

        // Clean up the dup2 and dup3 file descriptors
        #[cfg(target_arch = "x86_64")]
        libc::close(dup2_fd);
        libc::close(dup3_fd);
        libc::close(fd);
    }

    Ok(())
}

fn session_process_test() -> anyhow::Result<()> {
    unsafe {
        // Get current process group ID
        let current_pgid = libc::getpgid(0);
        if current_pgid < 0 {
            bail!("getpgid failed: {}", std::io::Error::last_os_error());
        }

        // Get current session ID
        let current_sid = libc::getsid(0);
        if current_sid < 0 {
            bail!("getsid failed: {}", std::io::Error::last_os_error());
        }

        // Set process group (should work with root privileges)
        let result = libc::setpgid(0, current_pgid);
        if result != 0 {
            bail!("setpgid failed: {}", std::io::Error::last_os_error());
        }

        // Create new session (should work with root privileges)
        let result = libc::setsid();
        if result < 0 {
            bail!("setsid failed: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn uid_gid_test() -> anyhow::Result<()> {
    unsafe {
        // Get current IDs
        let uid = libc::getuid();
        let gid = libc::getgid();

        // Set to same values (should work with root privileges)

        // Test setuid
        let result = libc::setuid(uid);
        if result != 0 {
            bail!("setuid failed: {}", std::io::Error::last_os_error());
        }

        // Test setgid
        let result = libc::setgid(gid);
        if result != 0 {
            bail!("setgid failed: {}", std::io::Error::last_os_error());
        }

        // Test setreuid
        let result = libc::setreuid(uid, uid);
        if result != 0 {
            bail!("setreuid failed: {}", std::io::Error::last_os_error());
        }

        // Test setregid
        let result = libc::setregid(gid, gid);
        if result != 0 {
            bail!("setregid failed: {}", std::io::Error::last_os_error());
        }

        // Test setresuid
        let result = libc::syscall(libc::SYS_setresuid, uid, uid, uid);
        if result != 0 {
            bail!("setresuid failed: {}", std::io::Error::last_os_error());
        }

        // Test setresgid
        let result = libc::syscall(libc::SYS_setresgid, gid, gid, gid);
        if result != 0 {
            bail!("setresgid failed: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn process_identity_test() -> anyhow::Result<()> {
    unsafe {
        // Test getresuid - get real, effective, and saved user IDs
        let mut ruid: libc::uid_t = 0;
        let mut euid: libc::uid_t = 0;
        let mut suid: libc::uid_t = 0;

        let result = libc::syscall(
            libc::SYS_getresuid,
            &mut ruid as *mut libc::uid_t,
            &mut euid as *mut libc::uid_t,
            &mut suid as *mut libc::uid_t,
        );

        if result != 0 {
            bail!("getresuid failed: {}", std::io::Error::last_os_error());
        }

        // Test getresgid - get real, effective, and saved group IDs
        let mut rgid: libc::gid_t = 0;
        let mut egid: libc::gid_t = 0;
        let mut sgid: libc::gid_t = 0;

        let result = libc::syscall(
            libc::SYS_getresgid,
            &mut rgid as *mut libc::gid_t,
            &mut egid as *mut libc::gid_t,
            &mut sgid as *mut libc::gid_t,
        );

        if result != 0 {
            bail!("getresgid failed: {}", std::io::Error::last_os_error());
        }

        // Test getgroups - get supplementary group IDs
        let mut groups: [libc::gid_t; 32] = [0; 32];
        let ngroups = libc::getgroups(32, groups.as_mut_ptr());

        if ngroups < 0 {
            bail!("getgroups failed: {}", std::io::Error::last_os_error());
        }

        // Test setgroups - set supplementary group IDs to the same values
        // (should work with root privileges)
        let result = libc::setgroups(ngroups as usize, groups.as_ptr());

        if result != 0 {
            bail!("setgroups failed: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn system_operations_test() -> anyhow::Result<()> {
    unsafe {
        // Test umask - get current mask and set it to 0o22, then back
        let old_mask = libc::umask(0o22);
        libc::umask(old_mask); // Restore original mask

        // Test sync - synchronize file systems
        libc::sync();
    }

    Ok(())
}

fn ioprio_test() -> anyhow::Result<()> {
    unsafe {
        // Test ioprio_get - get I/O priority
        let current_prio = libc::syscall(libc::SYS_ioprio_get, 1, 0); // IOPRIO_WHO_PROCESS, current process
        if current_prio < 0 {
            bail!("ioprio_get failed: {}", std::io::Error::last_os_error());
        }

        // Test ioprio_set - set I/O priority (should work with root privileges)
        let result = libc::syscall(libc::SYS_ioprio_set, 1, 0, current_prio); // IOPRIO_WHO_PROCESS, current process
        if result != 0 {
            bail!("ioprio_set failed: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn scheduler_test() -> anyhow::Result<()> {
    unsafe {
        // Test sched_getscheduler - get current scheduling policy
        let current_policy = libc::sched_getscheduler(0); // 0 = current process
        if current_policy < 0 {
            bail!(
                "sched_getscheduler failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test sched_setscheduler - set scheduling policy back to SCHED_OTHER
        // Create a sched_param structure with priority 0 (required for SCHED_OTHER)
        let param = libc::sched_param { sched_priority: 0 };

        let result = libc::sched_setscheduler(0, libc::SCHED_OTHER, &param);
        if result != 0 {
            bail!(
                "sched_setscheduler failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    Ok(())
}

fn pread_pwrite_test() -> anyhow::Result<()> {
    unsafe {
        // Create a temporary file for testing pread/pwrite
        let fd = libc::openat(
            libc::AT_FDCWD,
            c"/tmp/pread_pwrite_test".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );

        if fd < 0 {
            bail!(
                "Failed to create temporary file: {}",
                std::io::Error::last_os_error()
            );
        }

        // Write some initial data using regular write
        let initial_data = b"Hello, world! This is test data for pread/pwrite.";
        let write_result = libc::write(
            fd,
            initial_data.as_ptr() as *const libc::c_void,
            initial_data.len(),
        );
        if write_result < 0 {
            bail!("Initial write failed: {}", std::io::Error::last_os_error());
        }

        // Test pwrite - write at offset 7 (overwriting "world")
        let pwrite_data = b"pinch";
        let pwrite_result = libc::pwrite64(
            fd,
            pwrite_data.as_ptr() as *const libc::c_void,
            pwrite_data.len(),
            7,
        );
        if pwrite_result < 0 {
            bail!("pwrite64 failed: {}", std::io::Error::last_os_error());
        }

        // Test pread - read from offset 3, skipping "Hel"
        let mut read_buffer = vec![0u8; 28];
        let pread_result = libc::pread64(
            fd,
            read_buffer.as_mut_ptr() as *mut libc::c_void,
            read_buffer.len(),
            3,
        );
        if pread_result < 0 {
            bail!("pread64 failed: {}", std::io::Error::last_os_error());
        }

        // Clean up
        libc::close(fd);
        libc::unlink(c"/tmp/pread_pwrite_test".as_ptr());
    }

    Ok(())
}

fn readv_writev_test() -> anyhow::Result<()> {
    unsafe {
        // Create a temporary file for testing readv/writev
        let fd = libc::openat(
            libc::AT_FDCWD,
            c"/tmp/readv_writev_test".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );

        if fd < 0 {
            bail!(
                "Failed to create temporary file: {}",
                std::io::Error::last_os_error()
            );
        }

        // Prepare some data to write
        let data1 = b"Hello, ";
        let data2 = b"world!";
        let iov = [
            libc::iovec {
                iov_base: data1.as_ptr() as *mut libc::c_void,
                iov_len: data1.len(),
            },
            libc::iovec {
                iov_base: data2.as_ptr() as *mut libc::c_void,
                iov_len: data2.len(),
            },
        ];

        // Test writev - write both buffers in one call
        let result = libc::writev(fd, iov.as_ptr(), iov.len() as i32);
        if result < 0 {
            bail!("writev failed: {}", std::io::Error::last_os_error());
        }

        // Prepare buffers for reading
        let mut buffer1 = vec![0u8; 7]; // Enough space for "Hello, "
        let mut buffer2 = vec![0u8; 6]; // Enough space for "world!"
        let read_iov = [
            libc::iovec {
                iov_base: buffer1.as_mut_ptr() as *mut libc::c_void,
                iov_len: buffer1.len(),
            },
            libc::iovec {
                iov_base: buffer2.as_mut_ptr() as *mut libc::c_void,
                iov_len: buffer2.len(),
            },
        ];

        // Reset the file descriptor's position to the beginning of the file
        let result = libc::lseek(fd, 0, libc::SEEK_SET);
        if result < 0 {
            bail!("lseek failed: {}", std::io::Error::last_os_error());
        }

        // Test readv - read into both buffers in one call
        let result = libc::readv(fd, read_iov.as_ptr(), read_iov.len() as i32);
        if result < 0 {
            bail!("readv failed: {}", std::io::Error::last_os_error());
        }

        // Verify the data
        assert_eq!(&buffer1[..], &data1[..]);
        assert_eq!(&buffer2[..], &data2[..]);

        // Clean up
        libc::close(fd);
        libc::unlink(c"/tmp/readv_writev_test".as_ptr());
    }

    Ok(())
}

fn socket_lifecycle_test() -> anyhow::Result<()> {
    unsafe {
        // Test socket() syscall - create a TCP socket
        let sock_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if sock_fd < 0 {
            bail!("socket() failed");
        }

        // Test socket() syscall - create a UDP socket
        let udp_fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if udp_fd < 0 {
            bail!("UDP socket() failed");
        }

        // Create sockaddr_in for binding
        let mut server_addr: libc::sockaddr_in = std::mem::zeroed();
        server_addr.sin_family = libc::AF_INET as u16;
        server_addr.sin_port = 0u16.to_be(); // Let the OS choose port
        server_addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be(); // 127.0.0.1 in network byte order

        let server_addr_ptr = &server_addr as *const libc::sockaddr_in as *const libc::sockaddr;

        // Test bind() syscall
        let bind_result = libc::bind(
            sock_fd,
            server_addr_ptr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        if bind_result < 0 {
            bail!("bind() failed");
        }

        // Test listen() syscall
        let listen_result = libc::listen(sock_fd, 5);
        if listen_result < 0 {
            bail!("listen() failed");
        }

        // Get the actual port that was assigned
        let mut actual_addr: libc::sockaddr_in = std::mem::zeroed();
        let mut addr_len = std::mem::size_of::<libc::sockaddr_in>() as u32;
        let getsockname_result = libc::getsockname(
            sock_fd,
            &mut actual_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut addr_len,
        );
        if getsockname_result < 0 {
            bail!("getsockname() failed");
        }

        // Create client socket for connection test
        let client_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if client_fd < 0 {
            bail!("client socket() failed");
        }

        // Test connect() syscall
        let connect_result = libc::connect(
            client_fd,
            &actual_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        if connect_result < 0 {
            bail!("connect() failed");
        }

        // Test shutdown() syscall with different modes
        let shutdown_read = libc::shutdown(client_fd, libc::SHUT_RD);
        if shutdown_read < 0 {
            bail!("shutdown(SHUT_RD) failed");
        }

        let shutdown_write = libc::shutdown(client_fd, libc::SHUT_WR);
        if shutdown_write < 0 {
            bail!("shutdown(SHUT_WR) failed");
        }

        // Create another client for SHUT_RDWR test
        let client_fd2 = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if client_fd2 < 0 {
            bail!("second client socket() failed");
        }

        let connect_result2 = libc::connect(
            client_fd2,
            &actual_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        if connect_result2 < 0 {
            bail!("second connect() failed");
        }

        let shutdown_rdwr = libc::shutdown(client_fd2, libc::SHUT_RDWR);
        if shutdown_rdwr < 0 {
            bail!("shutdown(SHUT_RDWR) failed");
        }

        // Clean up
        libc::close(client_fd);
        libc::close(client_fd2);
        libc::close(sock_fd);
        libc::close(udp_fd);
    }

    Ok(())
}

fn pselect6_test() -> anyhow::Result<()> {
    unsafe {
        // Create a pipe for the test
        let mut pipe_fds = [0i32; 2];
        let pipe_result = libc::pipe(pipe_fds.as_mut_ptr());
        if pipe_result < 0 {
            bail!("pipe() failed");
        }

        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];

        // Test pselect6 with timeout (should timeout)
        let mut readfds: libc::fd_set = std::mem::zeroed();
        libc::FD_ZERO(&mut readfds);
        libc::FD_SET(read_fd, &mut readfds);

        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000, // 100ms
        };

        let nfds = read_fd + 1;
        let result = libc::pselect(
            nfds,
            &mut readfds,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &timeout,
            std::ptr::null(),
        );

        // Should timeout (return 0)
        if result != 0 {
            bail!("pselect6 should have timed out, got: {}", result);
        }

        // Write some data to make fd ready
        let test_data = b"test";
        let write_result = libc::write(
            write_fd,
            test_data.as_ptr() as *const c_void,
            test_data.len(),
        );
        if write_result < 0 {
            bail!("write() failed");
        }

        // Test pselect6 with ready fd (should return immediately)
        libc::FD_ZERO(&mut readfds);
        libc::FD_SET(read_fd, &mut readfds);

        let timeout2 = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };

        let result2 = libc::pselect(
            nfds,
            &mut readfds,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &timeout2,
            std::ptr::null(),
        );

        // Should return 1 (one fd ready)
        if result2 != 1 {
            bail!("pselect6 should have found 1 ready fd, got: {}", result2);
        }

        // Verify the fd is still set
        if !libc::FD_ISSET(read_fd, &readfds) {
            bail!("read_fd should be set in readfds");
        }

        // Clean up
        libc::close(read_fd);
        libc::close(write_fd);
    }

    Ok(())
}

fn filesystem_sync_test() -> anyhow::Result<()> {
    use std::{fs::OpenOptions, io::Write, os::fd::AsRawFd};

    // Create a temporary file for testing
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("/tmp/test_sync_file.tmp")?;

    let fd = file.as_raw_fd();

    // Write some data to the file
    file.write_all(b"Hello, fsync and fdatasync test!")?;

    // Test fsync syscall
    let result = unsafe { libc::fsync(fd) };
    if result != 0 {
        bail!("fsync failed with error: {}", result);
    }

    // Test fdatasync syscall
    let result = unsafe { libc::fdatasync(fd) };
    if result != 0 {
        bail!("fdatasync failed with error: {}", result);
    }

    // Test ftruncate syscall - truncate to 10 bytes
    let result = unsafe { libc::ftruncate(fd, 10) };
    if result != 0 {
        bail!("ftruncate failed with error: {}", result);
    }

    // Test ftruncate syscall - expand to 50 bytes
    let result = unsafe { libc::ftruncate(fd, 50) };
    if result != 0 {
        bail!("ftruncate expand failed with error: {}", result);
    }

    // Test fchmod syscall - change permissions to 644
    let result = unsafe { libc::fchmod(fd, 0o644) };
    if result != 0 {
        bail!("fchmod failed with error: {}", result);
    }

    // Test fchmod syscall - change permissions to 755
    let result = unsafe { libc::fchmod(fd, 0o755) };
    if result != 0 {
        bail!("fchmod 755 failed with error: {}", result);
    }

    // Clean up - the file will be closed when it goes out of scope
    drop(file);
    let _ = std::fs::remove_file("/tmp/test_sync_file.tmp");

    Ok(())
}

fn epoll_test() -> anyhow::Result<()> {
    unsafe {
        let epfd = libc::epoll_create1(libc::EPOLL_CLOEXEC);
        if epfd < 0 {
            bail!("epoll_create1 failed: {}", std::io::Error::last_os_error());
        }

        let efd = libc::eventfd(0, 0);
        if efd < 0 {
            bail!("eventfd failed: {}", std::io::Error::last_os_error());
        }

        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 0x1234,
        };
        if libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, efd, &mut event) != 0 {
            bail!("epoll_ctl add failed: {}", std::io::Error::last_os_error());
        }

        let val: u64 = 1;
        if libc::write(
            efd,
            &val as *const u64 as *const c_void,
            std::mem::size_of::<u64>(),
        ) < 0
        {
            bail!("eventfd write failed: {}", std::io::Error::last_os_error());
        }

        let mut events: [libc::epoll_event; 8] = std::mem::zeroed();
        let nfds = libc::epoll_pwait(epfd, events.as_mut_ptr(), 8, 0, std::ptr::null());
        if nfds < 0 {
            bail!("epoll_pwait failed: {}", std::io::Error::last_os_error());
        }
        assert_eq!(nfds, 1, "epoll_pwait should return 1");

        if libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, efd, std::ptr::null_mut()) != 0 {
            bail!("epoll_ctl del failed: {}", std::io::Error::last_os_error());
        }

        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // epoll_pwait2 requires a valid events buffer if maxevents > 0.
        // Passing maxevents == 0 can yield EINVAL on some kernels.
        // Use a small buffer and expect a timeout with 0 events.
        let mut events2: [libc::epoll_event; 8] = std::mem::zeroed();
        let nfds2 = libc::syscall(
            libc::SYS_epoll_pwait2,
            epfd,
            events2.as_mut_ptr(),
            events2.len() as libc::c_int,
            &timeout as *const libc::timespec,
            std::ptr::null::<libc::sigset_t>(),
            0usize,
        );
        if nfds2 < 0 {
            bail!("epoll_pwait2 failed: {}", std::io::Error::last_os_error());
        }
        assert_eq!(nfds2, 0);

        // Similarly, ensure maxevents > 0 for epoll_wait to avoid EINVAL.
        let mut events3: [libc::epoll_event; 8] = std::mem::zeroed();
        let nfds3 = libc::epoll_wait(epfd, events3.as_mut_ptr(), events3.len() as libc::c_int, 0);
        if nfds3 < 0 {
            bail!("epoll_wait failed: {}", std::io::Error::last_os_error());
        }
        assert_eq!(nfds3, 0);

        libc::close(efd);
        libc::close(epfd);
    }
    Ok(())
}

fn eventfd_test() -> anyhow::Result<()> {
    unsafe {
        // Test eventfd2 syscall with no flags (available on both x86_64 and aarch64)
        let efd = libc::syscall(libc::SYS_eventfd2, 0, 0);
        if efd < 0 {
            bail!("eventfd2 failed: {}", std::io::Error::last_os_error());
        }

        // Test eventfd2 with EFD_CLOEXEC flag
        let efd_cloexec = libc::syscall(libc::SYS_eventfd2, 5, libc::O_CLOEXEC);
        if efd_cloexec < 0 {
            bail!(
                "eventfd2 with EFD_CLOEXEC failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test eventfd2 with EFD_NONBLOCK flag
        let efd_nonblock = libc::syscall(libc::SYS_eventfd2, 10, libc::O_NONBLOCK);
        if efd_nonblock < 0 {
            bail!(
                "eventfd2 with EFD_NONBLOCK failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // On x86_64, also test the original eventfd syscall
        #[cfg(target_arch = "x86_64")]
        {
            let efd_old = libc::syscall(libc::SYS_eventfd, 42, 0);
            if efd_old < 0 {
                bail!("eventfd failed: {}", std::io::Error::last_os_error());
            }

            // Close the old eventfd
            libc::close(efd_old as i32);
        }

        // Close all the eventfds
        libc::close(efd as i32);
        libc::close(efd_cloexec as i32);
        libc::close(efd_nonblock as i32);
    }

    Ok(())
}

fn timer_test() -> anyhow::Result<()> {
    unsafe {
        // Test timer_create with different clock types and signal events
        let mut timerid: libc::timer_t = std::ptr::null_mut();

        // Test 1: timer_create with CLOCK_REALTIME and a sigevent structure
        // We'll create the sigevent structure manually due to libc complexity
        let mut sevp: libc::sigevent = std::mem::zeroed();
        sevp.sigev_notify = libc::SIGEV_SIGNAL;
        sevp.sigev_signo = libc::SIGUSR1;
        // Set the value using raw bytes since sigval is a union
        let value_ptr = &mut sevp.sigev_value as *mut libc::sigval as *mut i32;
        *value_ptr = 42;

        let result = libc::syscall(
            libc::SYS_timer_create,
            libc::CLOCK_REALTIME,
            &sevp as *const libc::sigevent,
            &mut timerid as *mut libc::timer_t,
        );

        if result != 0 {
            bail!("timer_create failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: timer_settime with relative time
        let new_value = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 1,
                tv_nsec: 0,
            }, // 1 second interval
            it_value: libc::timespec {
                tv_sec: 2,
                tv_nsec: 500_000_000,
            }, // 2.5 second initial
        };

        let mut old_value: libc::itimerspec = std::mem::zeroed();

        let result = libc::syscall(
            libc::SYS_timer_settime,
            timerid,
            0, // flags: 0 = relative time
            &new_value as *const libc::itimerspec,
            &mut old_value as *mut libc::itimerspec,
        );

        if result != 0 {
            bail!("timer_settime failed: {}", std::io::Error::last_os_error());
        }

        // Test 3: timer_gettime
        let mut curr_value: libc::itimerspec = std::mem::zeroed();

        let result = libc::syscall(
            libc::SYS_timer_gettime,
            timerid,
            &mut curr_value as *mut libc::itimerspec,
        );

        if result != 0 {
            bail!("timer_gettime failed: {}", std::io::Error::last_os_error());
        }

        // Test 4: timer_getoverrun
        let result = libc::syscall(libc::SYS_timer_getoverrun, timerid);

        if result < 0 {
            bail!(
                "timer_getoverrun failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 5: timer_delete
        let result = libc::syscall(libc::SYS_timer_delete, timerid);

        if result != 0 {
            bail!("timer_delete failed: {}", std::io::Error::last_os_error());
        }

        // Test 6: timer_create with NULL sigevent (should use default SIGEV_SIGNAL/SIGALRM)
        let mut timerid2: libc::timer_t = std::ptr::null_mut();

        let result = libc::syscall(
            libc::SYS_timer_create,
            libc::CLOCK_MONOTONIC,
            std::ptr::null::<libc::sigevent>(),
            &mut timerid2 as *mut libc::timer_t,
        );

        if result != 0 {
            bail!(
                "timer_create with NULL sigevent failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Clean up the second timer
        let result = libc::syscall(libc::SYS_timer_delete, timerid2);

        if result != 0 {
            bail!(
                "timer_delete for second timer failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    Ok(())
}

fn timerfd_test() -> anyhow::Result<()> {
    unsafe {
        // Test 1: timerfd_create with CLOCK_REALTIME and no flags
        let timerfd = libc::syscall(libc::SYS_timerfd_create, libc::CLOCK_REALTIME, 0);
        if timerfd < 0 {
            bail!("timerfd_create failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: timerfd_settime with relative time
        let new_value = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 1,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: 2,
                tv_nsec: 500_000_000,
            },
        };
        let mut old_value: libc::itimerspec = std::mem::zeroed();
        let result = libc::syscall(
            libc::SYS_timerfd_settime,
            timerfd,
            0, // flags = 0 (relative time)
            &new_value as *const libc::itimerspec,
            &mut old_value as *mut libc::itimerspec,
        );
        if result != 0 {
            bail!(
                "timerfd_settime failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 3: timerfd_gettime
        let mut curr_value: libc::itimerspec = std::mem::zeroed();
        let result = libc::syscall(
            libc::SYS_timerfd_gettime,
            timerfd,
            &mut curr_value as *mut libc::itimerspec,
        );
        if result != 0 {
            bail!(
                "timerfd_gettime failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Close the timerfd
        libc::close(timerfd as i32);

        // Test 4: timerfd_create with CLOCK_MONOTONIC and TFD_CLOEXEC
        let timerfd2 = libc::syscall(libc::SYS_timerfd_create, libc::CLOCK_MONOTONIC, 0o2000000); // TFD_CLOEXEC
        if timerfd2 < 0 {
            bail!(
                "timerfd_create with TFD_CLOEXEC failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 5: timerfd_settime with absolute time (TIMER_ABSTIME flag)
        let abs_time = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: 1675209600, // Some absolute time
                tv_nsec: 0,
            },
        };
        let result = libc::syscall(
            libc::SYS_timerfd_settime,
            timerfd2,
            1, // TIMER_ABSTIME
            &abs_time as *const libc::itimerspec,
            std::ptr::null_mut::<libc::itimerspec>(),
        );
        if result != 0 {
            bail!(
                "timerfd_settime with TIMER_ABSTIME failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 6: timerfd_gettime on the second timer
        let mut curr_value2: libc::itimerspec = std::mem::zeroed();
        let result = libc::syscall(
            libc::SYS_timerfd_gettime,
            timerfd2,
            &mut curr_value2 as *mut libc::itimerspec,
        );
        if result != 0 {
            bail!(
                "timerfd_gettime on second timer failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Close the second timerfd
        libc::close(timerfd2 as i32);
    }

    Ok(())
}

fn pipe_operations_test() -> anyhow::Result<()> {
    unsafe {
        // Test 1: pipe2 with no flags
        let mut pipe_fds = [0i32; 2];
        let result = libc::syscall(libc::SYS_pipe2, pipe_fds.as_mut_ptr(), 0);
        if result != 0 {
            bail!(
                "pipe2 with no flags failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let pipe1_read = pipe_fds[0];
        let pipe1_write = pipe_fds[1];

        // Test 2: pipe2 with O_NONBLOCK
        let mut pipe_fds2 = [0i32; 2];
        let result = libc::syscall(libc::SYS_pipe2, pipe_fds2.as_mut_ptr(), libc::O_NONBLOCK);
        if result != 0 {
            bail!(
                "pipe2 with O_NONBLOCK failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let pipe2_read = pipe_fds2[0];
        let pipe2_write = pipe_fds2[1];

        // Test 3: pipe2 with O_CLOEXEC
        let mut pipe_fds3 = [0i32; 2];
        let result = libc::syscall(libc::SYS_pipe2, pipe_fds3.as_mut_ptr(), libc::O_CLOEXEC);
        if result != 0 {
            bail!(
                "pipe2 with O_CLOEXEC failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let pipe3_read = pipe_fds3[0];
        let pipe3_write = pipe_fds3[1];

        // Test 4: pipe2 with O_NONBLOCK|O_CLOEXEC
        let mut pipe_fds4 = [0i32; 2];
        let result = libc::syscall(
            libc::SYS_pipe2,
            pipe_fds4.as_mut_ptr(),
            libc::O_NONBLOCK | libc::O_CLOEXEC,
        );
        if result != 0 {
            bail!(
                "pipe2 with O_NONBLOCK|O_CLOEXEC failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let pipe4_read = pipe_fds4[0];
        let pipe4_write = pipe_fds4[1];

        // Write some data to the first pipe for splice operations
        let test_data = b"Hello, splice world!";
        let bytes_written = libc::write(
            pipe1_write,
            test_data.as_ptr() as *const libc::c_void,
            test_data.len(),
        );
        if bytes_written != test_data.len() as isize {
            bail!("Failed to write test data to pipe");
        }

        // Test 5: splice from pipe1 to pipe2
        let bytes_spliced = libc::syscall(
            libc::SYS_splice,
            pipe1_read,
            std::ptr::null_mut::<libc::loff_t>(),
            pipe2_write,
            std::ptr::null_mut::<libc::loff_t>(),
            test_data.len(),
            libc::SPLICE_F_MOVE,
        );
        if bytes_spliced != test_data.len() as i64 {
            bail!(
                "splice failed: expected {}, got {}",
                test_data.len(),
                bytes_spliced
            );
        }

        // Test 6: tee from pipe2 to pipe3 (duplicate data)
        let bytes_teed = libc::syscall(
            libc::SYS_tee,
            pipe2_read,
            pipe3_write,
            test_data.len(),
            libc::SPLICE_F_NONBLOCK,
        );
        if bytes_teed != test_data.len() as i64 {
            bail!(
                "tee failed: expected {}, got {}",
                test_data.len(),
                bytes_teed
            );
        }

        // Test 7: vmsplice to write data from user space to pipe4
        let vmsplice_data = b"vmsplice test data";
        let iov = libc::iovec {
            iov_base: vmsplice_data.as_ptr() as *mut libc::c_void,
            iov_len: vmsplice_data.len(),
        };
        let bytes_vmspliced = libc::syscall(
            libc::SYS_vmsplice,
            pipe4_write,
            &iov as *const libc::iovec,
            1,
            libc::SPLICE_F_GIFT,
        );
        if bytes_vmspliced != vmsplice_data.len() as i64 {
            bail!(
                "vmsplice failed: expected {}, got {}",
                vmsplice_data.len(),
                bytes_vmspliced
            );
        }

        // Clean up - close all file descriptors
        libc::close(pipe1_read);
        libc::close(pipe1_write);
        libc::close(pipe2_read);
        libc::close(pipe2_write);
        libc::close(pipe3_read);
        libc::close(pipe3_write);
        libc::close(pipe4_read);
        libc::close(pipe4_write);
    }

    Ok(())
}

fn execveat_test() -> anyhow::Result<()> {
    use std::{ffi::CString, fs::File, os::unix::io::AsRawFd};

    // Open the directory containing the binary
    let dir = File::open("/bin")?;
    let dirfd = dir.as_raw_fd();

    // Test execveat with directory fd and relative path
    let argv = [
        CString::new("this-does-not-exist-for-sure")?,
        CString::new("arg1")?,
        CString::new("arg2")?,
    ];
    let envp = [
        CString::new("PATH=/bin:/usr/bin")?,
        CString::new("TEST_VAR=execveat_value")?,
    ];

    let pathname = CString::new("this-does-not-exist-for-sure")?;

    // Convert CString vectors to pointer arrays
    let argv_ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|arg| arg.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let envp_ptrs: Vec<*const libc::c_char> = envp
        .iter()
        .map(|env| env.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    unsafe {
        let _ = libc::syscall(
            libc::SYS_execveat,
            dirfd,
            pathname.as_ptr(),
            argv_ptrs.as_ptr(),
            envp_ptrs.as_ptr(),
            0, // flags
        );
    }

    Ok(())
}

fn io_multiplexing_test() -> anyhow::Result<()> {
    unsafe {
        // Create a pipe for testing I/O readiness
        let mut pipe_fds = [0i32; 2];
        let pipe_result = libc::pipe(pipe_fds.as_mut_ptr());
        if pipe_result < 0 {
            bail!("pipe() failed");
        }

        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];

        // Test 1: select (x86_64 only) - timeout case
        #[cfg(target_arch = "x86_64")]
        {
            let mut readfds: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut readfds);
            libc::FD_SET(read_fd, &mut readfds);

            let mut timeout = libc::timeval {
                tv_sec: 0,
                tv_usec: 0, // Immediate timeout
            };

            let nfds = read_fd + 1;
            let result = libc::syscall(
                libc::SYS_select,
                nfds,
                &mut readfds as *mut libc::fd_set,
                std::ptr::null_mut::<libc::fd_set>(),
                std::ptr::null_mut::<libc::fd_set>(),
                &mut timeout as *mut libc::timeval,
            );

            // Should timeout (return 0)
            if result != 0 {
                bail!("select should have timed out, got: {}", result);
            }
        }

        // Test 2: poll - timeout case
        #[cfg(target_arch = "x86_64")]
        {
            let mut pollfd = libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN,
                revents: 0,
            };

            let result = libc::poll(&mut pollfd, 1, 0); // 0ms timeout
            if result != 0 {
                bail!("poll should have timed out, got: {}", result);
            }
        }

        // Test 3: ppoll - timeout case (skip extra timeout, just test once)
        // Note: This test starts after some initial polling by the test framework

        // Write some data to make the fd ready
        let test_data = b"test data for multiplexing";
        let write_result = libc::write(
            write_fd,
            test_data.as_ptr() as *const c_void,
            test_data.len(),
        );
        if write_result < 0 {
            bail!("write() failed");
        }

        // Test 4: select (x86_64 only) - ready case
        #[cfg(target_arch = "x86_64")]
        {
            let mut readfds: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut readfds);
            libc::FD_SET(read_fd, &mut readfds);

            let mut timeout = libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            };

            let nfds = read_fd + 1;
            let result = libc::syscall(
                libc::SYS_select,
                nfds,
                &mut readfds as *mut libc::fd_set,
                std::ptr::null_mut::<libc::fd_set>(),
                std::ptr::null_mut::<libc::fd_set>(),
                &mut timeout as *mut libc::timeval,
            );

            // Should return 1 (one fd ready)
            if result != 1 {
                bail!("select should have found 1 ready fd, got: {}", result);
            }

            // Verify the fd is still set
            if !libc::FD_ISSET(read_fd, &readfds) {
                bail!("read_fd should be set in readfds");
            }
        }

        // Test 5: poll (x86_64 only) - ready case
        #[cfg(target_arch = "x86_64")]
        {
            let mut pollfd = libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN,
                revents: 0,
            };

            let result = libc::poll(&mut pollfd, 1, 1000); // 1 second timeout
            if result != 1 {
                bail!("poll should have found 1 ready fd, got: {}", result);
            }

            // Verify the fd is ready for reading
            if pollfd.revents & libc::POLLIN == 0 {
                bail!("read_fd should be ready for reading");
            }
        }

        // Test 6: ppoll - ready case
        let mut pollfd_ppoll_ready = libc::pollfd {
            fd: read_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let timeout_ppoll_ready = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };

        let result = libc::ppoll(
            &mut pollfd_ppoll_ready,
            1,
            &timeout_ppoll_ready,
            std::ptr::null(),
        );
        if result != 1 {
            bail!("ppoll should have found 1 ready fd, got: {}", result);
        }

        // Verify the fd is ready for reading
        if pollfd_ppoll_ready.revents & libc::POLLIN == 0 {
            bail!("read_fd should be ready for reading in ppoll");
        }

        // Clean up
        libc::close(read_fd);
        libc::close(write_fd);
    }

    Ok(())
}

fn xattr_test() -> anyhow::Result<()> {
    use std::{ffi::CString, fs::File, io::Write, os::unix::io::AsRawFd};

    // Create a temporary file for testing extended attributes
    let mut file = File::create("/tmp/xattr_test_file")?;
    file.write_all(b"test file for xattr operations")?;
    file.sync_all()?;
    let fd = file.as_raw_fd();

    // File path for path-based xattr operations
    let file_path = CString::new("/tmp/xattr_test_file")?;

    // Test attribute names and values
    let attr_name1 = CString::new("user.test_attr1")?;
    let attr_value1 = b"test_value_1";

    let attr_name2 = CString::new("user.test_attr2")?;
    let attr_value2 = b"another_test_value";

    unsafe {
        // Test 1: setxattr - set extended attribute via path
        let result = libc::setxattr(
            file_path.as_ptr(),
            attr_name1.as_ptr(),
            attr_value1.as_ptr() as *const libc::c_void,
            attr_value1.len(),
            0, // flags
        );
        if result != 0 {
            bail!("setxattr failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: fsetxattr - set extended attribute via file descriptor
        let result = libc::fsetxattr(
            fd,
            attr_name2.as_ptr(),
            attr_value2.as_ptr() as *const libc::c_void,
            attr_value2.len(),
            0, // flags
        );
        if result != 0 {
            bail!("fsetxattr failed: {}", std::io::Error::last_os_error());
        }

        // Test 3: getxattr - get extended attribute via path
        let mut buffer1 = vec![0u8; 64];
        let result = libc::getxattr(
            file_path.as_ptr(),
            attr_name1.as_ptr(),
            buffer1.as_mut_ptr() as *mut libc::c_void,
            buffer1.len(),
        );
        if result < 0 {
            bail!("getxattr failed: {}", std::io::Error::last_os_error());
        }
        // Verify we got the expected value
        assert_eq!(&buffer1[..result as usize], attr_value1);

        // Test 4: fgetxattr - get extended attribute via file descriptor
        let mut buffer2 = vec![0u8; 64];
        let result = libc::fgetxattr(
            fd,
            attr_name2.as_ptr(),
            buffer2.as_mut_ptr() as *mut libc::c_void,
            buffer2.len(),
        );
        if result < 0 {
            bail!("fgetxattr failed: {}", std::io::Error::last_os_error());
        }
        // Verify we got the expected value
        assert_eq!(&buffer2[..result as usize], attr_value2);

        // Test 5: listxattr - list all extended attributes via path
        let mut list_buffer = vec![0u8; 256];
        let result = libc::listxattr(
            file_path.as_ptr(),
            list_buffer.as_mut_ptr() as *mut libc::c_char,
            list_buffer.len(),
        );
        if result < 0 {
            bail!("listxattr failed: {}", std::io::Error::last_os_error());
        }
        // The result should contain both attribute names we set
        let list_str =
            std::str::from_utf8(&list_buffer[..result as usize]).unwrap_or("invalid_utf8");
        assert!(list_str.contains("user.test_attr1"));
        assert!(list_str.contains("user.test_attr2"));

        // Test 6: flistxattr - list all extended attributes via file descriptor
        let mut flist_buffer = vec![0u8; 256];
        let result = libc::flistxattr(
            fd,
            flist_buffer.as_mut_ptr() as *mut libc::c_char,
            flist_buffer.len(),
        );
        if result < 0 {
            bail!("flistxattr failed: {}", std::io::Error::last_os_error());
        }

        // Test 7: Test getxattr with NULL buffer to get size
        let size = libc::getxattr(
            file_path.as_ptr(),
            attr_name1.as_ptr(),
            std::ptr::null_mut(),
            0,
        );
        if size < 0 {
            bail!(
                "getxattr size query failed: {}",
                std::io::Error::last_os_error()
            );
        }
        assert_eq!(size as usize, attr_value1.len());

        // Test 8: Test error case - non-existent attribute
        let nonexistent_attr = CString::new("user.nonexistent")?;
        let mut error_buffer = vec![0u8; 64];
        let result = libc::getxattr(
            file_path.as_ptr(),
            nonexistent_attr.as_ptr(),
            error_buffer.as_mut_ptr() as *mut libc::c_void,
            error_buffer.len(),
        );
        // This should fail with ENODATA
        assert_eq!(result, -1);
    }

    // Clean up
    drop(file);
    let _ = std::fs::remove_file("/tmp/xattr_test_file");

    Ok(())
}

fn sysv_ipc_test() -> anyhow::Result<()> {
    unsafe {
        // === SHARED MEMORY TESTS ===

        // Test 1: shmget - create a shared memory segment
        let shm_key = 0x12345678; // IPC_PRIVATE would be 0, but we want a specific key
        let shm_size = 4096;
        let shm_id = libc::shmget(shm_key, shm_size, libc::IPC_CREAT | 0o666);
        if shm_id < 0 {
            bail!("shmget failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: shmat - attach the shared memory segment
        let shm_addr = libc::shmat(shm_id, std::ptr::null(), 0);
        if shm_addr == (-1isize) as *mut libc::c_void {
            bail!("shmat failed: {}", std::io::Error::last_os_error());
        }

        // Test 3: shmctl with IPC_STAT - get shared memory info
        let mut shm_ds: libc::shmid_ds = std::mem::zeroed();
        let result = libc::shmctl(shm_id, libc::IPC_STAT, &mut shm_ds);
        if result != 0 {
            bail!(
                "shmctl IPC_STAT failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 4: shmdt - detach the shared memory segment
        let result = libc::shmdt(shm_addr);
        if result != 0 {
            bail!("shmdt failed: {}", std::io::Error::last_os_error());
        }

        // Test 5: shmctl with IPC_RMID - remove the shared memory segment
        let result = libc::shmctl(shm_id, libc::IPC_RMID, std::ptr::null_mut());
        if result != 0 {
            bail!(
                "shmctl IPC_RMID failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // === MESSAGE QUEUE TESTS ===

        // Test 6: msgget - create a message queue
        let msg_key = 0x12345679; // Use a smaller key to avoid overflow
        let msg_id = libc::msgget(msg_key, libc::IPC_CREAT | 0o666);
        if msg_id < 0 {
            bail!("msgget failed: {}", std::io::Error::last_os_error());
        }

        // Prepare a test message
        #[repr(C)]
        struct TestMessage {
            mtype: libc::c_long,
            mtext: [libc::c_char; 32],
        }

        let mut test_msg = TestMessage {
            mtype: 1, // Message type 1
            mtext: [0; 32],
        };

        // Copy test data into message
        let test_data = b"Hello, SysV IPC message queue!";
        let copy_len = std::cmp::min(test_data.len(), test_msg.mtext.len() - 1);
        for (i, &byte) in test_data.iter().take(copy_len).enumerate() {
            test_msg.mtext[i] = byte as libc::c_char;
        }

        // Test 7: msgsnd - send a message
        let result = libc::msgsnd(
            msg_id,
            &test_msg as *const TestMessage as *const libc::c_void,
            test_data.len(),
            0, // no flags
        );
        if result != 0 {
            bail!("msgsnd failed: {}", std::io::Error::last_os_error());
        }

        // Test 8: msgctl with IPC_STAT - get message queue info
        let mut msg_ds: libc::msqid_ds = std::mem::zeroed();
        let result = libc::msgctl(msg_id, libc::IPC_STAT, &mut msg_ds);
        if result != 0 {
            bail!(
                "msgctl IPC_STAT failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 9: msgrcv - receive the message
        let mut recv_msg = TestMessage {
            mtype: 0,
            mtext: [0; 32],
        };
        let result = libc::msgrcv(
            msg_id,
            &mut recv_msg as *mut TestMessage as *mut libc::c_void,
            32, // max size
            0,  // any message type
            0,  // no flags
        );
        if result < 0 {
            bail!("msgrcv failed: {}", std::io::Error::last_os_error());
        }

        // Test 10: msgctl with IPC_RMID - remove the message queue
        let result = libc::msgctl(msg_id, libc::IPC_RMID, std::ptr::null_mut());
        if result != 0 {
            bail!(
                "msgctl IPC_RMID failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // === SEMAPHORE TESTS ===

        // Test 11: semget - create a semaphore set
        let sem_key = 0x11223344;
        let sem_count = 2; // Create 2 semaphores
        let sem_id = libc::semget(sem_key, sem_count, libc::IPC_CREAT | 0o666);
        if sem_id < 0 {
            bail!("semget failed: {}", std::io::Error::last_os_error());
        }

        // Test 12: semctl with SETVAL - set semaphore value
        let result = libc::semctl(sem_id, 0, libc::SETVAL, 5); // Set semaphore 0 to value 5
        if result != 0 {
            bail!("semctl SETVAL failed: {}", std::io::Error::last_os_error());
        }

        // Test 13: semctl with GETVAL - get semaphore value
        let sem_val = libc::semctl(sem_id, 0, libc::GETVAL, 0);
        if sem_val < 0 {
            bail!("semctl GETVAL failed: {}", std::io::Error::last_os_error());
        }
        assert_eq!(sem_val, 5, "Semaphore value should be 5");

        // Test 14: semop - perform semaphore operations
        let mut sem_ops = [
            libc::sembuf {
                sem_num: 0,                       // semaphore 0
                sem_op: -1,                       // decrement by 1
                sem_flg: libc::IPC_NOWAIT as i16, // don't block
            },
            libc::sembuf {
                sem_num: 1, // semaphore 1
                sem_op: 1,  // increment by 1
                sem_flg: 0, // default flags
            },
        ];

        let result = libc::semop(sem_id, sem_ops.as_mut_ptr(), sem_ops.len());
        if result != 0 {
            bail!("semop failed: {}", std::io::Error::last_os_error());
        }

        // Test 15: semctl with IPC_RMID - remove the semaphore set
        let result = libc::semctl(sem_id, 0, libc::IPC_RMID, 0);
        if result != 0 {
            bail!(
                "semctl IPC_RMID failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    Ok(())
}

fn posix_mq_test() -> anyhow::Result<()> {
    unsafe {
        // Declare the foreign POSIX MQ functions from libc
        // On modern glibc (2.34+), these are in libc, not a separate librt
        #[link(name = "c")]
        extern "C" {
            fn mq_open(name: *const libc::c_char, oflag: libc::c_int, ...) -> libc::c_int;
            fn mq_unlink(name: *const libc::c_char) -> libc::c_int;
            fn mq_timedsend(
                mqdes: libc::c_int,
                msg_ptr: *const libc::c_char,
                msg_len: libc::size_t,
                msg_prio: libc::c_uint,
                abs_timeout: *const libc::timespec,
            ) -> libc::c_int;
            fn mq_timedreceive(
                mqdes: libc::c_int,
                msg_ptr: *mut libc::c_char,
                msg_len: libc::size_t,
                msg_prio: *mut libc::c_uint,
                abs_timeout: *const libc::timespec,
            ) -> libc::ssize_t;
            fn mq_setattr(
                mqdes: libc::c_int,
                newattr: *const libc::mq_attr,
                oldattr: *mut libc::mq_attr,
            ) -> libc::c_int;
            fn mq_notify(mqdes: libc::c_int, notification: *const libc::sigevent) -> libc::c_int;
        }

        // Create a unique message queue name based on process ID
        let mq_name = CString::new(format!("/test_mq_{}", libc::getpid()))?;

        // Test 1: mq_open with O_CREAT to create a new message queue
        let mut attr: libc::mq_attr = std::mem::zeroed();
        attr.mq_flags = 0;
        attr.mq_maxmsg = 10;
        attr.mq_msgsize = 1024;

        let mqdes = mq_open(
            mq_name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o666,
            &attr as *const libc::mq_attr,
        );

        if mqdes < 0 {
            bail!("mq_open create failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: mq_timedsend - send a message with timeout
        let test_msg = b"Hello POSIX MQ!";
        let timeout = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };

        let result = mq_timedsend(
            mqdes,
            test_msg.as_ptr() as *const libc::c_char,
            test_msg.len(),
            10,
            &timeout as *const libc::timespec,
        );

        if result != 0 {
            let _cleanup = mq_unlink(mq_name.as_ptr());
            bail!("mq_timedsend failed: {}", std::io::Error::last_os_error());
        }

        // Test 3: mq_setattr - set O_NONBLOCK flag (syscall name is mq_getsetattr)
        let mut oldattr: libc::mq_attr = std::mem::zeroed();
        let mut newattr: libc::mq_attr = std::mem::zeroed();
        newattr.mq_flags = libc::O_NONBLOCK as libc::c_long;

        let result = mq_setattr(
            mqdes,
            &newattr as *const libc::mq_attr,
            &mut oldattr as *mut libc::mq_attr,
        );

        if result != 0 {
            let _cleanup = mq_unlink(mq_name.as_ptr());
            bail!("mq_setattr failed: {}", std::io::Error::last_os_error());
        }

        // Test 4: mq_timedreceive - receive the message
        let mut recv_buf = vec![0u8; 8192];
        let mut msg_prio: libc::c_uint = 0;

        let result = mq_timedreceive(
            mqdes,
            recv_buf.as_mut_ptr() as *mut libc::c_char,
            recv_buf.len(),
            &mut msg_prio as *mut libc::c_uint,
            &timeout as *const libc::timespec,
        );

        if result < 0 {
            let _cleanup = mq_unlink(mq_name.as_ptr());
            bail!(
                "mq_timedreceive failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 5: mq_notify - register for notification (then unregister with NULL)
        let mut sevp: libc::sigevent = std::mem::zeroed();
        sevp.sigev_notify = 0; // SIGEV_SIGNAL
        sevp.sigev_signo = libc::SIGUSR1;

        let result = mq_notify(mqdes, &sevp as *const libc::sigevent);

        if result != 0 {
            // Non-fatal - just testing tracing
        }

        // Unregister notification
        let _result = mq_notify(mqdes, std::ptr::null());

        // Test 6: Close the message queue descriptor
        libc::close(mqdes);

        // Test 7: mq_unlink - remove the message queue
        let result = mq_unlink(mq_name.as_ptr());
        if result != 0 {
            bail!("mq_unlink failed: {}", std::io::Error::last_os_error());
        }

        // Test 8: mq_open to open non-existent queue (should fail)
        let mqdes = mq_open(
            mq_name.as_ptr(),
            libc::O_RDONLY,
            0,
            std::ptr::null::<libc::mq_attr>(),
        );

        if mqdes >= 0 {
            // Should have failed, but clean up if it didn't
            libc::close(mqdes);
            let _cleanup = mq_unlink(mq_name.as_ptr());
            bail!("mq_open of non-existent queue unexpectedly succeeded");
        }
    }

    Ok(())
}

fn socketpair_sendmmsg_test() -> anyhow::Result<()> {
    unsafe {
        // Test 1: Create a socket pair (AF_UNIX SOCK_STREAM)
        let mut sv = [0i32; 2];
        let result = libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr());
        if result != 0 {
            bail!("socketpair failed: {}", std::io::Error::last_os_error());
        }

        let sock1 = sv[0];
        let sock2 = sv[1];

        // Test 2: Create another socket pair (AF_UNIX SOCK_DGRAM) for variety
        let mut sv_dgram = [0i32; 2];
        let result = libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv_dgram.as_mut_ptr());
        if result != 0 {
            bail!(
                "socketpair DGRAM failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 3: Prepare messages for sendmmsg
        let msg1 = b"First message";
        let msg2 = b"Second message";

        let mut iov1 = libc::iovec {
            iov_base: msg1.as_ptr() as *mut libc::c_void,
            iov_len: msg1.len(),
        };

        let mut iov2 = libc::iovec {
            iov_base: msg2.as_ptr() as *mut libc::c_void,
            iov_len: msg2.len(),
        };

        let msghdr1 = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov1,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let msghdr2 = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov2,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let mut mmsghdr = [
            libc::mmsghdr {
                msg_hdr: msghdr1,
                msg_len: 0,
            },
            libc::mmsghdr {
                msg_hdr: msghdr2,
                msg_len: 0,
            },
        ];

        // Test 4: Send multiple messages using sendmmsg
        let sent = libc::sendmmsg(sock1, mmsghdr.as_mut_ptr(), 2, 0);
        if sent < 0 {
            bail!("sendmmsg failed: {}", std::io::Error::last_os_error());
        }

        // Test 5: Prepare buffers for recvmmsg
        let mut recv_buf1 = [0u8; 64];
        let mut recv_buf2 = [0u8; 64];

        let mut recv_iov1 = libc::iovec {
            iov_base: recv_buf1.as_mut_ptr() as *mut libc::c_void,
            iov_len: recv_buf1.len(),
        };

        let mut recv_iov2 = libc::iovec {
            iov_base: recv_buf2.as_mut_ptr() as *mut libc::c_void,
            iov_len: recv_buf2.len(),
        };

        let recv_msghdr1 = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut recv_iov1,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let recv_msghdr2 = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut recv_iov2,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let mut recv_mmsghdr = [
            libc::mmsghdr {
                msg_hdr: recv_msghdr1,
                msg_len: 0,
            },
            libc::mmsghdr {
                msg_hdr: recv_msghdr2,
                msg_len: 0,
            },
        ];

        // Test 6: Receive multiple messages using recvmmsg
        let timeout = libc::timespec {
            tv_sec: 0,          // Make timeout very short to avoid hanging
            tv_nsec: 100000000, // 100ms
        };

        let received = libc::recvmmsg(
            sock2,
            recv_mmsghdr.as_mut_ptr(),
            2,
            libc::MSG_DONTWAIT, // Non-blocking to avoid hanging
            &timeout as *const libc::timespec as *mut libc::timespec,
        );
        if received < 0 {
            // It's ok if this fails in some cases, we just want to trigger the syscall
            eprintln!(
                "recvmmsg failed (expected in some cases): {}",
                std::io::Error::last_os_error()
            );
        } else {
            // For SOCK_STREAM, messages might be concatenated, so just verify we got some data
            eprintln!("recvmmsg received {} messages successfully", received);
            eprintln!(
                "Message 1 length: {}, Message 2 length: {}",
                recv_mmsghdr[0].msg_len, recv_mmsghdr[1].msg_len
            );
        }

        // Close all file descriptors
        libc::close(sock1);
        libc::close(sock2);
        libc::close(sv_dgram[0]);
        libc::close(sv_dgram[1]);
    }

    Ok(())
}

fn system_info_test() -> anyhow::Result<()> {
    unsafe {
        // Test 1: uname - get system information
        let mut utsname: libc::utsname = std::mem::zeroed();
        let result = libc::uname(&mut utsname);
        if result != 0 {
            bail!("uname failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: sysinfo - get system statistics
        let mut info: libc::sysinfo = std::mem::zeroed();
        let result = libc::sysinfo(&mut info);
        if result != 0 {
            bail!("sysinfo failed: {}", std::io::Error::last_os_error());
        }

        // Verify we got reasonable values
        assert!(info.uptime > 0, "System uptime should be positive");
        assert!(info.totalram > 0, "Total RAM should be positive");
    }

    Ok(())
}

fn prctl_test() -> anyhow::Result<()> {
    use std::ffi::CStr;

    unsafe {
        // Test 1: PR_SET_NAME - set process name
        let process_name = CString::new("pinchy_test").expect("CString::new failed");
        let result = libc::prctl(libc::PR_SET_NAME, process_name.as_ptr());
        if result != 0 {
            bail!("PR_SET_NAME failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: PR_GET_NAME - get process name back
        let mut name_buf = [0u8; 16]; // PR_GET_NAME buffer should be 16 bytes
        let result = libc::prctl(libc::PR_GET_NAME, name_buf.as_mut_ptr());
        if result != 0 {
            bail!("PR_GET_NAME failed: {}", std::io::Error::last_os_error());
        }

        // Verify the name was set correctly
        let name_cstr = CStr::from_ptr(name_buf.as_ptr() as *const libc::c_char);
        let name_str = name_cstr.to_str().expect("Invalid UTF-8 in process name");
        assert!(
            name_str.starts_with("pinchy_test"),
            "Process name should start with 'pinchy_test', got: {}",
            name_str
        );

        // Test 3: PR_GET_DUMPABLE - get current dumpable state
        let result = libc::prctl(libc::PR_GET_DUMPABLE);
        if result < 0 {
            bail!(
                "PR_GET_DUMPABLE failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let original_dumpable = result;

        // Test 4: PR_SET_DUMPABLE - set dumpable state to 0 (not dumpable)
        let result = libc::prctl(libc::PR_SET_DUMPABLE, 0);
        if result != 0 {
            bail!(
                "PR_SET_DUMPABLE failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 5: PR_GET_DUMPABLE again to verify change
        let result = libc::prctl(libc::PR_GET_DUMPABLE);
        if result < 0 {
            bail!(
                "PR_GET_DUMPABLE failed: {}",
                std::io::Error::last_os_error()
            );
        }
        assert_eq!(result, 0, "Dumpable state should be 0");

        // Test 6: Restore original dumpable state
        let result = libc::prctl(libc::PR_SET_DUMPABLE, original_dumpable);
        if result != 0 {
            bail!(
                "PR_SET_DUMPABLE restore failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 7: PR_CAPBSET_READ - read capability from bounding set
        // We'll read CAP_SYS_ADMIN (21) which may or may not be present
        let _result = libc::prctl(libc::PR_CAPBSET_READ, 21); // CAP_SYS_ADMIN
                                                              // This can return 0 (not present), 1 (present), or -1 (error)
                                                              // We'll accept any valid result since we're testing the tracing

        // Test 8: PR_CAPBSET_DROP - try to drop a capability (expected to fail for non-root)
        let _result = libc::prctl(libc::PR_CAPBSET_DROP, 21); // CAP_SYS_ADMIN
                                                              // This will likely fail with EPERM for non-root, which is fine for testing

        // Test 9: PR_GET_KEEPCAPS - get keep capabilities flag
        let result = libc::prctl(libc::PR_GET_KEEPCAPS);
        if result < 0 {
            bail!(
                "PR_GET_KEEPCAPS failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 10: PR_SET_KEEPCAPS - try to set keep capabilities (may fail for non-root)
        let _result = libc::prctl(libc::PR_SET_KEEPCAPS, 1);
        // This may fail for non-root users, which is fine for testing
    }

    Ok(())
}

fn mmap_test() -> anyhow::Result<()> {
    unsafe {
        let page_size = 4096;

        // Test 1: mmap with PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS
        let addr1 = libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if addr1 == libc::MAP_FAILED {
            bail!("mmap 1 failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: mmap with only PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS
        let addr2 = libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if addr2 == libc::MAP_FAILED {
            bail!("mmap 2 failed: {}", std::io::Error::last_os_error());
        }

        // Test 3: mmap with PROT_NONE
        let addr3 = libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if addr3 == libc::MAP_FAILED {
            bail!("mmap 3 failed: {}", std::io::Error::last_os_error());
        }

        // Test 4: mmap with additional flags (MAP_LOCKED, MAP_POPULATE)
        let addr4 = libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_LOCKED | libc::MAP_POPULATE,
            -1,
            0,
        );
        // This might fail due to permissions or limits, which is fine for testing
        let addr4_valid = addr4 != libc::MAP_FAILED;

        // Test 5: mmap with fixed address (might fail, which is good for error testing)
        let fixed_addr = 0x12345000usize as *mut libc::c_void;
        let addr5 = libc::mmap(
            fixed_addr,
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        );
        let addr5_valid = addr5 != libc::MAP_FAILED;

        // Test munmap for all successful mappings

        // Test 6: munmap addr1
        let result = libc::munmap(addr1, page_size);
        if result != 0 {
            bail!("munmap 1 failed: {}", std::io::Error::last_os_error());
        }

        // Test 7: munmap addr2
        let result = libc::munmap(addr2, page_size);
        if result != 0 {
            bail!("munmap 2 failed: {}", std::io::Error::last_os_error());
        }

        // Test 8: munmap addr3
        let result = libc::munmap(addr3, page_size);
        if result != 0 {
            bail!("munmap 3 failed: {}", std::io::Error::last_os_error());
        }

        // Test 9: munmap addr4 (only if mmap succeeded)
        if addr4_valid {
            let result = libc::munmap(addr4, page_size);
            if result != 0 {
                bail!("munmap 4 failed: {}", std::io::Error::last_os_error());
            }
        }

        // Test 10: munmap addr5 (only if mmap succeeded)
        if addr5_valid {
            let result = libc::munmap(addr5, page_size);
            if result != 0 {
                bail!("munmap 5 failed: {}", std::io::Error::last_os_error());
            }
        }

        // Test 11: munmap with invalid address (might succeed or fail depending on system)
        let _result = libc::munmap(std::ptr::null_mut(), page_size);
        // Result can vary by system - just generate the syscall for tracing

        // Test 12: munmap with invalid size (might succeed or fail depending on system)
        let _result = libc::munmap(0x1000 as *mut libc::c_void, 0);
        // Result can vary by system - just generate the syscall for tracing
    }

    Ok(())
}

fn memfd_test() -> anyhow::Result<()> {
    unsafe {
        // Test 1: memfd_create with MFD_CLOEXEC flag
        let name1 = CString::new("test_memfd_1").expect("CString creation failed");
        let fd1 = libc::syscall(
            syscalls::SYS_memfd_create,
            name1.as_ptr(),
            libc::MFD_CLOEXEC as i32,
        );

        if fd1 < 0 {
            bail!("memfd_create 1 failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: memfd_create with MFD_ALLOW_SEALING flag
        let name2 = CString::new("test_memfd_2").expect("CString creation failed");
        let fd2 = libc::syscall(
            syscalls::SYS_memfd_create,
            name2.as_ptr(),
            libc::MFD_ALLOW_SEALING as i32,
        );

        if fd2 < 0 {
            bail!("memfd_create 2 failed: {}", std::io::Error::last_os_error());
        }

        // Test 3: memfd_create with both MFD_CLOEXEC and MFD_ALLOW_SEALING
        let name3 = CString::new("test_memfd_3").expect("CString creation failed");
        let fd3 = libc::syscall(
            syscalls::SYS_memfd_create,
            name3.as_ptr(),
            (libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) as i32,
        );

        if fd3 < 0 {
            bail!("memfd_create 3 failed: {}", std::io::Error::last_os_error());
        }

        // Close all file descriptors
        libc::close(fd1 as i32);
        libc::close(fd2 as i32);
        libc::close(fd3 as i32);
    }

    Ok(())
}

fn ioctl_test() -> anyhow::Result<()> {
    unsafe {
        // Open the GPLv2 file for testing ioctl operations
        let fd = libc::openat(
            libc::AT_FDCWD,
            c"pinchy/tests/GPLv2".as_ptr(),
            libc::O_RDONLY,
        );
        if fd < 0 {
            bail!(
                "Failed to open test file: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 1: FIONREAD ioctl - get number of bytes available to read
        let mut bytes_available: libc::c_int = 0;
        let result = libc::ioctl(fd, libc::FIONREAD, &mut bytes_available as *mut libc::c_int);
        if result != 0 {
            bail!("FIONREAD ioctl failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: Invalid ioctl request - should fail
        let mut dummy_arg: libc::c_int = 0;
        let _result = libc::ioctl(fd, 0xDEADBEEF, &mut dummy_arg as *mut libc::c_int);
        // This should fail with EINVAL, but we still trace the syscall

        // Test 3: Another valid ioctl - FIOCLEX (set close-on-exec flag)
        let result = libc::ioctl(fd, libc::FIOCLEX, 0);
        if result != 0 {
            bail!("FIOCLEX ioctl failed: {}", std::io::Error::last_os_error());
        }

        // Clean up
        libc::close(fd);
    }

    Ok(())
}

fn filesystem_links_test() -> anyhow::Result<()> {
    use std::ffi::CString;

    unsafe {
        // Create a temporary target file for our link operations
        let target_fd = libc::openat(
            libc::AT_FDCWD,
            c"/tmp/filesystem_links_target".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if target_fd < 0 {
            bail!(
                "Failed to create target file: {}",
                std::io::Error::last_os_error()
            );
        }

        // Write some content to the target file
        let content = b"This is a test file for link operations";
        let bytes_written = libc::write(
            target_fd,
            content.as_ptr() as *const libc::c_void,
            content.len(),
        );
        if bytes_written != content.len() as isize {
            bail!("Failed to write content to target file");
        }
        libc::close(target_fd);

        // Test 1: symlinkat - Create a symbolic link
        let target_path = CString::new("/tmp/filesystem_links_target")?;
        let symlink_path = CString::new("/tmp/filesystem_links_symlink")?;

        let result = libc::syscall(
            libc::SYS_symlinkat,
            target_path.as_ptr(),
            libc::AT_FDCWD,
            symlink_path.as_ptr(),
        );
        if result != 0 {
            bail!("symlinkat failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: readlinkat - Read the symbolic link back
        let mut read_buffer = [0u8; 256];
        let bytes_read = libc::syscall(
            libc::SYS_readlinkat,
            libc::AT_FDCWD,
            symlink_path.as_ptr(),
            read_buffer.as_mut_ptr(),
            read_buffer.len(),
        );
        if bytes_read < 0 {
            bail!("readlinkat failed: {}", std::io::Error::last_os_error());
        }

        // Verify we got the expected target path back
        let read_target = std::str::from_utf8(&read_buffer[..bytes_read as usize])
            .expect("Invalid UTF-8 in symlink target");
        assert_eq!(read_target, "/tmp/filesystem_links_target");

        // Test 3: linkat - Create a hard link
        let hardlink_path = CString::new("/tmp/filesystem_links_hardlink")?;
        let result = libc::syscall(
            libc::SYS_linkat,
            libc::AT_FDCWD,
            target_path.as_ptr(),
            libc::AT_FDCWD,
            hardlink_path.as_ptr(),
            0, // flags
        );
        if result != 0 {
            bail!("linkat failed: {}", std::io::Error::last_os_error());
        }

        // Test 4: link syscall (x86_64 only) - Create another hard link
        #[cfg(target_arch = "x86_64")]
        {
            let link2_path = CString::new("/tmp/filesystem_links_link2")?;
            let result = libc::syscall(libc::SYS_link, target_path.as_ptr(), link2_path.as_ptr());
            if result != 0 {
                bail!("link failed: {}", std::io::Error::last_os_error());
            }
        }

        // Test 5: Error case - readlinkat on non-existent symlink
        let nonexistent_path = CString::new("/tmp/filesystem_links_nonexistent")?;
        let mut error_buffer = [0u8; 256];
        let _ = libc::syscall(
            libc::SYS_readlinkat,
            libc::AT_FDCWD,
            nonexistent_path.as_ptr(),
            error_buffer.as_mut_ptr(),
            error_buffer.len(),
        );
        // This should fail, but we still trace it

        // Test 6: Error case - linkat with non-existent source
        let result = libc::syscall(
            libc::SYS_linkat,
            libc::AT_FDCWD,
            nonexistent_path.as_ptr(),
            libc::AT_FDCWD,
            c"/tmp/filesystem_links_error_link".as_ptr(),
            0,
        );
        // This should fail, but we still trace it
        assert_eq!(result, -1, "linkat with non-existent source should fail");

        // Clean up all created files
        libc::unlink(target_path.as_ptr());
        libc::unlink(symlink_path.as_ptr());
        libc::unlink(hardlink_path.as_ptr());

        #[cfg(target_arch = "x86_64")]
        {
            let link2_path = CString::new("/tmp/filesystem_links_link2")?;
            libc::unlink(link2_path.as_ptr());
        }
    }

    Ok(())
}

fn aio_test() -> anyhow::Result<()> {
    use std::{fs::OpenOptions, io::Write, mem, os::unix::io::AsRawFd};

    // Create a temporary file for AIO operations
    let mut temp_file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .truncate(true)
        .open("/tmp/aio_test_file")?;

    // Write some initial data
    temp_file.write_all(b"Hello, AIO World! This is a test file for async I/O operations.")?;
    temp_file.sync_all()?;
    let fd = temp_file.as_raw_fd();

    unsafe {
        // Step 1: Setup AIO context
        let mut ctx: u64 = 0;
        let ctx_ptr = &mut ctx as *mut u64;
        let ret = libc::syscall(libc::SYS_io_setup, 128, ctx_ptr);
        if ret != 0 {
            // AIO might not be supported, just return Ok to avoid test failure
            println!("io_setup failed (AIO not supported?), skipping AIO test");
            return Ok(());
        }

        // Step 2: Prepare an IOCB structure using the proper struct
        let mut buffer = vec![0u8; 64];

        let iocb = pinchy_common::kernel_types::IoCb {
            aio_data: 0xdeadbeef,
            aio_key: 0,
            aio_rw_flags: 0,
            aio_lio_opcode: 0, // IOCB_CMD_PREAD
            aio_reqprio: 0,
            aio_fildes: fd as u32,
            aio_buf: buffer.as_mut_ptr() as u64,
            aio_nbytes: buffer.len() as u64,
            aio_offset: 0,
            aio_reserved2: 0,
            aio_flags: 0,
            aio_resfd: 0,
        };

        // Step 3: Submit the IOCB
        let iocb_ptr = &iocb as *const pinchy_common::kernel_types::IoCb;
        let iocb_ptrs = [iocb_ptr];
        let ret = libc::syscall(libc::SYS_io_submit, ctx, 1, iocb_ptrs.as_ptr());
        if ret != 1 {
            println!("io_submit failed, cleaning up");
            libc::syscall(libc::SYS_io_destroy, ctx);
            return Ok(());
        }

        // Step 4: Try to get events
        let mut events = [0u64; 8]; // 2 io_event structures (32 bytes each)
        let timeout = [1i64, 0i64]; // 1 second timeout (timespec-like)
        let ret = libc::syscall(
            libc::SYS_io_getevents,
            ctx,
            1,                   // min_nr
            2,                   // nr
            events.as_mut_ptr(), // events
            timeout.as_ptr(),    // timeout
        );

        // Step 5: Try io_pgetevents with empty signal set (if supported)
        if ret >= 0 {
            let sigset = [0u64; 16]; // Empty sigset_t
            let aio_sigset = [
                sigset.as_ptr() as u64,           // sigmask pointer
                mem::size_of_val(&sigset) as u64, // sigsetsize
            ];

            let _ret2 = libc::syscall(
                syscalls::SYS_io_pgetevents,
                ctx,
                0,                   // min_nr
                2,                   // nr
                events.as_mut_ptr(), // events
                timeout.as_ptr(),    // timeout
                aio_sigset.as_ptr(), // usig
            );
        }

        // Step 6: Try to cancel operations (might fail, that's ok)
        let mut result_event = [0u64; 4]; // io_event structure
        let _ret = libc::syscall(
            libc::SYS_io_cancel,
            ctx,
            iocb_ptr,
            result_event.as_mut_ptr(),
        );

        // Step 7: Destroy the AIO context
        libc::syscall(libc::SYS_io_destroy, ctx);
    }

    // Clean up the temp file
    std::fs::remove_file("/tmp/aio_test_file").ok();

    Ok(())
}

fn io_uring_test() -> anyhow::Result<()> {
    const ENTRIES: u32 = 8;
    const PROBE_OPS: usize = 4;

    let mut params = pinchy_common::kernel_types::IoUringParams::default();

    let ring_fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, ENTRIES, &mut params) } as i32;

    if ring_fd < 0 {
        bail!("io_uring_setup failed: {ring_fd}");
    }

    let enter_flags = pinchy_common::IORING_ENTER_GETEVENTS | pinchy_common::IORING_ENTER_SQ_WAIT;

    let enter_res = unsafe {
        libc::syscall(
            libc::SYS_io_uring_enter,
            ring_fd,
            0,
            0,
            enter_flags,
            std::ptr::null::<libc::sigset_t>(),
            0usize,
        )
    };

    if enter_res < 0 {
        unsafe {
            libc::close(ring_fd);
        }

        bail!("io_uring_enter failed: {enter_res}");
    }

    let mut probe = IoUringProbe::<PROBE_OPS> {
        ops_len: PROBE_OPS as u8,
        ..Default::default()
    };

    let register_res = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            ring_fd,
            pinchy_common::IORING_REGISTER_PROBE,
            &mut probe as *mut _ as *const c_void,
            PROBE_OPS as u32,
        )
    };

    // Probe registration may fail on some kernels or configurations; we still keep the trace.
    let _ = register_res;

    unsafe {
        libc::close(ring_fd);
    }

    Ok(())
}

fn landlock_test() -> anyhow::Result<()> {
    unsafe {
        // Test landlock_create_ruleset
        // First try with null attr and VERSION flag to check version/support
        let ruleset_fd = libc::syscall(
            syscalls::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(), // attr (NULL to check version)
            0,                      // size
            1,                      // LANDLOCK_CREATE_RULESET_VERSION flag
        );

        // Close the fd if it was opened
        if ruleset_fd >= 0 {
            libc::close(ruleset_fd as i32);
        }

        // Now create an actual ruleset with valid parameters
        // Define a minimal landlock_ruleset_attr structure
        #[repr(C)]
        struct LandlockRulesetAttr {
            handled_access_fs: u64,
        }

        let attr = LandlockRulesetAttr {
            handled_access_fs: 0, // No FS access restrictions
        };

        let ruleset_fd = libc::syscall(
            syscalls::SYS_landlock_create_ruleset,
            &attr as *const _ as *const u8,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0, // flags = 0
        );

        // Test landlock_add_rule with PATH_BENEATH rule type
        // Use the fd from create_ruleset if it succeeded, otherwise use -1
        let fd_for_add_rule = if ruleset_fd >= 0 {
            ruleset_fd as i32
        } else {
            -1
        };

        // Create a valid path_beneath rule attribute
        #[repr(C)]
        struct LandlockPathBeneathAttr {
            allowed_access: u64,
            parent_fd: i32,
        }

        let path_attr = LandlockPathBeneathAttr {
            allowed_access: pinchy_common::LANDLOCK_ACCESS_FS_EXECUTE
                | pinchy_common::LANDLOCK_ACCESS_FS_WRITE_FILE
                | pinchy_common::LANDLOCK_ACCESS_FS_READ_FILE
                | pinchy_common::LANDLOCK_ACCESS_FS_READ_DIR
                | pinchy_common::LANDLOCK_ACCESS_FS_REMOVE_DIR
                | pinchy_common::LANDLOCK_ACCESS_FS_REMOVE_FILE,
            parent_fd: 4, // Some valid fd
        };

        let _result = libc::syscall(
            syscalls::SYS_landlock_add_rule,
            fd_for_add_rule,
            1, // LANDLOCK_RULE_PATH_BENEATH
            &path_attr as *const _ as *const u8,
            0, // flags
        );

        // Test landlock_add_rule with NET_PORT rule type
        #[repr(C)]
        struct LandlockNetPortAttr {
            allowed_access: u64,
            port: u64,
        }

        let net_attr = LandlockNetPortAttr {
            allowed_access: pinchy_common::LANDLOCK_ACCESS_NET_BIND_TCP
                | pinchy_common::LANDLOCK_ACCESS_NET_CONNECT_TCP,
            port: 8080,
        };

        let _result = libc::syscall(
            syscalls::SYS_landlock_add_rule,
            fd_for_add_rule,
            2, // LANDLOCK_RULE_NET_PORT
            &net_attr as *const _ as *const u8,
            0, // flags
        );

        // Test landlock_restrict_self
        let fd_for_restrict = if ruleset_fd >= 0 {
            ruleset_fd as i32
        } else {
            -1
        };

        let _result = libc::syscall(
            syscalls::SYS_landlock_restrict_self,
            fd_for_restrict,
            0, // flags
        );

        // Close the file descriptor if it was created
        if ruleset_fd >= 0 {
            libc::close(ruleset_fd as i32);
        }
    }

    Ok(())
}
fn key_management_test() -> anyhow::Result<()> {
    use std::ffi::CString;

    unsafe {
        // Ensure we have a usable session keyring; ignore errors but prefer success
        let _ = libc::syscall(
            syscalls::SYS_keyctl,
            libc::KEYCTL_JOIN_SESSION_KEYRING,
            std::ptr::null::<libc::c_char>(),
        );

        // Test add_key with "user" key type
        let key_type = CString::new("user")?;
        let description = CString::new("test_key_1")?;
        let payload = b"test_payload_data";

        let key_id = libc::syscall(
            syscalls::SYS_add_key,
            key_type.as_ptr(),
            description.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            libc::KEY_SPEC_SESSION_KEYRING,
        );

        // Test add_key with "keyring" type (no payload)
        let keyring_type = CString::new("keyring")?;
        let keyring_desc = CString::new("test_keyring")?;

        let _keyring_id = libc::syscall(
            syscalls::SYS_add_key,
            keyring_type.as_ptr(),
            keyring_desc.as_ptr(),
            std::ptr::null::<u8>(),
            0,
            libc::KEY_SPEC_SESSION_KEYRING,
        );

        // Test request_key
        let req_type = CString::new("user")?;
        let req_desc = CString::new("test_key_1")?;
        let req_info = CString::new("test_call_info")?;

        let _req_key = libc::syscall(
            syscalls::SYS_request_key,
            req_type.as_ptr(),
            req_desc.as_ptr(),
            req_info.as_ptr(),
            libc::KEY_SPEC_THREAD_KEYRING,
        );

        // Test keyctl operations
        if key_id >= 0 {
            // KEYCTL_DESCRIBE
            let desc_buf = vec![0u8; 256];
            let _desc = libc::syscall(
                syscalls::SYS_keyctl,
                6, // KEYCTL_DESCRIBE
                key_id as usize,
                desc_buf.as_ptr(),
                desc_buf.len(),
            );

            // KEYCTL_READ
            let read_buf = vec![0u8; 256];
            let _read = libc::syscall(
                syscalls::SYS_keyctl,
                11, // KEYCTL_READ
                key_id as usize,
                read_buf.as_ptr(),
                read_buf.len(),
            );

            // KEYCTL_SETPERM
            let _setperm = libc::syscall(
                syscalls::SYS_keyctl,
                5, // KEYCTL_SETPERM
                key_id as usize,
                0x3f010000u64, // Standard permissions
            );

            // KEYCTL_GET_KEYRING_ID with session keyring
            let _get_kr = libc::syscall(
                syscalls::SYS_keyctl,
                0, // KEYCTL_GET_KEYRING_ID
                libc::KEY_SPEC_SESSION_KEYRING as usize,
                1, // create = true
            );

            // KEYCTL_SEARCH to find our key in session keyring
            let search_type = CString::new("user")?;
            let search_desc = CString::new("test_key_1")?;

            let _search = libc::syscall(
                syscalls::SYS_keyctl,
                10, // KEYCTL_SEARCH
                libc::KEY_SPEC_SESSION_KEYRING as usize,
                search_type.as_ptr(),
                search_desc.as_ptr(),
                0,
            );

            // KEYCTL_REVOKE to revoke the key
            let _revoke = libc::syscall(
                syscalls::SYS_keyctl,
                3, // KEYCTL_REVOKE
                key_id as usize,
            );
        }
    }

    Ok(())
}

fn perf_event_test() -> anyhow::Result<()> {
    // perf_event_attr structure (simplified for software events)
    #[repr(C)]
    #[derive(Default)]
    struct PerfEventAttr {
        type_: u32,
        size: u32,
        config: u64,
        sample_period_or_freq: u64,
        sample_type: u64,
        read_format: u64,
        flags: u64,
        wakeup_events_or_watermark: u32,
        bp_type: u32,
        bp_addr_or_config1: u64,
        bp_len_or_config2: u64,
        branch_sample_type: u64,
        sample_regs_user: u64,
        sample_stack_user: u32,
        clockid: i32,
        sample_regs_intr: u64,
        aux_watermark: u32,
        sample_max_stack: u16,
        reserved: u16,
    }

    const PERF_TYPE_SOFTWARE: u32 = 1;
    const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;
    const PERF_FLAG_FD_CLOEXEC: u64 = 1 << 3;

    unsafe {
        // Create a simple software counter for CPU clock
        let mut attr: PerfEventAttr = std::mem::zeroed();
        attr.type_ = PERF_TYPE_SOFTWARE;
        attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
        attr.config = PERF_COUNT_SW_CPU_CLOCK;
        attr.flags = 1; // disabled initially

        // Test 1: perf_event_open with basic settings (pid=0 means current process, cpu=-1 means any)
        let fd = libc::syscall(
            syscalls::SYS_perf_event_open,
            &attr as *const PerfEventAttr,
            0i32,  // pid: current process
            -1i32, // cpu: any CPU
            -1i32, // group_fd: no group
            0u64,  // flags
        );

        if fd >= 0 {
            libc::close(fd as i32);
        }

        // Test 2: perf_event_open with CLOEXEC flag
        let fd2 = libc::syscall(
            syscalls::SYS_perf_event_open,
            &attr as *const PerfEventAttr,
            0i32,
            -1i32,
            -1i32,
            PERF_FLAG_FD_CLOEXEC,
        );

        if fd2 >= 0 {
            libc::close(fd2 as i32);
        }

        // Test 3: perf_event_open with invalid parameters (expect error)
        let _fd3 = libc::syscall(
            syscalls::SYS_perf_event_open,
            std::ptr::null::<PerfEventAttr>(),
            0i32,
            -1i32,
            -1i32,
            0u64,
        );
        // This should fail with EFAULT, which is expected
    }

    Ok(())
}

fn bpf_test() -> anyhow::Result<()> {
    // BPF commands
    const BPF_MAP_CREATE: i32 = 0;
    const BPF_MAP_LOOKUP_ELEM: i32 = 1;

    // BPF map types
    const BPF_MAP_TYPE_ARRAY: u32 = 2;

    // bpf_attr union for BPF_MAP_CREATE
    #[repr(C)]
    #[derive(Default)]
    struct BpfAttrMapCreate {
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
        inner_map_fd: u32,
        numa_node: u32,
        map_name: [u8; 16],
        map_ifindex: u32,
        btf_fd: u32,
        btf_key_type_id: u32,
        btf_value_type_id: u32,
        btf_vmlinux_value_type_id: u32,
        map_extra: u64,
    }

    unsafe {
        // Test 1: BPF_MAP_CREATE - create a simple array map
        let mut attr: BpfAttrMapCreate = std::mem::zeroed();
        attr.map_type = BPF_MAP_TYPE_ARRAY;
        attr.key_size = 4;
        attr.value_size = 8;
        attr.max_entries = 1;

        let fd = libc::syscall(
            syscalls::SYS_bpf,
            BPF_MAP_CREATE,
            &attr as *const BpfAttrMapCreate,
            std::mem::size_of::<BpfAttrMapCreate>(),
        );

        if fd >= 0 {
            // Test 2: BPF_MAP_LOOKUP_ELEM on our new map
            #[repr(C)]
            struct BpfAttrElem {
                map_fd: u32,
                pad: u32,
                key: u64,
                value_or_next_key: u64,
                flags: u64,
            }

            let key: u32 = 0;
            let mut value: u64 = 0;

            let elem_attr = BpfAttrElem {
                map_fd: fd as u32,
                pad: 0,
                key: &key as *const u32 as u64,
                value_or_next_key: &mut value as *mut u64 as u64,
                flags: 0,
            };

            let _lookup = libc::syscall(
                syscalls::SYS_bpf,
                BPF_MAP_LOOKUP_ELEM,
                &elem_attr as *const BpfAttrElem,
                std::mem::size_of::<BpfAttrElem>(),
            );

            libc::close(fd as i32);
        }

        // Test 3: BPF with invalid command (expect error)
        let _err = libc::syscall(syscalls::SYS_bpf, 9999, std::ptr::null::<u8>(), 0);
        // This should fail, which is expected
    }

    Ok(())
}

fn fanotify_test() -> anyhow::Result<()> {
    use std::ffi::CString;

    // fanotify_init flags
    const FAN_CLOEXEC: u32 = 0x00000001;
    const FAN_CLASS_NOTIF: u32 = 0x00000000;

    // fanotify_mark flags
    const FAN_MARK_ADD: u32 = 0x00000001;

    // fanotify event mask
    const FAN_ACCESS: u64 = 0x00000001;
    const FAN_MODIFY: u64 = 0x00000002;

    unsafe {
        // Test 1: fanotify_init with basic settings
        let fd = libc::syscall(
            syscalls::SYS_fanotify_init,
            FAN_CLASS_NOTIF | FAN_CLOEXEC,
            libc::O_RDONLY as u32,
        );

        if fd >= 0 {
            let fd = fd as i32;

            // Test 2: fanotify_mark to add a watch on /tmp
            let path = CString::new("/tmp")?;

            let _mark = libc::syscall(
                syscalls::SYS_fanotify_mark,
                fd,
                FAN_MARK_ADD,
                FAN_ACCESS | FAN_MODIFY,
                libc::AT_FDCWD,
                path.as_ptr(),
            );

            libc::close(fd);
        }

        // Test 3: fanotify_init with invalid flags (expect error)
        let _err = libc::syscall(
            syscalls::SYS_fanotify_init,
            0xFFFFFFFFu32,
            libc::O_RDONLY as u32,
        );
        // This should fail with EINVAL, which is expected
    }

    Ok(())
}

fn file_handles_test() -> anyhow::Result<()> {
    use std::{
        fs::File,
        io::Write,
        os::fd::AsRawFd,
        time::{SystemTime, UNIX_EPOCH},
    };

    // Create a temporary file for testing
    let tmp_path = CString::new("/tmp/pinchy_file_handles_test.txt")?;

    // Create test file
    {
        let mut file = File::create("/tmp/pinchy_file_handles_test.txt")?;
        file.write_all(b"Test content for file handle operations\n")?;
    }

    // Test copy_file_range
    {
        let src = File::open("/tmp/pinchy_file_handles_test.txt")?;
        let dst = File::create("/tmp/pinchy_file_handles_test_copy.txt")?;

        let mut off_in: i64 = 0;
        let mut off_out: i64 = 0;

        unsafe {
            let _result = libc::syscall(
                syscalls::SYS_copy_file_range,
                src.as_raw_fd(),
                &mut off_in as *mut i64,
                dst.as_raw_fd(),
                &mut off_out as *mut i64,
                1024usize,
                0u32,
            );
        }
    }

    // Test sync_file_range
    {
        let file = File::options()
            .write(true)
            .open("/tmp/pinchy_file_handles_test.txt")?;

        unsafe {
            let _result = libc::syscall(
                syscalls::SYS_sync_file_range,
                file.as_raw_fd(),
                0i64,
                0i64,
                libc::SYNC_FILE_RANGE_WRITE,
            );
        }
    }

    // Test syncfs
    {
        let file = File::open("/tmp/pinchy_file_handles_test.txt")?;

        unsafe {
            let _result = libc::syscall(syscalls::SYS_syncfs, file.as_raw_fd());
        }
    }

    // Test utimensat - update access and modification times
    {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let times: [libc::timespec; 2] = [
            libc::timespec {
                tv_sec: now.as_secs() as i64,
                tv_nsec: now.subsec_nanos() as i64,
            },
            libc::timespec {
                tv_sec: now.as_secs() as i64,
                tv_nsec: now.subsec_nanos() as i64,
            },
        ];

        unsafe {
            let _result = libc::syscall(
                syscalls::SYS_utimensat,
                libc::AT_FDCWD,
                tmp_path.as_ptr(),
                times.as_ptr(),
                0i32,
            );
        }

        // Test utimensat with NULL times (sets to current time)
        unsafe {
            let _result = libc::syscall(
                syscalls::SYS_utimensat,
                libc::AT_FDCWD,
                tmp_path.as_ptr(),
                std::ptr::null::<libc::timespec>(),
                0i32,
            );
        }
    }

    // Test name_to_handle_at and open_by_handle_at
    // Note: These require CAP_DAC_READ_SEARCH; might fail without it
    {
        // file_handle struct from linux/fcntl.h
        #[repr(C)]
        struct FileHandle {
            handle_bytes: u32,
            handle_type: i32,
            f_handle: [u8; 128],
        }

        let mut handle = FileHandle {
            handle_bytes: 128,
            handle_type: 0,
            f_handle: [0u8; 128],
        };
        let mut mount_id: i32 = 0;

        unsafe {
            // name_to_handle_at
            let _result = libc::syscall(
                syscalls::SYS_name_to_handle_at,
                libc::AT_FDCWD,
                tmp_path.as_ptr(),
                &mut handle as *mut FileHandle,
                &mut mount_id as *mut i32,
                0i32,
            );

            // open_by_handle_at - requires a mount fd
            // This will likely fail without CAP_DAC_READ_SEARCH, but we trace it anyway
            let _fd = libc::syscall(
                syscalls::SYS_open_by_handle_at,
                libc::AT_FDCWD,
                &mut handle as *mut FileHandle,
                libc::O_RDONLY,
            );
        }
    }

    // Cleanup
    let _ = std::fs::remove_file("/tmp/pinchy_file_handles_test.txt");
    let _ = std::fs::remove_file("/tmp/pinchy_file_handles_test_copy.txt");

    Ok(())
}

fn itimer_test() -> anyhow::Result<()> {
    unsafe {
        // Test getitimer and setitimer with ITIMER_REAL
        let mut curr_value: libc::itimerval = std::mem::zeroed();

        // Test 1: getitimer with ITIMER_REAL
        let result = libc::syscall(
            libc::SYS_getitimer,
            libc::ITIMER_REAL,
            &mut curr_value as *mut libc::itimerval,
        );

        if result != 0 {
            bail!("getitimer failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: setitimer with ITIMER_VIRTUAL
        let new_value = libc::itimerval {
            it_interval: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            }, // No repeat
            it_value: libc::timeval {
                tv_sec: 0,
                tv_usec: 100000,
            }, // 100ms
        };

        let mut old_value: libc::itimerval = std::mem::zeroed();

        let result = libc::syscall(
            libc::SYS_setitimer,
            libc::ITIMER_VIRTUAL,
            &new_value as *const libc::itimerval,
            &mut old_value as *mut libc::itimerval,
        );

        if result != 0 {
            bail!("setitimer failed: {}", std::io::Error::last_os_error());
        }

        // Test 3: getitimer with ITIMER_VIRTUAL to see the value we just set
        let result = libc::syscall(
            libc::SYS_getitimer,
            libc::ITIMER_VIRTUAL,
            &mut curr_value as *mut libc::itimerval,
        );

        if result != 0 {
            bail!("getitimer failed: {}", std::io::Error::last_os_error());
        }

        // Clear the timer
        let zero_value: libc::itimerval = std::mem::zeroed();
        let _ = libc::syscall(
            libc::SYS_setitimer,
            libc::ITIMER_VIRTUAL,
            &zero_value as *const libc::itimerval,
            std::ptr::null_mut::<libc::itimerval>(),
        );
    }

    Ok(())
}

fn syslog_test() -> anyhow::Result<()> {
    unsafe {
        // Test syslog syscall with different actions
        // Integration tests run as root, so we can test privileged operations

        // Test 1: SYSLOG_ACTION_SIZE_BUFFER
        let result = libc::syscall(
            libc::SYS_syslog,
            syslog_constants::SYSLOG_ACTION_SIZE_BUFFER,
            std::ptr::null_mut::<u8>(),
            0i32,
        );

        if result < 0 {
            eprintln!("syslog SIZE_BUFFER returned: {}", result);
        }

        // Test 2: SYSLOG_ACTION_SIZE_UNREAD
        let result = libc::syscall(
            libc::SYS_syslog,
            syslog_constants::SYSLOG_ACTION_SIZE_UNREAD,
            std::ptr::null_mut::<u8>(),
            0i32,
        );

        if result < 0 {
            eprintln!("syslog SIZE_UNREAD returned: {}", result);
        }

        // Test 3: SYSLOG_ACTION_READ_ALL
        let mut buffer = [0u8; 1024];
        let _result = libc::syscall(
            libc::SYS_syslog,
            syslog_constants::SYSLOG_ACTION_READ_ALL,
            buffer.as_mut_ptr(),
            buffer.len() as i32,
        );

        // Test 4: SYSLOG_ACTION_CONSOLE_LEVEL (privileged)
        // Get current console level first
        let _result = libc::syscall(
            libc::SYS_syslog,
            syslog_constants::SYSLOG_ACTION_CONSOLE_LEVEL,
            std::ptr::null_mut::<u8>(),
            7i32, // Set to KERN_DEBUG level
        );

        // Test 5: SYSLOG_ACTION_CONSOLE_OFF (privileged)
        let _result = libc::syscall(
            libc::SYS_syslog,
            syslog_constants::SYSLOG_ACTION_CONSOLE_OFF,
            std::ptr::null_mut::<u8>(),
            0i32,
        );

        // Test 6: SYSLOG_ACTION_CONSOLE_ON (privileged)
        // Turn it back on immediately
        let _result = libc::syscall(
            libc::SYS_syslog,
            syslog_constants::SYSLOG_ACTION_CONSOLE_ON,
            std::ptr::null_mut::<u8>(),
            0i32,
        );

        // Test 7: SYSLOG_ACTION_CLEAR (privileged)
        // Note: This actually clears the ring buffer, but we're root in tests
        let _result = libc::syscall(
            libc::SYS_syslog,
            syslog_constants::SYSLOG_ACTION_CLEAR,
            std::ptr::null_mut::<u8>(),
            0i32,
        );
    }

    Ok(())
}

fn ptrace_test() -> anyhow::Result<()> {
    unsafe {
        // Test ptrace syscalls
        // Note: ptrace usually needs special setup, these calls may fail
        // but we just need them to be traced

        // Test 1: PTRACE_TRACEME - allows parent to trace this process
        // This should succeed
        let result = libc::syscall(
            libc::SYS_ptrace,
            0i32,   // PTRACE_TRACEME
            0i32,   // pid (ignored for TRACEME)
            0usize, // addr
            0usize, // data
        );

        if result < 0 {
            // This is expected to fail in many contexts
            eprintln!("ptrace TRACEME returned: {}", result);
        }

        // Test 2: PTRACE_PEEKTEXT - try to read from own memory
        // This will likely fail but will be traced
        let _result = libc::syscall(
            libc::SYS_ptrace,
            1i32, // PTRACE_PEEKTEXT
            std::process::id() as i32,
            0x1000usize, // arbitrary address
            0usize,
        );

        // Test 3: PTRACE_CONT - continue a traced process
        // This will likely fail but will be traced
        let _result = libc::syscall(
            libc::SYS_ptrace,
            7i32, // PTRACE_CONT
            1i32, // arbitrary pid
            0usize,
            0usize,
        );
    }

    Ok(())
}

fn seccomp_test() -> anyhow::Result<()> {
    unsafe {
        // Test seccomp syscalls
        // Note: these may fail without proper permissions or kernel support
        // but we just need them to be traced

        // Test 1: SECCOMP_GET_ACTION_AVAIL - check if an action is available
        let mut action: u32 = 0; // SECCOMP_RET_KILL_PROCESS
        let _result = libc::syscall(
            libc::SYS_seccomp,
            2u32, // SECCOMP_GET_ACTION_AVAIL
            0u32, // flags
            &mut action as *mut u32,
        );

        // Test 2: SECCOMP_GET_NOTIF_SIZES - get notification sizes
        // This may fail on older kernels
        let mut sizes = [0u8; 32];
        let _result = libc::syscall(
            libc::SYS_seccomp,
            3u32, // SECCOMP_GET_NOTIF_SIZES
            0u32, // flags
            sizes.as_mut_ptr(),
        );

        // Test 3: Invalid operation - should fail
        let _result = libc::syscall(
            libc::SYS_seccomp,
            255u32, // invalid operation
            0u32,
            std::ptr::null_mut::<u8>(),
        );
    }

    Ok(())
}

fn quotactl_test() -> anyhow::Result<()> {
    use pinchy_common::*;

    unsafe {
        // Test quotactl syscalls
        // Note: these will likely fail without quotas enabled on the filesystem
        // but we just need them to be traced

        // Test 1: Q_SYNC - sync quota info to disk
        let _result = libc::syscall(
            pinchy_common::syscalls::SYS_quotactl,
            Q_SYNC,                     // Q_SYNC
            std::ptr::null::<u8>(),     // special (can be NULL for Q_SYNC)
            0i32,                       // id (ignored for Q_SYNC)
            std::ptr::null_mut::<u8>(), // addr (ignored for Q_SYNC)
        );

        // Test 2: Q_GETFMT - get quota format
        let mut fmt: u32 = 0;
        let path = std::ffi::CString::new("/").unwrap();
        let _result = libc::syscall(
            pinchy_common::syscalls::SYS_quotactl,
            Q_GETFMT,                        // Q_GETFMT
            path.as_ptr(),                   // special
            0i32,                            // id
            &mut fmt as *mut u32 as *mut u8, // addr
        );

        // Test 3: Q_GETQUOTA - get quota limits (likely to fail)
        let mut dqblk = [0u8; 128]; // large enough for struct dqblk
        let _result = libc::syscall(
            pinchy_common::syscalls::SYS_quotactl,
            Q_GETQUOTA,         // Q_GETQUOTA
            path.as_ptr(),      // special
            1000i32,            // uid
            dqblk.as_mut_ptr(), // addr
        );

        // Test 4: quotactl_fd if available (will fail on older kernels)
        // Open a file descriptor for testing
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
        if fd >= 0 {
            let _result = libc::syscall(
                pinchy_common::syscalls::SYS_quotactl_fd,
                fd,                 // fd
                Q_GETQUOTA as u32,  // Q_GETQUOTA
                1000i32,            // uid
                dqblk.as_mut_ptr(), // addr
            );

            libc::close(fd);
        }
    }

    Ok(())
}
