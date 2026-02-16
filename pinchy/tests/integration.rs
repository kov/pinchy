// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

mod common;

use assert_cmd::assert::Assert;
use common::{run_workload, PinchyTest, TestMode};
use indoc::indoc;
use predicates::prelude::*;

#[test]
fn basic_output() {
    let pinchy = PinchyTest::new();
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn memory_policy_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises memory policy syscalls
    let handle = run_workload(
        &pinchy,
        &[
            "set_mempolicy",
            "mbind",
            "get_mempolicy",
            "mincore",
            "migrate_pages",
            "move_pages",
        ],
        "mempolicy_test",
    );

    // Expected output - we should see memory policy syscalls being traced
    // On single-node systems, some syscalls may fail with specific error codes
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ set_mempolicy(mode: MPOL_DEFAULT, nodemask: NULL, maxnode: 0) = 0 (success)
        @PID@ mbind(addr: @ADDR@, len: 4096, mode: MPOL_PREFERRED, nodemask: [0], maxnode: 1, flags: 0) = @NUMBER@ (success)
        @PID@ get_mempolicy(mode: NULL, nodemask: NULL, maxnode: 64, addr: @ADDR@, flags: 0x1 (MPOL_F_NODE)) = -@NUMBER@ (error)
        @PID@ mincore(addr: @ADDR@, length: 8192, vec: [0,0]) = 0 (success)
        @PID@ migrate_pages(pid: @NUMBER@, maxnode: 64, old_nodes: [0], new_nodes: [0]) = 0 (pages not migrated)
        @PID@ move_pages(pid: @NUMBER@, count: 1, pages: [@ADDR@], nodes: [0], status: [-@NUMBER@], flags: 0) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}
#[test]
fn epoll_syscalls() {
    let pinchy = PinchyTest::new();

    #[cfg(target_arch = "x86_64")]
    let handle = run_workload(
        &pinchy,
        &[
            "epoll_create1",
            "epoll_ctl",
            "epoll_pwait",
            "epoll_pwait2",
            "epoll_wait",
        ],
        "epoll_test",
    );

    #[cfg(target_arch = "aarch64")]
    let handle = run_workload(
        &pinchy,
        &["epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_pwait2"],
        "epoll_test",
    );

    #[cfg(target_arch = "x86_64")]
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ epoll_create1(flags: EPOLL_CLOEXEC) = @NUMBER@ (fd)
        @PID@ epoll_ctl(epfd: @NUMBER@, op: EPOLL_CTL_ADD, fd: @NUMBER@, event: epoll_event { events: POLLIN, data: @ADDR@ }) = 0 (success)
        @PID@ epoll_pwait(epfd: @NUMBER@, events: [ epoll_event { events: POLLIN, data: @ADDR@ } ], max_events: 8, timeout: 0, sigmask) = 1
        @PID@ epoll_ctl(epfd: @NUMBER@, op: EPOLL_CTL_DEL, fd: @NUMBER@, event: epoll_event { events: 0, data: 0x0 }) = 0 (success)
        @PID@ epoll_pwait2(epfd: @NUMBER@, events: [  ], max_events: 8, timeout: { secs: 0, nanos: 0 }, sigmask: 0x0, sigsetsize: 0) = 0 (success)
        @PID@ epoll_wait(epfd: @NUMBER@, events: [  ], max_events: 8, timeout: 0) = 0 (success)
    "#});

    #[cfg(target_arch = "aarch64")]
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ epoll_create1(flags: EPOLL_CLOEXEC) = @NUMBER@ (fd)
        @PID@ epoll_ctl(epfd: @NUMBER@, op: EPOLL_CTL_ADD, fd: @NUMBER@, event: epoll_event { events: POLLIN, data: @ADDR@ }) = 0 (success)
        @PID@ epoll_pwait(epfd: @NUMBER@, events: [ epoll_event { events: POLLIN, data: @ADDR@ } ], max_events: 8, timeout: 0, sigmask) = 1
        @PID@ epoll_ctl(epfd: @NUMBER@, op: EPOLL_CTL_DEL, fd: @NUMBER@, event: epoll_event { events: 0, data: 0x0 }) = 0 (success)
        @PID@ epoll_pwait2(epfd: @NUMBER@, events: [  ], max_events: 8, timeout: { secs: 0, nanos: 0 }, sigmask: 0x0, sigsetsize: 0) = 0 (success)
        @PID@ epoll_pwait(epfd: @NUMBER@, events: [  ], max_events: 8, timeout: 0, sigmask) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn drop_privileges() {
    let pinchy = PinchyTest::with_mode(TestMode::CheckCaps);

    // read_file triggers UML boot and reads the captured proc status
    let status = pinchy.read_file("proc_status");

    let mut dropped_cap_inh = false;
    let mut dropped_cap_prm = false;
    let mut dropped_cap_eff = false;

    for line in status.split('\n') {
        if line.starts_with("CapInh:\t0000000000000000") {
            dropped_cap_inh = true;
        } else if line.starts_with("CapPrm:\t0000000000000000") {
            dropped_cap_prm = true;
        } else if line.starts_with("CapEff:\t0000000000000000") {
            dropped_cap_eff = true;
        }
    }

    assert!(dropped_cap_inh);
    assert!(dropped_cap_prm);
    assert!(dropped_cap_eff);

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn pinchy_reads() {
    let pinchy = PinchyTest::new();

    // Run a workload
    let handle = run_workload(
        &pinchy,
        &["openat", "openat2", "read", "lseek"],
        "pinchy_reads",
    );

    // Client's output
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ openat(dfd: AT_FDCWD, pathname: "pinchy/tests/GPLv2", flags: 0x0 (O_RDONLY), mode: 0) = 3 (fd)
        @PID@ read(fd: 3, buf: "                    GNU GENERAL PUBLIC LICENSE\n                       Version 2, June 1991\n\n Copyright (C) 1989, 1991 Free Softw", count: 128) = 128 (bytes)
        @PID@ read(fd: 3, buf: "are Foundation, Inc.,\n 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA\n Everyone is permitted to copy and distribute " ... (896 more bytes), count: 1024) = 1024 (bytes)
        @PID@ lseek(fd: 3, offset: 0, whence: 2) = 18092
        @PID@ read(fd: 3, buf: "", count: 1024) = 0 (bytes)
        @PID@ openat2(dfd: AT_FDCWD, pathname: "pinchy/tests/GPLv2", how: { flags: 0x0 (O_RDONLY), mode: 0, resolve: 0xc (RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) }, size: 24) = @NUMBER@ (fd)
        @PID@ openat2(dfd: AT_FDCWD, pathname: "pinchy/tests/GPLv2", how: { flags: 0x0 (O_RDONLY), mode: 0, resolve: 0 }, size: 24) = @NUMBER@ (fd)
        @PID@ openat2(dfd: AT_FDCWD, pathname: "pinchy/tests/non-existent-file", how: { flags: 0x0 (O_RDONLY), mode: 0, resolve: 0x4 (RESOLVE_NO_SYMLINKS) }, size: 24) = -2 (error)
    "#});

    let output = handle.join().unwrap();
    // stderr().write_all(&output.stderr).unwrap();
    // stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn filesystem_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises getdents64, fstat, newfstatat, faccessat, faccessat2
    let handle = run_workload(
        &pinchy,
        &[
            "getdents64",
            "fstat",
            "newfstatat",
            "faccessat",
            "faccessat2",
        ],
        "filesystem_syscalls_test",
    );

    // Client's output - we expect the syscalls from the workload
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ getdents64(fd: @NUMBER@, count: @NUMBER@, entries: [ dirent { ino: @NUMBER@, off: @NUMBER@, reclen: @NUMBER@, type: @NUMBER@, name: "@ALPHANUM@"@MAYBETRUNCATED@ }, dirent { ino: @NUMBER@, off: @NUMBER@, reclen: @NUMBER@, type: @NUMBER@, name: "@ALPHANUM@"@MAYBETRUNCATED@ }, dirent { ino: @NUMBER@, off: @NUMBER@, reclen: @NUMBER@, type: @NUMBER@, name: "@ALPHANUM@"@MAYBETRUNCATED@ }, dirent { ino: @NUMBER@, off: @NUMBER@, reclen: @NUMBER@, type: @NUMBER@, name: "@ALPHANUM@"@MAYBETRUNCATED@ } ]) = @NUMBER@ (bytes)
        @PID@ fstat(fd: @NUMBER@, struct stat: { mode: 0o@NUMBER@ (@MODE@), ino: @NUMBER@, dev: @NUMBER@, nlink: @NUMBER@, uid: @NUMBER@, gid: @NUMBER@, size: 18092, blksize: @NUMBER@, blocks: @NUMBER@, atime: @NUMBER@, mtime: @NUMBER@, ctime: @NUMBER@ }) = 0 (success)
        @PID@ newfstatat(dirfd: AT_FDCWD, pathname: "pinchy/tests/GPLv2", struct stat: { mode: 0o@NUMBER@ (@MODE@), ino: @NUMBER@, dev: @NUMBER@, nlink: @NUMBER@, uid: @NUMBER@, gid: @NUMBER@, size: 18092, blksize: @NUMBER@, blocks: @NUMBER@, atime: @NUMBER@, mtime: @NUMBER@, ctime: @NUMBER@ }, flags: 0) = 0 (success)
        @PID@ faccessat(dirfd: AT_FDCWD, pathname: "pinchy/tests/GPLv2", mode: R_OK) = 0 (success)
        @PID@ faccessat2(dirfd: AT_FDCWD, pathname: "pinchy/tests/GPLv2", mode: R_OK, flags: 0) = 0 (success)
        @PID@ faccessat2(dirfd: AT_FDCWD, pathname: "pinchy/tests/non-existent-file", mode: R_OK, flags: 0) = -2 (error)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn statfs_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises statfs and fstatfs
    let handle = run_workload(&pinchy, &["statfs", "fstatfs"], "statfs_test");

    // Expected output - we test both success and error cases
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ statfs(pathname: "pinchy/tests/GPLv2", buf: { type: @ALPHANUM@ (0x@HEXNUMBER@), block_size: @NUMBER@, blocks: @NUMBER@, blocks_free: @NUMBER@, blocks_available: @NUMBER@, files: @NUMBER@, files_free: @NUMBER@, fsid: [@SIGNEDNUMBER@, @SIGNEDNUMBER@], name_max: @NUMBER@, fragment_size: @NUMBER@, mount_flags: 0x@HEXNUMBER@ (@ALPHANUM@) }) = 0 (success)
        @PID@ statfs(pathname: "/non/existent/path", buf: <unavailable>) = -2 (error)
        @PID@ fstatfs(fd: @NUMBER@, buf: { type: @ALPHANUM@ (0x@HEXNUMBER@), block_size: @NUMBER@, blocks: @NUMBER@, blocks_free: @NUMBER@, blocks_available: @NUMBER@, files: @NUMBER@, files_free: @NUMBER@, fsid: [@SIGNEDNUMBER@, @SIGNEDNUMBER@], name_max: @NUMBER@, fragment_size: @NUMBER@, mount_flags: 0x@HEXNUMBER@ (@ALPHANUM@) }) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn rt_sig() {
    let pinchy = PinchyTest::new();

    // Run a workload
    let handle = run_workload(&pinchy, &["rt_sigprocmask"], "rt_sig");

    // Client's output - we expect pretty-printed signal sets
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ rt_sigprocmask(how: SIG_BLOCK, set: [SIGUSR1], oldset: [], sigsetsize: 8) = 0 (success)
        @PID@ rt_sigprocmask(how: SIG_SETMASK, set: NULL, oldset: [SIGUSR1], sigsetsize: 8) = 0 (success)
        @PID@ rt_sigprocmask(how: SIG_UNBLOCK, set: [SIGUSR1], oldset: NULL, sigsetsize: 8) = 0 (success)
        @PID@ rt_sigprocmask(how: SIG_SETMASK, set: [], oldset: NULL, sigsetsize: 8) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn rt_sigaction_realtime() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises rt_sigaction with real-time signals
    let handle = run_workload(&pinchy, &["rt_sigaction"], "rt_sigaction_realtime");

    // Client's output - we expect rt_sigaction calls with SIGRT1
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ rt_sigaction(signum: SIGRT1, act: @ADDR@, oldact: @ADDR@, sigsetsize: 8) = 0 (success)
        @PID@ rt_sigaction(signum: SIGRT1, act: 0x0, oldact: @ADDR@, sigsetsize: 8) = 0 (success)
        @PID@ rt_sigaction(signum: SIGRT1, act: @ADDR@, oldact: 0x0, sigsetsize: 8) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn rt_sigaction_standard() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises rt_sigaction with standard signals
    let handle = run_workload(&pinchy, &["rt_sigaction"], "rt_sigaction_standard");

    // Client's output - we expect rt_sigaction calls with SIGUSR1
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ rt_sigaction(signum: SIGUSR1, act: @ADDR@, oldact: @ADDR@, sigsetsize: 8) = 0 (success)
        @PID@ rt_sigaction(signum: SIGUSR1, act: 0x0, oldact: @ADDR@, sigsetsize: 8) = 0 (success)
        @PID@ rt_sigaction(signum: SIGUSR1, act: @ADDR@, oldact: 0x0, sigsetsize: 8) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn fcntl_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises fcntl syscalls
    let handle = run_workload(&pinchy, &["fcntl"], "fcntl_test");

    // Client's output - we expect several fcntl calls
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ fcntl(fd: 3, cmd: F_GETFL, arg: 0x0) = @NUMBER@
        @PID@ fcntl(fd: 3, cmd: F_GETFD, arg: 0x0) = 0 (success)
        @PID@ fcntl(fd: 3, cmd: F_SETFD, arg: 0x1) = 0 (success)
        @PID@ fcntl(fd: 3, cmd: F_DUPFD, arg: 0xa) = 10
        @PID@ fcntl(fd: 3, cmd: F_DUPFD_CLOEXEC, arg: 0x14) = 20
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn pipe_operations_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises pipe operations
    let handle = run_workload(
        &pinchy,
        &["pipe2", "splice", "tee", "vmsplice"],
        "pipe_operations_test",
    );

    // Expected output - we should see all pipe operations
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ pipe2(pipefd: [ @NUMBER@, @NUMBER@ ], flags: 0) = 0 (success)
        @PID@ pipe2(pipefd: [ @NUMBER@, @NUMBER@ ], flags: 0x800 (O_NONBLOCK)) = 0 (success)
        @PID@ pipe2(pipefd: [ @NUMBER@, @NUMBER@ ], flags: 0x80000 (O_CLOEXEC)) = 0 (success)
        @PID@ pipe2(pipefd: [ @NUMBER@, @NUMBER@ ], flags: 0x80800 (O_CLOEXEC|O_NONBLOCK)) = 0 (success)
        @PID@ splice(fd_in: @NUMBER@, off_in: 0x0, fd_out: @NUMBER@, off_out: 0x0, len: 20, flags: 0x1 (SPLICE_F_MOVE)) = 20 (bytes)
        @PID@ tee(fd_in: @NUMBER@, fd_out: @NUMBER@, len: 20, flags: 0x2 (SPLICE_F_NONBLOCK)) = 20 (bytes)
        @PID@ vmsplice(fd: @NUMBER@, iov: [ iovec { base: @ADDR@, len: 18, buf: "vmsplice test data" } ], iovcnt: 1, flags: 0x8 (SPLICE_F_GIFT)) = 18 (bytes)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn io_uring_syscalls() {
    let pinchy = PinchyTest::new();

    let handle = run_workload(
        &pinchy,
        &["io_uring_setup", "io_uring_enter", "io_uring_register"],
        "io_uring_test",
    );

    let expected_output = escaped_regex(indoc! {r#"
        @PID@ io_uring_setup(entries: 8, params_ptr: @ADDR@, params: { sq_entries: 8, cq_entries: 16, flags: 0, sq_thread_cpu: 0, sq_thread_idle: 0, features: 0x@HEXNUMBER@ (IORING_FEAT_SINGLE_MMAP|IORING_FEAT_NODROP|IORING_FEAT_SUBMIT_STABLE|IORING_FEAT_RW_CUR_POS|IORING_FEAT_CUR_PERSONALITY|IORING_FEAT_FAST_POLL|IORING_FEAT_POLL_32BITS|IORING_FEAT_SQPOLL_NONFIXED|IORING_FEAT_EXT_ARG|IORING_FEAT_NATIVE_WORKERS|IORING_FEAT_RSRC_TAGS|IORING_FEAT_CQE_SKIP|IORING_FEAT_LINKED_FILE|IORING_FEAT_REG_REG_RING|IORING_FEAT_RECVSEND_BUNDLE|IORING_FEAT_MIN_TIMEOUT|IORING_FEAT_RW_ATTR|IORING_FEAT_NO_IOWAIT), wq_fd: 0 }) = @NUMBER@ (fd)
        @PID@ io_uring_enter(fd: @NUMBER@, to_submit: 0, min_complete: 0, flags: 0x5 (IORING_ENTER_GETEVENTS|IORING_ENTER_SQ_WAIT), sig: 0x0, sigsz: 0) = @NUMBER@ (submitted)
        @PID@ io_uring_register(fd: @NUMBER@, opcode: IORING_REGISTER_PROBE, arg: @ADDR@, nr_args: 4) = -@NUMBER@ (error)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn io_multiplexing_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises I/O multiplexing syscalls
    // Architecture-specific syscalls: select and poll are x86_64 only
    #[cfg(target_arch = "x86_64")]
    let handle = run_workload(
        &pinchy,
        &["select", "poll", "ppoll"],
        "io_multiplexing_test",
    );

    #[cfg(target_arch = "aarch64")]
    let handle = run_workload(&pinchy, &["ppoll"], "io_multiplexing_test");

    // Expected output - architecture-specific formatting
    #[cfg(target_arch = "x86_64")]
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ poll(fds: [ pollfd { fd: @NUMBER@, events: @NUMBER@, revents: @NUMBER@ }, pollfd { fd: @NUMBER@, events: @NUMBER@, revents: @NUMBER@ }, pollfd { fd: @NUMBER@, events: @NUMBER@, revents: @NUMBER@ } ], nfds: 3, timeout: 0) = 0 (timeout)
        @PID@ select(nfds: @NUMBER@, readfds: [  ], writefds: NULL, exceptfds: NULL, timeout:, tv_sec: 0, tv_usec: 0) = 0 (timeout)
        @PID@ poll(fds: [ pollfd { fd: @NUMBER@, events: POLLIN, revents: 0 } ], nfds: 1, timeout: 0) = 0 (timeout)
        @PID@ select(nfds: @NUMBER@, readfds: [ @NUMBER@ ], writefds: NULL, exceptfds: NULL, timeout:, tv_sec: 0, tv_usec: @NUMBER@) = 1 (ready)
        @PID@ poll(fds: [ pollfd { fd: @NUMBER@, events: POLLIN, revents: POLLIN } ], nfds: 1, timeout: 1000) = 1 (ready)
        @PID@ ppoll(fds: [ { @NUMBER@, POLLIN } ], nfds: 1, timeout: { secs: 0, nanos: @NUMBER@ }, sigmask) = 1 (ready) [@NUMBER@ = POLLIN]
    "#});

    #[cfg(target_arch = "aarch64")]
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ ppoll(fds: [ { 0 }, { 1 }, { 2 } ], nfds: 3, timeout: { secs: 0, nanos: 0 }, sigmask) = 0 (timeout)
        @PID@ ppoll(fds: [ { @NUMBER@, POLLIN } ], nfds: 1, timeout: { secs: 0, nanos: @NUMBER@ }, sigmask) = 1 (ready) [@NUMBER@ = POLLIN]
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

fn escaped_regex(expected_output: &str) -> String {
    // Use unique markers to avoid accidental partial replacements
    let mut escaped = regex::escape(expected_output);
    escaped = escaped.replace("@PID@", r"\d+");
    escaped = escaped.replace("@ADDR@", "0x[0-9a-f]+");
    escaped = escaped.replace("@HEXNUMBER@", "[0-9a-f]+");
    escaped = escaped.replace("@SIGNEDNUMBER@", "-?[0-9]+");
    escaped = escaped.replace("@NUMBER@", "[0-9]+");
    escaped = escaped.replace("@MODE@", "[rwx-]+");
    escaped = escaped.replace("@ALPHANUM@", "[^ \"]+");
    escaped = escaped.replace("@QUOTEDSTRING@", "\"[^\"]*\"");
    escaped = escaped.replace("@MAYBEITEM_@", "([^ \"]+ )?");
    escaped = escaped.replace("@MAYBETRUNCATED@", r"( ... \(truncated\))?");
    escaped = escaped.replace("@GROUPLIST@", r"[0-9, ]*");
    escaped = escaped.replace("@ANY@", ".+");
    escaped
}

#[test]
fn fchdir_syscall() {
    let pinchy = PinchyTest::new();

    let handle = run_workload(&pinchy, &["fchdir"], "fchdir_test");

    let expected_output = escaped_regex(indoc! {r#"
        @PID@ fchdir(fd: 3) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn filesystem_sync_syscalls() {
    let pinchy = PinchyTest::new();

    let handle = run_workload(
        &pinchy,
        &["fsync", "fdatasync", "ftruncate", "fchmod"],
        "filesystem_sync_test",
    );

    let expected_output = escaped_regex(indoc! {r#"
        @PID@ fsync(fd: @NUMBER@) = 0 (success)
        @PID@ fdatasync(fd: @NUMBER@) = 0 (success)
        @PID@ ftruncate(fd: @NUMBER@, length: 10) = 0 (success)
        @PID@ ftruncate(fd: @NUMBER@, length: 50) = 0 (success)
        @PID@ fchmod(fd: @NUMBER@, mode: 0o644 (rw-r--r--)) = 0 (success)
        @PID@ fchmod(fd: @NUMBER@, mode: 0o755 (rwxr-xr-x)) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn network_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises network syscalls
    let handle = run_workload(&pinchy, &["accept4", "recvmsg", "sendmsg"], "network_test");

    // Expected output - we should see accept4, recvmsg, and sendmsg calls
    // The exact addresses and file descriptors will vary, so we use regex patterns
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ accept4(sockfd: @NUMBER@, addr: { family: AF_INET, addr: 127.0.0.1:@NUMBER@ }, addrlen: 16, flags: 0x80000 (SOCK_CLOEXEC)) = @NUMBER@ (fd)
        @PID@ sendmsg(sockfd: @NUMBER@, msg: { name: NULL, iov: [  { base: @ADDR@, len: @NUMBER@ } ], iovlen: 1, control: NULL, flags: 0 }, flags: 0) = @NUMBER@ (bytes)
        @PID@ recvmsg(sockfd: @NUMBER@, msg: { name: NULL, iov: [  { base: @ADDR@, len: 1024 } ], iovlen: 1, control: NULL, flags: 0 }, flags: 0) = @NUMBER@ (bytes)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn socket_introspection_syscalls() {
    let pinchy = PinchyTest::new();

    let handle = run_workload(
        &pinchy,
        &[
            "getsockname",
            "getpeername",
            "setsockopt",
            "getsockopt",
            "sendto",
        ],
        "socket_introspection_test",
    );

    let expected_output = escaped_regex(indoc! {r#"
        @PID@ getsockname(sockfd: @NUMBER@, addr: { family: AF_INET, addr: 127.0.0.1:@NUMBER@ }, addrlen: 16) = 0 (success)
        @PID@ getsockname(sockfd: @NUMBER@, addr: { family: AF_INET, addr: 127.0.0.1:@NUMBER@ }, addrlen: 16) = 0 (success)
        @PID@ getpeername(sockfd: @NUMBER@, addr: { family: AF_INET, addr: 127.0.0.1:@NUMBER@ }, addrlen: 16) = 0 (success)
        @PID@ setsockopt(sockfd: @NUMBER@, level: SOL_SOCKET, optname: SO_REUSEADDR, optval: "\u{1}\0\0\0", optlen: 4) = 0 (success)
        @PID@ getsockopt(sockfd: @NUMBER@, level: SOL_SOCKET, optname: SO_REUSEADDR, optval: "\u{1}\0\0\0", optlen: 4) = 0 (success)
        @PID@ setsockopt(sockfd: @NUMBER@, level: SOL_SOCKET, optname: SO_KEEPALIVE, optval: "\u{1}\0\0\0", optlen: 4) = 0 (success)
        @PID@ getsockopt(sockfd: @NUMBER@, level: SOL_SOCKET, optname: SO_KEEPALIVE, optval: "\u{1}\0\0\0", optlen: 4) = 0 (success)
        @PID@ setsockopt(sockfd: @NUMBER@, level: IPPROTO_TCP, optname: TCP_NODELAY, optval: "\u{1}\0\0\0", optlen: 4) = 0 (success)
        @PID@ getsockopt(sockfd: @NUMBER@, level: IPPROTO_TCP, optname: TCP_NODELAY, optval: "\u{1}\0\0\0", optlen: 4) = 0 (success)
        @PID@ sendto(sockfd: @NUMBER@, buf: "socket introspection", size: 20, flags: 0, dest_addr: { family: AF_INET, addr: 127.0.0.1:9 }, addrlen: 16) = 20 (bytes)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn recvfrom_syscall() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises recvfrom syscall
    let handle = run_workload(&pinchy, &["recvfrom"], "recvfrom_test");

    // Expected output - we should see recvfrom calls with and without source address
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ recvfrom(sockfd: @NUMBER@, buf: "UDP recvfrom test!", size: 1024, flags: 0, src_addr: { family: AF_INET, addr: 127.0.0.1:@NUMBER@ }, addrlen: @NUMBER@) = 18 (bytes)
        @PID@ recvfrom(sockfd: @NUMBER@, buf: "second message", size: 1024, flags: 0, src_addr: NULL, addrlen: 0) = 14 (bytes)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn identity_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises identity-related syscalls
    let handle = run_workload(
        &pinchy,
        &[
            "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid", "getppid",
        ],
        "identity_syscalls",
    );

    // Expected output - we should see all identity syscalls returning reasonable values
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ getpid() = @PID@ (pid)
        @PID@ gettid() = @NUMBER@ (pid)
        @PID@ getuid() = @NUMBER@ (id)
        @PID@ geteuid() = @NUMBER@ (id)
        @PID@ getgid() = @NUMBER@ (id)
        @PID@ getegid() = @NUMBER@ (id)
        @PID@ getppid() = @NUMBER@ (pid)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn mmap_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises mmap and munmap syscalls
    let handle = run_workload(&pinchy, &["mmap", "munmap"], "mmap_test");

    // Verify that our specific test mmap calls are present in the output
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ mmap(addr: 0x0, length: 4096, prot: 0x3 (PROT_READ|PROT_WRITE), flags: 0x22 (MAP_PRIVATE|MAP_ANONYMOUS), fd: -1, offset: 0x0) = @ADDR@ (addr)
        @PID@ mmap(addr: 0x0, length: 4096, prot: 0x1 (PROT_READ), flags: 0x22 (MAP_PRIVATE|MAP_ANONYMOUS), fd: -1, offset: 0x0) = @ADDR@ (addr)
        @PID@ mmap(addr: 0x0, length: 4096, prot: 0x0, flags: 0x22 (MAP_PRIVATE|MAP_ANONYMOUS), fd: -1, offset: 0x0) = @ADDR@ (addr)
        @PID@ mmap(addr: 0x0, length: 4096, prot: 0x3 (PROT_READ|PROT_WRITE), flags: 0xa022 (MAP_PRIVATE|MAP_ANONYMOUS|MAP_LOCKED|MAP_POPULATE), fd: -1, offset: 0x0) = @ADDR@ (addr)
        @PID@ mmap(addr: 0x12345000, length: 4096, prot: 0x3 (PROT_READ|PROT_WRITE), flags: 0x32 (MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS), fd: -1, offset: 0x0) = 0x12345000 (addr)
        @PID@ munmap(addr: @ADDR@, length: 4096) = 0 (success)
        @PID@ munmap(addr: @ADDR@, length: 4096) = 0 (success)
        @PID@ munmap(addr: @ADDR@, length: 4096) = 0 (success)
        @PID@ munmap(addr: @ADDR@, length: 4096) = 0 (success)
        @PID@ munmap(addr: 0x12345000, length: 4096) = 0 (success)
        @PID@ munmap(addr: 0x0, length: 4096) = 0 (success)
        @PID@ munmap(addr: 0x1000, length: 0) = -22 (error)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn memfd_create_syscall() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises memfd_create syscall
    let handle = run_workload(&pinchy, &["memfd_create", "close"], "memfd_test");

    // Verify that our memfd_create calls are present in the output
    // Note: Names are truncated to 8 bytes (SMALL_READ_SIZE)
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ memfd_create(name: "test_mem" ... (truncated), flags: 0x1 (MFD_CLOEXEC)) = @NUMBER@ (fd)
        @PID@ memfd_create(name: "test_mem" ... (truncated), flags: 0x2 (MFD_ALLOW_SEALING)) = @NUMBER@ (fd)
        @PID@ memfd_create(name: "test_mem" ... (truncated), flags: 0x3 (MFD_CLOEXEC|MFD_ALLOW_SEALING)) = @NUMBER@ (fd)
        @PID@ close(fd: @NUMBER@) = 0 (success)
        @PID@ close(fd: @NUMBER@) = 0 (success)
        @PID@ close(fd: @NUMBER@) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn madvise_syscall() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises madvise syscall
    let handle = run_workload(&pinchy, &["madvise"], "madvise_test");

    // Expected output - we should see multiple madvise calls with different advice values
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ madvise(addr: @ADDR@, length: 4096, advice: MADV_WILLNEED (3)) = 0 (success)
        @PID@ madvise(addr: @ADDR@, length: 4096, advice: MADV_DONTNEED (4)) = 0 (success)
        @PID@ madvise(addr: @ADDR@, length: 4096, advice: MADV_NORMAL (0)) = 0 (success)
        @PID@ madvise(addr: 0x0, length: 4096, advice: MADV_WILLNEED (3)) = -12 (error)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn mlock_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises memory locking syscalls
    let handle = run_workload(&pinchy, &["mlock", "munlockall"], "mlock_test");

    // Expected output - we should see mlock and munlockall calls
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ mlock(addr: @ADDR@, len: 4096) = 0 (success)
        @PID@ munlockall() = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn file_descriptor_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises file descriptor syscalls
    #[cfg(target_arch = "x86_64")]
    let handle = run_workload(
        &pinchy,
        &["dup", "dup2", "dup3", "close_range"],
        "file_descriptor_test",
    );

    #[cfg(target_arch = "aarch64")]
    let handle = run_workload(
        &pinchy,
        &["dup", "dup3", "close_range"],
        "file_descriptor_test",
    );

    // Expected output - we should see dup, dup2, dup3 and close_range calls
    #[cfg(target_arch = "x86_64")]
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ dup(oldfd: @NUMBER@) = @NUMBER@ (fd)
        @PID@ dup2(oldfd: @NUMBER@, newfd: 10) = 10 (fd)
        @PID@ dup3(oldfd: @NUMBER@, newfd: 11, flags: 0) = 11 (fd)
        @PID@ close_range(fd: @NUMBER@, max_fd: @NUMBER@, flags: 0x0) = 0 (success)
    "#});

    #[cfg(target_arch = "aarch64")]
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ dup(oldfd: @NUMBER@) = @NUMBER@ (fd)
        @PID@ dup3(oldfd: @NUMBER@, newfd: 11, flags: 0) = 11 (fd)
        @PID@ close_range(fd: @NUMBER@, max_fd: @NUMBER@, flags: 0x0) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn session_process_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises session and process group syscalls
    let handle = run_workload(
        &pinchy,
        &["getpgid", "getsid", "setpgid", "setsid"],
        "session_process_test",
    );

    // Expected output - we should see process group and session calls
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ getpgid(pid: 0) = @NUMBER@ (pid)
        @PID@ getsid(pid: 0) = @NUMBER@ (pid)
        @PID@ setpgid(pid: 0, pgid: @NUMBER@) = 0 (success)
        @PID@ setsid() = @NUMBER@ (pid)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn uid_gid_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises user/group ID syscalls
    let handle = run_workload(
        &pinchy,
        &[
            "setuid",
            "setgid",
            "setreuid",
            "setregid",
            "setresuid",
            "setresgid",
        ],
        "uid_gid_test",
    );

    // Expected output - these should succeed with root privileges
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ setuid(uid: @NUMBER@) = 0 (success)
        @PID@ setgid(gid: @NUMBER@) = 0 (success)
        @PID@ setreuid(ruid: @NUMBER@, euid: @NUMBER@) = 0 (success)
        @PID@ setregid(rgid: @NUMBER@, egid: @NUMBER@) = 0 (success)
        @PID@ setresuid(ruid: @NUMBER@, euid: @NUMBER@, suid: @NUMBER@) = 0 (success)
        @PID@ setresgid(rgid: @NUMBER@, egid: @NUMBER@, sgid: @NUMBER@) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn system_operations() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises system operation syscalls
    let handle = run_workload(&pinchy, &["umask", "sync"], "system_operations_test");

    // Expected output - umask and sync calls
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ umask(mask: 0o22) = 18
        @PID@ umask(mask: 0o22) = 18
        @PID@ sync() = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn uname_sysinfo_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises system information syscalls
    let handle = run_workload(&pinchy, &["uname", "sysinfo"], "system_info_test");

    // Expected output - uname and sysinfo calls
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ uname(struct utsname: { sysname: @QUOTEDSTRING@, nodename: @QUOTEDSTRING@, release: @QUOTEDSTRING@, version: @QUOTEDSTRING@, machine: @QUOTEDSTRING@, domainname: @QUOTEDSTRING@ }) = 0 (success)
        @PID@ sysinfo(info: { uptime: @NUMBER@ seconds, loads: [@NUMBER@, @NUMBER@, @NUMBER@], totalram: @NUMBER@ MB, freeram: @NUMBER@ MB, sharedram: @NUMBER@ MB, bufferram: @NUMBER@ MB, totalswap: @NUMBER@ MB, freeswap: @NUMBER@ MB, procs: @NUMBER@, mem_unit: @NUMBER@ bytes }) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn prctl_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises various prctl operations
    let handle = run_workload(&pinchy, &["prctl"], "prctl_test");

    // Expected output - prctl operations with various argument patterns
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ prctl(PR_SET_NAME, @ADDR@) = 0 (success)
        @PID@ prctl(PR_GET_NAME, @ADDR@) = 0 (success)
        @PID@ prctl(PR_GET_DUMPABLE) = @NUMBER@
        @PID@ prctl(PR_SET_DUMPABLE, 0x0) = 0 (success)
        @PID@ prctl(PR_GET_DUMPABLE) = 0 (success)
        @PID@ prctl(PR_SET_DUMPABLE, 0x1) = 0 (success)
        @PID@ prctl(PR_CAPBSET_READ, 0x15) = @NUMBER@
        @PID@ prctl(PR_CAPBSET_DROP, 0x15) = 0 (success)
        @PID@ prctl(PR_GET_KEEPCAPS) = 0 (success)
        @PID@ prctl(PR_SET_KEEPCAPS, 0x1) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn ioprio_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises I/O priority syscalls
    let handle = run_workload(&pinchy, &["ioprio_get", "ioprio_set"], "ioprio_test");

    // Expected output - ioprio_get and ioprio_set calls
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ ioprio_get(which: 1, who: 0) = 0
        @PID@ ioprio_set(which: 1, who: 0, ioprio: 0) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn scheduler_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises scheduler syscalls
    let handle = run_workload(
        &pinchy,
        &["sched_getscheduler", "sched_setscheduler"],
        "scheduler_test",
    );

    // Expected output - sched_getscheduler and sched_setscheduler calls
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ sched_getscheduler(pid: 0) = 0 (success)
        @PID@ sched_setscheduler(pid: 0, policy: SCHED_OTHER, param: { sched_priority: 0 }) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn pread_pwrite_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises pread and pwrite syscalls
    let handle = run_workload(
        &pinchy,
        &["write", "pread64", "pwrite64"],
        "pread_pwrite_test",
    );

    // Expected output - pread and pwrite calls
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ write(fd: @NUMBER@, buf: "Hello, world! This is test data for pread/pwrite.", count: 49) = 49 (bytes)
        @PID@ pwrite64(fd: @NUMBER@, buf: "pinch", count: 5, offset: 7) = 5 (bytes)
        @PID@ pread64(fd: @NUMBER@, buf: "lo, pinch! This is test data", count: 28, offset: 3) = 28 (bytes)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn readv_writev_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises readv and writev syscalls
    let handle = run_workload(&pinchy, &["writev", "readv"], "readv_writev_test");

    // Expected output - readv and writev calls
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ writev(fd: @NUMBER@, iov: [ iovec { base: @ADDR@, len: 7, buf: "Hello, " }, iovec { base: @ADDR@, len: 6, buf: "world!" } ], iovcnt: 2) = 13 (bytes)
        @PID@ readv(fd: @NUMBER@, iov: [ iovec { base: @ADDR@, len: 7, buf: "Hello, " }, iovec { base: @ADDR@, len: 6, buf: "world!" } ], iovcnt: 2) = 13 (bytes)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn socket_lifecycle_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises socket lifecycle syscalls
    let handle = run_workload(
        &pinchy,
        &["socket", "bind", "connect", "listen", "shutdown"],
        "socket_lifecycle_test",
    );

    // Expected output - we should see all socket lifecycle syscalls
    // The exact addresses and file descriptors will vary, so we use regex patterns
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ socket(domain: AF_INET, type: SOCK_STREAM, protocol: 0) = @NUMBER@ (fd)
        @PID@ socket(domain: AF_INET, type: SOCK_DGRAM, protocol: 0) = @NUMBER@ (fd)
        @PID@ bind(sockfd: @NUMBER@, addr: { family: AF_INET, addr: 127.0.0.1:0 }, addrlen: 16) = 0 (success)
        @PID@ listen(sockfd: @NUMBER@, backlog: 5) = 0 (success)
        @PID@ socket(domain: AF_INET, type: SOCK_STREAM, protocol: 0) = @NUMBER@ (fd)
        @PID@ connect(sockfd: @NUMBER@, addr: { family: AF_INET, addr: 127.0.0.1:@NUMBER@ }, addrlen: 16) = 0 (success)
        @PID@ shutdown(sockfd: @NUMBER@, how: SHUT_RD) = 0 (success)
        @PID@ shutdown(sockfd: @NUMBER@, how: SHUT_WR) = 0 (success)
        @PID@ socket(domain: AF_INET, type: SOCK_STREAM, protocol: 0) = @NUMBER@ (fd)
        @PID@ connect(sockfd: @NUMBER@, addr: { family: AF_INET, addr: 127.0.0.1:@NUMBER@ }, addrlen: 16) = 0 (success)
        @PID@ shutdown(sockfd: @NUMBER@, how: SHUT_RDWR) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn accept_syscall() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises accept syscall
    let handle = run_workload(&pinchy, &["accept"], "accept_test");

    // Expected output - we should see accept call
    // The exact addresses and file descriptors will vary, so we use regex patterns
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ accept(sockfd: @NUMBER@, addr: { family: AF_INET, addr: 127.0.0.1:@NUMBER@ }, addrlen: 16) = @NUMBER@ (fd)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn pselect6_syscall() {
    let pinchy = PinchyTest::new();

    let handle = run_workload(&pinchy, &["pselect6"], "pselect6_test");

    // Expected output - we should see two pselect6 calls:
    // 1. One that times out (return 0)
    // 2. One that finds a ready fd (return 1)
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ pselect6(nfds: 4, readfds: [  ], writefds: NULL, exceptfds: NULL, timeout: { secs: 0, nanos: 0 }, sigmask: <present>) = 0 (timeout)
        @PID@ pselect6(nfds: 4, readfds: [ 3 ], writefds: NULL, exceptfds: NULL, timeout: { secs: 0, nanos: @NUMBER@ }, sigmask: <present>) = 1 (ready)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn eventfd_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises eventfd syscalls
    // FIXME: in the future we should alias eventfd to eventfd2, I suppose.
    #[cfg(target_arch = "x86_64")]
    let handle = run_workload(&pinchy, &["eventfd", "eventfd2", "close"], "eventfd_test");

    #[cfg(target_arch = "aarch64")]
    let handle = run_workload(&pinchy, &["eventfd2", "close"], "eventfd_test");

    // Expected output - we should see eventfd2 calls with different flags and closes
    // eventfd() syscall (x86_64 only) and eventfd2() are both tested
    #[cfg(target_arch = "x86_64")]
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ eventfd2(initval: 0, flags: 0) = @NUMBER@ (fd)
        @PID@ eventfd2(initval: 5, flags: 0x80000 (EFD_CLOEXEC)) = @NUMBER@ (fd)
        @PID@ eventfd2(initval: 10, flags: 0x800 (EFD_NONBLOCK)) = @NUMBER@ (fd)
        @PID@ eventfd(initval: 42, flags: 0) = @NUMBER@ (fd)
        @PID@ close(fd: @NUMBER@) = 0 (success)
        @PID@ close(fd: @NUMBER@) = 0 (success)
        @PID@ close(fd: @NUMBER@) = 0 (success)
        @PID@ close(fd: @NUMBER@) = 0 (success)
    "#});

    #[cfg(target_arch = "aarch64")]
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ eventfd2(initval: 0, flags: 0) = @NUMBER@ (fd)
        @PID@ eventfd2(initval: 5, flags: 0x80000 (EFD_CLOEXEC)) = @NUMBER@ (fd)
        @PID@ eventfd2(initval: 10, flags: 0x800 (EFD_NONBLOCK)) = @NUMBER@ (fd)
        @PID@ close(fd: @NUMBER@) = 0 (success)
        @PID@ close(fd: @NUMBER@) = 0 (success)
        @PID@ close(fd: @NUMBER@) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn execveat_syscall() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises execveat syscalls
    let handle = run_workload(&pinchy, &["execveat"], "execveat_test");

    // Expected output - we should see execveat calls with different arguments and flags
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ execveat(dirfd: @NUMBER@, pathname: "this-does-not-exist-for-sure", argv: [this-doe, arg1, arg2], envp: [@ALPHANUM@, @ALPHANUM@], flags: 0) = -2 (error)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn xattr_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises extended attribute syscalls
    let handle = run_workload(
        &pinchy,
        &[
            "setxattr",
            "fsetxattr",
            "getxattr",
            "fgetxattr",
            "listxattr",
            "flistxattr",
        ],
        "xattr_test",
    );

    // Expected output - we should see all xattr operations. MAYBEITEM_ is to catch systems that have selinux attrs.
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ setxattr(pathname: "/tmp/xattr_test_file", name: "user.test_attr1", value: "test_value_1", size: 12, flags: 0) = 0 (success)
        @PID@ fsetxattr(fd: @NUMBER@, name: "user.test_attr2", value: "another_test_value", size: 18, flags: 0) = 0 (success)
        @PID@ getxattr(pathname: "/tmp/xattr_test_file", name: "user.test_attr1", value: "test_value_1", size: 64) = 12
        @PID@ fgetxattr(fd: @NUMBER@, name: "user.test_attr2", value: "another_test_value", size: 64) = 18
        @PID@ listxattr(pathname: "/tmp/xattr_test_file", list: [ @MAYBEITEM_@@ALPHANUM@, @ALPHANUM@ ], size: 256) = @NUMBER@
        @PID@ flistxattr(fd: @NUMBER@, list: [ @MAYBEITEM_@@ALPHANUM@, @ALPHANUM@ ], size: 256) = @NUMBER@
        @PID@ getxattr(pathname: "/tmp/xattr_test_file", name: "user.test_attr1", value: "@ALPHANUM@", size: 0) = 12
        @PID@ getxattr(pathname: "/tmp/xattr_test_file", name: "user.nonexistent", value: @ADDR@, size: 64) = -61 (error)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn sysv_ipc_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises SysV IPC syscalls
    let handle = run_workload(
        &pinchy,
        &[
            "shmget", "shmat", "shmdt", "shmctl", "msgget", "msgsnd", "msgrcv", "msgctl", "semget",
            "semop", "semctl",
        ],
        "sysv_ipc_test",
    );

    // Expected output - we should see all SysV IPC operations
    // The exact IDs and addresses will vary, so we use regex patterns
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ shmget(key: 0x12345678, size: 4096, shmflg: 0o666|IPC_CREAT) = @NUMBER@ (shmid)
        @PID@ shmat(shmid: @NUMBER@, shmaddr: 0x0, shmflg: 0x0) = @ADDR@
        @PID@ shmctl(shmid: @NUMBER@, cmd: IPC_STAT, buf: { ipc_perm { key: 0x12345678, uid: @NUMBER@, gid: @NUMBER@, cuid: @NUMBER@, cgid: @NUMBER@, mode: 0o666 (rw-rw-rw-), seq: @NUMBER@ }, segsz: @NUMBER@, atime: @NUMBER@, dtime: @NUMBER@, ctime: @NUMBER@, cpid: @NUMBER@, lpid: @NUMBER@, nattch: @NUMBER@ }) = 0 (success)
        @PID@ shmdt(shmaddr: @ADDR@) = 0 (success)
        @PID@ shmctl(shmid: @NUMBER@, cmd: IPC_RMID, buf: NULL) = 0 (success)
        @PID@ msgget(key: 0x12345679, msgflg: IPC_CREAT) = @NUMBER@ (msqid)
        @PID@ msgsnd(msqid: @NUMBER@, msgp: @ADDR@, msgsz: 30, msgflg: 0x0) = 0 (success)
        @PID@ msgctl(msqid: @NUMBER@, cmd: IPC_STAT, buf: { ipc_perm { key: 0x12345679, uid: @NUMBER@, gid: @NUMBER@, cuid: @NUMBER@, cgid: @NUMBER@, mode: 0o666 (rw-rw-rw-), seq: @NUMBER@ }, stime: @NUMBER@, rtime: @NUMBER@, ctime: @NUMBER@, cbytes: @NUMBER@, qnum: @NUMBER@, qbytes: @NUMBER@, lspid: @NUMBER@, lrpid: @NUMBER@ }) = 0 (success)
        @PID@ msgrcv(msqid: @NUMBER@, msgp: @ADDR@, msgsz: 32, msgtyp: 0, msgflg: 0x0) = 30
        @PID@ msgctl(msqid: @NUMBER@, cmd: IPC_RMID, buf: NULL) = 0 (success)
        @PID@ semget(key: 0x11223344, nsems: 2, semflg: IPC_CREAT) = @NUMBER@ (semid)
        @PID@ semctl(semid: @NUMBER@, semnum: 0, op: SETVAL, val: 0) = 0 (success)
        @PID@ semctl(semid: @NUMBER@, semnum: 0, op: GETVAL) = 5
        @PID@ semctl(semid: @NUMBER@, semnum: 0, op: IPC_RMID, arg: 0x0 (unknown)) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn socketpair_sendmmsg_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises socketpair, sendmmsg, and recvmmsg syscalls
    let handle = run_workload(
        &pinchy,
        &["socketpair", "sendmmsg", "recvmmsg"],
        "socketpair_sendmmsg_test",
    );

    // Expected output - we should see socketpair creating socket pairs,
    // then sendmmsg and recvmmsg for batch message operations
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ socketpair(domain: AF_UNIX, type: SOCK_STREAM, protocol: 0, sv: [@NUMBER@, @NUMBER@]) = 0 (success)
        @PID@ socketpair(domain: AF_UNIX, type: SOCK_DGRAM, protocol: 0, sv: [@NUMBER@, @NUMBER@]) = 0 (success)
        @PID@ sendmmsg(sockfd: @NUMBER@, msgvec: [  { msg_hdr: { name: NULL, iov: [  { base: @ADDR@, len: 13 } ], iovlen: 1, control: NULL, flags: 0 }, msg_len: 0 } { msg_hdr: { name: NULL, iov: [  { base: @ADDR@, len: 14 } ], iovlen: 1, control: NULL, flags: 0 }, msg_len: 0 } ], vlen: 2, flags: 0) = 2 (messages)
        @PID@ recvmmsg(sockfd: @NUMBER@, msgvec: [  { msg_hdr: { name: NULL, iov: [  { base: @ADDR@, len: 64 } ], iovlen: 1, control: NULL, flags: 0 }, msg_len: 27 } { msg_hdr: { name: NULL, iov: [  { base: @ADDR@, len: 64 } ], iovlen: 1, control: NULL, flags: 0 }, msg_len: 0 } ], vlen: 2, flags: 0x40 (MSG_DONTWAIT), timeout: { tv_sec: 0, tv_nsec: @NUMBER@ }) = 1 (messages)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn timer_test() {
    let pinchy = PinchyTest::new();

    let handle = run_workload(
        &pinchy,
        &[
            "timer_create",
            "timer_settime",
            "timer_gettime",
            "timer_getoverrun",
            "timer_delete",
        ],
        "timer_test",
    );

    let expected_output = escaped_regex(indoc! {r#"
        @PID@ timer_create(clockid: CLOCK_REALTIME, sevp: { sigev_notify: SIGEV_SIGNAL, sigev_signo: 10, sigev_value.sival_int: 42 }, timerid: <output>) = 0 (success)
        @PID@ timer_settime(timerid: @ADDR@, flags: 0, new_value: { it_interval: { secs: 1, nanos: 0 }, it_value: { secs: 2, nanos: 500000000 } }, old_value: { it_interval: { secs: 0, nanos: 0 }, it_value: { secs: 0, nanos: 0 } }) = 0 (success)
        @PID@ timer_gettime(timerid: @ADDR@, curr_value: { it_interval: { secs: 1, nanos: 0 }, it_value: { secs: @NUMBER@, nanos: @NUMBER@ } }) = 0 (success)
        @PID@ timer_getoverrun(timerid: @ADDR@) = 0 (overruns)
        @PID@ timer_delete(timerid: @ADDR@) = 0 (success)
        @PID@ timer_create(clockid: CLOCK_MONOTONIC, sevp: NULL, timerid: <output>) = 0 (success)
        @PID@ timer_delete(timerid: @ADDR@) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn timerfd_test() {
    let pinchy = PinchyTest::new();

    let handle = run_workload(
        &pinchy,
        &[
            "timerfd_create",
            "timerfd_settime",
            "timerfd_gettime",
            "close",
        ],
        "timerfd_test",
    );

    let expected_output = escaped_regex(indoc! {r#"
        @PID@ timerfd_create(clockid: CLOCK_REALTIME, flags: 0) = @NUMBER@ (fd)
        @PID@ timerfd_settime(fd: @NUMBER@, flags: 0, new_value: { it_interval: { secs: 1, nanos: 0 }, it_value: { secs: 2, nanos: 500000000 } }, old_value: { it_interval: { secs: 0, nanos: 0 }, it_value: { secs: 0, nanos: 0 } }) = 0 (success)
        @PID@ timerfd_gettime(fd: @NUMBER@, curr_value: { it_interval: { secs: 1, nanos: 0 }, it_value: { secs: @NUMBER@, nanos: @NUMBER@ } }) = 0 (success)
        @PID@ close(fd: @NUMBER@) = 0 (success)
        @PID@ timerfd_create(clockid: CLOCK_MONOTONIC, flags: TFD_CLOEXEC) = @NUMBER@ (fd)
        @PID@ timerfd_settime(fd: @NUMBER@, flags: TIMER_ABSTIME, new_value: { it_interval: { secs: 0, nanos: 0 }, it_value: { secs: 1675209600, nanos: 0 } }, old_value: NULL) = 0 (success)
        @PID@ timerfd_gettime(fd: @NUMBER@, curr_value: { it_interval: { secs: 0, nanos: 0 }, it_value: { secs: @NUMBER@, nanos: @NUMBER@ } }) = 0 (success)
        @PID@ close(fd: @NUMBER@) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn ioctl_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises ioctl syscalls
    let handle = run_workload(&pinchy, &["ioctl"], "ioctl_test");

    // Expected output - we should see ioctl calls with different requests
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ ioctl(fd: 3, request: (0x541b) tty::FIONREAD, arg: @ADDR@) = 0 (success)
        @PID@ ioctl(fd: 3, request: (0xdeadbeef) other::unknown, arg: @ADDR@) = -25 (error)
        @PID@ ioctl(fd: 3, request: (0x5451) tty::FIOCLEX, arg: 0x0) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn filesystem_links_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises filesystem link operations
    #[cfg(target_arch = "x86_64")]
    let handle = run_workload(
        &pinchy,
        &["symlinkat", "readlinkat", "linkat", "link"],
        "filesystem_links_test",
    );

    #[cfg(target_arch = "aarch64")]
    let handle = run_workload(
        &pinchy,
        &["symlinkat", "readlinkat", "linkat"],
        "filesystem_links_test",
    );

    // Expected output - we should see all filesystem link operations
    #[cfg(target_arch = "x86_64")]
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ symlinkat(target: "/tmp/filesystem_links_target", newdirfd: AT_FDCWD, linkpath: "/tmp/filesystem_links_symlink") = 0 (success)
        @PID@ readlinkat(dirfd: AT_FDCWD, pathname: "/tmp/filesystem_links_symlink", buf: "/tmp/filesystem_links_target", bufsiz: 256) = 28
        @PID@ linkat(olddirfd: AT_FDCWD, oldpath: "/tmp/filesystem_links_target", newdirfd: AT_FDCWD, newpath: "/tmp/filesystem_links_hardlink", flags: 0) = 0 (success)
        @PID@ link(oldpath: "/tmp/filesystem_links_target", newpath: "/tmp/filesystem_links_link2") = 0 (success)
        @PID@ readlinkat(dirfd: AT_FDCWD, pathname: "/tmp/filesystem_links_nonexistent", buf: "", bufsiz: 256) = -2 (error)
        @PID@ linkat(olddirfd: AT_FDCWD, oldpath: "/tmp/filesystem_links_nonexisten"@MAYBETRUNCATED@, newdirfd: AT_FDCWD, newpath: "/tmp/filesystem_links_error_link"@MAYBETRUNCATED@, flags: 0) = -2 (error)
    "#});

    #[cfg(target_arch = "aarch64")]
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ symlinkat(target: "/tmp/filesystem_links_target", newdirfd: AT_FDCWD, linkpath: "/tmp/filesystem_links_symlink") = 0 (success)
        @PID@ readlinkat(dirfd: AT_FDCWD, pathname: "/tmp/filesystem_links_symlink", buf: "/tmp/filesystem_links_target", bufsiz: 256) = 28
        @PID@ linkat(olddirfd: AT_FDCWD, oldpath: "/tmp/filesystem_links_target", newdirfd: AT_FDCWD, newpath: "/tmp/filesystem_links_hardlink", flags: 0) = 0 (success)
        @PID@ readlinkat(dirfd: AT_FDCWD, pathname: "/tmp/filesystem_links_nonexistent", buf: "", bufsiz: 256) = -2 (error)
        @PID@ linkat(olddirfd: AT_FDCWD, oldpath: "/tmp/filesystem_links_nonexisten"@MAYBETRUNCATED@, newdirfd: AT_FDCWD, newpath: "/tmp/filesystem_links_error_link"@MAYBETRUNCATED@, flags: 0) = -2 (error)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn aio_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises Async I/O syscalls
    let handle = run_workload(
        &pinchy,
        &[
            "io_setup",
            "io_submit",
            "io_getevents",
            "io_pgetevents",
            "io_cancel",
            "io_destroy",
        ],
        "aio_test",
    );

    // Expected output - we should see all AIO syscalls
    // Note: Some syscalls might fail if AIO is not supported, but we should still see the traces
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ io_setup(nr_events: 128, ctx_idp: @ADDR@) = 0 (success)
        @PID@ io_submit(ctx_id: @ADDR@, nr: 1, iocbpp: @ADDR@, iocbs: [ iocb { data: @ADDR@, key: @NUMBER@, rw_flags: @NUMBER@, lio_opcode: IOCB_CMD_PREAD, reqprio: @NUMBER@, fildes: @NUMBER@, buf: @ADDR@, nbytes: 64, offset: 0, flags: @NUMBER@ } ]) = 1 (requests)
        @PID@ io_getevents(ctx_id: @ADDR@, min_nr: 1, nr: 2, events: @ADDR@, timeout: { secs: 1, nanos: 0 }, events_returned: [ event { data: @ADDR@, obj: @ADDR@, res: @SIGNEDNUMBER@, res2: @SIGNEDNUMBER@ } ]) = 1 (events)
        @PID@ io_pgetevents(ctx_id: @ADDR@, min_nr: 0, nr: 2, events: @ADDR@, timeout: { secs: 1, nanos: 0 }, usig: { sigmask: @ADDR@, sigsetsize: @NUMBER@, sigset: [] }) = -@NUMBER@ (error)
        @PID@ io_cancel(ctx_id: @ADDR@, iocb: @ADDR@, result: @ADDR@) = -@NUMBER@ (error)
        @PID@ io_destroy(ctx_id: @ADDR@) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn landlock_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises Landlock syscalls
    let handle = run_workload(
        &pinchy,
        &[
            "landlock_create_ruleset",
            "landlock_add_rule",
            "landlock_restrict_self",
        ],
        "landlock_test",
    );

    // Expected output - we should see all landlock syscalls with parsed rule attributes
    // 1. First create_ruleset with NULL attr and VERSION flag (checks version)
    // 2. Second create_ruleset with actual attributes (may succeed or fail)
    // 3. landlock_add_rule with PATH_BENEATH rule type (parsed attributes)
    // 4. landlock_add_rule with NET_PORT rule type (parsed attributes)
    // 5. landlock_restrict_self
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ landlock_create_ruleset(attr: 0x0, size: 0, flags: 0x1 (LANDLOCK_CREATE_RULESET_VERSION)) = @NUMBER@ (fd)
        @PID@ landlock_create_ruleset(attr: @ADDR@, size: @NUMBER@, flags: 0) = -@NUMBER@ (error)
        @PID@ landlock_add_rule(ruleset_fd: -1, rule_type: LANDLOCK_RULE_PATH_BENEATH, parent_fd: 4, allowed_access: 0x3f (EXECUTE|WRITE_FILE|READ_FILE|READ_DIR|REMOVE_DIR|REMOVE_FILE), flags: 0) = -@NUMBER@ (error)
        @PID@ landlock_add_rule(ruleset_fd: -1, rule_type: LANDLOCK_RULE_NET_PORT, port: 8080, access_rights: 0x3 (BIND_TCP|CONNECT_TCP), flags: 0) = -@NUMBER@ (error)
        @PID@ landlock_restrict_self(ruleset_fd: -1, flags: 0) = -@NUMBER@ (error)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn posix_mq_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises POSIX message queue syscalls
    let handle = run_workload(
        &pinchy,
        &[
            "mq_open",
            "mq_timedsend",
            "mq_getsetattr",
            "mq_timedreceive",
            "mq_notify",
            "mq_unlink",
        ],
        "posix_mq_test",
    );

    // Expected output:
    // 1. mq_open with O_CREAT to create new queue
    // 2. mq_timedsend to send a message
    // 3. mq_getsetattr to change flags to O_NONBLOCK
    // 4. mq_timedreceive to receive the message
    // 5. mq_notify to register notification
    // 6. mq_notify with NULL to unregister
    // 7. mq_unlink to remove the queue
    // 8. mq_open attempting to open non-existent queue (should fail)
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ mq_open(name: @ADDR@, flags: 0xc2 (O_RDWR|O_CREAT|O_EXCL), mode: 0o666 (rw-rw-rw-), attr: { mq_flags: 0, mq_maxmsg: 10, mq_msgsize: 1024, mq_curmsgs: 0 }) = @NUMBER@
        @PID@ mq_timedsend(mqdes: @NUMBER@, msg_ptr: @ADDR@, msg_len: 15, msg_prio: 10, abs_timeout: @ADDR@) = 0 (success)
        @PID@ mq_getsetattr(mqdes: @NUMBER@, newattr: { mq_flags: 2048, mq_maxmsg: 0, mq_msgsize: 0, mq_curmsgs: 0 }, oldattr: { mq_flags: 0, mq_maxmsg: 10, mq_msgsize: 1024, mq_curmsgs: 1 }) = 0 (success)
        @PID@ mq_timedreceive(mqdes: @NUMBER@, msg_ptr: @ADDR@, msg_len: 8192, msg_prio: 10, abs_timeout: @ADDR@) = 15
        @PID@ mq_notify(mqdes: @NUMBER@, sevp: @ADDR@) = 0 (success)
        @PID@ mq_notify(mqdes: @NUMBER@, sevp: 0x0) = 0 (success)
        @PID@ mq_unlink(name: @ADDR@) = 0 (success)
        @PID@ mq_open(name: @ADDR@, flags: 0x0 (O_RDONLY), mode: 0, attr: NULL) = -@NUMBER@ (error)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn key_management_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises key management syscalls
    let handle = run_workload(
        &pinchy,
        &["add_key", "request_key", "keyctl"],
        "key_management_test",
    );

    // Expected output - we should see key management syscalls being traced
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ keyctl(operation: JOIN_SESSION_KEYRING, name: @ADDR@) = @SIGNEDNUMBER@ (key)
        @PID@ add_key(type: "user", description: "test_key_1", payload: @ANY@, keyring: KEY_SPEC_SESSION_KEYRING) = @SIGNEDNUMBER@
        @PID@ add_key(type: "keyring", description: "test_keyring", payload: (empty), keyring: KEY_SPEC_SESSION_KEYRING) = @SIGNEDNUMBER@
        @PID@ request_key(type: "user", description: "test_key_1", callout_info: "test_call_info", dest_keyring: KEY_SPEC_THREAD_KEYRING) = @SIGNEDNUMBER@
        @PID@ keyctl(operation: DESCRIBE, key: @SIGNEDNUMBER@, buffer: @ADDR@, buflen: @ADDR@) = @SIGNEDNUMBER@ (bytes)
        @PID@ keyctl(operation: READ, key: @SIGNEDNUMBER@, buffer: @ADDR@, buflen: @ADDR@) = @SIGNEDNUMBER@ (bytes)
        @PID@ keyctl(operation: SETPERM, key: @SIGNEDNUMBER@, permissions: @ADDR@) = @SIGNEDNUMBER@ (success)
        @PID@ keyctl(operation: GET_KEYRING_ID, keyring: @ALPHANUM@, create: @ADDR@) = @SIGNEDNUMBER@ (key)
        @PID@ keyctl(operation: SEARCH, keyring: @ALPHANUM@, type: @ADDR@, description: @ADDR@, dest_keyring: @ALPHANUM@) = @SIGNEDNUMBER@ (key)
        @PID@ keyctl(operation: REVOKE, key: @SIGNEDNUMBER@) = @SIGNEDNUMBER@ (success)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    // Server output - has to be at the end, since we kill the server for waiting.
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn perf_event_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises perf_event_open syscall
    let handle = run_workload(&pinchy, &["perf_event_open"], "perf_event_test");

    // Expected output - perf_event_open calls (may succeed or fail depending on permissions)
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ perf_event_open(attr: { type: PERF_TYPE_SOFTWARE, size: @NUMBER@, config: 0x0, sample_period: 0 }, pid: 0, cpu: -1, group_fd: -1, flags: 0) = @NUMBER@ (fd)
        @PID@ perf_event_open(attr: { type: PERF_TYPE_SOFTWARE, size: @NUMBER@, config: 0x0, sample_period: 0 }, pid: 0, cpu: -1, group_fd: -1, flags: 0x8 (FD_CLOEXEC)) = @NUMBER@ (fd)
        @PID@ perf_event_open(attr: { type: PERF_TYPE_HARDWARE, size: 0, config: 0x0, sample_period: 0 }, pid: 0, cpu: -1, group_fd: -1, flags: 0) = -@NUMBER@ (error)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn bpf_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises bpf syscall
    let handle = run_workload(&pinchy, &["bpf"], "bpf_test");

    // Expected output - bpf calls (BPF_MAP_CREATE may succeed if CAP_BPF is present)
    // The test-helper makes 3 calls: BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM (if map created), and an invalid command
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ bpf(cmd: BPF_MAP_CREATE, attr: { map_type: BPF_MAP_TYPE_ARRAY, key_size: 4, value_size: 8, max_entries: 1 }, size: @NUMBER@) = @ANY@
        @PID@ bpf(cmd: BPF_MAP_LOOKUP_ELEM, size: @NUMBER@) = @ANY@
        @PID@ bpf(cmd: UNKNOWN(@NUMBER@), size: @NUMBER@) = @ANY@
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn fanotify_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises fanotify syscalls
    let handle = run_workload(
        &pinchy,
        &["fanotify_init", "fanotify_mark"],
        "fanotify_test",
    );

    // Expected output - fanotify calls (requires CAP_SYS_ADMIN typically)
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ fanotify_init(flags: @ANY@, event_f_flags: @ANY@) = @NUMBER@ (fd)
        @PID@ fanotify_mark(fanotify_fd: @NUMBER@, flags: @ANY@, mask: @ANY@, dirfd: AT_FDCWD, pathname: "/tmp") = 0 (success)
        @PID@ fanotify_init(flags: @ANY@, event_f_flags: @ANY@) = -@NUMBER@ (error)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn file_handles_syscalls() {
    let pinchy = PinchyTest::new();

    // Run a workload that exercises file handle and range operations
    let handle = run_workload(
        &pinchy,
        &[
            "copy_file_range",
            "sync_file_range",
            "syncfs",
            "utimensat",
            "name_to_handle_at",
            "open_by_handle_at",
        ],
        "file_handles_test",
    );

    // Expected output - file handle/range syscalls
    // Note: name_to_handle_at and open_by_handle_at may fail without CAP_DAC_READ_SEARCH
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ copy_file_range(fd_in: @NUMBER@, off_in: @NUMBER@, fd_out: @NUMBER@, off_out: @NUMBER@, len: 1024, flags: 0) = @SIGNEDNUMBER@ (bytes)
        @PID@ sync_file_range(fd: @NUMBER@, offset: 0, nbytes: 0, flags: 0x2 (SYNC_FILE_RANGE_WRITE)) = 0 (success)
        @PID@ syncfs(fd: @NUMBER@) = 0 (success)
        @PID@ utimensat(dirfd: AT_FDCWD, pathname: "/tmp/pinchy_file_handles_test.txt", times: @ANY@, flags: 0) = 0 (success)
        @PID@ utimensat(dirfd: AT_FDCWD, pathname: "/tmp/pinchy_file_handles_test.txt", times: NULL, flags: 0) = 0 (success)
        @PID@ name_to_handle_at(dirfd: AT_FDCWD, pathname: "/tmp/pinchy_file_handles_test.txt", handle: @ADDR@, mount_id: @ADDR@, flags: 0) = 0 (success)
        @PID@ open_by_handle_at(mount_fd: AT_FDCWD, handle: @ADDR@, flags: @ANY@) = @SIGNEDNUMBER@ (error)
    "#});

    let output = handle.join().unwrap();
    // Uncomment for debugging:
    // use std::io::Write;
    // std::io::stderr().write_all(&output.stderr).unwrap();
    // std::io::stderr().write_all(&output.stdout).unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn itimer_test() {
    let pinchy = PinchyTest::new();

    let handle = run_workload(&pinchy, &["getitimer", "setitimer"], "itimer_test");

    let expected_output = escaped_regex(indoc! {r#"
        @PID@ getitimer(which: ITIMER_REAL, curr_value: { it_interval: { tv_sec: 0, tv_usec: 0 }, it_value: { tv_sec: 0, tv_usec: 0 } }) = 0 (success)
        @PID@ setitimer(which: ITIMER_VIRTUAL, new_value: { it_interval: { tv_sec: 0, tv_usec: 0 }, it_value: { tv_sec: 0, tv_usec: 100000 } }, old_value: { it_interval: { tv_sec: 0, tv_usec: 0 }, it_value: { tv_sec: 0, tv_usec: 0 } }) = 0 (success)
        @PID@ getitimer(which: ITIMER_VIRTUAL, curr_value: { it_interval: { tv_sec: 0, tv_usec: 0 }, it_value: { tv_sec: 0, tv_usec: @NUMBER@ } }) = 0 (success)
        @PID@ setitimer(which: ITIMER_VIRTUAL, new_value: { it_interval: { tv_sec: 0, tv_usec: 0 }, it_value: { tv_sec: 0, tv_usec: 0 } }, old_value: NULL) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn syslog_test() {
    let pinchy = PinchyTest::new();

    let handle = run_workload(&pinchy, &["syslog"], "syslog_test");

    let expected_output = escaped_regex(indoc! {r#"
        @PID@ syslog(type: SYSLOG_ACTION_SIZE_BUFFER, bufp: 0x0, size: 0) = @NUMBER@
        @PID@ syslog(type: SYSLOG_ACTION_SIZE_UNREAD, bufp: 0x0, size: 0) = @NUMBER@
        @PID@ syslog(type: SYSLOG_ACTION_READ_ALL, bufp: 0x@HEXNUMBER@, size: 1024) = @ANY@
        @PID@ syslog(type: SYSLOG_ACTION_CONSOLE_LEVEL, bufp: 0x0, size: 7) = 0 (success)
        @PID@ syslog(type: SYSLOG_ACTION_CONSOLE_OFF, bufp: 0x0, size: 0) = 0 (success)
        @PID@ syslog(type: SYSLOG_ACTION_CONSOLE_ON, bufp: 0x0, size: 0) = 0 (success)
        @PID@ syslog(type: SYSLOG_ACTION_CLEAR, bufp: 0x0, size: 0) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn ptrace_test() {
    let pinchy = PinchyTest::new();

    let handle = run_workload(&pinchy, &["ptrace"], "ptrace_test");

    let expected_output = escaped_regex(indoc! {r#"
        @PID@ ptrace(request: PTRACE_TRACEME, pid: 0, addr: @ADDR@, data: @ADDR@) = 0 (success)
        @PID@ ptrace(request: PTRACE_PEEKTEXT, pid: @NUMBER@, addr: @ADDR@, data: @ADDR@) = @SIGNEDNUMBER@ (error) (data ptr)
        @PID@ ptrace(request: PTRACE_CONT, pid: 1, addr: @ADDR@, sig: @ALPHANUM@) = @SIGNEDNUMBER@ (error)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn seccomp_test() {
    let pinchy = PinchyTest::new();

    let handle = run_workload(&pinchy, &["seccomp"], "seccomp_test");

    let expected_output = escaped_regex(indoc! {r#"
        @PID@ seccomp(operation: SECCOMP_GET_ACTION_AVAIL, flags: 0, action: SECCOMP_RET_KILL_THREAD) = 0 (success)
        @PID@ seccomp(operation: SECCOMP_GET_NOTIF_SIZES, flags: 0, sizes: {notif: @NUMBER@, resp: @NUMBER@, data: @NUMBER@}) = 0 (success)
        @PID@ seccomp(operation: 255, flags: 0, args: NULL) = @SIGNEDNUMBER@ (error)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn quotactl_test() {
    let pinchy = PinchyTest::new();

    let handle = run_workload(&pinchy, &["quotactl"], "quotactl_test");

    let expected_output = escaped_regex(indoc! {r#"
        @PID@ quotactl(op: 0x800001 (QCMD(Q_SYNC, USRQUOTA)), special: "", id: 0, addr: @ADDR@) = @SIGNEDNUMBER@ (error)
        @PID@ quotactl(op: 0x800004 (QCMD(Q_GETFMT, USRQUOTA)), special: "/", id: 0, addr: @ADDR@) = @SIGNEDNUMBER@ (error)
        @PID@ quotactl(op: 0x800007 (QCMD(Q_GETQUOTA, USRQUOTA)), special: "/", id: 1000, addr: @ADDR@) = @SIGNEDNUMBER@ (error)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn process_identity_test() {
    let pinchy = PinchyTest::new();

    let handle = run_workload(
        &pinchy,
        &["getresuid", "getresgid", "getgroups", "setgroups"],
        "process_identity_test",
    );

    let expected_output = escaped_regex(indoc! {r#"
        @PID@ getresuid(ruid: @NUMBER@, euid: @NUMBER@, suid: @NUMBER@) = 0 (success)
        @PID@ getresgid(rgid: @NUMBER@, egid: @NUMBER@, sgid: @NUMBER@) = 0 (success)
        @PID@ getgroups(size: 32, list: [@GROUPLIST@]) = @NUMBER@ (groups)
        @PID@ setgroups(size: @NUMBER@, list: [@GROUPLIST@]) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn auto_quit() {
    let pinchy = PinchyTest::with_mode(TestMode::AutoQuit);

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn auto_quit_timing() {
    let pinchy = PinchyTest::with_mode(TestMode::AutoQuit);

    // Read timestamps before wait() which consumes self
    let start = pinchy
        .read_timestamp("pinchyd.start_time")
        .expect("missing pinchyd.start_time");

    let end = pinchy
        .read_timestamp("pinchyd.end_time")
        .expect("missing pinchyd.end_time");

    let elapsed = end - start;

    assert!(
        (10..=20).contains(&elapsed),
        "auto_quit idle time {elapsed}s outside expected \
         10..=20s range"
    );

    let output = pinchy.wait();
    Assert::new(output).success();
}

#[test]
fn auto_quit_after_client() {
    let pinchy = PinchyTest::with_mode(TestMode::AutoQuitAfterClient);

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::contains("Currently serving: 0"))
        .stdout(predicate::str::contains(
            "Pinchy has been idle for a while, shutting down",
        ))
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn auto_quit_after_client_timing() {
    let pinchy = PinchyTest::with_mode(TestMode::AutoQuitAfterClient);

    // Read timestamps before wait() which consumes self
    let kill_time = pinchy
        .read_timestamp("client.kill_time")
        .expect("missing client.kill_time");

    let end = pinchy
        .read_timestamp("pinchyd.end_time")
        .expect("missing pinchyd.end_time");

    let elapsed = end - kill_time;

    assert!(
        elapsed < 22,
        "auto_quit_after_client took {elapsed}s after client \
         kill, expected < 22s"
    );

    let output = pinchy.wait();
    Assert::new(output).success();
}

// Tests for syscall aliases - these verify that users can use aliased names
// and get the same behavior as using canonical names

#[test]
fn signal_alias_sigprocmask() {
    let pinchy = PinchyTest::new();

    // Use the alias "sigprocmask" instead of "rt_sigprocmask"
    let handle = run_workload(&pinchy, &["sigprocmask"], "rt_sig");

    // Expected output should show rt_sigprocmask (the canonical name)
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ rt_sigprocmask(how: SIG_BLOCK, set: [SIGUSR1], oldset: [], sigsetsize: 8) = 0 (success)
        @PID@ rt_sigprocmask(how: SIG_SETMASK, set: NULL, oldset: [SIGUSR1], sigsetsize: 8) = 0 (success)
        @PID@ rt_sigprocmask(how: SIG_UNBLOCK, set: [SIGUSR1], oldset: NULL, sigsetsize: 8) = 0 (success)
        @PID@ rt_sigprocmask(how: SIG_SETMASK, set: [], oldset: NULL, sigsetsize: 8) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn signal_alias_sigaction() {
    let pinchy = PinchyTest::new();

    // Use the alias "sigaction" instead of "rt_sigaction"
    let handle = run_workload(&pinchy, &["sigaction"], "rt_sigaction_standard");

    // Expected output should show rt_sigaction (the canonical name)
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ rt_sigaction(signum: SIGUSR1, act: @ADDR@, oldact: @ADDR@, sigsetsize: 8) = 0 (success)
        @PID@ rt_sigaction(signum: SIGUSR1, act: 0x0, oldact: @ADDR@, sigsetsize: 8) = 0 (success)
        @PID@ rt_sigaction(signum: SIGUSR1, act: @ADDR@, oldact: 0x0, sigsetsize: 8) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn aarch64_alias_open() {
    let pinchy = PinchyTest::new();

    // On aarch64, use the alias "open" which maps to "openat"
    let handle = run_workload(&pinchy, &["open", "read", "lseek"], "pinchy_reads");

    // Expected output should show openat (the canonical name on aarch64)
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ openat(dfd: AT_FDCWD, pathname: "pinchy/tests/GPLv2", flags: 0x0 (O_RDONLY), mode: 0) = 3 (fd)
        @PID@ read(fd: 3, buf: @ANY@, count: 128) = 128 (bytes)
        @PID@ read(fd: 3, buf: @ANY@, count: 1024) = 1024 (bytes)
        @PID@ lseek(fd: 3, offset: 0, whence: 2) = 18092
        @PID@ read(fd: 3, buf: "", count: 1024) = 0 (bytes)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn aarch64_alias_stat() {
    let pinchy = PinchyTest::new();

    // On aarch64, use the alias "stat" which maps to "newfstatat"
    let handle = run_workload(&pinchy, &["stat", "fstat"], "filesystem_syscalls_test");

    // Expected output should show newfstatat (the canonical name on aarch64)
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ fstat(fd: @NUMBER@, struct stat: { mode: 0o@NUMBER@ (@MODE@), ino: @NUMBER@, dev: @NUMBER@, nlink: @NUMBER@, uid: @NUMBER@, gid: @NUMBER@, size: 18092, blksize: @NUMBER@, blocks: @NUMBER@, atime: @NUMBER@, mtime: @NUMBER@, ctime: @NUMBER@ }) = 0 (success)
        @PID@ newfstatat(dirfd: AT_FDCWD, pathname: "pinchy/tests/GPLv2", struct stat: { mode: 0o@NUMBER@ (@MODE@), ino: @NUMBER@, dev: @NUMBER@, nlink: @NUMBER@, uid: @NUMBER@, gid: @NUMBER@, size: 18092, blksize: @NUMBER@, blocks: @NUMBER@, atime: @NUMBER@, mtime: @NUMBER@, ctime: @NUMBER@ }, flags: 0) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
fn mixed_aliases_and_canonical() {
    let pinchy = PinchyTest::new();

    // Mix aliases and canonical names in the same filter
    let handle = run_workload(&pinchy, &["sigprocmask"], "rt_sig");

    // Should capture both rt_sigprocmask (from sigprocmask alias)
    let expected_output = escaped_regex(indoc! {r#"
        @PID@ rt_sigprocmask(how: SIG_BLOCK, set: [SIGUSR1], oldset: [], sigsetsize: 8) = 0 (success)
        @PID@ rt_sigprocmask(how: SIG_SETMASK, set: NULL, oldset: [SIGUSR1], sigsetsize: 8) = 0 (success)
        @PID@ rt_sigprocmask(how: SIG_UNBLOCK, set: [SIGUSR1], oldset: NULL, sigsetsize: 8) = 0 (success)
        @PID@ rt_sigprocmask(how: SIG_SETMASK, set: [], oldset: NULL, sigsetsize: 8) = 0 (success)
    "#});

    let output = handle.join().unwrap();
    Assert::new(output)
        .success()
        .stdout(predicate::str::is_match(&expected_output).unwrap());

    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}
