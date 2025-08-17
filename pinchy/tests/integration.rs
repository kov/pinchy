// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

mod common;

use std::{
    fs,
    process::{Command, Output},
    thread::JoinHandle,
};

use assert_cmd::{assert::Assert, cargo::cargo_bin};
use common::PinchyTest;
use indoc::indoc;
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[serial]
#[ignore = "runs in special environment"]
fn basic_output() {
    let pinchy = PinchyTest::new(None, None);
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
#[serial]
#[ignore = "runs in special environment"]
fn drop_privileges() {
    let pinchy = PinchyTest::new(None, None);

    let pid = pinchy.get_pid();
    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .expect("Failed to read process status from /proc");

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
#[serial]
#[ignore = "runs in special environment"]
fn pinchy_reads() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload
    let handle = run_workload(&["openat", "read", "lseek"], "pinchy_reads");

    // Client's output
    let expected_output = escaped_regex(indoc! {r#"
           PID openat(dfd: AT_FDCWD, pathname: "pinchy/tests/GPLv2", flags: 0x0 (O_RDONLY), mode: 0) = 3 (fd)
           PID read(fd: 3, buf: "                    GNU GENERAL PUBLIC LICENSE\n                       Version 2, June 1991\n\n Copyright (C) 1989, 1991 Free Softw", count: 128) = 128 (bytes)
           PID read(fd: 3, buf: "are Foundation, Inc.,\n 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA\n Everyone is permitted to copy and distribute " ... (896 more bytes), count: 1024) = 1024 (bytes)
           PID lseek(fd: 3, offset: 0, whence: 2) = 18092
           PID read(fd: 3, buf: "", count: 1024) = 0 (bytes)
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
#[serial]
#[ignore = "runs in special environment"]
fn filesystem_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises getdents64, fstat, newfstatat, faccessat
    let handle = run_workload(
        &["getdents64", "fstat", "newfstatat", "faccessat"],
        "filesystem_syscalls_test",
    );

    // Client's output - we expect the syscalls from the workload
    let expected_output = escaped_regex(indoc! {r#"
        PID getdents64(fd: NUMBER, count: NUMBER, entries: [ dirent { ino: NUMBER, off: NUMBER, reclen: NUMBER, type: NUMBER, name: "ALPHANUM"MAYBETRUNCATED }, dirent { ino: NUMBER, off: NUMBER, reclen: NUMBER, type: NUMBER, name: "ALPHANUM"MAYBETRUNCATED }, dirent { ino: NUMBER, off: NUMBER, reclen: NUMBER, type: NUMBER, name: "ALPHANUM"MAYBETRUNCATED }, dirent { ino: NUMBER, off: NUMBER, reclen: NUMBER, type: NUMBER, name: "ALPHANUM"MAYBETRUNCATED } ]) = 184 (bytes)
        PID fstat(fd: NUMBER, struct stat: { mode: 0oNUMBER (MODE), ino: NUMBER, dev: NUMBER, nlink: NUMBER, uid: NUMBER, gid: NUMBER, size: 18092, blksize: NUMBER, blocks: NUMBER, atime: NUMBER, mtime: NUMBER, ctime: NUMBER }) = 0 (success)
        PID newfstatat(dirfd: AT_FDCWD, pathname: "pinchy/tests/GPLv2", struct stat: { mode: 0oNUMBER (MODE), ino: NUMBER, dev: NUMBER, nlink: NUMBER, uid: NUMBER, gid: NUMBER, size: 18092, blksize: NUMBER, blocks: NUMBER, atime: NUMBER, mtime: NUMBER, ctime: NUMBER }, flags: 0) = 0 (success)
        PID faccessat(dirfd: AT_FDCWD, pathname: "pinchy/tests/GPLv2", mode: R_OK, flags: 0) = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn rt_sig() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload
    let handle = run_workload(&["rt_sigprocmask"], "rt_sig");

    // Client's output - we expect pretty-printed signal sets
    let expected_output = escaped_regex(indoc! {r#"
        PID rt_sigprocmask(how: SIG_BLOCK, set: [SIGUSR1], oldset: [], sigsetsize: 8) = 0 (success)
        PID rt_sigprocmask(how: SIG_SETMASK, set: NULL, oldset: [SIGUSR1], sigsetsize: 8) = 0 (success)
        PID rt_sigprocmask(how: SIG_UNBLOCK, set: [SIGUSR1], oldset: NULL, sigsetsize: 8) = 0 (success)
        PID rt_sigprocmask(how: SIG_SETMASK, set: [], oldset: NULL, sigsetsize: 8) = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn rt_sigaction_realtime() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises rt_sigaction with real-time signals
    let handle = run_workload(&["rt_sigaction"], "rt_sigaction_realtime");

    // Client's output - we expect rt_sigaction calls with SIGRT1
    let expected_output = escaped_regex(indoc! {r#"
        PID rt_sigaction(signum: SIGRT1, act: ADDR, oldact: ADDR, sigsetsize: 8) = 0 (success)
        PID rt_sigaction(signum: SIGRT1, act: 0x0, oldact: ADDR, sigsetsize: 8) = 0 (success)
        PID rt_sigaction(signum: SIGRT1, act: ADDR, oldact: 0x0, sigsetsize: 8) = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn rt_sigaction_standard() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises rt_sigaction with standard signals
    let handle = run_workload(&["rt_sigaction"], "rt_sigaction_standard");

    // Client's output - we expect rt_sigaction calls with SIGUSR1
    let expected_output = escaped_regex(indoc! {r#"
        PID rt_sigaction(signum: SIGUSR1, act: ADDR, oldact: ADDR, sigsetsize: 8) = 0 (success)
        PID rt_sigaction(signum: SIGUSR1, act: 0x0, oldact: ADDR, sigsetsize: 8) = 0 (success)
        PID rt_sigaction(signum: SIGUSR1, act: ADDR, oldact: 0x0, sigsetsize: 8) = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn fcntl_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises fcntl syscalls
    let handle = run_workload(&["fcntl"], "fcntl_test");

    // Client's output - we expect several fcntl calls
    let expected_output = escaped_regex(indoc! {r#"
        PID fcntl(fd: 3, cmd: F_GETFL, arg: 0x0) = NUMBER
        PID fcntl(fd: 3, cmd: F_GETFD, arg: 0x0) = 0 (success)
        PID fcntl(fd: 3, cmd: F_SETFD, arg: 0x1) = 0 (success)
        PID fcntl(fd: 3, cmd: F_DUPFD, arg: 0xa) = 10
        PID fcntl(fd: 3, cmd: F_DUPFD_CLOEXEC, arg: 0x14) = 20
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

fn run_workload(events: &[&str], test_name: &str) -> JoinHandle<Output> {
    let events: Vec<String> = events.iter().map(|&s| s.to_owned()).collect();
    let test_name = test_name.to_owned();
    std::thread::spawn(move || {
        let mut cmd = Command::new(cargo_bin("pinchy"));

        // Add event filters
        for event in events {
            cmd.args(["-e", &event]);
        }

        // Add the test helper command
        cmd.arg("--")
            .arg(cargo_bin("test-helper"))
            .arg(&test_name)
            .output()
            .expect("Failed to run pinchy")
    })
}

fn escaped_regex(expected_output: &str) -> String {
    regex::escape(expected_output)
        .replace("PID", r"\d+")
        .replace("ADDR", "0x[0-9a-f]+")
        .replace("NUMBER", "[0-9]+")
        .replace("MODE", "[rwx-]+")
        .replace("ALPHANUM", "[^ \"]+")
        .replace("MAYBETRUNCATED", r"( ... \(truncated\))?")
}

#[test]
#[serial]
#[ignore = "runs in special environment"]
fn fchdir_syscall() {
    let pinchy = PinchyTest::new(None, None);

    let handle = run_workload(&["fchdir"], "fchdir_test");

    let expected_output = escaped_regex(indoc! {r#"
        PID fchdir(fd: 3) = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn filesystem_sync_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    let handle = run_workload(
        &["fsync", "fdatasync", "ftruncate", "fchmod"],
        "filesystem_sync_test",
    );

    let expected_output = escaped_regex(indoc! {r#"
        PID fsync(fd: PID) = 0 (success)
        PID fdatasync(fd: PID) = 0 (success)
        PID ftruncate(fd: PID, length: 10) = 0 (success)
        PID ftruncate(fd: PID, length: 50) = 0 (success)
        PID fchmod(fd: PID, mode: 0o644 (rw-r--r--)) = 0 (success)
        PID fchmod(fd: PID, mode: 0o755 (rwxr-xr-x)) = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn network_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises network syscalls
    let handle = run_workload(&["accept4", "recvmsg", "sendmsg"], "network_test");

    // Expected output - we should see accept4, recvmsg, and sendmsg calls
    // The exact addresses and file descriptors will vary, so we use regex patterns
    let expected_output = escaped_regex(indoc! {r#"
        PID accept4(sockfd: NUMBER, addr: { family: AF_INET, addr: 127.0.0.1:NUMBER }, addrlen: 16, flags: 0x80000 (SOCK_CLOEXEC)) = NUMBER (fd)
        PID sendmsg(sockfd: NUMBER, msg: { name: NULL, iov: [  { base: ADDR, len: NUMBER } ], iovlen: 1, control: NULL, flags: 0 }, flags: 0) = NUMBER (bytes)
        PID recvmsg(sockfd: NUMBER, msg: { name: NULL, iov: [  { base: ADDR, len: 1024 } ], iovlen: 1, control: NULL, flags: 0 }, flags: 0) = NUMBER (bytes)
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
#[serial]
#[ignore = "runs in special environment"]
fn recvfrom_syscall() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises recvfrom syscall
    let handle = run_workload(&["recvfrom"], "recvfrom_test");

    // Expected output - we should see recvfrom calls with and without source address
    let expected_output = escaped_regex(indoc! {r#"
        PID recvfrom(sockfd: NUMBER, buf: "UDP recvfrom test!", size: 1024, flags: 0, src_addr: { family: AF_INET, addr: 127.0.0.1:NUMBER }, addrlen: NUMBER) = 18 (bytes)
        PID recvfrom(sockfd: NUMBER, buf: "second message", size: 1024, flags: 0, src_addr: NULL, addrlen: 0) = 14 (bytes)
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
#[serial]
#[ignore = "runs in special environment"]
fn identity_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises identity-related syscalls
    let handle = run_workload(
        &[
            "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid", "getppid",
        ],
        "identity_syscalls",
    );

    // Expected output - we should see all identity syscalls returning reasonable values
    let expected_output = escaped_regex(indoc! {r#"
        PID getpid() = PID (pid)
        PID gettid() = NUMBER (pid)
        PID getuid() = NUMBER (id)
        PID geteuid() = NUMBER (id)
        PID getgid() = NUMBER (id)
        PID getegid() = NUMBER (id)
        PID getppid() = NUMBER (pid)
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
#[serial]
#[ignore = "runs in special environment"]
fn madvise_syscall() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises madvise syscall
    let handle = run_workload(&["madvise"], "madvise_test");

    // Expected output - we should see multiple madvise calls with different advice values
    let expected_output = escaped_regex(indoc! {r#"
        PID madvise(addr: ADDR, length: 4096, advice: MADV_WILLNEED (3)) = 0 (success)
        PID madvise(addr: ADDR, length: 4096, advice: MADV_DONTNEED (4)) = 0 (success)
        PID madvise(addr: ADDR, length: 4096, advice: MADV_NORMAL (0)) = 0 (success)
        PID madvise(addr: 0x0, length: 4096, advice: MADV_WILLNEED (3)) = -12 (error)
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
#[serial]
#[ignore = "runs in special environment"]
fn mlock_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises memory locking syscalls
    let handle = run_workload(&["mlock", "munlockall"], "mlock_test");

    // Expected output - we should see mlock and munlockall calls
    let expected_output = escaped_regex(indoc! {r#"
        PID mlock(addr: ADDR, len: 4096) = 0 (success)
        PID munlockall() = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn file_descriptor_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises file descriptor syscalls
    let handle = run_workload(&["dup", "close_range"], "file_descriptor_test");

    // Expected output - we should see dup and close_range calls
    let expected_output = escaped_regex(indoc! {r#"
        PID dup(oldfd: NUMBER) = NUMBER (fd)
        PID close_range(fd: NUMBER, max_fd: NUMBER, flags: 0x0) = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn session_process_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises session and process group syscalls
    let handle = run_workload(
        &["getpgid", "getsid", "setpgid", "setsid"],
        "session_process_test",
    );

    // Expected output - we should see process group and session calls
    let expected_output = escaped_regex(indoc! {r#"
        PID getpgid(pid: 0) = NUMBER (pid)
        PID getsid(pid: 0) = NUMBER (pid)
        PID setpgid(pid: 0, pgid: NUMBER) = 0 (success)
        PID setsid() = NUMBER (pid)
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
#[serial]
#[ignore = "runs in special environment"]
fn uid_gid_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises user/group ID syscalls
    let handle = run_workload(
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
        PID setuid(uid: NUMBER) = 0 (success)
        PID setgid(gid: NUMBER) = 0 (success)
        PID setreuid(ruid: NUMBER, euid: NUMBER) = 0 (success)
        PID setregid(rgid: NUMBER, egid: NUMBER) = 0 (success)
        PID setresuid(ruid: NUMBER, euid: NUMBER, suid: NUMBER) = 0 (success)
        PID setresgid(rgid: NUMBER, egid: NUMBER, sgid: NUMBER) = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn system_operations() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises system operation syscalls
    let handle = run_workload(&["umask", "sync"], "system_operations_test");

    // Expected output - umask and sync calls
    let expected_output = escaped_regex(indoc! {r#"
        PID umask(mask: 0o22) = 18
        PID umask(mask: 0o22) = 18
        PID sync() = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn ioprio_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises I/O priority syscalls
    let handle = run_workload(&["ioprio_get", "ioprio_set"], "ioprio_test");

    // Expected output - ioprio_get and ioprio_set calls
    let expected_output = escaped_regex(indoc! {r#"
        PID ioprio_get(which: 1, who: 0) = 0
        PID ioprio_set(which: 1, who: 0, ioprio: 0) = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn scheduler_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises scheduler syscalls
    let handle = run_workload(
        &["sched_getscheduler", "sched_setscheduler"],
        "scheduler_test",
    );

    // Expected output - sched_getscheduler and sched_setscheduler calls
    let expected_output = escaped_regex(indoc! {r#"
        PID sched_getscheduler(pid: 0) = 0 (success)
        PID sched_setscheduler(pid: 0, policy: SCHED_OTHER, param: { sched_priority: 0 }) = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn pread_pwrite_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises pread and pwrite syscalls
    let handle = run_workload(&["write", "pread64", "pwrite64"], "pread_pwrite_test");

    // Expected output - pread and pwrite calls
    let expected_output = escaped_regex(indoc! {r#"
        PID write(fd: NUMBER, buf: "Hello, world! This is test data for pread/pwrite.", count: 49) = 49 (bytes)
        PID pwrite64(fd: NUMBER, buf: "pinch", count: 5, offset: 7) = 5 (bytes)
        PID pread64(fd: NUMBER, buf: "lo, pinch! This is test data", count: 28, offset: 3) = 28 (bytes)
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
#[serial]
#[ignore = "runs in special environment"]
fn readv_writev_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises readv and writev syscalls
    let handle = run_workload(&["writev", "readv"], "readv_writev_test");

    // Expected output - readv and writev calls
    let expected_output = escaped_regex(indoc! {r#"
        PID writev(fd: NUMBER, iov: [ iovec { base: ADDR, len: 7, buf: "Hello, " }, iovec { base: ADDR, len: 6, buf: "world!" } ], iovcnt: 2) = 13 (bytes)
        PID readv(fd: NUMBER, iov: [ iovec { base: ADDR, len: 7, buf: "Hello, " }, iovec { base: ADDR, len: 6, buf: "world!" } ], iovcnt: 2) = 13 (bytes)
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
#[serial]
#[ignore = "runs in special environment"]
fn socket_lifecycle_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises socket lifecycle syscalls
    let handle = run_workload(
        &["socket", "bind", "connect", "listen", "shutdown"],
        "socket_lifecycle_test",
    );

    // Expected output - we should see all socket lifecycle syscalls
    // The exact addresses and file descriptors will vary, so we use regex patterns
    let expected_output = escaped_regex(indoc! {r#"
        PID socket(domain: AF_INET, type: SOCK_STREAM, protocol: 0) = NUMBER (fd)
        PID socket(domain: AF_INET, type: SOCK_DGRAM, protocol: 0) = NUMBER (fd)
        PID bind(sockfd: NUMBER, addr: { family: AF_INET, addr: 127.0.0.1:0 }, addrlen: 16) = 0 (success)
        PID listen(sockfd: NUMBER, backlog: 5) = 0 (success)
        PID socket(domain: AF_INET, type: SOCK_STREAM, protocol: 0) = NUMBER (fd)
        PID connect(sockfd: NUMBER, addr: { family: AF_INET, addr: 127.0.0.1:NUMBER }, addrlen: 16) = 0 (success)
        PID shutdown(sockfd: NUMBER, how: SHUT_RD) = 0 (success)
        PID shutdown(sockfd: NUMBER, how: SHUT_WR) = 0 (success)
        PID socket(domain: AF_INET, type: SOCK_STREAM, protocol: 0) = NUMBER (fd)
        PID connect(sockfd: NUMBER, addr: { family: AF_INET, addr: 127.0.0.1:NUMBER }, addrlen: 16) = 0 (success)
        PID shutdown(sockfd: NUMBER, how: SHUT_RDWR) = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn accept_syscall() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises accept syscall
    let handle = run_workload(&["accept"], "accept_test");

    // Expected output - we should see accept call
    // The exact addresses and file descriptors will vary, so we use regex patterns
    let expected_output = escaped_regex(indoc! {r#"
        PID accept(sockfd: NUMBER, addr: { family: AF_INET, addr: 127.0.0.1:NUMBER }, addrlen: 16) = NUMBER (fd)
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
#[serial]
#[ignore = "runs in special environment"]
fn pselect6_syscall() {
    let pinchy = PinchyTest::new(None, None);

    let handle = run_workload(&["pselect6"], "pselect6_test");

    // Expected output - we should see two pselect6 calls:
    // 1. One that times out (return 0)
    // 2. One that finds a ready fd (return 1)
    let expected_output = escaped_regex(indoc! {r#"
        PID pselect6(nfds: 4, readfds: [  ], writefds: NULL, exceptfds: NULL, timeout: { secs: 0, nanos: 0 }, sigmask: <present>) = 0 (timeout)
        PID pselect6(nfds: 4, readfds: [ 3 ], writefds: NULL, exceptfds: NULL, timeout: { secs: 0, nanos: NUMBER }, sigmask: <present>) = 1 (ready)
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
#[serial]
#[ignore = "runs in special environment"]
fn eventfd_syscalls() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises eventfd syscalls
    // FIXME: in the future we should alias eventfd to eventfd2, I suppose.
    #[cfg(target_arch = "x86_64")]
    let handle = run_workload(&["eventfd", "eventfd2", "close"], "eventfd_test");

    #[cfg(target_arch = "aarch64")]
    let handle = run_workload(&["eventfd2", "close"], "eventfd_test");

    // Expected output - we should see eventfd2 calls with different flags and closes
    // eventfd() syscall (x86_64 only) and eventfd2() are both tested
    #[cfg(target_arch = "x86_64")]
    let expected_output = escaped_regex(indoc! {r#"
        PID eventfd2(initval: 0, flags: 0) = NUMBER (fd)
        PID eventfd2(initval: 5, flags: 0x80000 (EFD_CLOEXEC)) = NUMBER (fd)
        PID eventfd2(initval: 10, flags: 0x800 (EFD_NONBLOCK)) = NUMBER (fd)
        PID eventfd(initval: 42, flags: 0) = NUMBER (fd)
        PID close(fd: NUMBER) = 0 (success)
        PID close(fd: NUMBER) = 0 (success)
        PID close(fd: NUMBER) = 0 (success)
        PID close(fd: NUMBER) = 0 (success)
    "#});

    #[cfg(target_arch = "aarch64")]
    let expected_output = escaped_regex(indoc! {r#"
        PID eventfd2(initval: 0, flags: 0) = NUMBER (fd)
        PID eventfd2(initval: 5, flags: 0x80000 (EFD_CLOEXEC)) = NUMBER (fd)
        PID eventfd2(initval: 10, flags: 0x800 (EFD_NONBLOCK)) = NUMBER (fd)
        PID close(fd: NUMBER) = 0 (success)
        PID close(fd: NUMBER) = 0 (success)
        PID close(fd: NUMBER) = 0 (success)
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
#[serial]
#[ignore = "runs in special environment"]
fn execveat_syscall() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload that exercises execveat syscalls
    let handle = run_workload(&["execveat"], "execveat_test");

    // Expected output - we should see execveat calls with different arguments and flags
    let expected_output = escaped_regex(indoc! {r#"
        PID execveat(dirfd: NUMBER, pathname: "this-does-not-exist-for-sure", argv: [this-doe, arg1, arg2], envp: [ALPHANUM, ALPHANUM], flags: 0) = -2 (error)
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
