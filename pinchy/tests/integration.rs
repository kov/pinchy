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
fn rt_sig() {
    let pinchy = PinchyTest::new(None, None);

    // Run a workload
    let handle = run_workload(&["rt_sigprocmask"], "rt_sig");

    // Client's output - we expect multiple rt_sigprocmask calls from our test
    let expected_output = escaped_regex(indoc! {r#"
        PID rt_sigprocmask(how: SIG_BLOCK, set: ADDR, oldset: ADDR, sigsetsize: 8) = 0
        PID rt_sigprocmask(how: SIG_SETMASK, set: 0x0, oldset: ADDR, sigsetsize: 8) = 0
        PID rt_sigprocmask(how: SIG_UNBLOCK, set: ADDR, oldset: 0x0, sigsetsize: 8) = 0
        PID rt_sigprocmask(how: SIG_SETMASK, set: ADDR, oldset: 0x0, sigsetsize: 8) = 0
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
        PID rt_sigaction(signum: SIGRT1, act: ADDR, oldact: ADDR, sigsetsize: 8) = 0
        PID rt_sigaction(signum: SIGRT1, act: 0x0, oldact: ADDR, sigsetsize: 8) = 0
        PID rt_sigaction(signum: SIGRT1, act: ADDR, oldact: 0x0, sigsetsize: 8) = 0
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
        PID rt_sigaction(signum: SIGUSR1, act: ADDR, oldact: ADDR, sigsetsize: 8) = 0
        PID rt_sigaction(signum: SIGUSR1, act: 0x0, oldact: ADDR, sigsetsize: 8) = 0
        PID rt_sigaction(signum: SIGUSR1, act: ADDR, oldact: 0x0, sigsetsize: 8) = 0
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
        PID fcntl(fd: 3, cmd: F_GETFD, arg: 0x0) = 0
        PID fcntl(fd: 3, cmd: F_SETFD, arg: 0x1) = 0
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
}

#[test]
#[serial]
#[ignore = "runs in special environment"]
fn fchdir_syscall() {
    let pinchy = PinchyTest::new(None, None);

    let handle = run_workload(&["fchdir"], "fchdir_test");

    let expected_output = escaped_regex(indoc! {r#"
        PID fchdir(fd: 3) = 0
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
        PID sched_getscheduler(pid: 0) = 0
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
