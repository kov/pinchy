// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::{
    fs,
    io::{BufRead as _, BufReader, PipeReader},
    os::fd::OwnedFd,
    process::{self, Child, Command, Output, Stdio},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use assert_cmd::{assert::Assert, cargo::cargo_bin};
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
fn auto_quit() {
    // We won't start any tracing, after a minute we should see this message.
    let now = Instant::now();

    let pinchy = PinchyTest::new(
        None,
        Some("Pinchy has been idle for a while, shutting down".to_string()),
    );
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));

    let elapsed = now.elapsed().as_secs();

    // Check if we exited in around 15 seconds.
    assert!(elapsed.abs_diff(15) < 5);
}

#[test]
#[serial]
#[ignore = "runs in special environment"]
fn auto_quit_after_client() {
    // We won't start any tracing, after a minute we should see this message.
    let pinchy = PinchyTest::new(None, Some("Currently serving: 1".to_string()));

    // Start pinchy client to monitor our own PID.
    let mut child = Command::new(cargo_bin("pinchy"))
        //.env("RUST_LOG", "trace")
        .arg(cargo_bin("test-helper"))
        .arg("pinchy_reads")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();

    // Give it time to establish connection and get some data.
    std::thread::sleep(Duration::from_secs(1));

    child.kill().unwrap();

    // We start counting idle time after we killed the client.
    let now = Instant::now();

    // Now check the server gave us the expected output
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::contains("Currently serving: 0"))
        .stdout(predicate::str::contains(
            "Pinchy has been idle for a while, shutting down",
        ))
        .stdout(predicate::str::ends_with("Exiting...\n"));

    let elapsed = now.elapsed().as_secs();

    // Check if we exited in under 20 seconds (worst case of hitting the idle check at exactly
    // the same time we kill the client), with a bit of leeway
    assert!(elapsed < 22);

    let _ = child.wait();
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

fn run_pinchyd(pid: Option<u32>) -> Child {
    let mut cmd = process::Command::new(cargo_bin("pinchyd"));
    let mut cmd = cmd
        //.env("RUST_LOG", "trace")
        .stdout(Stdio::piped());

    if let Some(pid) = pid {
        cmd = cmd.arg(pid.to_string())
    }

    let child = cmd.spawn().unwrap_or_else(|e| {
        panic!("Failed to run pinchyd process under dbus-launch for testing: {e}")
    });

    child
}

fn wait_for_output(child: Child) -> Output {
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };

    child.wait_with_output().unwrap()
}

fn ensure_root() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "Need to run test as root (using, for instance, cargo sudo)"
    );
}

fn read_until(
    mut reader: BufReader<PipeReader>,
    needle: String,
) -> JoinHandle<(BufReader<PipeReader>, Vec<u8>)> {
    let reader_thread = std::thread::spawn(move || {
        let mut data = vec![];
        let mut buf = String::new();
        while let Ok(bytes_read) = reader.read_line(&mut buf) {
            if bytes_read == 0 {
                break;
            }
            data.extend_from_slice(buf.as_bytes());
            // eprintln!("{}", buf);
            if buf.contains(&needle) {
                // Minor wait as what we are actually waiting for may come right
                // after the message being printed.
                std::thread::sleep(Duration::from_millis(10));
                break;
            }
            buf.clear();
        }
        (reader, data)
    });

    reader_thread
}

fn wrap_stdout(child: &mut Child) -> BufReader<PipeReader> {
    BufReader::new(PipeReader::from(OwnedFd::from(
        child.stdout.take().unwrap(),
    )))
}

enum TestState {
    Running {
        reader: BufReader<PipeReader>,
    },
    BackgroundThread {
        handle: JoinHandle<(BufReader<PipeReader>, Vec<u8>)>,
    },
}
struct PinchyTest {
    child: Child,
    data: Vec<u8>,
    state: TestState,
}

impl PinchyTest {
    fn new(pid: Option<u32>, first_needle: Option<String>) -> Self {
        ensure_root();
        ensure_dbus_env();

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(wait_for_name_to_disappear(
                "org.pinchy.Service",
                Duration::from_secs(10),
            ));
        assert!(result.is_ok());

        let mut child = run_pinchyd(pid);

        // Wait synchronously for startup
        let reader = wrap_stdout(&mut child);
        let (reader, data) = read_until(reader, "Waiting for Ctrl-C...".to_string())
            .join()
            .unwrap();

        let state = if let Some(needle) = first_needle {
            let handle = read_until(reader, needle);
            TestState::BackgroundThread { handle }
        } else {
            TestState::Running { reader }
        };

        // Wait for name to show up in the bus before we go forward.
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(wait_for_name("org.pinchy.Service", Duration::from_secs(1)));
        assert!(result.is_ok());

        PinchyTest { child, data, state }
    }

    fn get_pid(&self) -> u32 {
        self.child.id()
    }

    fn wait(mut self) -> Output {
        if let TestState::BackgroundThread { handle } = self.state {
            let (reader, more_data) = handle.join().unwrap();
            self.data.extend_from_slice(&more_data);
            self.state = TestState::Running { reader };
        }

        // Now wait for the process to exit
        let TestState::Running { reader } = self.state else {
            unreachable!();
        };

        // Signal the child to exit and obtain the Output object
        let handle = read_until(reader, "Exiting...".to_string());

        let mut output = wait_for_output(self.child);

        let (reader, more_data) = handle.join().unwrap();
        self.data.extend_from_slice(&more_data);

        // Read the left-overs from the buffer just so it doesn't block trying to print something
        let _ = read_until(reader, "something unexpected!".to_string());

        output.stdout = self.data;

        output
    }
}

use once_cell::sync::Lazy;

extern "C" fn kill_dbus_daemon() {
    if let Ok(pid) = std::env::var("DBUS_SESSION_BUS_PID") {
        let pid: i32 = pid.parse().unwrap();
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
}

static DBUS_ENV: Lazy<()> = Lazy::new(|| {
    unsafe {
        libc::atexit(kill_dbus_daemon);
    }

    std::env::set_var("PINCHYD_USE_SESSION_BUS", "true");

    let output = Command::new("dbus-launch")
        .output()
        .expect("failed to run dbus-launch");
    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim_end_matches(';');
            eprintln!("Setting {key} to {value}");
            std::env::set_var(key, value);
        }
    }
});

fn ensure_dbus_env() {
    Lazy::force(&DBUS_ENV);
}

use std::convert::TryFrom;

use anyhow::bail;
use futures::StreamExt;
use zbus::{fdo::DBusProxy, names::BusName, Connection};

async fn wait_for_name_to_disappear(bus_name: &str, timeout: Duration) -> anyhow::Result<()> {
    let connection = Connection::session().await?;
    let proxy = DBusProxy::new(&connection).await?;

    let bus_name = BusName::try_from(bus_name)
        .map_err(|e| zbus::Error::Address(format!("Invalid bus name: {e}")))?;

    let start = Instant::now();
    loop {
        if !proxy.name_has_owner(bus_name.clone()).await? {
            return Ok(());
        }
        let _ = Command::new("pkill").arg("pinchyd").status();
        if start.elapsed() > timeout {
            break;
        }
    }

    bail!("Timeout waiting for name to be dropped")
}

async fn wait_for_name(bus_name: &str, timeout: Duration) -> anyhow::Result<()> {
    let connection = Connection::session().await?;
    let proxy = DBusProxy::new(&connection).await?;

    let bus_name = BusName::try_from(bus_name)
        .map_err(|e| zbus::Error::Address(format!("Invalid bus name: {e}")))?;

    if proxy.name_has_owner(bus_name.clone()).await? {
        return Ok(());
    }

    let mut stream = proxy.receive_name_owner_changed().await?;
    let start = Instant::now();
    while let Some(signal) = stream.next().await {
        let args = signal.args()?;
        if args.name == bus_name && !args.new_owner.is_none() {
            return Ok(());
        }
        if start.elapsed() > timeout {
            break;
        }
    }

    bail!("Time out waiting for Pinchyd to appear")
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
