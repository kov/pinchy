use std::{
    ffi::c_void,
    io::{BufRead as _, BufReader, PipeReader},
    os::fd::OwnedFd,
    process::{self, Child, Output, Stdio},
    thread::JoinHandle,
    time::Duration,
};

use assert_cmd::{assert::Assert, cargo::cargo_bin};
use pinchy_common::DATA_READ_SIZE;
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[serial]
fn basic_output() {
    let pinchy = PinchyTest::new(None, None);
    let output = pinchy.wait();
    Assert::new(output)
        .success()
        .stdout(predicate::str::ends_with("Exiting...\n"));
}

#[test]
#[serial]
fn basic_reads() {
    // Wait for our marker close async
    let pinchy = PinchyTest::new(Some(process::id()), Some(format!("close(fd: 1042)")));

    // Run a workload
    let mut buf = vec![0u8; DATA_READ_SIZE];
    let fd = unsafe {
        let fd = libc::openat(libc::AT_FDCWD, c"/etc/os-release".as_ptr(), libc::O_RDONLY);
        let _ = libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len());
        libc::close(fd);
        fd
    };

    unsafe {
        libc::close(1042);
    } // marker close

    let output = pinchy.wait();

    Assert::new(output)
        .success()
        .stdout(predicate::str::contains(format!("openat(dfd: AT_FDCWD, pathname: \"/etc/os-release\", flags: 0x0 (O_RDONLY), mode: 0) = {fd}")))
        .stdout(predicate::str::contains(format!("read(fd: {fd}, buf: {:?}, count: 128) = 128", String::from_utf8(buf).unwrap())))
        .stdout(predicate::str::contains(format!("close(fd: {fd}) = 0")));
}

fn run_pinchyd(pid: Option<u32>) -> Child {
    let mut cmd = process::Command::new("/usr/bin/dbus-launch");
    let mut cmd = cmd
        .stdout(Stdio::piped())
        .env("PINCHYD_USE_SESSION_BUS", "true")
        //.env("RUST_LOG", "trace")
        .arg("--exit-with-session");

    cmd.arg(cargo_bin("pinchyd"));
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
            eprintln!("{}", buf);
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

        let mut child = run_pinchyd(pid);

        // Wait synchronously for startup
        let reader = wrap_stdout(&mut child);
        let (reader, data) = read_until(reader, format!("Waiting for Ctrl-C..."))
            .join()
            .unwrap();

        let state = if let Some(needle) = first_needle {
            let handle = read_until(reader, needle);
            TestState::BackgroundThread { handle }
        } else {
            TestState::Running { reader }
        };

        PinchyTest { child, data, state }
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
        let handle = read_until(reader, format!("Exiting..."));

        let mut output = wait_for_output(self.child);

        let (reader, more_data) = handle.join().unwrap();
        self.data.extend_from_slice(&more_data);

        // Read the left-overs from the buffer just so it doesn't block trying to print something
        let _ = read_until(reader, format!("something unexpected!"));

        output.stdout = self.data;

        output
    }
}
