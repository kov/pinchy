// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::{
    convert::TryFrom,
    io::{BufRead as _, BufReader, PipeReader},
    process::{self, Child, Command, Output},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::bail;
use assert_cmd::cargo::cargo_bin;
use futures::StreamExt;
use once_cell::sync::Lazy;
use zbus::{fdo::DBusProxy, names::BusName, Connection};

pub fn run_pinchyd(pid: Option<u32>) -> (PipeReader, Child) {
    let mut cmd = process::Command::new(cargo_bin("pinchyd"));

    let (reader, writer) = std::io::pipe().unwrap();

    let mut cmd = cmd
        //.env("RUST_LOG", "trace")
        .stdout(writer.try_clone().unwrap())
        .stderr(writer);

    if let Some(pid) = pid {
        cmd = cmd.arg(pid.to_string())
    }

    let child = cmd.spawn().unwrap_or_else(|e| {
        panic!("Failed to run pinchyd process under dbus-launch for testing: {e}")
    });

    (reader, child)
}

pub fn wait_for_output(child: Child) -> Output {
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };

    child.wait_with_output().unwrap()
}

pub fn ensure_root() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "Need to run test as root (using, for instance, cargo sudo)"
    );
}

pub fn read_until(
    mut reader: BufReader<PipeReader>,
    needle: String,
) -> JoinHandle<(BufReader<PipeReader>, Vec<u8>)> {
    let reader_thread = std::thread::spawn(move || {
        let mut data = vec![];
        let mut buf = String::new();
        let mut found_error = false;
        while let Ok(bytes_read) = reader.read_line(&mut buf) {
            if bytes_read == 0 {
                break;
            }
            data.extend_from_slice(buf.as_bytes());

            eprint!("{}", buf);

            if buf.contains("Caused by:")
                || buf.contains("Stack backtrace")
                || buf.contains(" panicked at ")
            {
                found_error = true;
            }

            if buf.contains(&needle) {
                // Minor wait as what we are actually waiting for may come right
                // after the message being printed.
                std::thread::sleep(Duration::from_millis(10));
                break;
            }
            buf.clear();
        }
        if found_error {
            panic!("Found fatal error in pinchyd output");
        }
        (reader, data)
    });

    reader_thread
}

pub fn wrap_stdout(reader: PipeReader) -> BufReader<PipeReader> {
    BufReader::new(PipeReader::from(reader))
}

pub enum TestState {
    Running {
        reader: BufReader<PipeReader>,
    },
    BackgroundThread {
        handle: JoinHandle<(BufReader<PipeReader>, Vec<u8>)>,
    },
}

pub struct PinchyTest {
    child: Child,
    data: Vec<u8>,
    state: TestState,
}

impl PinchyTest {
    pub fn new(pid: Option<u32>, first_needle: Option<String>) -> Self {
        ensure_root();
        ensure_dbus_env();

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(wait_for_name_to_disappear(
                "org.pinchy.Service",
                Duration::from_secs(10),
            ));
        assert!(result.is_ok());

        let (reader, child) = run_pinchyd(pid);

        // Wait synchronously for startup
        let reader = wrap_stdout(reader);
        let (reader, data) = read_until(reader, "Waiting for Ctrl-C...".to_string())
            .join()
            .expect("pinchyd probably failed to run");

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

    #[allow(dead_code)] // This is not used in the auto_quit target.
    pub fn get_pid(&self) -> u32 {
        self.child.id()
    }

    pub fn wait(mut self) -> Output {
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

pub fn ensure_dbus_env() {
    Lazy::force(&DBUS_ENV);
}

pub async fn wait_for_name_to_disappear(bus_name: &str, timeout: Duration) -> anyhow::Result<()> {
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

pub async fn wait_for_name(bus_name: &str, timeout: Duration) -> anyhow::Result<()> {
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
