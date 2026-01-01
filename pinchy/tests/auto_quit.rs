// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

mod common;

use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use assert_cmd::assert::Assert;
use common::PinchyTest;
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[serial]
#[ignore = "runs in special environment"]
fn auto_quit() {
    let pinchy = PinchyTest::new(
        None,
        Some("Pinchy has been idle for a while, shutting down".to_string()),
    );

    // We won't start any tracing, after a minute we should see this message.
    let now = Instant::now();

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
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!("pinchy"))
        //.env("RUST_LOG", "trace")
        .arg(assert_cmd::cargo::cargo_bin!("test-helper"))
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
