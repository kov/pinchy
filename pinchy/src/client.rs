// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::{
    io::{Read as _, Write as _},
    os::fd::AsRawFd,
};

use clap::Parser;
use pinchy_common::syscalls::{syscall_nr_from_name, ALL_SUPPORTED_SYSCALLS};
use zbus::{names::WellKnownName, proxy, Connection};

#[proxy(interface = "org.pinchy.Service", default_path = "/org/pinchy/Service")]
trait Pinchy {
    fn trace_pid(&self, pid: u32, syscalls: Vec<i64>) -> zbus::Result<zbus::zvariant::OwnedFd>;
}

fn parse_syscall_names(names: &[String]) -> Result<Vec<i64>, String> {
    let mut out = Vec::new();
    for name in names {
        match syscall_nr_from_name(name) {
            Some(nr) if ALL_SUPPORTED_SYSCALLS.contains(&nr) => out.push(nr),
            Some(_) => return Err(format!("Syscall '{name}' is not supported by this build")),
            None => return Err(format!("Unknown syscall name: {name}")),
        }
    }
    Ok(out)
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Pinchy client: trace syscalls for a PID", long_about = None)]
struct Args {
    /// Syscall(s) to trace (can be repeated or comma-separated)
    #[arg(short = 'e', long = "event", value_delimiter = ',', num_args = 1, action = clap::ArgAction::Append)]
    syscalls: Vec<String>,

    /// PID to trace (must be the last argument)
    pid: u32,
}

#[tokio::main]
async fn main() -> zbus::Result<()> {
    let args = Args::parse();
    let syscalls = if !args.syscalls.is_empty() {
        match parse_syscall_names(&args.syscalls) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    } else {
        ALL_SUPPORTED_SYSCALLS.to_vec()
    };
    let connection = Connection::system().await?;
    let destination = WellKnownName::try_from("org.pinchy.Service").unwrap();
    let proxy = PinchyProxy::new(&connection, destination).await?;
    let pid = args.pid;
    println!("Syscalls to trace: {:?}", syscalls);

    let fd: std::os::fd::OwnedFd = proxy.trace_pid(pid, syscalls).await?.into();

    println!("Received file descriptor: {}", fd.as_raw_fd());

    let mut reader = std::fs::File::from(fd);
    let mut buf = [0u8; 4096];
    let mut stdout = std::io::stdout().lock();
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                stdout.write_all(&buf[..n])?;
            }
            Err(e) => {
                eprintln!("Read error: {e}");
                break;
            }
        }
    }

    Ok(())
}
