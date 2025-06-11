// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::{
    io::{Read as _, Write as _},
    os::fd::AsRawFd,
};

use anyhow::Result;
use clap::Parser;
use log::trace;
use pinchy_common::syscalls::{syscall_nr_from_name, ALL_SYSCALLS};
use zbus::{fdo, names::WellKnownName, proxy, Connection, Error as ZBusError};

#[proxy(interface = "org.pinchy.Service", default_path = "/org/pinchy/Service")]
trait Pinchy {
    fn trace_pid(&self, pid: u32, syscalls: Vec<i64>) -> zbus::Result<zbus::zvariant::OwnedFd>;
}

fn parse_syscall_names(names: &[String]) -> Result<Vec<i64>, String> {
    let mut out = Vec::new();
    for name in names {
        match syscall_nr_from_name(name) {
            Some(nr) if ALL_SYSCALLS.contains(&nr) => out.push(nr),
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
async fn main() -> Result<()> {
    env_logger::init();

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
        ALL_SYSCALLS.to_vec()
    };

    // Handle D-Bus connection with proper error handling
    let connection = match Connection::system().await {
        Ok(conn) => conn,
        Err(e) => handle_dbus_error(e),
    };

    let destination = WellKnownName::try_from("org.pinchy.Service").unwrap();

    // Handle proxy creation with proper error handling
    let proxy = match PinchyProxy::new(&connection, destination).await {
        Ok(proxy) => proxy,
        Err(e) => handle_dbus_error(e),
    };

    let pid = args.pid;

    trace!("Syscalls to trace: {:?}", syscalls);

    // Handle method call with proper error handling
    let fd: std::os::fd::OwnedFd = match proxy.trace_pid(pid, syscalls).await {
        Ok(fd) => fd.into(),
        Err(e) => handle_dbus_error(e),
    };

    trace!(
        "Received file descriptor from dbus service: {}",
        fd.as_raw_fd()
    );

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

fn handle_dbus_error(error: ZBusError) -> ! {
    match error {
        // Connection-related errors
        ZBusError::InputOutput(io_err) => {
            eprintln!("Failed to connect to D-Bus: {}", io_err);
            eprintln!("Make sure the D-Bus system bus is running and accessible.");
            std::process::exit(2);
        }
        ZBusError::Address(addr) => {
            eprintln!("Invalid D-Bus address: {}", addr);
            eprintln!("The D-Bus system bus address may be misconfigured.");
            std::process::exit(2);
        }
        ZBusError::Handshake(msg) => {
            eprintln!("D-Bus authentication failed: {}", msg);
            eprintln!("You may not have permission to access the system D-Bus.");
            std::process::exit(2);
        }

        // Service-related errors
        ZBusError::MethodError(error_name, description, _) => match error_name.as_str() {
            "org.freedesktop.DBus.Error.ServiceUnknown" => {
                eprintln!("Pinchy service is not running.");
                eprintln!("Please start the pinchyd daemon first.");
                std::process::exit(3);
            }
            "org.freedesktop.DBus.Error.AccessDenied" | "org.freedesktop.DBus.Error.AuthFailed" => {
                eprintln!("Permission denied: You don't have access to trace this process.");
                eprintln!("Make sure you own the process or run with appropriate privileges.");
                std::process::exit(4);
            }
            "org.freedesktop.DBus.Error.NoReply" | "org.freedesktop.DBus.Error.TimedOut" => {
                eprintln!("Timeout: The pinchy service didn't respond in time.");
                eprintln!("The service may be overloaded or the process may not exist.");
                std::process::exit(5);
            }
            "org.freedesktop.DBus.Error.InvalidArgs" => {
                if let Some(desc) = description {
                    eprintln!("Invalid arguments: {}", desc);
                } else {
                    eprintln!("Invalid arguments provided to the pinchy service.");
                }
                std::process::exit(6);
            }
            _ => {
                eprintln!("D-Bus method call failed: {}", error_name);
                if let Some(desc) = description {
                    eprintln!("Details: {}", desc);
                }
                std::process::exit(7);
            }
        },

        // Proxy/Interface errors
        ZBusError::InterfaceNotFound => {
            eprintln!("Pinchy service interface not found.");
            eprintln!("The running pinchyd may be incompatible with this client version.");
            std::process::exit(8);
        }

        // FDO standard errors
        ZBusError::FDO(fdo_error) => match *fdo_error {
            fdo::Error::ServiceUnknown(_) => {
                eprintln!("Pinchy service is not running.");
                eprintln!("Please start the pinchyd daemon first.");
                std::process::exit(3);
            }
            fdo::Error::AccessDenied(_) | fdo::Error::AuthFailed(_) => {
                eprintln!("Permission denied: You don't have access to trace this process.");
                eprintln!("Make sure you own the process or run with appropriate privileges.");
                std::process::exit(4);
            }
            fdo::Error::NoReply(_) | fdo::Error::TimedOut(_) => {
                eprintln!("Timeout: The pinchy service didn't respond in time.");
                eprintln!("The service may be overloaded or the process may not exist.");
                std::process::exit(5);
            }
            fdo::Error::InvalidArgs(ref msg) => {
                eprintln!("Invalid arguments: {}", msg);
                std::process::exit(6);
            }
            fdo::Error::UnknownMethod(ref msg) => {
                eprintln!("Method not supported: {}", msg);
                eprintln!("The running pinchyd may be incompatible with this client version.");
                std::process::exit(8);
            }
            _ => {
                eprintln!("D-Bus error: {}", fdo_error);
                std::process::exit(7);
            }
        },

        // Generic/Other errors
        _ => {
            eprintln!("Unexpected D-Bus error: {}", error);
            std::process::exit(1);
        }
    }
}
