// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#![allow(non_snake_case, non_upper_case_globals)]
use std::{
    ffi::{c_char, CString, OsString},
    os::{fd::OwnedFd, unix::ffi::OsStrExt},
    pin::Pin,
};

use anyhow::Result;
use clap::{CommandFactory as _, Parser};
use log::trace;
use pinchy_common::syscalls::{syscall_nr_from_name, ALL_SYSCALLS};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zbus::{fdo, names::WellKnownName, proxy, Error as ZBusError};

use crate::formatting::{Formatter, FormattingStyle};

mod events;
mod formatting;
mod ioctls;
mod util;

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
#[command(author, version, about, trailing_var_arg = true)]
struct Args {
    /// Syscall(s) to trace (can be repeated or comma-separated)
    #[arg(short = 'e', long = "event", value_delimiter = ',', action = clap::ArgAction::Append)]
    syscalls: Vec<String>,

    // Formatting style, `one-line` or `multi-line`
    #[arg(long = "format", value_enum, default_value_t = FormattingStyle::default())]
    style: FormattingStyle,

    /// PID to trace
    #[arg(short = 'p', long = "pid", action = clap::ArgAction::Set, conflicts_with = "command")]
    pid: Option<u32>,

    /// Command to run and its arguments
    #[arg(conflicts_with = "pid")]
    command: Option<Vec<OsString>>,
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

    let style = args.style;

    // Handle D-Bus connection with proper error handling

    let (conn, bus_type) = match std::env::var("PINCHYD_USE_SESSION_BUS") {
        Ok(value) if value == "true" => (zbus::Connection::session().await, "session"),
        _ => (zbus::Connection::system().await, "system"),
    };

    let connection = match conn {
        Ok(conn) => conn,
        Err(e) => handle_dbus_error(e),
    };

    trace!("Connected to {bus_type} bus");

    let destination = WellKnownName::try_from("org.pinchy.Service").unwrap();

    // Handle proxy creation with proper error handling
    let proxy = match PinchyProxy::new(&connection, destination).await {
        Ok(proxy) => proxy,
        Err(e) => handle_dbus_error(e),
    };

    if let Some(command) = args.command {
        let command: Vec<CString> = command
            .into_iter()
            .map(|s| CString::new(s.as_bytes()).unwrap())
            .collect();
        let mut argv: Vec<*const c_char> = command
            .iter()
            .map(|s| s.as_ptr() as *const c_char)
            .collect();
        argv.push(std::ptr::null());

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            eprintln!(
                "Failed to fork a new process: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(1);
        }
        if pid == 0 {
            unsafe {
                // Wait for a signal before we exec
                libc::raise(libc::SIGSTOP);
                let result = libc::execvp(command[0].as_ptr(), argv.as_ptr());
                std::process::exit(result);
            }
        }

        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, libc::WUNTRACED);
            if !libc::WIFSTOPPED(status) {
                eprintln!("Child process did not stop as expected (status: {status:#x})");
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    std::process::exit(128 + libc::WTERMSIG(status));
                }
                std::process::exit(1);
            }
        }
        let fd = match proxy.trace_pid(pid as u32, syscalls).await {
            Ok(fd) => fd.into(),
            Err(e) => handle_dbus_error(e),
        };

        // Signal we can exec the child
        unsafe {
            libc::kill(pid, libc::SIGCONT);
        }

        // Read everything there is to read, the server will close the write end
        // of the pipe
        relay_trace(fd, style).await?;

        unsafe {
            libc::waitpid(pid, &mut status, libc::WUNTRACED);
            if libc::WIFEXITED(status) {
                std::process::exit(libc::WEXITSTATUS(status));
            } else if libc::WIFSIGNALED(status) {
                std::process::exit(128 + libc::WTERMSIG(status));
            }
            std::process::exit(1);
        }
    } else if let Some(pid) = args.pid {
        let fd = match proxy.trace_pid(pid, syscalls).await {
            Ok(fd) => fd.into(),
            Err(e) => handle_dbus_error(e),
        };
        relay_trace(fd, style).await?;
    } else {
        // Print clap's usage message and exit
        Args::command().print_help().expect("Failed to print usage");
        println!();
        std::process::exit(2);
    };

    Ok(())
}

async fn relay_trace(fd: OwnedFd, formatting_style: FormattingStyle) -> Result<()> {
    let mut reader = tokio::io::BufReader::new(tokio::fs::File::from(std::fs::File::from(fd)));
    let mut stdout = tokio::io::BufWriter::new(tokio::io::stdout());
    let mut buf = vec![0u8; std::mem::size_of::<pinchy_common::SyscallEvent>()];

    let mut output: Vec<u8> = vec![];
    loop {
        match reader.read_exact(&mut buf).await {
            Ok(_) => {
                let event: pinchy_common::SyscallEvent =
                    unsafe { std::ptr::read(buf.as_ptr() as *const pinchy_common::SyscallEvent) };

                output.clear();

                // Safety: we own the output vector and won't progress before handle_event() returns.
                let pin_output = unsafe { Pin::new_unchecked(&mut output) };
                let formatter = Formatter::new(pin_output, formatting_style.clone());

                let string_output = events::handle_event(&event, formatter).await?;
                // stdout.write_all(&output).await?;
                stdout.write_all(string_output.as_bytes()).await?;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(stdout.flush().await?)
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
