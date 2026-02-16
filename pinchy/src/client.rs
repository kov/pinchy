// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#![allow(non_snake_case, non_upper_case_globals)]
use std::{ffi::OsString, os::fd::OwnedFd, pin::Pin};

use anyhow::Result;
use clap::{CommandFactory as _, Parser};
use pinchy_common::{
    syscalls::{syscall_nr_from_name, ALL_SYSCALLS},
    SyscallEvent, WireEventHeader, WIRE_KIND_COMPACT_SYSCALL_EVENT, WIRE_KIND_LEGACY_SYSCALL_EVENT,
    WIRE_VERSION,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zbus::proxy;

use crate::formatting::{Formatter, FormattingStyle};

mod events;
mod format_helpers;
mod formatting;
mod ioctls;

#[cfg(test)]
mod tests;

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
    /// Syscall(s) to trace (can be repeated or comma-separated). Supports aliases like 'sigaction' for 'rt_sigaction'.
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

    if let Some(command) = args.command {
        let (pid, fd) = pinchy_client::trace_child(command, syscalls).await;

        // Read everything there is to read, the server will close the write end
        // of the pipe
        relay_trace(fd, style).await?;

        pinchy_client::cleanup_and_quit(pid);
    } else if let Some(pid) = args.pid {
        let fd = pinchy_client::attach(pid, syscalls).await;

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
    let mut header_buf = vec![0u8; std::mem::size_of::<WireEventHeader>()];

    let mut output: Vec<u8> = vec![];
    loop {
        match reader.read_exact(&mut header_buf).await {
            Ok(_) => {
                let header: WireEventHeader = unsafe {
                    std::ptr::read_unaligned(header_buf.as_ptr() as *const WireEventHeader)
                };

                if header.version != WIRE_VERSION {
                    continue;
                }

                let mut payload = vec![0u8; header.payload_len as usize];
                reader.read_exact(&mut payload).await?;

                output.clear();

                // Safety: we own the output vector and won't progress before handle_event() returns.
                let pin_output = unsafe { Pin::new_unchecked(&mut output) };
                let formatter = Formatter::new(pin_output, formatting_style.clone());

                if is_compact_event_kind(header.kind) {
                    if !events::handle_compact_event(&header, &payload, formatter).await? {
                        continue;
                    }
                } else {
                    let event = match decode_event(&header, &payload) {
                        Some(event) => event,
                        None => continue,
                    };

                    events::handle_event(&event, formatter).await?;
                }

                stdout.write_all(&output).await?;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(stdout.flush().await?)
}

fn is_compact_event_kind(kind: u16) -> bool {
    kind == WIRE_KIND_COMPACT_SYSCALL_EVENT
}

fn decode_event(header: &WireEventHeader, payload: &[u8]) -> Option<SyscallEvent> {
    match header.kind {
        WIRE_KIND_LEGACY_SYSCALL_EVENT => {
            if payload.len() != std::mem::size_of::<SyscallEvent>() {
                return None;
            }

            Some(unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const SyscallEvent) })
        }

        _ => None,
    }
}
