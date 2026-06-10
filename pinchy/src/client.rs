// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#![allow(non_snake_case, non_upper_case_globals)]
use std::{ffi::OsString, io::IsTerminal, os::fd::OwnedFd, pin::Pin};

use anyhow::Result;
use clap::{CommandFactory as _, Parser};
use pinchy_common::{
    compact_payload_size, max_compact_payload_size,
    syscalls::{syscall_name_from_nr, syscall_nr_from_name, ALL_SYSCALLS, SYSCALL_ALIASES},
    WireEventHeader, WIRE_VERSION,
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
    fn trace_pid(
        &self,
        pid: u32,
        syscalls: Vec<i64>,
        follow_forks: bool,
    ) -> zbus::Result<zbus::zvariant::OwnedFd>;
}

const DEFAULT_STDOUT_FLUSH_BYTES: usize = 1;
const DEFAULT_NON_TTY_FLUSH_BYTES: usize = 65536;

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();

    for (i, ca) in a.iter().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;

        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { prev } else { prev + 1 };
            prev = row[j + 1];
            row[j + 1] = cost.min(prev + 1).min(row[j] + 1);
        }
    }

    row[b.len()]
}

fn closest_syscall_name(name: &str) -> Option<&'static str> {
    ALL_SYSCALLS
        .iter()
        .filter_map(|&nr| syscall_name_from_nr(nr))
        .chain(SYSCALL_ALIASES.iter().map(|&(alias, _)| alias))
        .map(|candidate| (levenshtein(name, candidate), candidate))
        .min()
        .filter(|&(distance, _)| distance <= 2)
        .map(|(_, candidate)| candidate)
}

fn parse_syscall_names(names: &[String]) -> Result<Vec<i64>, String> {
    let mut out = Vec::new();
    for name in names {
        // Accept strace's -e trace=name,name qualifier syntax.
        let name = name.strip_prefix("trace=").unwrap_or(name);

        match syscall_nr_from_name(name) {
            Some(nr) if ALL_SYSCALLS.contains(&nr) => out.push(nr),
            Some(_) => return Err(format!("Syscall '{name}' is not supported by this build")),
            None => {
                let mut msg = format!("Unknown syscall name: {name}.");

                if let Some(suggestion) = closest_syscall_name(name) {
                    msg.push_str(&format!(" Did you mean '{suggestion}'?"));
                }

                msg.push_str(" Run 'pinchy --list-syscalls' to see supported names.");
                return Err(msg);
            }
        }
    }
    Ok(out)
}

fn list_syscalls() {
    use std::io::Write as _;

    let mut names: Vec<&'static str> = ALL_SYSCALLS
        .iter()
        .filter_map(|&nr| syscall_name_from_nr(nr))
        .collect();
    names.sort_unstable();

    let mut out = std::io::stdout().lock();
    for name in names {
        if let Err(e) = writeln!(out, "{name}") {
            // Tolerate a closed pipe (e.g. `pinchy --list-syscalls | head`),
            // but surface real write failures.
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                return;
            }

            eprintln!("error writing syscall list: {e}");
            std::process::exit(1);
        }
    }
}

fn parse_stdout_flush_bytes() -> usize {
    std::env::var("PINCHY_STDOUT_FLUSH_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_STDOUT_FLUSH_BYTES)
}

fn low_latency_flush_enabled(sink_is_terminal: bool) -> bool {
    if let Ok(value) = std::env::var("PINCHY_LOW_LATENCY_FLUSH") {
        return value == "1" || value.eq_ignore_ascii_case("true");
    }

    sink_is_terminal
}

#[derive(Parser, Debug)]
#[command(author, version, about, trailing_var_arg = true)]
struct Args {
    /// Syscall(s) to trace (can be repeated or comma-separated). Supports aliases like 'sigaction' for 'rt_sigaction'.
    #[arg(short = 'e', long = "event", value_delimiter = ',', action = clap::ArgAction::Append)]
    syscalls: Vec<String>,

    /// Formatting style for trace output
    #[arg(long = "format", value_enum, default_value_t = FormattingStyle::default())]
    style: FormattingStyle,

    /// List the syscall names supported by this build and exit
    #[arg(long = "list-syscalls")]
    list_syscalls: bool,

    /// Follow forks: also trace child processes created by the tracee
    #[arg(short = 'f', long = "follow-forks")]
    follow_forks: bool,

    /// Write trace output to FILE instead of stderr
    #[arg(short = 'o', long = "output")]
    output: Option<std::path::PathBuf>,

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

    if args.list_syscalls {
        list_syscalls();
        return Ok(());
    }

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
        let (pid, fd) = pinchy_client::trace_child(command, syscalls, args.follow_forks).await;

        // Read everything there is to read, the server will close the write end
        // of the pipe
        relay_to_sink(fd, style, args.output).await?;

        pinchy_client::cleanup_and_quit(pid);
    } else if let Some(pid) = args.pid {
        let fd = pinchy_client::attach(pid, syscalls, args.follow_forks).await;

        relay_to_sink(fd, style, args.output).await?;
    } else {
        // Print clap's usage message to stderr and exit
        eprintln!("{}", Args::command().render_help());
        std::process::exit(2);
    };

    Ok(())
}

// Trace output goes to stderr by default (like strace), keeping the traced
// program's stdout clean, or to a file with -o.
async fn relay_to_sink(
    fd: OwnedFd,
    style: FormattingStyle,
    output: Option<std::path::PathBuf>,
) -> Result<()> {
    match output {
        Some(path) => {
            let file = tokio::fs::File::create(&path).await?;
            relay_trace(fd, style, file, false).await
        }
        None => {
            let is_terminal = std::io::stderr().is_terminal();
            relay_trace(fd, style, tokio::io::stderr(), is_terminal).await
        }
    }
}

async fn relay_trace<W: tokio::io::AsyncWrite + Unpin>(
    fd: OwnedFd,
    formatting_style: FormattingStyle,
    sink: W,
    sink_is_terminal: bool,
) -> Result<()> {
    let mut reader = tokio::io::BufReader::with_capacity(
        64 * 1024,
        tokio::fs::File::from(std::fs::File::from(fd)),
    );
    let mut sink = tokio::io::BufWriter::new(sink);
    let mut header_buf = [0u8; std::mem::size_of::<WireEventHeader>()];
    let mut payload = Vec::new();
    let max_payload_size = max_compact_payload_size();
    let low_latency_flush = low_latency_flush_enabled(sink_is_terminal);
    let flush_bytes = if low_latency_flush {
        parse_stdout_flush_bytes()
    } else {
        DEFAULT_NON_TTY_FLUSH_BYTES
    };
    let mut pending_flush_bytes = 0usize;

    let mut output: Vec<u8> = vec![];

    let read_result = loop {
        match reader.read_exact(&mut header_buf).await {
            Ok(_) => {
                let header: WireEventHeader = unsafe {
                    std::ptr::read_unaligned(header_buf.as_ptr() as *const WireEventHeader)
                };

                if header.version != WIRE_VERSION {
                    continue;
                }

                let payload_len = header.payload_len as usize;

                if payload_len > max_payload_size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "invalid payload_len {} (max {}) for syscall {}",
                            payload_len, max_payload_size, header.syscall_nr
                        ),
                    )
                    .into());
                }

                payload.resize(payload_len, 0);
                reader.read_exact(&mut payload).await?;

                // handle_event() reads the payload as a fixed-size struct;
                // a short payload would be an out-of-bounds read.
                if let Some(expected) = compact_payload_size(header.syscall_nr) {
                    if payload_len != expected {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "payload_len {} does not match expected {} for syscall {}",
                                payload_len, expected, header.syscall_nr
                            ),
                        )
                        .into());
                    }
                }

                output.clear();

                // Safety: we own the output vector and won't progress before handle_event() returns.
                let pin_output = unsafe { Pin::new_unchecked(&mut output) };
                let formatter = Formatter::new(pin_output, formatting_style);

                events::handle_event(&header, &payload, formatter).await?;

                sink.write_all(&output).await?;
                pending_flush_bytes += output.len();

                // Flush on threshold, but also whenever we have caught up
                // with the pipe (empty read buffer means the next read
                // would block); otherwise output lags behind a slow tracee
                // by up to the threshold.
                if pending_flush_bytes >= flush_bytes || reader.buffer().is_empty() {
                    sink.flush().await?;
                    pending_flush_bytes = 0;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break Ok(()),
            Err(e) => break Err(e.into()),
        }
    };
    sink.flush().await?;

    read_result
}
