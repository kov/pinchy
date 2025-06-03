use std::{borrow::Cow, io::Write};

use log::trace;
use pinchy_common::{
    kernel_types::Timespec,
    syscalls::{SYS_epoll_pwait, SYS_ppoll, SYS_read},
    SyscallEvent,
};

use crate::util::poll_bits_to_strs;

pub async fn handle_event(event: SyscallEvent, ebpf: super::SharedEbpf, pipe_map: super::PipeMap) {
    trace!("handle_event for syscall {}", event.syscall_nr);
    let mut output = match event.syscall_nr {
        SYS_epoll_pwait => {
            let data = unsafe { event.data.epoll_pwait };
            let epoll_events =
                data.events
                    .iter()
                    .join_take_map(event.return_value as usize, |event| {
                        format!(
                            "{{events={}, data={:#x}}}",
                            poll_bits_to_strs(&(event.events as i16)).join("|"),
                            event.data
                        )
                    });

            format!(
                "{} epoll_pwait(epfd: {}, events: {}, max_events: {}, timeout: {}, sigmask) = {}",
                event.tid,
                data.epfd,
                epoll_events,
                data.max_events,
                data.timeout,
                event.return_value
            )
        }
        SYS_ppoll => {
            let data = unsafe { event.data.ppoll };

            let return_meaning = match event.return_value {
                0 => Cow::Borrowed("Timeout [0]"),
                -1 => Cow::Borrowed("Error [-1]"),
                _ => Cow::Owned(format!(
                    "{} ready -> [{}]",
                    data.nfds,
                    data.fds.iter().zip(data.revents.iter()).join_take_map(
                        data.nfds as usize,
                        |(fd, event)| format!("{fd} = {}", poll_bits_to_strs(event).join("|"))
                    )
                )),
            };

            let fds = data
                .fds
                .iter()
                .zip(data.events.iter())
                .join_take_map(data.nfds as usize, |(fd, event)| {
                    format!("{{{fd}, {}}}", poll_bits_to_strs(event).join("|"))
                });

            format!(
                "{} ppoll(fds: [{}], nfds: {}, timeout: {}, sigmask) = {}",
                event.tid,
                fds,
                data.nfds,
                format_timespec(data.timeout),
                return_meaning
            )
        }
        SYS_read => {
            let data = unsafe { event.data.read };
            let bytes_read = event.return_value as usize;
            let buf = &data.buf[..bytes_read.min(data.buf.len())];

            let left_over = if event.return_value as usize > buf.len() {
                format!(
                    " ... ({} more bytes)",
                    event.return_value as usize - buf.len()
                )
            } else {
                String::new()
            };

            format!(
                "{} read(fd: {}, buf: {}{}, count: {}) = {}",
                event.tid,
                data.fd,
                format_bytes(&buf),
                left_over,
                data.count,
                event.return_value
            )
        }
        _ => format!("{} unknown syscall {}", event.tid, event.syscall_nr),
    };

    // Add a final new line.
    output.push('\n');

    // Spawn as a separate task so we do not hold up reading and processing of new events while
    // writing this lot.
    tokio::spawn(async move {
        let mut map = pipe_map.lock().await;
        match map.get_mut(&event.pid) {
            Some(writers) => {
                let mut keep = Vec::with_capacity(writers.len());

                for w in writers.iter_mut() {
                    if let Err(_err) = w
                        .writable_mut()
                        .await
                        .unwrap()
                        .get_inner_mut()
                        .write_all(output.as_bytes())
                    {
                        keep.push(false);
                    } else {
                        keep.push(true);
                    }
                }

                // Remove any writers that had errors.
                let mut keep_iter = keep.iter();
                writers.retain(|_| *keep_iter.next().unwrap());

                if writers.is_empty() {
                    if let Err(e) = super::remove_pid_trace(&ebpf, event.pid).await {
                        log::error!(
                            "Failed to remove PID {} from eBPF filter map: {}",
                            event.pid,
                            e.to_string()
                        );
                    }
                    log::trace!("No more writers for PID {}", event.pid);
                }
            }
            None => {
                eprintln!("Unexpected: do not have writers for PID, but still monitoring it...")
            }
        }
    });
}

fn format_timespec(timespec: Timespec) -> String {
    format!(
        "{{ secs: {}, nanos: {} }}",
        timespec.seconds, timespec.nanos
    )
}

fn format_bytes(bytes: &[u8]) -> String {
    if let Ok(s) = str::from_utf8(bytes) {
        format!("{:?}", s)
    } else {
        bytes
            .iter()
            .map(|b| format!("{:>2x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

trait JoinTakeMap: Iterator + Sized {
    fn join_take_map<F>(self, n: usize, f: F) -> String
    where
        F: FnMut(Self::Item) -> String,
    {
        self.take(n).map(f).collect::<Vec<_>>().join(", ")
    }
}

impl<I: Iterator> JoinTakeMap for I {}
