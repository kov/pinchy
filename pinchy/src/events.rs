use std::{borrow::Cow, io::Write};

use pinchy_common::{syscalls::SYS_ppoll, SyscallEvent};

use crate::util::poll_bits_to_strs;

pub async fn handle_event(event: SyscallEvent, pipe_map: super::PipeMap) {
    let output = match event.syscall_nr {
        SYS_ppoll => {
            let data = unsafe { event.data.ppoll };

            let return_meaning = match event.return_value {
                0 => Cow::Borrowed("Timeout [0]"),
                -1 => Cow::Borrowed("Error [-1]"),
                _ => Cow::Owned(format!(
                    "{} ready -> [{}]",
                    data.nfds,
                    data.fds
                        .iter()
                        .zip(data.revents.iter())
                        .take(data.nfds as usize)
                        .map(|(fd, event)| format!("{fd} = {}", poll_bits_to_strs(event).join("|")))
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            };

            let fds = data
                .fds
                .iter()
                .zip(data.events.iter())
                .take(data.nfds as usize)
                .map(|(fd, event)| format!("{{{fd}, {}}}", poll_bits_to_strs(event).join("|")))
                .collect::<Vec<_>>()
                .join(", ");

            format!(
                "{} ppoll(fds: [{}], nfds: {}, timeout: {{ secs: {}, nanos: {} }}, sigmask) = {}\n",
                event.tid, fds, data.nfds, data.timeout.seconds, data.timeout.nanos, return_meaning
            )
        }
        _ => format!("{} unknown syscall {}\n", event.tid, event.syscall_nr),
    };

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

                // FIXME: need a way to let the tracer know that we no longer care about this PID.
                if writers.is_empty() {
                    eprintln!("No more writers for PID {}", event.pid);
                }
            }
            None => {
                eprintln!("Unexpected: do not have writers for PID, but still monitoring it...")
            }
        }
    });
}
