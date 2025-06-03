use std::borrow::Cow;

use pinchy_common::{syscalls::SYS_ppoll, SyscallEvent};
use tokio::io::AsyncWriteExt as _;

use crate::util::poll_bits_to_strs;

pub async fn handle_event(event: SyscallEvent) {
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
                "{} ppoll(fds: [{}], nfds = {}, timeout, sigmask) = {}\n",
                event.tid, fds, data.nfds, return_meaning
            )
        }
        _ => format!("{} unknown syscall {}\n", event.tid, event.syscall_nr),
    };

    let _ = tokio::io::stdout().write_all(output.as_bytes()).await;
}
