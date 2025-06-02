use std::borrow::Cow;

use pinchy_common::{syscalls::SYS_ppoll, SyscallEvent};
use tokio::io::AsyncWriteExt as _;

fn poll_bits_to_strs(event: &i16) -> Vec<&'static str> {
    let mut strs = vec![];

    if event & libc::POLLIN != 0 {
        strs.push("POLLIN");
    }

    if event & libc::POLLPRI != 0 {
        strs.push("POLLPRI");
    }

    if event & libc::POLLOUT != 0 {
        strs.push("POLLOUT");
    }

    if event & libc::POLLRDHUP != 0 {
        strs.push("POLLRDHUP");
    }

    if event & libc::POLLERR != 0 {
        strs.push("POLLERR");
    }

    if event & libc::POLLHUP != 0 {
        strs.push("POLLHUP");
    }

    if event & libc::POLLNVAL != 0 {
        strs.push("POLLNVAL");
    }

    if event & libc::POLLRDNORM != 0 {
        strs.push("POLLRDNORM");
    }

    if event & libc::POLLRDBAND != 0 {
        strs.push("POLLRDBAND");
    }

    if event & libc::POLLWRNORM != 0 {
        strs.push("POLLWRNORM");
    }

    if event & libc::POLLWRBAND != 0 {
        strs.push("POLLWRBAND");
    }

    strs
}

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
