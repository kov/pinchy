use std::borrow::Cow;

use log::trace;
use pinchy_common::{
    kernel_types::Timespec,
    syscalls::{
        SYS_close, SYS_epoll_pwait, SYS_futex, SYS_ioctl, SYS_lseek, SYS_openat, SYS_ppoll,
        SYS_read, SYS_sched_yield,
    },
    SyscallEvent,
};

use crate::util::poll_bits_to_strs;

pub async fn handle_event(event: &SyscallEvent) -> String {
    trace!("handle_event for syscall {}", event.syscall_nr);
    let mut output = match event.syscall_nr {
        SYS_close => {
            let data = unsafe { event.data.close };
            format!(
                "{} close(fd: {}) = {}",
                event.tid, data.fd, event.return_value
            )
        }
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
        SYS_lseek => {
            let data = unsafe { event.data.lseek };
            format!(
                "{} lseek(fd: {}, offset: {}, whence: {}) = {}",
                event.tid, data.fd, data.offset, data.whence, event.return_value
            )
        }
        SYS_sched_yield => {
            format!("{} sched_yield() = {}", event.tid, event.return_value)
        }
        SYS_openat => {
            use std::ffi::CStr;
            let data = unsafe { event.data.openat };
            let pathname = CStr::from_bytes_until_nul(&data.pathname)
                .unwrap_or(CStr::from_bytes_with_nul(b"<invalid>\0").unwrap());
            format!(
                "{} openat(dfd: {}, pathname: {:?}, flags: {}, mode: {}) = {}",
                event.tid,
                format_dirfd(data.dfd),
                pathname,
                format_flags(data.flags),
                format_mode(data.mode),
                event.return_value
            )
        }
        SYS_futex => {
            let data = unsafe { event.data.futex };
            format!(
                "{} futex(uaddr: 0x{:x}, op: {}, val: {}, uaddr2: 0x{:x}, val3: {}, timeout: {}) = {}",
                event.tid, data.uaddr, data.op, data.val, data.uaddr2, data.val3, format_timespec(data.timeout), event.return_value
            )
        }
        SYS_ioctl => {
            let data = unsafe { event.data.ioctl };
            let request = format_ioctl_request(data.request);
            format!(
                "{} ioctl(fd: {}, request: {}::{}, arg: 0x{:x}) = {}",
                event.tid, data.fd, request.0, request.1, data.arg, event.return_value
            )
        }
        _ => format!("{} unknown syscall {}", event.tid, event.syscall_nr),
    };

    // Add a final new line.
    output.push('\n');

    output
}

fn format_ioctl_request(request: u32) -> (&'static str, &'static str) {
    include!("ioctls-match.rsinc")
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

fn format_dirfd(dfd: i32) -> String {
    const AT_FDCWD: i32 = -100;
    if dfd == AT_FDCWD {
        "AT_FDCWD".to_string()
    } else {
        dfd.to_string()
    }
}

fn format_mode(mode: u32) -> String {
    // Only show if nonzero (O_CREAT was used)
    if mode == 0 {
        return "0".to_string();
    }
    // Show as octal and symbolic (e.g. rwxr-xr-x)
    let mut s = format!("0o{:03o}", mode & 0o777);
    s.push_str(" (");
    let perms = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    for (bit, chr) in perms.iter() {
        s.push(if (mode & bit) != 0 { *chr } else { '-' });
    }
    s.push(')');
    s
}

fn format_flags(flags: i32) -> String {
    // Access mode (lowest two bits)
    let access = match flags & 0b11 {
        0 => "O_RDONLY",
        1 => "O_WRONLY",
        2 => "O_RDWR",
        _ => "<invalid>",
    };
    let mut parts = vec![access.to_string()];
    // Common open(2) flags
    let flag_defs = [
        (libc::O_CREAT, "O_CREAT"),
        (libc::O_EXCL, "O_EXCL"),
        (libc::O_NOCTTY, "O_NOCTTY"),
        (libc::O_TRUNC, "O_TRUNC"),
        (libc::O_APPEND, "O_APPEND"),
        (libc::O_NONBLOCK, "O_NONBLOCK"),
        (libc::O_SYNC, "O_SYNC"),
        (libc::O_DSYNC, "O_DSYNC"),
        (libc::O_RSYNC, "O_RSYNC"),
        (libc::O_DIRECTORY, "O_DIRECTORY"),
        (libc::O_NOFOLLOW, "O_NOFOLLOW"),
        (libc::O_CLOEXEC, "O_CLOEXEC"),
        (libc::O_ASYNC, "O_ASYNC"),
        (libc::O_LARGEFILE, "O_LARGEFILE"),
        (libc::O_DIRECT, "O_DIRECT"),
        (libc::O_TMPFILE, "O_TMPFILE"),
        (libc::O_PATH, "O_PATH"),
        (libc::O_NDELAY, "O_NDELAY"), // alias for O_NONBLOCK
        (libc::O_NOATIME, "O_NOATIME"),
    ];
    for (bit, name) in flag_defs.iter() {
        if (flags as u32) & (*bit as u32) != 0 {
            parts.push(name.to_string());
        }
    }
    format!("0x{:x} ({})", flags, parts.join("|"))
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
