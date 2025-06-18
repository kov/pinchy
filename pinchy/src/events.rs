// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::borrow::Cow;

use log::trace;
use pinchy_common::{
    kernel_types::{Stat, Timespec},
    syscalls::{
        syscall_name_from_nr, SYS_brk, SYS_close, SYS_epoll_pwait, SYS_execve, SYS_fstat,
        SYS_futex, SYS_getdents64, SYS_ioctl, SYS_lseek, SYS_mmap, SYS_mprotect, SYS_munmap,
        SYS_openat, SYS_ppoll, SYS_read, SYS_sched_yield, SYS_write,
    },
    SyscallEvent,
};

use crate::{ioctls::format_ioctl_request, util::poll_bits_to_strs};

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
                            "{{ events={}, data={:#x} }}",
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
                    format!("{{ {fd}, {} }}", poll_bits_to_strs(event).join("|"))
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
        SYS_write => {
            let data = unsafe { event.data.write };
            let bytes_written = event.return_value as usize;
            let buf = &data.buf[..bytes_written.min(data.buf.len())];

            let left_over = if event.return_value as usize > buf.len() {
                format!(
                    " ... ({} more bytes)",
                    event.return_value as usize - buf.len()
                )
            } else {
                String::new()
            };

            format!(
                "{} write(fd: {}, buf: {}{}, count: {}) = {}",
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
        SYS_execve => {
            use std::{ffi::OsString, os::unix::ffi::OsStringExt};
            let data = unsafe { event.data.execve };

            // Format filename, showing ... if truncated
            let filename = {
                let nul_pos = data
                    .filename
                    .iter()
                    .position(|&b| b == b'\0')
                    .unwrap_or_else(|| data.filename.len());
                let s = OsString::from_vec(data.filename[..nul_pos].to_vec());
                if data.filename_truncated {
                    // Truncated: no nul byte among the ones we read
                    format!("{:?} ... (truncated)", s)
                } else {
                    format!("{:?}", s)
                }
            };

            // Format argv, skipping empty slots and showing ... if truncated
            let argc = data.argc as usize;
            let argv = data
                .argv
                .iter()
                .zip(data.argv_len.iter())
                .take(argc)
                .map(|(arg, &len)| {
                    OsString::from_vec(arg[..(len as usize)].to_vec())
                        .to_string_lossy()
                        .into_owned()
                })
                .collect::<Vec<_>>();
            let argv_trunc = if argc > data.argv.len() {
                format!(", ... ({} more)", argc - data.argv.len())
            } else {
                String::new()
            };
            let argv_str = argv.join(", ") + &argv_trunc;

            // Format envp, skipping empty slots and showing ... if truncated
            let envc = data.envc as usize;
            let envp = data
                .envp
                .iter()
                .zip(data.envp_len.iter())
                .take(envc)
                .map(|(env, &len)| {
                    OsString::from_vec(env[..(len as usize)].to_vec())
                        .to_string_lossy()
                        .into_owned()
                })
                .collect::<Vec<_>>();
            let envp_trunc = if envc > data.envp.len() {
                format!(", ... ({} more)", envc - data.envp.len())
            } else {
                String::new()
            };
            let envp_str = envp.join(", ") + &envp_trunc;
            format!(
                "{} execve(filename: {}, argv: [{}], envp: [{}]) = {}",
                event.tid, filename, argv_str, envp_str, event.return_value
            )
        }
        SYS_fstat => {
            let data = unsafe { event.data.fstat };
            format!(
                "{} fstat(fd: {}, struct stat: {}) = {}",
                event.tid,
                data.fd,
                format_stat(&data.stat),
                event.return_value
            )
        }
        SYS_getdents64 => {
            let data = unsafe { event.data.getdents64 };
            let mut entries = Vec::new();
            for dirent in data.dirents.iter().take(data.num_dirents as usize) {
                let (name_end, truncated) = match dirent.d_name.iter().position(|&b| b == 0) {
                    Some(pos) => (pos, false),
                    None => (dirent.d_name.len(), true),
                };

                let mut d_name = format!(
                    "\"{}\"",
                    String::from_utf8_lossy(&dirent.d_name[..name_end])
                );
                if truncated {
                    d_name.push_str(" ... (truncated)");
                }

                entries.push(format!(
                    "{{ ino: {}, off: {}, reclen: {}, type: {}, name: {} }}",
                    dirent.d_ino, dirent.d_off, dirent.d_reclen, dirent.d_type, d_name
                ));
            }
            format!(
                "{} getdents64(fd: {}, count: {}, entries: [{}]) = {}",
                event.tid,
                data.fd,
                data.count,
                entries.join(", "),
                event.return_value
            )
        }
        SYS_mmap => {
            let data = unsafe { event.data.mmap };
            let ret_str = if event.return_value == -1 {
                "-1 (error)".to_string()
            } else {
                format!("0x{:x}", event.return_value as usize)
            };
            format!(
                "{} mmap(addr: 0x{:x}, length: {}, prot: {}, flags: {}, fd: {}, offset: 0x{:x}) = {}",
                event.tid,
                data.addr,
                data.length,
                format_mmap_prot(data.prot),
                format_mmap_flags(data.flags),
                data.fd,
                data.offset,
                ret_str
            )
        }
        SYS_munmap => {
            let data = unsafe { event.data.munmap };
            format!(
                "{} munmap(addr: 0x{:x}, length: {}) = {}",
                event.tid, data.addr, data.length, event.return_value
            )
        }
        SYS_mprotect => {
            let data = unsafe { event.data.mprotect };
            format!(
                "{} mprotect(addr: 0x{:x}, length: {}, prot: {}) = {}",
                event.tid,
                data.addr,
                data.length,
                format_mmap_prot(data.prot),
                event.return_value
            )
        }
        SYS_brk => {
            let data = unsafe { event.data.brk };
            format!(
                "{} brk(addr: 0x{:x}) = 0x{:x}",
                event.tid, data.addr, event.return_value
            )
        }
        _ => {
            // Check if this is a generic syscall with raw arguments
            if let Some(name) = syscall_name_from_nr(event.syscall_nr) {
                let data = unsafe { event.data.generic };
                format!(
                    "{} {}({}, {}, {}, {}, {}, {}) = {} <STUB>",
                    event.tid,
                    name,
                    data.args[0],
                    data.args[1],
                    data.args[2],
                    data.args[3],
                    data.args[4],
                    data.args[5],
                    event.return_value
                )
            } else {
                format!("{} unknown syscall {}", event.tid, event.syscall_nr)
            }
        }
    };

    // Add a final new line.
    output.push('\n');

    output
}

fn format_stat(stat: &Stat) -> String {
    format!("{{ mode: {}, ino: {}, dev: {}, nlink: {}, uid: {}, gid: {}, size: {}, blksize: {}, blocks: {}, atime: {}, mtime: {}, ctime: {} }}",  
                format_mode(stat.st_mode),
                stat.st_ino,
                stat.st_dev,
                stat.st_nlink,
                stat.st_uid,
                stat.st_gid,
                stat.st_size,
                stat.st_blksize,
                stat.st_blocks,
                stat.st_atime,
                stat.st_mtime,
                stat.st_ctime,
    )
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

fn format_mmap_flags(flags: i32) -> String {
    let defs = [
        (libc::MAP_SHARED, "MAP_SHARED"),
        (libc::MAP_PRIVATE, "MAP_PRIVATE"),
        (libc::MAP_FIXED, "MAP_FIXED"),
        (libc::MAP_ANONYMOUS, "MAP_ANONYMOUS"),
        #[cfg(target_arch = "x86_64")]
        (libc::MAP_32BIT, "MAP_32BIT"),
        (libc::MAP_GROWSDOWN, "MAP_GROWSDOWN"),
        (libc::MAP_DENYWRITE, "MAP_DENYWRITE"),
        (libc::MAP_EXECUTABLE, "MAP_EXECUTABLE"),
        (libc::MAP_LOCKED, "MAP_LOCKED"),
        (libc::MAP_NORESERVE, "MAP_NORESERVE"),
        (libc::MAP_POPULATE, "MAP_POPULATE"),
        (libc::MAP_NONBLOCK, "MAP_NONBLOCK"),
        (libc::MAP_STACK, "MAP_STACK"),
        (libc::MAP_HUGETLB, "MAP_HUGETLB"),
        (libc::MAP_SYNC, "MAP_SYNC"),
        (libc::MAP_FIXED_NOREPLACE, "MAP_FIXED_NOREPLACE"),
    ];
    let mut parts = Vec::new();
    for (bit, name) in defs.iter() {
        if (flags as u32) & (*bit as u32) != 0 {
            parts.push(*name);
        }
    }
    if parts.is_empty() {
        format!("0x{:x}", flags)
    } else {
        format!("0x{:x} ({})", flags, parts.join("|"))
    }
}

fn format_mmap_prot(prot: i32) -> String {
    let defs = [
        (libc::PROT_READ, "PROT_READ"),
        (libc::PROT_WRITE, "PROT_WRITE"),
        (libc::PROT_EXEC, "PROT_EXEC"),
        (libc::PROT_NONE, "PROT_NONE"),
        (libc::PROT_GROWSDOWN, "PROT_GROWSDOWN"),
        (libc::PROT_GROWSUP, "PROT_GROWSUP"),
    ];
    let mut parts = Vec::new();
    for (bit, name) in defs.iter() {
        if (prot as u32) & (*bit as u32) != 0 {
            parts.push(*name);
        }
    }
    if parts.is_empty() {
        format!("0x{:x}", prot)
    } else {
        format!("0x{:x} ({})", prot, parts.join("|"))
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
