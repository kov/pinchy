// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::borrow::Cow;

use log::trace;
use pinchy_common::{
    syscalls::{
        syscall_name_from_nr, SYS_brk, SYS_close, SYS_epoll_pwait, SYS_execve, SYS_fstat,
        SYS_futex, SYS_getdents64, SYS_getrandom, SYS_ioctl, SYS_lseek, SYS_mmap, SYS_mprotect,
        SYS_munmap, SYS_openat, SYS_ppoll, SYS_prctl, SYS_read, SYS_sched_yield, SYS_statfs,
        SYS_write,
    },
    SyscallEvent,
};

use crate::{
    arg, argf, finish,
    formatting::Formatter,
    ioctls::format_ioctl_request,
    raw,
    util::{
        format_bytes, format_dirfd, format_flags, format_getrandom_flags, format_mmap_flags,
        format_mmap_prot, format_mode, format_path, format_prctl_op, format_stat, format_statfs,
        format_timespec, old_format_stat, old_format_statfs, old_format_timespec,
        poll_bits_to_strs, prctl_op_arg_count,
    },
    with_array, with_struct,
};

pub async fn handle_event(
    event: &SyscallEvent,
    formatter: Formatter<'_>,
) -> anyhow::Result<String> {
    trace!("handle_event for syscall {}", event.syscall_nr);

    let Ok(mut sf) = formatter.push_syscall(event.tid, event.syscall_nr).await else {
        return Ok(format!(
            "{} unknown syscall {}",
            event.tid, event.syscall_nr
        ));
    };

    let mut string_output = match event.syscall_nr {
        SYS_close => {
            let data = unsafe { event.data.close };

            argf!(sf, "fd: {}", data.fd);
            finish!(sf, event.return_value);

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
                            "epoll_event {{ events: {}, data: {:#x} }}",
                            poll_bits_to_strs(&(event.events as i16)).join("|"),
                            event.data
                        )
                    });

            argf!(sf, "epfd: {}", data.epfd);
            arg!(sf, "events:");

            with_array!(sf, {
                let nevents = (event.return_value as usize).min(data.events.len());
                for i in 0..nevents {
                    let epoll_event = data.events[i];
                    arg!(sf, "epoll_event");
                    with_struct!(sf, {
                        argf!(
                            sf,
                            "events: {}",
                            poll_bits_to_strs(&(epoll_event.events as i16)).join("|")
                        );
                        argf!(sf, "data: {:#x}", epoll_event.data);
                    });
                }
            });

            argf!(sf, "max_events: {}", data.max_events);
            argf!(sf, "timeout: {}", data.timeout);
            arg!(sf, "sigmask");

            finish!(sf, event.return_value);

            format!(
                "{} epoll_pwait(epfd: {}, events: [ {} ], max_events: {}, timeout: {}, sigmask) = {}",
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

            arg!(sf, "fds:");

            with_array!(sf, {
                for (fd, events) in data
                    .fds
                    .iter()
                    .zip(data.events.iter())
                    .take(data.nfds as usize)
                {
                    argf!(sf, "{{ {fd}, {} }}", poll_bits_to_strs(events).join("|"));
                }
            });

            argf!(sf, "nfds: {}", data.nfds);
            arg!(sf, "timeout:");

            format_timespec(&mut sf, data.timeout).await?;

            arg!(sf, "sigmask");

            finish!(sf, return_meaning);

            format!(
                "{} ppoll(fds: [ {} ], nfds: {}, timeout: {}, sigmask) = {}",
                event.tid,
                fds,
                data.nfds,
                old_format_timespec(data.timeout),
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

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "buf: {}{}", format_bytes(&buf), left_over);
            argf!(sf, "count: {}", data.count);

            finish!(sf, event.return_value);

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

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "buf: {}{}", format_bytes(&buf), left_over);
            argf!(sf, "count: {}", data.count);

            finish!(sf, event.return_value);

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

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "offset: {}", data.offset);
            argf!(sf, "whence: {}", data.whence);

            finish!(sf, event.return_value);

            format!(
                "{} lseek(fd: {}, offset: {}, whence: {}) = {}",
                event.tid, data.fd, data.offset, data.whence, event.return_value
            )
        }
        SYS_sched_yield => {
            finish!(sf, event.return_value);

            format!("{} sched_yield() = {}", event.tid, event.return_value)
        }
        SYS_openat => {
            let data = unsafe { event.data.openat };

            argf!(sf, "dfd: {}", format_dirfd(data.dfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "flags: {}", format_flags(data.flags));
            argf!(sf, "mode: {}", format_mode(data.mode));

            finish!(sf, event.return_value);

            format!(
                "{} openat(dfd: {}, pathname: {}, flags: {}, mode: {}) = {}",
                event.tid,
                format_dirfd(data.dfd),
                format_path(&data.pathname, false),
                format_flags(data.flags),
                format_mode(data.mode),
                event.return_value
            )
        }
        SYS_futex => {
            let data = unsafe { event.data.futex };

            argf!(sf, "uaddr: 0x{:x}", data.uaddr);
            argf!(sf, "op: {}", data.op);
            argf!(sf, "val: {}", data.val);
            argf!(sf, "uaddr2: 0x{:x}", data.uaddr2);
            argf!(sf, "val3: {}", data.val3);

            arg!(sf, "timeout:");
            format_timespec(&mut sf, data.timeout).await?;

            finish!(sf, event.return_value);

            format!(
                "{} futex(uaddr: 0x{:x}, op: {}, val: {}, uaddr2: 0x{:x}, val3: {}, timeout: {}) = {}",
                event.tid, data.uaddr, data.op, data.val, data.uaddr2, data.val3, old_format_timespec(data.timeout), event.return_value
            )
        }
        SYS_ioctl => {
            let data = unsafe { event.data.ioctl };
            let request = format_ioctl_request(data.request);

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "request: {}::{}", request.0, request.1);
            argf!(sf, "arg: 0x{}", data.arg);

            finish!(sf, event.return_value);

            format!(
                "{} ioctl(fd: {}, request: {}::{}, arg: 0x{:x}) = {}",
                event.tid, data.fd, request.0, request.1, data.arg, event.return_value
            )
        }
        SYS_execve => {
            use std::{ffi::OsString, os::unix::ffi::OsStringExt};
            let data = unsafe { event.data.execve };

            // Format filename, showing ... if truncated
            let filename = format_path(&data.filename, data.filename_truncated);

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

            argf!(sf, "filename: {}", filename);
            argf!(sf, "argv: [{}]", argv_str);
            argf!(sf, "envp: [{}]", envp_str);

            finish!(sf, event.return_value);

            format!(
                "{} execve(filename: {}, argv: [{}], envp: [{}]) = {}",
                event.tid, filename, argv_str, envp_str, event.return_value
            )
        }
        SYS_fstat => {
            let data = unsafe { event.data.fstat };

            argf!(sf, "fd: {}", data.fd);
            arg!(sf, "struct stat:");
            with_struct!(sf, {
                format_stat(&mut sf, &data.stat).await?;
            });

            finish!(sf, event.return_value);

            format!(
                "{} fstat(fd: {}, struct stat: {}) = {}",
                event.tid,
                data.fd,
                old_format_stat(&data.stat),
                event.return_value
            )
        }
        SYS_getdents64 => {
            let data = unsafe { event.data.getdents64 };
            let mut entries = Vec::new();

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "count: {}", data.count);
            arg!(sf, "entries:");

            with_array!(sf, {
                for dirent in data.dirents.iter().take(data.num_dirents as usize) {
                    arg!(sf, "dirent");
                    with_struct!(sf, {
                        argf!(sf, "ino: {}", dirent.d_ino);
                        argf!(sf, "off: {}", dirent.d_off);
                        argf!(sf, "reclen: {}", dirent.d_reclen);
                        argf!(sf, "type: {}", dirent.d_type);
                        argf!(sf, "name: {}", format_path(&dirent.d_name, false));
                    });
                }
            });

            finish!(sf, event.return_value);

            for dirent in data.dirents.iter().take(data.num_dirents as usize) {
                // Use the format_path_display helper which handles truncation
                let d_name = format_path(&dirent.d_name, false);

                entries.push(format!(
                    "dirent {{ ino: {}, off: {}, reclen: {}, type: {}, name: {} }}",
                    dirent.d_ino, dirent.d_off, dirent.d_reclen, dirent.d_type, d_name
                ));
            }
            format!(
                "{} getdents64(fd: {}, count: {}, entries: [ {} ]) = {}",
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

            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "length: {}", data.length);
            argf!(sf, "prot: {}", format_mmap_prot(data.prot));
            argf!(sf, "flags: {}", format_mmap_flags(data.flags));
            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "offset: 0x{:x}", data.offset);

            finish!(sf, ret_str);

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

            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "length: {}", data.length);

            finish!(sf, event.return_value);

            format!(
                "{} munmap(addr: 0x{:x}, length: {}) = {}",
                event.tid, data.addr, data.length, event.return_value
            )
        }
        SYS_mprotect => {
            let data = unsafe { event.data.mprotect };

            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "length: {}", data.length);
            argf!(sf, "prot: {}", format_mmap_prot(data.prot));

            finish!(sf, event.return_value);

            format!(
                "{} mprotect(addr: 0x{:x}, length: {}, prot: {}) = {}",
                event.tid,
                data.addr,
                data.length,
                format_mmap_prot(data.prot),
                event.return_value
            )
        }
        SYS_getrandom => {
            let data = unsafe { event.data.getrandom };

            argf!(sf, "buf: 0x{:x}", data.buf);
            argf!(sf, "buflen: {}", data.buflen);
            argf!(sf, "flags: {}", format_getrandom_flags(data.flags));

            finish!(sf, event.return_value);

            format!(
                "{} getrandom(buf: 0x{:x}, buflen: {}, flags: {}) = {}",
                event.tid,
                data.buf,
                data.buflen,
                format_getrandom_flags(data.flags),
                event.return_value
            )
        }
        SYS_brk => {
            let data = unsafe { event.data.brk };

            argf!(sf, "addr: 0x{:x}", data.addr);

            finish!(sf, format!("0x{:x}", event.return_value));

            format!(
                "{} brk(addr: 0x{:x}) = 0x{:x}",
                event.tid, data.addr, event.return_value
            )
        }
        SYS_statfs => {
            let data = unsafe { event.data.statfs };

            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            arg!(sf, "buf:");
            if event.return_value == 0 {
                with_struct!(sf, {
                    format_statfs(&mut sf, &data.statfs).await?;
                });
            } else {
                raw!(sf, " <unavailable>");
            }

            finish!(sf, event.return_value);

            format!(
                "{} statfs(pathname: {}, buf: {}) = {}",
                event.tid,
                format_path(&data.pathname, false),
                if event.return_value == 0 {
                    old_format_statfs(&data.statfs)
                } else {
                    "<unavailable>".to_string()
                },
                event.return_value
            )
        }
        SYS_prctl => {
            let data = unsafe { event.data.generic };
            let op_code = data.args[0] as i32;
            let op_name = format_prctl_op(op_code);

            arg!(sf, op_name);

            let arg_count = prctl_op_arg_count(op_code);

            for i in 1..arg_count {
                argf!(sf, "0x{:x}", data.args[i]);
            }

            let args_formatted = match arg_count {
                1 => String::new(),
                2 => format!(", 0x{:x}", data.args[1]),
                3 => format!(", 0x{:x}, 0x{:x}", data.args[1], data.args[2]),
                4 => format!(
                    ", 0x{:x}, 0x{:x}, 0x{:x}",
                    data.args[1], data.args[2], data.args[3]
                ),
                _ => format!(
                    ", 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}",
                    data.args[1], data.args[2], data.args[3], data.args[4]
                ),
            };

            finish!(sf, event.return_value);

            format!(
                "{} prctl({}{}) = {}",
                event.tid, op_name, args_formatted, event.return_value
            )
        }
        _ => {
            // Check if this is a generic syscall with raw arguments
            if let Some(name) = syscall_name_from_nr(event.syscall_nr) {
                let data = unsafe { event.data.generic };

                for i in 0..data.args.len() {
                    argf!(sf, "{}", data.args[i]);
                }

                finish!(sf, event.return_value, b" <STUB>");

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
    string_output.push('\n');

    Ok(string_output)
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

#[cfg(test)]
mod test;
