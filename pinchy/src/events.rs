// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::borrow::Cow;

use log::{error, trace};
use pinchy_common::{syscalls, SyscallEvent};

use crate::{
    arg, argf, finish, formatting::Formatter, ioctls::format_ioctl_request, raw, util::*,
    with_array, with_struct,
};

pub async fn handle_event(event: &SyscallEvent, formatter: Formatter<'_>) -> anyhow::Result<()> {
    trace!("handle_event for syscall {}", event.syscall_nr);

    let Ok(mut sf) = formatter.push_syscall(event.tid, event.syscall_nr).await else {
        error!("{} unknown syscall {}", event.tid, event.syscall_nr);
        return Ok(());
    };

    match event.syscall_nr {
        syscalls::SYS_readv
        | syscalls::SYS_writev
        | syscalls::SYS_preadv
        | syscalls::SYS_pwritev
        | syscalls::SYS_preadv2
        | syscalls::SYS_pwritev2 => {
            let data = unsafe { event.data.vector_io };
            argf!(sf, "fd: {}", data.fd);
            arg!(sf, "iov:");
            with_array!(sf, {
                for i in 0..data.iovcnt {
                    arg!(sf, "iovec");
                    with_struct!(sf, {
                        let buf = &data.iov_bufs[i];
                        let len = data.iov_lens[i].min(buf.len());
                        if len > 0 {
                            argf!(sf, "base: {}", format_bytes(&buf[..len]));
                        } else {
                            arg!(sf, "base: NULL");
                        }
                        argf!(sf, "len: {}", data.iov_lens[i]);
                    });
                }
            });
            argf!(sf, "iovcnt: {}", data.iovcnt);
            if event.syscall_nr == syscalls::SYS_preadv
                || event.syscall_nr == syscalls::SYS_pwritev
                || event.syscall_nr == syscalls::SYS_preadv2
                || event.syscall_nr == syscalls::SYS_pwritev2
            {
                argf!(sf, "offset: {}", data.offset);
            }
            if event.syscall_nr == syscalls::SYS_preadv2
                || event.syscall_nr == syscalls::SYS_pwritev2
            {
                argf!(sf, "flags: 0x{:x}", data.flags);
            }
            finish!(sf, event.return_value);
        }
        syscalls::SYS_rt_sigreturn
        | syscalls::SYS_sched_yield
        | syscalls::SYS_getpid
        | syscalls::SYS_gettid
        | syscalls::SYS_getuid
        | syscalls::SYS_geteuid
        | syscalls::SYS_getgid
        | syscalls::SYS_getegid
        | syscalls::SYS_getppid
        | syscalls::SYS_sync
        | syscalls::SYS_setsid
        | syscalls::SYS_vhangup => {
            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_pause => {
            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_getpgrp => {
            finish!(sf, event.return_value);
        }
        syscalls::SYS_flistxattr => {
            let data = unsafe { event.data.flistxattr };
            argf!(sf, "fd: {}", data.fd);

            arg!(sf, "list:");
            format_xattr_list(&mut sf, &data.xattr_list).await?;

            argf!(sf, "size: {}", data.size);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_listxattr => {
            let data = unsafe { event.data.listxattr };
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));

            arg!(sf, "list:");
            format_xattr_list(&mut sf, &data.xattr_list).await?;

            argf!(sf, "size: {}", data.size);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_llistxattr => {
            let data = unsafe { event.data.llistxattr };
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));

            arg!(sf, "list:");
            format_xattr_list(&mut sf, &data.xattr_list).await?;

            argf!(sf, "size: {}", data.size);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_exit_group => {
            let data = unsafe { event.data.exit_group };
            argf!(sf, "status: {}", data.status);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_close => {
            let data = unsafe { event.data.close };

            argf!(sf, "fd: {}", data.fd);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_pipe2 => {
            let data = unsafe { event.data.pipe2 };
            arg!(sf, "pipefd:");
            with_array!(sf, {
                argf!(sf, "{}", data.pipefd[0]);
                argf!(sf, "{}", data.pipefd[1]);
            });
            argf!(sf, "flags: 0x{:x}", data.flags);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_dup3 => {
            let data = unsafe { event.data.dup3 };

            argf!(sf, "oldfd: {}", data.oldfd);
            argf!(sf, "newfd: {}", data.newfd);
            argf!(sf, "flags: {}", format_dup3_flags(data.flags));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_dup => {
            let data = unsafe { event.data.dup };

            argf!(sf, "oldfd: {}", data.oldfd);
            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_dup2 => {
            let data = unsafe { event.data.dup2 };

            argf!(sf, "oldfd: {}", data.oldfd);
            argf!(sf, "newfd: {}", data.newfd);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_setuid => {
            let data = unsafe { event.data.setuid };

            argf!(sf, "uid: {}", data.uid);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_setgid => {
            let data = unsafe { event.data.setgid };

            argf!(sf, "gid: {}", data.gid);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_close_range => {
            let data = unsafe { event.data.close_range };

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "max_fd: {}", data.max_fd);
            argf!(sf, "flags: 0x{:x}", data.flags);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_getpgid => {
            let data = unsafe { event.data.getpgid };

            argf!(sf, "pid: {}", data.pid);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_getsid => {
            let data = unsafe { event.data.getsid };

            argf!(sf, "pid: {}", data.pid);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_setpgid => {
            let data = unsafe { event.data.setpgid };

            argf!(sf, "pid: {}", data.pid);
            argf!(sf, "pgid: {}", data.pgid);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_umask => {
            let data = unsafe { event.data.umask };

            argf!(sf, "mask: 0o{:o}", data.mask);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_ioprio_get => {
            let data = unsafe { event.data.ioprio_get };

            argf!(sf, "which: {}", data.which);
            argf!(sf, "who: {}", data.who);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_ioprio_set => {
            let data = unsafe { event.data.ioprio_set };

            argf!(sf, "which: {}", data.which);
            argf!(sf, "who: {}", data.who);
            argf!(sf, "ioprio: {}", data.ioprio);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_setregid => {
            let data = unsafe { event.data.setregid };

            argf!(sf, "rgid: {}", data.rgid);
            argf!(sf, "egid: {}", data.egid);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_setresgid => {
            let data = unsafe { event.data.setresgid };

            argf!(sf, "rgid: {}", data.rgid);
            argf!(sf, "egid: {}", data.egid);
            argf!(sf, "sgid: {}", data.sgid);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_setresuid => {
            let data = unsafe { event.data.setresuid };

            argf!(sf, "ruid: {}", data.ruid);
            argf!(sf, "euid: {}", data.euid);
            argf!(sf, "suid: {}", data.suid);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_setreuid => {
            let data = unsafe { event.data.setreuid };

            argf!(sf, "ruid: {}", data.ruid);
            argf!(sf, "euid: {}", data.euid);
            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_alarm => {
            let data = unsafe { event.data.alarm };

            argf!(sf, "seconds: {}", data.seconds);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_times => {
            let data = unsafe { event.data.times };

            arg!(sf, "buf:");
            if data.has_buf {
                with_struct!(sf, {
                    format_tms(&mut sf, &data.buf).await?;
                });
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_personality => {
            let data = unsafe { event.data.personality };

            argf!(sf, "persona: 0x{:x}", data.persona);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_sysinfo => {
            let data = unsafe { event.data.sysinfo };

            arg!(sf, "info:");
            if data.has_info {
                with_struct!(sf, {
                    format_sysinfo(&mut sf, &data.info).await?;
                });
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_gettimeofday => {
            let data = unsafe { event.data.gettimeofday };

            arg!(sf, "tv:");
            if data.has_tv {
                with_struct!(sf, {
                    format_timeval(&mut sf, &data.tv).await?;
                });
            } else {
                raw!(sf, " NULL");
            }

            arg!(sf, "tz:");
            if data.has_tz {
                with_struct!(sf, {
                    format_timezone(&mut sf, &data.tz).await?;
                });
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_settimeofday => {
            let data = unsafe { event.data.settimeofday };

            arg!(sf, "tv:");
            if data.has_tv {
                with_struct!(sf, {
                    format_timeval(&mut sf, &data.tv).await?;
                });
            } else {
                raw!(sf, " NULL");
            }

            arg!(sf, "tz:");
            if data.has_tz {
                with_struct!(sf, {
                    format_timezone(&mut sf, &data.tz).await?;
                });
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_nanosleep => {
            let data = unsafe { event.data.nanosleep };

            arg!(sf, "req:");
            format_timespec(&mut sf, data.req).await?;

            arg!(sf, "rem:");
            if data.has_rem {
                format_timespec(&mut sf, data.rem).await?;
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_clock_nanosleep => {
            let data = unsafe { event.data.clock_nanosleep };

            argf!(sf, "clockid: {}", format_clockid(data.clockid));
            argf!(sf, "flags: {}", format_clock_nanosleep_flags(data.flags));

            arg!(sf, "req:");
            format_timespec(&mut sf, data.req).await?;

            arg!(sf, "rem:");
            if data.has_rem {
                format_timespec(&mut sf, data.rem).await?;
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_getpriority => {
            let data = unsafe { event.data.getpriority };

            argf!(sf, "which: {}", format_priority_which(data.which as u32));
            argf!(sf, "who: {}", data.who);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_setpriority => {
            let data = unsafe { event.data.setpriority };

            argf!(sf, "which: {}", format_priority_which(data.which as u32));
            argf!(sf, "who: {}", data.who);
            argf!(sf, "prio: {}", data.prio);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_tkill => {
            let data = unsafe { event.data.tkill };

            argf!(sf, "pid: {}", data.pid);
            argf!(sf, "sig: {}", format_signal_number(data.signal));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_tgkill => {
            let data = unsafe { event.data.tgkill };

            argf!(sf, "tgid: {}", data.tgid);
            argf!(sf, "pid: {}", data.pid);
            argf!(sf, "sig: {}", format_signal_number(data.signal));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_kill => {
            let data = unsafe { event.data.kill };

            argf!(sf, "pid: {}", data.pid);
            argf!(sf, "sig: {}", format_signal_number(data.signal));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_pidfd_send_signal => {
            let data = unsafe { event.data.pidfd_send_signal };

            argf!(sf, "pidfd: {}", data.pidfd);
            argf!(sf, "sig: {}", format_signal_number(data.sig));

            arg!(sf, "siginfo:");
            format_siginfo(&mut sf, &data.info).await?;

            argf!(sf, "flags: 0x{:x}", data.flags);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_process_mrelease => {
            let data = unsafe { event.data.process_mrelease };
            argf!(sf, "pidfd: {}", data.pidfd);
            argf!(sf, "flags: 0x{:x}", data.flags);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_exit => {
            let data = unsafe { event.data.exit };

            argf!(sf, "status: {}", data.status);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_sched_getscheduler => {
            let data = unsafe { event.data.sched_getscheduler };

            argf!(sf, "pid: {}", data.pid);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_sched_setscheduler => {
            let data = unsafe { event.data.sched_setscheduler };

            argf!(sf, "pid: {}", data.pid);

            // Handle policy flags - extract SCHED_RESET_ON_FORK flag if present
            let reset_on_fork = (data.policy & libc::SCHED_RESET_ON_FORK) != 0;
            let base_policy = data.policy & !libc::SCHED_RESET_ON_FORK;

            if reset_on_fork {
                argf!(
                    sf,
                    "policy: {}|SCHED_RESET_ON_FORK",
                    format_sched_policy(base_policy)
                );
            } else {
                argf!(sf, "policy: {}", format_sched_policy(base_policy));
            }

            if data.has_param {
                arg!(sf, "param:");
                with_struct!(sf, {
                    argf!(sf, "sched_priority: {}", data.param.sched_priority);
                });
            } else {
                argf!(sf, "param: NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_setfsuid => {
            let data = unsafe { event.data.setfsuid };

            argf!(sf, "uid: {}", data.uid);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_setfsgid => {
            let data = unsafe { event.data.setfsgid };

            argf!(sf, "gid: {}", data.gid);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_sched_get_priority_max => {
            let data = unsafe { event.data.sched_get_priority_max };

            argf!(sf, "policy: {}", format_sched_policy(data.policy));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_sched_get_priority_min => {
            let data = unsafe { event.data.sched_get_priority_min };

            argf!(sf, "policy: {}", format_sched_policy(data.policy));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_epoll_pwait => {
            let data = unsafe { event.data.epoll_pwait };

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
        }
        syscalls::SYS_epoll_pwait2 => {
            let data = unsafe { event.data.epoll_pwait2 };
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

            arg!(sf, "timeout:");
            format_timespec(&mut sf, data.timeout).await?;

            argf!(sf, "sigmask: 0x{:x}", data.sigmask);
            argf!(sf, "sigsetsize: {}", data.sigsetsize);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_epoll_ctl => {
            let data = unsafe { event.data.epoll_ctl };
            argf!(sf, "epfd: {}", data.epfd);
            argf!(sf, "op: {}", format_epoll_ctl_op(data.op));
            argf!(sf, "fd: {}", data.fd);
            arg!(sf, "event: epoll_event");
            with_struct!(sf, {
                argf!(
                    sf,
                    "events: {}",
                    poll_bits_to_strs(&(data.event.events as i16)).join("|")
                );
                argf!(sf, "data: {:#x}", data.event.data);
            });
            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_epoll_wait => {
            let data = unsafe { event.data.epoll_wait };

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

            finish!(sf, event.return_value);
        }
        syscalls::SYS_ppoll => {
            let data = unsafe { event.data.ppoll };

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

            // For ppoll, provide detailed ready state information as extra output
            let extra_info = match event.return_value {
                0 => None,  // Timeout case
                -1 => None, // Error case
                _ => Some(format!(
                    " [{}]",
                    data.fds.iter().zip(data.revents.iter()).join_take_map(
                        data.nfds as usize,
                        |(fd, event)| format!("{fd} = {}", poll_bits_to_strs(event).join("|"))
                    )
                )),
            };

            match extra_info {
                Some(extra) => finish!(sf, event.return_value, extra.as_bytes()),
                None => finish!(sf, event.return_value),
            };
        }
        syscalls::SYS_pselect6 => {
            let data = unsafe { event.data.pselect6 };

            argf!(sf, "nfds: {}", data.nfds);

            arg!(sf, "readfds:");
            if data.has_readfds {
                format_fdset(&mut sf, &data.readfds).await?;
            } else {
                raw!(sf, " NULL");
            }

            arg!(sf, "writefds:");
            if data.has_writefds {
                format_fdset(&mut sf, &data.writefds).await?;
            } else {
                raw!(sf, " NULL");
            }

            arg!(sf, "exceptfds:");
            if data.has_exceptfds {
                format_fdset(&mut sf, &data.exceptfds).await?;
            } else {
                raw!(sf, " NULL");
            }

            arg!(sf, "timeout:");
            if data.has_timeout {
                format_timespec(&mut sf, data.timeout).await?;
            } else {
                raw!(sf, " NULL");
            }

            arg!(sf, "sigmask:");
            if data.has_sigmask {
                raw!(sf, " <present>");
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_select => {
            let data = unsafe { event.data.select };

            argf!(sf, "nfds: {}", data.nfds);

            arg!(sf, "readfds:");
            if data.has_readfds {
                format_fdset(&mut sf, &data.readfds).await?;
            } else {
                raw!(sf, " NULL");
            }

            arg!(sf, "writefds:");
            if data.has_writefds {
                format_fdset(&mut sf, &data.writefds).await?;
            } else {
                raw!(sf, " NULL");
            }

            arg!(sf, "exceptfds:");
            if data.has_exceptfds {
                format_fdset(&mut sf, &data.exceptfds).await?;
            } else {
                raw!(sf, " NULL");
            }

            arg!(sf, "timeout:");
            if data.has_timeout {
                format_timeval(&mut sf, &data.timeout).await?;
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_read => {
            let data = unsafe { event.data.read };

            argf!(sf, "fd: {}", data.fd);

            if event.return_value >= 0 {
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

                argf!(sf, "buf: {}{}", format_bytes(buf), left_over);
            } else {
                argf!(sf, "buf: <error>");
            }

            argf!(sf, "count: {}", data.count);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_write => {
            let data = unsafe { event.data.write };

            argf!(sf, "fd: {}", data.fd);

            if event.return_value >= 0 {
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

                argf!(sf, "buf: {}{}", format_bytes(buf), left_over);
            } else {
                argf!(sf, "buf: <error>");
            }

            argf!(sf, "count: {}", data.count);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_pread64 => {
            let data = unsafe { event.data.pread };

            argf!(sf, "fd: {}", data.fd);

            if event.return_value >= 0 {
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

                argf!(sf, "buf: {}{}", format_bytes(buf), left_over);
            } else {
                argf!(sf, "buf: <e>");
            }

            argf!(sf, "count: {}", data.count);
            argf!(sf, "offset: {}", data.offset);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_pwrite64 => {
            let data = unsafe { event.data.pwrite };

            argf!(sf, "fd: {}", data.fd);

            if event.return_value >= 0 {
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

                argf!(sf, "buf: {}{}", format_bytes(buf), left_over);
            } else {
                argf!(sf, "buf: <e>");
            }

            argf!(sf, "count: {}", data.count);
            argf!(sf, "offset: {}", data.offset);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_lseek => {
            let data = unsafe { event.data.lseek };

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "offset: {}", data.offset);
            argf!(sf, "whence: {}", data.whence);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_openat => {
            let data = unsafe { event.data.openat };

            argf!(sf, "dfd: {}", format_dirfd(data.dfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "flags: {}", format_flags(data.flags));
            argf!(sf, "mode: {}", format_mode(data.mode));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_futex => {
            let data = unsafe { event.data.futex };

            argf!(sf, "uaddr: 0x{:x}", data.uaddr);
            argf!(sf, "op: {}", data.op);
            argf!(sf, "val: {}", data.val);
            argf!(sf, "uaddr2: 0x{:x}", data.uaddr2);
            argf!(sf, "val3: {}", data.val3);

            arg!(sf, "timeout:");
            format_timespec(&mut sf, data.timeout).await?;

            finish!(sf, event.return_value);
        }
        syscalls::SYS_ioctl => {
            let data = unsafe { event.data.ioctl };
            let request = format_ioctl_request(data.request);

            argf!(sf, "fd: {}", data.fd);
            argf!(
                sf,
                "request: (0x{:x}) {}::{}",
                data.request,
                request.0,
                request.1
            );
            argf!(sf, "arg: 0x{}", data.arg);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_fcntl => {
            let data = unsafe { event.data.fcntl };

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "cmd: {}", format_fcntl_cmd(data.cmd));
            argf!(sf, "arg: 0x{:x}", data.arg);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_execve => {
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
        }
        syscalls::SYS_fstat => {
            let data = unsafe { event.data.fstat };

            argf!(sf, "fd: {}", data.fd);
            arg!(sf, "struct stat:");
            with_struct!(sf, {
                format_stat(&mut sf, &data.stat).await?;
            });

            finish!(sf, event.return_value);
        }
        syscalls::SYS_newfstatat => {
            let data = unsafe { event.data.newfstatat };

            argf!(sf, "dirfd: {}", format_dirfd(data.dirfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            arg!(sf, "struct stat:");
            if event.return_value == 0 {
                with_struct!(sf, {
                    format_stat(&mut sf, &data.stat).await?;
                });
            } else {
                raw!(sf, " <unavailable>");
            }
            argf!(sf, "flags: {}", format_at_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_getdents64 => {
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
        }
        syscalls::SYS_mmap => {
            let data = unsafe { event.data.mmap };

            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "length: {}", data.length);
            argf!(sf, "prot: {}", format_mmap_prot(data.prot));
            argf!(sf, "flags: {}", format_mmap_flags(data.flags));
            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "offset: 0x{:x}", data.offset);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_munmap => {
            let data = unsafe { event.data.munmap };

            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "length: {}", data.length);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_mprotect => {
            let data = unsafe { event.data.mprotect };

            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "length: {}", data.length);
            argf!(sf, "prot: {}", format_mmap_prot(data.prot));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_madvise => {
            let data = unsafe { event.data.madvise };

            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "length: {}", data.length);
            argf!(sf, "advice: {}", format_madvise_advice(data.advice));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_process_madvise => {
            let data = unsafe { event.data.process_madvise };

            argf!(sf, "pidfd: {}", data.pidfd);
            arg!(sf, "iov:");
            with_array!(sf, {
                for i in 0..data.iovcnt {
                    arg!(sf, "iovec");
                    with_struct!(sf, {
                        argf!(sf, "base: 0x{:x}", data.iovecs[i].iov_base);
                        argf!(sf, "len: {}", data.iovecs[i].iov_len);
                    });
                }
            });
            argf!(sf, "iovcnt: {}", data.iovcnt);
            argf!(sf, "advice: {}", format_madvise_advice(data.advice));
            argf!(sf, "flags: {}", data.flags);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_getrandom => {
            let data = unsafe { event.data.getrandom };

            argf!(sf, "buf: 0x{:x}", data.buf);
            argf!(sf, "buflen: {}", data.buflen);
            argf!(sf, "flags: {}", format_getrandom_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_brk => {
            let data = unsafe { event.data.brk };

            argf!(sf, "addr: 0x{:x}", data.addr);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_statfs => {
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
        }
        syscalls::SYS_prctl => {
            let data = unsafe { event.data.generic };
            let op_code = data.args[0] as i32;
            let op_name = format_prctl_op(op_code);

            arg!(sf, op_name);

            let arg_count = prctl_op_arg_count(op_code);

            for i in 1..arg_count {
                argf!(sf, "0x{:x}", data.args[i]);
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_faccessat => {
            let data = unsafe { event.data.faccessat };

            argf!(sf, "dirfd: {}", format_dirfd(data.dirfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "mode: {}", format_access_mode(data.mode));

            // FIXME: I believe this argument is not used for faccessat, only
            // for faccessat2?
            argf!(sf, "flags: {}", format_at_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_set_robust_list => {
            let data = unsafe { event.data.set_robust_list };

            argf!(sf, "head: 0x{:x}", data.head);
            argf!(sf, "len: {}", data.len);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_set_tid_address => {
            let data = unsafe { event.data.set_tid_address };

            argf!(sf, "tidptr: 0x{:x}", data.tidptr);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_rt_sigprocmask => {
            let data = unsafe { event.data.rt_sigprocmask };

            argf!(sf, "how: {}", format_sigprocmask_how(data.how));

            // TODO: we can probably do better and parse the sets. It gets a bit tricky, because the
            // sigset_t types are not necessarily the same in libc vs kernel.
            argf!(sf, "set: 0x{:x}", data.set);
            argf!(sf, "oldset: 0x{:x}", data.oldset);

            argf!(sf, "sigsetsize: {}", data.sigsetsize);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_rt_sigaction => {
            let data = unsafe { event.data.rt_sigaction };

            argf!(sf, "signum: {}", format_signal_number(data.signum));
            argf!(sf, "act: 0x{:x}", data.act);
            argf!(sf, "oldact: 0x{:x}", data.oldact);
            argf!(sf, "sigsetsize: {}", data.sigsetsize);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_prlimit64 => {
            let data = unsafe { event.data.prlimit };

            argf!(sf, "pid: {}", data.pid);
            argf!(
                sf,
                "resource: {}",
                crate::util::format_resource_type(data.resource)
            );

            // Handle new_limit
            if data.has_new {
                arg!(sf, "new_limit:");
                with_struct!(sf, {
                    crate::util::format_rlimit(&mut sf, &data.new_limit).await?;
                });
            } else {
                arg!(sf, "new_limit: NULL");
            }

            // Handle old_limit
            arg!(sf, "old_limit:");
            if data.has_old && event.return_value == 0 {
                with_struct!(sf, {
                    crate::util::format_rlimit(&mut sf, &data.old_limit).await?;
                });
            } else if data.has_old {
                raw!(sf, " (content unavailable)");
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_rseq => {
            let data = unsafe { event.data.rseq };

            argf!(
                sf,
                "rseq: {}",
                if data.has_rseq {
                    format!("0x{:x}", data.rseq_ptr)
                } else {
                    "NULL".to_string()
                }
            );
            argf!(sf, "rseq_len: {}", data.rseq_len);
            argf!(sf, "flags: {}", format_rseq_flags(data.flags));
            argf!(sf, "signature: 0x{:x}", data.signature);

            if data.has_rseq {
                arg!(sf, "rseq content:");
                with_struct!(sf, {
                    let req_cs = if data.has_rseq_cs {
                        Some(&data.rseq_cs)
                    } else {
                        None
                    };
                    format_rseq(&mut sf, &data.rseq, req_cs).await?;
                });
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_uname => {
            let data = unsafe { event.data.uname };

            arg!(sf, "struct utsname:");
            with_struct!(sf, {
                format_utsname(&mut sf, &data.utsname).await?;
            });

            finish!(sf, event.return_value);
        }
        syscalls::SYS_fchdir => {
            let data = unsafe { event.data.fchdir };
            argf!(sf, "fd: {}", data.fd);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_fsync => {
            let data = unsafe { event.data.fsync };
            argf!(sf, "fd: {}", data.fd);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_fdatasync => {
            let data = unsafe { event.data.fdatasync };
            argf!(sf, "fd: {}", data.fd);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_ftruncate => {
            let data = unsafe { event.data.ftruncate };
            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "length: {}", data.length);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_fchmod => {
            let data = unsafe { event.data.fchmod };
            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "mode: {}", format_mode(data.mode));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_fchmodat => {
            let data = unsafe { event.data.fchmodat };

            argf!(sf, "dirfd: {}", data.dirfd);
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "mode: {}", format_mode(data.mode));
            argf!(sf, "flags: {}", data.flags);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_readlinkat => {
            let data = unsafe { event.data.readlinkat };

            argf!(sf, "dirfd: {}", format_dirfd(data.dirfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "buf: {}", format_path(&data.buf, false));
            argf!(sf, "bufsiz: {}", data.bufsiz);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_getcwd => {
            let data = unsafe { event.data.getcwd };

            argf!(sf, "buf: 0x{:x}", data.buf);
            argf!(sf, "size: {}", data.size);

            // Show the actual path if syscall succeeded
            if event.return_value > 0 {
                argf!(sf, "path: {}", format_path(&data.path, false));
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_chdir => {
            let data = unsafe { event.data.chdir };

            argf!(sf, "path: {}", format_path(&data.path, false));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_mkdirat => {
            let data = unsafe { event.data.mkdirat };

            argf!(sf, "dirfd: {}", format_dirfd(data.dirfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "mode: {}", format_mode(data.mode));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_recvmsg => {
            let data = unsafe { event.data.recvmsg };

            argf!(sf, "sockfd: {}", data.sockfd);
            arg!(sf, "msg:");
            with_struct!(sf, {
                format_msghdr(&mut sf, &data.msghdr).await?;
            });
            argf!(sf, "flags: {}", format_recvmsg_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_recvfrom => {
            let data = unsafe { event.data.recvfrom };

            argf!(sf, "sockfd: {}", data.sockfd);

            if event.return_value > 0 {
                let buf = &data.received_data[..data.received_len];
                let left_over = if event.return_value as usize > buf.len() {
                    format!(
                        " ... ({} more bytes)",
                        event.return_value as usize - buf.len()
                    )
                } else {
                    String::new()
                };
                argf!(sf, "buf: {}{}", format_bytes(buf), left_over);
            } else {
                argf!(sf, "buf: NULL");
            }

            argf!(sf, "size: {}", data.size);
            argf!(sf, "flags: {}", format_recvmsg_flags(data.flags));

            arg!(sf, "src_addr:");
            if data.has_addr {
                with_struct!(sf, {
                    format_sockaddr(&mut sf, &data.addr).await?;
                });
            } else {
                raw!(sf, " NULL");
            }

            argf!(sf, "addrlen: {}", data.addrlen);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_sendmsg => {
            let data = unsafe { event.data.sendmsg };

            argf!(sf, "sockfd: {}", data.sockfd);
            arg!(sf, "msg:");
            with_struct!(sf, {
                format_msghdr(&mut sf, &data.msghdr).await?;
            });
            argf!(sf, "flags: {}", format_sendmsg_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_accept => {
            let data = unsafe { event.data.accept };

            argf!(sf, "sockfd: {}", data.sockfd);

            arg!(sf, "addr:");
            if data.has_addr {
                with_struct!(sf, {
                    format_sockaddr(&mut sf, &data.addr).await?;
                });
            } else {
                raw!(sf, " NULL");
            }

            argf!(sf, "addrlen: {}", data.addrlen);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_accept4 => {
            let data = unsafe { event.data.accept4 };

            argf!(sf, "sockfd: {}", data.sockfd);

            arg!(sf, "addr:");
            if data.has_addr {
                with_struct!(sf, {
                    format_sockaddr(&mut sf, &data.addr).await?;
                });
            } else {
                raw!(sf, " NULL");
            }

            argf!(sf, "addrlen: {}", data.addrlen);
            argf!(sf, "flags: {}", format_accept4_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_bind | syscalls::SYS_connect => {
            let data = unsafe { event.data.sockaddr };

            argf!(sf, "sockfd: {}", data.sockfd);
            arg!(sf, "addr:");
            with_struct!(sf, {
                format_sockaddr(&mut sf, &data.addr).await?;
            });
            argf!(sf, "addrlen: {}", data.addrlen);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_socket => {
            let data = unsafe { event.data.socket };

            argf!(sf, "domain: {}", format_socket_domain(data.domain));
            argf!(sf, "type: {}", format_socket_type(data.type_));
            argf!(sf, "protocol: {}", data.protocol);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_listen => {
            let data = unsafe { event.data.listen };

            argf!(sf, "sockfd: {}", data.sockfd);
            argf!(sf, "backlog: {}", data.backlog);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_shutdown => {
            let data = unsafe { event.data.shutdown };

            argf!(sf, "sockfd: {}", data.sockfd);
            argf!(sf, "how: {}", format_shutdown_how(data.how));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_wait4 => {
            let data = unsafe { event.data.wait4 };

            argf!(sf, "pid: {}", data.pid);

            // Show wait status (only if successful)
            if event.return_value >= 0 {
                argf!(sf, "wstatus: {}", format_wait_status(data.wstatus));
            } else {
                argf!(sf, "wstatus: 0x{:x}", data.wstatus);
            }

            argf!(sf, "options: {}", format_wait_options(data.options));

            arg!(sf, "rusage:");
            if data.has_rusage {
                with_struct!(sf, {
                    format_rusage(&mut sf, &data.rusage).await?;
                });
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_getrusage => {
            let data = unsafe { event.data.getrusage };

            argf!(sf, "who: {}", format_rusage_who(data.who));

            arg!(sf, "rusage:");
            if event.return_value >= 0 {
                with_struct!(sf, {
                    format_rusage(&mut sf, &data.rusage).await?;
                });
            } else {
                raw!(sf, " NULL"); // For failed calls, just show NULL
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_clone3 => {
            let data = unsafe { event.data.clone3 };

            arg!(sf, "cl_args:");
            with_struct!(sf, {
                argf!(sf, "flags: {}", format_clone_flags(data.cl_args.flags));
                argf!(sf, "pidfd: {:#x}", data.cl_args.pidfd);
                argf!(sf, "child_tid: {:#x}", data.cl_args.child_tid);
                argf!(sf, "parent_tid: {:#x}", data.cl_args.parent_tid);
                argf!(sf, "exit_signal: {}", data.cl_args.exit_signal);
                argf!(sf, "stack: {:#x}", data.cl_args.stack);
                argf!(sf, "stack_size: {}", data.cl_args.stack_size);
                argf!(sf, "tls: {:#x}", data.cl_args.tls);
                if data.cl_args.set_tid != 0 || data.set_tid_count > 0 {
                    if data.set_tid_count > 0 {
                        arg!(sf, "set_tid:");
                        with_array!(sf, {
                            for i in 0..data.set_tid_count as usize {
                                argf!(sf, "{}", data.set_tid_array[i]);
                            }
                        });
                    } else {
                        argf!(sf, "set_tid: {:#x}", data.cl_args.set_tid);
                    }
                    argf!(sf, "set_tid_size: {}", data.cl_args.set_tid_size);
                }
                if data.cl_args.cgroup != 0 {
                    argf!(sf, "cgroup: {}", data.cl_args.cgroup);
                }
            });

            argf!(sf, "size: {}", data.size);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_clone => {
            let data = unsafe { event.data.clone };

            argf!(sf, "flags: {}", format_clone_flags(data.flags));
            argf!(sf, "stack: {:#x}", data.stack);
            argf!(sf, "parent_tid: {}", data.parent_tid);
            argf!(sf, "child_tid: {}", data.child_tid);
            argf!(sf, "tls: {:#x}", data.tls);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_fchown => {
            let data = unsafe { event.data.fchown };
            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "uid: {}", data.uid);
            argf!(sf, "gid: {}", data.gid);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_fchownat => {
            let data = unsafe { event.data.fchownat };
            argf!(sf, "dirfd: {}", format_dirfd(data.dirfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "uid: {}", data.uid);
            argf!(sf, "gid: {}", data.gid);
            argf!(sf, "flags: {}", data.flags);
            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_chown | syscalls::SYS_lchown => {
            let data = unsafe { event.data.chown };
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "uid: {}", data.uid);
            argf!(sf, "gid: {}", data.gid);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_truncate => {
            let data = unsafe { event.data.truncate };
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "length: {}", data.length);
            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_rename => {
            let data = unsafe { event.data.rename };
            argf!(sf, "oldpath: {}", format_path(&data.oldpath, false));
            argf!(sf, "newpath: {}", format_path(&data.newpath, false));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_renameat => {
            let data = unsafe { event.data.renameat };
            argf!(sf, "olddirfd: {}", format_dirfd(data.olddirfd));
            argf!(sf, "oldpath: {}", format_path(&data.oldpath, false));
            argf!(sf, "newdirfd: {}", format_dirfd(data.newdirfd));
            argf!(sf, "newpath: {}", format_path(&data.newpath, false));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_renameat2 => {
            let data = unsafe { event.data.renameat2 };
            argf!(sf, "olddirfd: {}", format_dirfd(data.olddirfd));
            argf!(sf, "oldpath: {}", format_path(&data.oldpath, false));
            argf!(sf, "newdirfd: {}", format_dirfd(data.newdirfd));
            argf!(sf, "newpath: {}", format_path(&data.newpath, false));
            argf!(sf, "flags: {}", format_renameat2_flags(data.flags));
            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_poll => {
            let data = unsafe { event.data.poll };
            arg!(sf, "fds:");
            with_array!(sf, {
                for i in 0..data.actual_nfds as usize {
                    arg!(sf, "pollfd");
                    with_struct!(sf, {
                        argf!(sf, "fd: {}", data.fds[i].fd);
                        argf!(
                            sf,
                            "events: {}",
                            crate::util::format_poll_events(data.fds[i].events)
                        );
                        argf!(
                            sf,
                            "revents: {}",
                            crate::util::format_poll_events(data.fds[i].revents)
                        );
                    });
                }
            });
            argf!(sf, "nfds: {}", data.nfds);
            argf!(sf, "timeout: {}", data.timeout);
            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_epoll_create => {
            let data = unsafe { event.data.epoll_create };
            argf!(sf, "size: {}", data.size);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_epoll_create1 => {
            let data = unsafe { event.data.epoll_create1 };
            argf!(sf, "flags: {}", format_epoll_create1_flags(data.flags));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_splice => {
            let data = unsafe { event.data.splice };

            argf!(sf, "fd_in: {}", data.fd_in);
            argf!(sf, "off_in: 0x{:x}", data.off_in);
            argf!(sf, "fd_out: {}", data.fd_out);
            argf!(sf, "off_out: 0x{:x}", data.off_out);
            argf!(sf, "len: {}", data.len);
            argf!(sf, "flags: {}", format_splice_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_tee => {
            let data = unsafe { event.data.tee };

            argf!(sf, "fd_in: {}", data.fd_in);
            argf!(sf, "fd_out: {}", data.fd_out);
            argf!(sf, "len: {}", data.len);
            argf!(sf, "flags: {}", format_splice_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_vmsplice => {
            let data = unsafe { event.data.vmsplice };
            argf!(sf, "fd: {}", data.fd);
            arg!(sf, "iov:");
            with_array!(sf, {
                for i in 0..data.iovcnt {
                    arg!(sf, "iovec");
                    with_struct!(sf, {
                        let buf = &data.iov_bufs[i];
                        let len = data.iov_lens[i].min(buf.len());
                        if len > 0 {
                            argf!(sf, "base: {}", format_bytes(&buf[..len]));
                        } else {
                            arg!(sf, "base: NULL");
                        }
                        argf!(sf, "len: {}", data.iov_lens[i]);
                    });
                }
            });
            argf!(sf, "iovcnt: {}", data.iovcnt);
            argf!(sf, "flags: {}", format_splice_flags(data.flags));
            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_rmdir => {
            let data = unsafe { event.data.rmdir };

            argf!(sf, "pathname: {}", format_path(&data.pathname, false));

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_unlink => {
            let data = unsafe { event.data.unlink };

            argf!(sf, "pathname: {}", format_path(&data.pathname, false));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_unlinkat => {
            let data = unsafe { event.data.unlinkat };

            argf!(sf, "dirfd: {}", format_dirfd(data.dirfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "flags: {}", format_at_flags(data.flags));
            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_symlink => {
            let data = unsafe { event.data.symlink };
            argf!(sf, "target: {}", format_path(&data.target, false));
            argf!(sf, "linkpath: {}", format_path(&data.linkpath, false));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_symlinkat => {
            let data = unsafe { event.data.symlinkat };
            argf!(sf, "target: {}", format_path(&data.target, false));
            argf!(sf, "newdirfd: {}", format_dirfd(data.newdirfd));
            argf!(sf, "linkpath: {}", format_path(&data.linkpath, false));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_shmat => {
            let data = unsafe { event.data.shmat };

            argf!(sf, "shmid: {}", data.shmid);
            argf!(sf, "shmaddr: 0x{:x}", data.shmaddr);
            argf!(sf, "shmflg: {}", format_shmflg(data.shmflg));

            finish!(sf, event.return_value);
        }

        syscalls::SYS_shmdt => {
            let data = unsafe { event.data.shmdt };

            argf!(sf, "shmaddr: 0x{:x}", data.shmaddr);

            finish!(sf, event.return_value);
        }

        syscalls::SYS_shmget => {
            let data = unsafe { event.data.shmget };

            argf!(sf, "key: 0x{:x}", data.key);
            argf!(sf, "size: {}", data.size);
            argf!(sf, "shmflg: {}", format_shmflg(data.shmflg));

            finish!(sf, event.return_value);
        }

        syscalls::SYS_shmctl => {
            let data = unsafe { event.data.shmctl };

            argf!(sf, "shmid: {}", data.shmid);
            argf!(sf, "cmd: {}", format_shmctl_cmd(data.cmd));

            arg!(sf, "buf:");
            if data.has_buf {
                format_shmid_ds(&mut sf, &data.buf).await?;
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_msgget => {
            let data = unsafe { event.data.msgget };

            argf!(sf, "key: 0x{:x}", data.key);
            argf!(sf, "msgflg: {}", format_msgflg(data.msgflg));

            finish!(sf, event.return_value);
        }

        syscalls::SYS_msgsnd => {
            let data = unsafe { event.data.msgsnd };

            argf!(sf, "msqid: {}", data.msqid);
            argf!(sf, "msgp: 0x{:x}", data.msgp);
            argf!(sf, "msgsz: {}", data.msgsz);
            argf!(sf, "msgflg: {}", format_msgflg(data.msgflg));

            finish!(sf, event.return_value);
        }

        syscalls::SYS_msgrcv => {
            let data = unsafe { event.data.msgrcv };

            argf!(sf, "msqid: {}", data.msqid);
            argf!(sf, "msgp: 0x{:x}", data.msgp);
            argf!(sf, "msgsz: {}", data.msgsz);
            argf!(sf, "msgtyp: {}", data.msgtyp);
            argf!(sf, "msgflg: {}", format_msgflg(data.msgflg));

            finish!(sf, event.return_value);
        }

        syscalls::SYS_msgctl => {
            let data = unsafe { event.data.msgctl };

            argf!(sf, "msqid: {}", data.msqid);
            argf!(sf, "cmd: {}", format_msgctl_cmd(data.op));

            arg!(sf, "buf:");
            if data.has_buf {
                format_msqid_ds(&mut sf, &data.buf).await?;
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_semget => {
            let data = unsafe { event.data.semget };

            argf!(sf, "key: 0x{:x}", data.key);
            argf!(sf, "nsems: {}", data.nsems);
            argf!(sf, "semflg: {}", format_semflg(data.semflg));

            finish!(sf, event.return_value);
        }

        syscalls::SYS_semop => {
            let data = unsafe { event.data.semop };

            argf!(sf, "semid: {}", data.semid);
            argf!(sf, "sops: 0x{:x}", data.sops);
            argf!(sf, "nsops: {}", data.nsops);

            finish!(sf, event.return_value);
        }

        syscalls::SYS_semctl => {
            let data = unsafe { event.data.semctl };

            argf!(sf, "semid: {}", data.semid);
            argf!(sf, "semnum: {}", data.semnum);
            argf!(sf, "op: {}", format_semctl_cmd(data.op));

            match data.op {
                // SETVAL expects .val
                libc::SETVAL => {
                    argf!(sf, "val: {}", unsafe { data.arg.val });
                }

                // SETALL and GETALL expect .array
                // FIXME: we need to look at the actual array in data.array, but we need to keep track
                // of the semget call ot know how many values are valid...
                libc::SETALL | libc::GETALL => {
                    argf!(sf, "array: 0x{:x}", unsafe { data.arg.array });
                }

                // IPC_STAT and IPC_SET expect .buf (struct semid_ds)
                libc::IPC_STAT | libc::IPC_SET => {
                    arg!(sf, "buf:");
                    format_semid_ds(&mut sf, unsafe { &data.arg.buf }).await?;
                }

                // IPC_INFO and SEM_INFO expect .info (struct seminfo)
                libc::IPC_INFO | libc::SEM_INFO => {
                    arg!(sf, "info:");
                    format_seminfo(&mut sf, unsafe { &data.arg.info }).await?;
                }

                // GETPID, GETVAL, GETNCNT, GETZCNT expect no union argument
                libc::GETPID | libc::GETVAL | libc::GETNCNT | libc::GETZCNT => {}

                // For unknown/unsupported ops, just show the raw union pointer
                _ => {
                    argf!(sf, "arg: 0x{:x} (unknown)", unsafe { data.arg.array });
                }
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_acct => {
            let data = unsafe { event.data.acct };
            argf!(sf, "filename: {}", format_path(&data.filename, false));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_getcpu => {
            let data = unsafe { event.data.getcpu };
            let cpu_val = if data.has_cpu {
                Cow::Owned(data.cpu.to_string())
            } else {
                Cow::Borrowed("NULL")
            };
            let node_val = if data.has_node {
                Cow::Owned(data.node.to_string())
            } else {
                Cow::Borrowed("NULL")
            };
            argf!(sf, "cpu: {}", cpu_val);
            argf!(sf, "node: {}", node_val);
            argf!(sf, "tcache: 0x{:x}", data.tcache);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_pidfd_open => {
            let data = unsafe { event.data.pidfd_open };
            argf!(sf, "pid: {}", data.pid);
            argf!(sf, "flags: {}", format_pidfd_open_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_pidfd_getfd => {
            let data = unsafe { event.data.pidfd_getfd };
            argf!(sf, "pidfd: {}", data.pidfd);
            argf!(sf, "targetfd: {}", data.targetfd);
            argf!(sf, "flags: 0x{:x}", data.flags);
            finish!(sf, event.return_value);
        }
        _ => {
            let data = unsafe { event.data.generic };

            for i in 0..data.args.len() {
                argf!(sf, "{}", data.args[i]);
            }

            finish!(sf, event.return_value, b" <STUB>");
        }
    };

    Ok(())
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
