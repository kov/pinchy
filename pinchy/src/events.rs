// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::borrow::Cow;

use log::{error, trace};
use pinchy_common::{
    compact_payload_size, kernel_types, syscalls, wire_validation_enabled, CloseData, EpollCtlData,
    EpollPWait2Data, EpollPWaitData, LseekData, OpenAt2Data, OpenAtData, Pipe2Data, PpollData,
    PreadData, Pselect6Data, PwriteData, ReadData, SpliceData, SyscallEvent, TeeData, VectorIOData,
    VmspliceData, WireEventHeader, WriteData,
};
#[cfg(target_arch = "x86_64")]
use pinchy_common::{PollData, SelectData, SendfileData};

use crate::{
    arg, argf, finish,
    format_helpers::{aio_constants, format_futex_waitv_flags, KEYCTL_WATCH_KEY, *},
    formatting::Formatter,
    ioctls::format_ioctl_request,
    raw, with_array, with_struct,
};

pub async fn handle_compact_event(
    header: &WireEventHeader,
    payload: &[u8],
    formatter: Formatter<'_>,
) -> anyhow::Result<bool> {
    let syscall_nr = match header.syscall_nr {
        syscalls::SYS_close
        | syscalls::SYS_openat
        | syscalls::SYS_read
        | syscalls::SYS_lseek
        | syscalls::SYS_write
        | syscalls::SYS_pread64
        | syscalls::SYS_pwrite64
        | syscalls::SYS_readv
        | syscalls::SYS_writev
        | syscalls::SYS_preadv
        | syscalls::SYS_pwritev
        | syscalls::SYS_preadv2
        | syscalls::SYS_pwritev2
        | syscalls::SYS_openat2
        | syscalls::SYS_epoll_pwait
        | syscalls::SYS_epoll_pwait2
        | syscalls::SYS_epoll_ctl
        | syscalls::SYS_ppoll
        | syscalls::SYS_pselect6
        | syscalls::SYS_pipe2
        | syscalls::SYS_splice
        | syscalls::SYS_tee
        | syscalls::SYS_vmsplice => header.syscall_nr,
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_epoll_wait
        | syscalls::SYS_poll
        | syscalls::SYS_select
        | syscalls::SYS_sendfile => header.syscall_nr,
        _ => return Ok(false),
    };

    if wire_validation_enabled() {
        let Some(expected_payload_size) = compact_payload_size(header.syscall_nr) else {
            return Ok(false);
        };

        if payload.len() != expected_payload_size {
            return Ok(true);
        }
    }

    let Ok(mut sf) = formatter.push_syscall(header.tid, syscall_nr).await else {
        error!("{} unknown syscall {}", header.tid, syscall_nr);
        return Ok(true);
    };

    match header.syscall_nr {
        syscalls::SYS_close => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const CloseData) };

            argf!(sf, "fd: {}", data.fd);
            finish!(sf, header.return_value);
        }
        syscalls::SYS_openat => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const OpenAtData) };

            argf!(sf, "dfd: {}", format_dirfd(data.dfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "flags: {}", format_flags(data.flags));
            argf!(sf, "mode: {}", format_mode(data.mode));
            finish!(sf, header.return_value);
        }
        syscalls::SYS_read => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const ReadData) };

            argf!(sf, "fd: {}", data.fd);

            if header.return_value >= 0 {
                let bytes_read = header.return_value as usize;
                let buf = &data.buf[..bytes_read.min(data.buf.len())];

                let left_over = if header.return_value as usize > buf.len() {
                    format!(
                        " ... ({} more bytes)",
                        header.return_value as usize - buf.len()
                    )
                } else {
                    String::new()
                };

                argf!(sf, "buf: {}{}", format_bytes(buf), left_over);
            } else {
                argf!(sf, "buf: <error>");
            }

            argf!(sf, "count: {}", data.count);
            finish!(sf, header.return_value);
        }

        syscalls::SYS_lseek => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const LseekData) };

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "offset: {}", data.offset);
            argf!(sf, "whence: {}", data.whence);
            finish!(sf, header.return_value);
        }
        syscalls::SYS_write => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const WriteData) };

            argf!(sf, "fd: {}", data.fd);

            if header.return_value >= 0 {
                let bytes_written = header.return_value as usize;
                let buf = &data.buf[..bytes_written.min(data.buf.len())];

                let left_over = if header.return_value as usize > buf.len() {
                    format!(
                        " ... ({} more bytes)",
                        header.return_value as usize - buf.len()
                    )
                } else {
                    String::new()
                };

                argf!(sf, "buf: {}{}", format_bytes(buf), left_over);
            } else {
                argf!(sf, "buf: <error>");
            }

            argf!(sf, "count: {}", data.count);
            finish!(sf, header.return_value);
        }
        syscalls::SYS_pread64 => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const PreadData) };

            argf!(sf, "fd: {}", data.fd);

            if header.return_value >= 0 {
                let bytes_read = header.return_value as usize;
                let buf = &data.buf[..bytes_read.min(data.buf.len())];

                let left_over = if header.return_value as usize > buf.len() {
                    format!(
                        " ... ({} more bytes)",
                        header.return_value as usize - buf.len()
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
            finish!(sf, header.return_value);
        }
        syscalls::SYS_pwrite64 => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const PwriteData) };

            argf!(sf, "fd: {}", data.fd);

            if header.return_value >= 0 {
                let bytes_written = header.return_value as usize;
                let buf = &data.buf[..bytes_written.min(data.buf.len())];

                let left_over = if header.return_value as usize > buf.len() {
                    format!(
                        " ... ({} more bytes)",
                        header.return_value as usize - buf.len()
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
            finish!(sf, header.return_value);
        }
        syscalls::SYS_readv
        | syscalls::SYS_writev
        | syscalls::SYS_preadv
        | syscalls::SYS_pwritev
        | syscalls::SYS_preadv2
        | syscalls::SYS_pwritev2 => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const VectorIOData) };

            argf!(sf, "fd: {}", data.fd);
            arg!(sf, "iov:");

            format_iovec_array(
                &mut sf,
                &data.iovecs,
                &data.iov_lens,
                &data.iov_bufs,
                data.read_count,
                &IovecFormatOptions::for_io_syscalls(),
            )
            .await?;

            argf!(sf, "iovcnt: {}", data.iovcnt);

            if header.syscall_nr == syscalls::SYS_preadv
                || header.syscall_nr == syscalls::SYS_pwritev
                || header.syscall_nr == syscalls::SYS_preadv2
                || header.syscall_nr == syscalls::SYS_pwritev2
            {
                argf!(sf, "offset: {}", data.offset);
            }

            if header.syscall_nr == syscalls::SYS_preadv2
                || header.syscall_nr == syscalls::SYS_pwritev2
            {
                argf!(sf, "flags: 0x{:x}", data.flags);
            }

            finish!(sf, header.return_value);
        }
        syscalls::SYS_openat2 => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const OpenAt2Data) };

            argf!(sf, "dfd: {}", format_dirfd(data.dfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            arg!(sf, "how:");
            with_struct!(sf, {
                argf!(sf, "flags: {}", format_flags(data.how.flags as i32));
                argf!(sf, "mode: {}", format_mode(data.how.mode as u32));
                argf!(sf, "resolve: {}", format_resolve_flags(data.how.resolve));
            });
            argf!(sf, "size: {}", data.size);

            finish!(sf, header.return_value);
        }
        syscalls::SYS_epoll_pwait => {
            let data =
                unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const EpollPWaitData) };

            argf!(sf, "epfd: {}", data.epfd);

            arg!(sf, "events:");
            with_array!(sf, {
                let nevents = (header.return_value as usize).min(data.events.len());
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
            finish!(sf, header.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_epoll_wait => {
            let data =
                unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const EpollPWaitData) };

            argf!(sf, "epfd: {}", data.epfd);

            arg!(sf, "events:");
            with_array!(sf, {
                let nevents = (header.return_value as usize).min(data.events.len());
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
            finish!(sf, header.return_value);
        }
        syscalls::SYS_epoll_pwait2 => {
            let data =
                unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const EpollPWait2Data) };

            argf!(sf, "epfd: {}", data.epfd);

            arg!(sf, "events:");
            with_array!(sf, {
                let nevents = (header.return_value as usize).min(data.events.len());
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
            finish!(sf, header.return_value);
        }
        syscalls::SYS_epoll_ctl => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const EpollCtlData) };

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
            finish!(sf, header.return_value);
        }
        syscalls::SYS_ppoll => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const PpollData) };
            arg!(sf, "fds:");
            with_array!(sf, {
                for i in 0..data.nfds as usize {
                    arg!(sf, "{");
                    raw!(sf, format!(" {}", data.fds[i]));

                    if data.events[i] != 0 {
                        raw!(
                            sf,
                            format!(", {}", poll_bits_to_strs(&data.events[i]).join("|"))
                        );
                    }

                    if data.revents[i] != 0 {
                        raw!(
                            sf,
                            format!(", {}", poll_bits_to_strs(&data.revents[i]).join("|"))
                        );
                    }

                    raw!(sf, " }");
                }
            });
            argf!(sf, "nfds: {}", data.nfds);
            arg!(sf, "timeout:");
            format_timespec(&mut sf, data.timeout).await?;
            arg!(sf, "sigmask");

            let extra_info = match header.return_value {
                0 => None,
                -1 => None,
                _ => Some(format!(
                    " [{}]",
                    data.fds.iter().zip(data.revents.iter()).join_take_map(
                        data.nfds as usize,
                        |(fd, event)| format!("{fd} = {}", poll_bits_to_strs(event).join("|"))
                    )
                )),
            };

            match extra_info {
                Some(extra) => finish!(sf, header.return_value, extra.as_bytes()),
                None => finish!(sf, header.return_value),
            };
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_poll => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const PollData) };
            arg!(sf, "fds:");
            with_array!(sf, {
                for i in 0..data.actual_nfds as usize {
                    arg!(sf, "pollfd");
                    with_struct!(sf, {
                        argf!(sf, "fd: {}", data.fds[i].fd);
                        argf!(
                            sf,
                            "events: {}",
                            crate::format_helpers::format_poll_events(data.fds[i].events)
                        );
                        argf!(
                            sf,
                            "revents: {}",
                            crate::format_helpers::format_poll_events(data.fds[i].revents)
                        );
                    });
                }
            });
            argf!(sf, "nfds: {}", data.nfds);
            argf!(sf, "timeout: {}", data.timeout);
            finish!(sf, header.return_value);
        }
        syscalls::SYS_pselect6 => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const Pselect6Data) };

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

            finish!(sf, header.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_select => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const SelectData) };

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

            finish!(sf, header.return_value);
        }
        syscalls::SYS_pipe2 => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const Pipe2Data) };
            arg!(sf, "pipefd:");
            with_array!(sf, {
                argf!(sf, "{}", data.pipefd[0]);
                argf!(sf, "{}", data.pipefd[1]);
            });
            argf!(sf, "flags: {}", format_pipe2_flags(data.flags));
            finish!(sf, header.return_value);
        }
        syscalls::SYS_splice => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const SpliceData) };

            argf!(sf, "fd_in: {}", data.fd_in);
            argf!(sf, "off_in: 0x{:x}", data.off_in);
            argf!(sf, "fd_out: {}", data.fd_out);
            argf!(sf, "off_out: 0x{:x}", data.off_out);
            argf!(sf, "len: {}", data.len);
            argf!(sf, "flags: {}", format_splice_flags(data.flags));

            finish!(sf, header.return_value);
        }
        syscalls::SYS_tee => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const TeeData) };

            argf!(sf, "fd_in: {}", data.fd_in);
            argf!(sf, "fd_out: {}", data.fd_out);
            argf!(sf, "len: {}", data.len);
            argf!(sf, "flags: {}", format_splice_flags(data.flags));

            finish!(sf, header.return_value);
        }
        syscalls::SYS_vmsplice => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const VmspliceData) };
            argf!(sf, "fd: {}", data.fd);
            arg!(sf, "iov:");
            format_iovec_array(
                &mut sf,
                &data.iovecs,
                &data.iov_lens,
                &data.iov_bufs,
                data.read_count,
                &IovecFormatOptions::for_io_syscalls(),
            )
            .await?;
            argf!(sf, "iovcnt: {}", data.iovcnt);
            argf!(sf, "flags: {}", format_splice_flags(data.flags));
            finish!(sf, header.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_sendfile => {
            let data = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const SendfileData) };

            argf!(sf, "out_fd: {}", data.out_fd);
            argf!(sf, "in_fd: {}", data.in_fd);

            if data.offset_is_null != 0 {
                arg!(sf, "offset: NULL");
            } else {
                argf!(sf, "offset: {}", data.offset);
            }

            argf!(sf, "count: {}", data.count);

            finish!(sf, header.return_value);
        }

        _ => return Ok(false),
    }

    Ok(true)
}

pub async fn handle_event(event: &SyscallEvent, formatter: Formatter<'_>) -> anyhow::Result<()> {
    trace!("handle_event for syscall {}", event.syscall_nr);

    let Ok(mut sf) = formatter.push_syscall(event.tid, event.syscall_nr).await else {
        error!("{} unknown syscall {}", event.tid, event.syscall_nr);
        return Ok(());
    };

    #[allow(unreachable_patterns)]
    match event.syscall_nr {
        syscalls::SYS_openat2
        | syscalls::SYS_epoll_pwait
        | syscalls::SYS_epoll_pwait2
        | syscalls::SYS_epoll_ctl
        | syscalls::SYS_ppoll
        | syscalls::SYS_pselect6
        | syscalls::SYS_pipe2
        | syscalls::SYS_splice
        | syscalls::SYS_tee
        | syscalls::SYS_vmsplice => {
            unreachable!("migrated syscall should be handled by compact path");
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_epoll_wait
        | syscalls::SYS_poll
        | syscalls::SYS_select
        | syscalls::SYS_sendfile => {
            unreachable!("migrated syscall should be handled by compact path");
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
        | syscalls::SYS_munlockall
        | syscalls::SYS_sync
        | syscalls::SYS_setsid
        | syscalls::SYS_vhangup => {
            finish!(sf, event.return_value);
        }
        syscalls::SYS_flock => {
            let data = unsafe { event.data.flock };
            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "operation: {}", format_flock_operation(data.operation));
            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_pause
        | syscalls::SYS_inotify_init
        | syscalls::SYS_getpgrp
        | syscalls::SYS_fork
        | syscalls::SYS_vfork => {
            finish!(sf, event.return_value);
        }
        syscalls::SYS_capget | syscalls::SYS_capset => {
            let data = unsafe { event.data.capsetget };

            arg!(sf, "header:");
            with_struct!(sf, {
                argf!(sf, "version: 0x{:x}", data.header.version);
                argf!(sf, "pid: {}", data.header.pid);
            });

            arg!(sf, "data:");
            with_array!(sf, {
                for i in 0..data.data_count as usize {
                    let cap = data.data[i];
                    arg!(sf, "cap_data");
                    with_struct!(sf, {
                        argf!(sf, "effective: 0x{:x}", cap.effective,);
                        argf!(sf, "permitted: 0x{:x}", cap.permitted,);
                        argf!(sf, "inheritable: 0x{:x}", cap.inheritable,);
                    });
                }
            });

            raw!(
                sf,
                format!(
                    " (effective: {}, permitted: {}, inheritable: {}",
                    format_capabilities(
                        &data
                            .data
                            .iter()
                            .take(data.data_count as usize)
                            .map(|cap| cap.effective)
                            .collect::<Vec<_>>()
                    ),
                    format_capabilities(
                        &data
                            .data
                            .iter()
                            .take(data.data_count as usize)
                            .map(|cap| cap.permitted)
                            .collect::<Vec<_>>()
                    ),
                    format_capabilities(
                        &data
                            .data
                            .iter()
                            .take(data.data_count as usize)
                            .map(|cap| cap.inheritable)
                            .collect::<Vec<_>>()
                    ),
                )
            );

            finish!(sf, event.return_value);
        }
        syscalls::SYS_mlock => {
            let data = unsafe { event.data.mlock };
            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "len: {}", data.len);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_mlock2 => {
            let data = unsafe { event.data.mlock2 };
            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "len: {}", data.len);
            argf!(sf, "flags: {}", format_mlock2_flags(data.flags as u32));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_mlockall => {
            let data = unsafe { event.data.mlockall };
            argf!(sf, "flags: {}", format_mlockall_flags(data.flags));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_membarrier => {
            let data = unsafe { event.data.membarrier };
            argf!(sf, "cmd: {}", format_membarrier_cmd(data.cmd));
            argf!(sf, "flags: {}", format_membarrier_flags(data.flags));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_mremap => {
            let data = unsafe { event.data.mremap };
            argf!(sf, "old_address: 0x{:x}", data.old_address);
            argf!(sf, "old_size: {}", data.old_size);
            argf!(sf, "new_size: {}", data.new_size);
            argf!(sf, "flags: {}", format_mremap_flags(data.flags));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_msync => {
            let data = unsafe { event.data.msync };
            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "length: {}", data.length);
            argf!(sf, "flags: {}", format_msync_flags(data.flags));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_munlock => {
            let data = unsafe { event.data.munlock };
            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "len: {}", data.len);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_readahead => {
            let data = unsafe { event.data.readahead };
            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "offset: {}", data.offset);
            argf!(sf, "count: {}", data.count);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_setns => {
            let data = unsafe { event.data.setns };
            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "nstype: {}", format_clone_flags(data.nstype as u64));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_unshare => {
            let data = unsafe { event.data.unshare };
            argf!(sf, "flags: {}", format_clone_flags(data.flags as u64));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_memfd_secret => {
            let data = unsafe { event.data.memfd_secret };
            argf!(sf, "flags: {}", format_memfd_secret_flags(data.flags));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_userfaultfd => {
            let data = unsafe { event.data.userfaultfd };
            argf!(sf, "flags: {}", format_userfaultfd_flags(data.flags));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_pkey_alloc => {
            let data = unsafe { event.data.pkey_alloc };
            argf!(sf, "flags: {}", format_pkey_alloc_flags(data.flags));
            argf!(
                sf,
                "access_rights: {}",
                format_pkey_access_rights(data.access_rights)
            );
            finish!(sf, event.return_value);
        }
        syscalls::SYS_pkey_free => {
            let data = unsafe { event.data.pkey_free };
            argf!(sf, "pkey: {}", data.pkey);
            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_eventfd => {
            let data = unsafe { event.data.eventfd };
            argf!(sf, "initval: {}", data.initval);
            argf!(sf, "flags: {}", format_eventfd_flags(data.flags));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_eventfd2 => {
            let data = unsafe { event.data.eventfd2 };
            argf!(sf, "initval: {}", data.initval);
            argf!(sf, "flags: {}", format_eventfd_flags(data.flags));
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
        syscalls::SYS_setxattr => {
            let data = unsafe { event.data.setxattr };
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "name: {}", format_path(&data.name, false));
            argf!(
                sf,
                "value: {}",
                format_bytes(&data.value[..data.size.min(data.value.len())])
            );
            argf!(sf, "size: {}", data.size);
            argf!(sf, "flags: {}", format_xattr_flags(data.flags));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_lsetxattr => {
            let data = unsafe { event.data.lsetxattr };
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "name: {}", format_path(&data.name, false));
            argf!(
                sf,
                "value: {}",
                format_bytes(&data.value[..data.size.min(data.value.len())])
            );
            argf!(sf, "size: {}", data.size);
            argf!(sf, "flags: {}", format_xattr_flags(data.flags));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_fsetxattr => {
            let data = unsafe { event.data.fsetxattr };
            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "name: {}", format_path(&data.name, false));
            argf!(
                sf,
                "value: {}",
                format_bytes(&data.value[..data.size.min(data.value.len())])
            );
            argf!(sf, "size: {}", data.size);
            argf!(sf, "flags: {}", format_xattr_flags(data.flags));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_getxattr => {
            let data = unsafe { event.data.getxattr };
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "name: {}", format_path(&data.name, false));

            if event.return_value > 0 {
                let bytes_read = event.return_value as usize;
                let buf = &data.value[..bytes_read.min(data.value.len())];
                argf!(sf, "value: {}", format_bytes(buf));
            } else {
                argf!(sf, "value: 0x{:x}", data.value.as_ptr() as u64);
            }

            argf!(sf, "size: {}", data.size);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_lgetxattr => {
            let data = unsafe { event.data.lgetxattr };
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "name: {}", format_path(&data.name, false));

            if event.return_value > 0 {
                let bytes_read = event.return_value as usize;
                let buf = &data.value[..bytes_read.min(data.value.len())];
                argf!(sf, "value: {}", format_bytes(buf));
            } else {
                argf!(sf, "value: 0x{:x}", data.value.as_ptr() as u64);
            }

            argf!(sf, "size: {}", data.size);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_fgetxattr => {
            let data = unsafe { event.data.fgetxattr };
            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "name: {}", format_path(&data.name, false));

            if event.return_value > 0 {
                let bytes_read = event.return_value as usize;
                let buf = &data.value[..bytes_read.min(data.value.len())];
                argf!(sf, "value: {}", format_bytes(buf));
            } else {
                argf!(sf, "value: 0x{:x}", data.value.as_ptr() as u64);
            }

            argf!(sf, "size: {}", data.size);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_removexattr => {
            let data = unsafe { event.data.removexattr };
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "name: {}", format_path(&data.name, false));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_lremovexattr => {
            let data = unsafe { event.data.lremovexattr };
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "name: {}", format_path(&data.name, false));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_fremovexattr => {
            let data = unsafe { event.data.fremovexattr };
            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "name: {}", format_path(&data.name, false));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_exit_group => {
            let data = unsafe { event.data.exit_group };
            argf!(sf, "status: {}", data.status);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_pipe2 => {
            let data = unsafe { event.data.pipe2 };
            arg!(sf, "pipefd:");
            with_array!(sf, {
                argf!(sf, "{}", data.pipefd[0]);
                argf!(sf, "{}", data.pipefd[1]);
            });
            argf!(sf, "flags: {}", format_pipe2_flags(data.flags));
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
        syscalls::SYS_inotify_add_watch => {
            let data = unsafe { event.data.inotify_add_watch };
            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "mask: {}", format_inotify_mask(data.mask));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_inotify_rm_watch => {
            let data = unsafe { event.data.inotify_rm_watch };
            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "wd: {}", data.wd);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_inotify_init1 => {
            let data = unsafe { event.data.inotify_init1 };
            argf!(sf, "flags: {}", format_inotify_init1_flags(data.flags));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_reboot => {
            let data = unsafe { event.data.reboot };

            argf!(sf, "magic1: {}", format_reboot_magic(data.magic1));
            argf!(sf, "magic2: {}", format_reboot_magic(data.magic2));
            argf!(sf, "cmd: {}", format_reboot_cmd(data.cmd));
            argf!(sf, "arg: 0x{:x}", data.arg);

            if data.has_restart2 {
                argf!(sf, "restart2: {}", format_path(&data.restart2, false));
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
        syscalls::SYS_adjtimex => {
            let data = unsafe { event.data.adjtimex };

            arg!(sf, "timex:");
            format_timex(&mut sf, &data.timex).await?;

            finish!(sf, event.return_value);
        }
        syscalls::SYS_clock_adjtime => {
            let data = unsafe { event.data.clock_adjtime };

            argf!(sf, "clockid: {}", format_clockid(data.clockid));
            arg!(sf, "timex:");
            format_timex(&mut sf, &data.timex).await?;

            finish!(sf, event.return_value);
        }
        syscalls::SYS_clock_getres | syscalls::SYS_clock_gettime | syscalls::SYS_clock_settime => {
            let data = unsafe { event.data.clock_time };

            argf!(sf, "clockid: {}", format_clockid(data.clockid));

            if event.syscall_nr == syscalls::SYS_clock_getres {
                arg!(sf, "res:");
            } else {
                arg!(sf, "tp:");
            }

            if data.has_tp {
                format_timespec(&mut sf, data.tp).await?;
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_timer_create => {
            let data = unsafe { event.data.timer_create };

            argf!(sf, "clockid: {}", format_clockid(data.clockid));

            if data.has_sevp {
                arg!(sf, "sevp:");
                with_struct!(sf, {
                    argf!(
                        sf,
                        "sigev_notify: {}",
                        format_sigev_notify(data.sevp.sigev_notify)
                    );
                    argf!(sf, "sigev_signo: {}", data.sevp.sigev_signo);
                    argf!(sf, "sigev_value.sival_int: {}", unsafe {
                        data.sevp.sigev_value.sival_int
                    });

                    // Show thread ID only when using SIGEV_THREAD_ID.
                    // TODO: parse the rest of the union?
                    if data.sevp.sigev_notify == pinchy_common::kernel_types::SIGEV_THREAD_ID {
                        argf!(sf, "sigev_notify_thread_id: {}", unsafe {
                            data.sevp.sigev_un.tid
                        });
                    }
                });
            } else {
                arg!(sf, "sevp: NULL");
            }

            arg!(sf, "timerid: <output>");

            finish!(sf, event.return_value);
        }
        syscalls::SYS_timer_delete => {
            let data = unsafe { event.data.timer_delete };

            argf!(sf, "timerid: {:#x}", data.timerid);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_timer_getoverrun => {
            let data = unsafe { event.data.timer_getoverrun };

            argf!(sf, "timerid: {:#x}", data.timerid);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_timer_gettime => {
            let data = unsafe { event.data.timer_gettime };

            argf!(sf, "timerid: {:#x}", data.timerid);
            arg!(sf, "curr_value:");
            format_itimerspec(&mut sf, data.curr_value).await?;

            finish!(sf, event.return_value);
        }
        syscalls::SYS_timer_settime => {
            let data = unsafe { event.data.timer_settime };

            argf!(sf, "timerid: {:#x}", data.timerid);
            argf!(sf, "flags: {}", format_timer_settime_flags(data.flags));

            if data.has_new_value {
                arg!(sf, "new_value:");
                format_itimerspec(&mut sf, data.new_value).await?;
            } else {
                arg!(sf, "new_value: NULL");
            }

            if data.has_old_value {
                arg!(sf, "old_value:");
                format_itimerspec(&mut sf, data.old_value).await?;
            } else {
                arg!(sf, "old_value: NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_timerfd_create => {
            let data = unsafe { event.data.timerfd_create };

            argf!(sf, "clockid: {}", format_clockid(data.clockid));
            argf!(sf, "flags: {}", format_timerfd_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_timerfd_gettime => {
            let data = unsafe { event.data.timerfd_gettime };

            argf!(sf, "fd: {}", data.fd);
            arg!(sf, "curr_value:");
            format_itimerspec(&mut sf, data.curr_value).await?;

            finish!(sf, event.return_value);
        }
        syscalls::SYS_timerfd_settime => {
            let data = unsafe { event.data.timerfd_settime };

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "flags: {}", format_timer_settime_flags(data.flags));

            if data.has_new_value {
                arg!(sf, "new_value:");
                format_itimerspec(&mut sf, data.new_value).await?;
            } else {
                arg!(sf, "new_value: NULL");
            }

            if data.has_old_value {
                arg!(sf, "old_value:");
                format_itimerspec(&mut sf, data.old_value).await?;
            } else {
                arg!(sf, "old_value: NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_getitimer => {
            let data = unsafe { event.data.getitimer };

            argf!(sf, "which: {}", format_timer_which(data.which));

            arg!(sf, "curr_value:");
            format_itimerval(&mut sf, &data.curr_value).await?;

            finish!(sf, event.return_value);
        }
        syscalls::SYS_setitimer => {
            let data = unsafe { event.data.setitimer };

            argf!(sf, "which: {}", format_timer_which(data.which));

            arg!(sf, "new_value:");
            format_itimerval(&mut sf, &data.new_value).await?;

            if data.has_old_value {
                arg!(sf, "old_value:");
                format_itimerval(&mut sf, &data.old_value).await?;
            } else {
                arg!(sf, "old_value: NULL");
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
        syscalls::SYS_sigaltstack => {
            let data = unsafe { event.data.sigaltstack };

            argf!(sf, "ss_ptr: 0x{:x}", data.ss_ptr);

            if data.has_ss {
                arg!(sf, "ss:");
                with_struct!(sf, {
                    argf!(sf, "ss_sp: 0x{:x}", data.ss.ss_sp);
                    argf!(sf, "ss_flags: {}", format_ss_flags(data.ss.ss_flags));
                    argf!(sf, "ss_size: {}", data.ss.ss_size);
                });
            } else {
                arg!(sf, "ss: NULL");
            }

            argf!(sf, "old_ss_ptr: 0x{:x}", data.old_ss_ptr);

            if data.has_old_ss {
                arg!(sf, "old_ss:");
                with_struct!(sf, {
                    argf!(sf, "ss_sp: 0x{:x}", data.old_ss.ss_sp);
                    argf!(sf, "ss_flags: {}", format_ss_flags(data.old_ss.ss_flags));
                    argf!(sf, "ss_size: {}", data.old_ss.ss_size);
                });
            } else {
                arg!(sf, "old_ss: NULL");
            }

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_signalfd => {
            let data = unsafe { event.data.signalfd };

            argf!(sf, "fd: {}", data.fd);

            if data.has_mask {
                argf!(
                    sf,
                    "mask: {}",
                    format_sigset(&data.mask, size_of::<kernel_types::Sigset>())
                );
            } else {
                arg!(sf, "mask: NULL");
            }

            argf!(sf, "flags: {}", format_signalfd_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_signalfd4 => {
            let data = unsafe { event.data.signalfd4 };

            argf!(sf, "fd: {}", data.fd);

            if data.has_mask {
                argf!(
                    sf,
                    "mask: {}",
                    format_sigset(&data.mask, size_of::<kernel_types::Sigset>())
                );
            } else {
                arg!(sf, "mask: NULL");
            }

            argf!(sf, "flags: {}", format_signalfd_flags(data.flags));

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
        syscalls::SYS_sched_getaffinity => {
            let data = unsafe { event.data.sched_getaffinity };
            argf!(sf, "pid: {}", data.pid);
            argf!(sf, "cpusetsize: {}", data.cpusetsize);
            argf!(sf, "mask: 0x{:x}", data.mask);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_sched_setaffinity => {
            let data = unsafe { event.data.sched_setaffinity };
            argf!(sf, "pid: {}", data.pid);
            argf!(sf, "cpusetsize: {}", data.cpusetsize);
            argf!(sf, "mask: 0x{:x}", data.mask);
            finish!(sf, event.return_value);
        }
        syscalls::SYS_sched_getparam => {
            let data = unsafe { event.data.sched_getparam };
            argf!(sf, "pid: {}", data.pid);
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
        syscalls::SYS_sched_getattr => {
            let data = unsafe { event.data.sched_getattr };
            argf!(sf, "pid: {}", data.pid);
            argf!(sf, "size: {}", data.size);
            argf!(
                sf,
                "flags: {}",
                crate::format_helpers::format_sched_attr_flags(data.flags as i32)
            );
            arg!(sf, "attr:");
            format_sched_attr(&mut sf, &data.attr).await?;
            finish!(sf, event.return_value);
        }
        syscalls::SYS_sched_setattr => {
            let data = unsafe { event.data.sched_setattr };
            argf!(sf, "pid: {}", data.pid);
            argf!(
                sf,
                "flags: {}",
                crate::format_helpers::format_sched_attr_flags(data.flags as i32)
            );
            arg!(sf, "attr:");
            format_sched_attr(&mut sf, &data.attr).await?;
            finish!(sf, event.return_value);
        }
        syscalls::SYS_sched_setparam => {
            let data = unsafe { event.data.sched_setparam };
            argf!(sf, "pid: {}", data.pid);
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
        syscalls::SYS_sched_rr_get_interval => {
            let data = unsafe { event.data.sched_rr_get_interval };
            argf!(sf, "pid: {}", data.pid);
            arg!(sf, "interval:");
            format_timespec(&mut sf, data.interval).await?;
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
        syscalls::SYS_openat2 => {
            let data = unsafe { event.data.openat2 };

            argf!(sf, "dfd: {}", format_dirfd(data.dfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            arg!(sf, "how:");
            with_struct!(sf, {
                argf!(sf, "flags: {}", format_flags(data.how.flags as i32));
                argf!(sf, "mode: {}", format_mode(data.how.mode as u32));
                argf!(sf, "resolve: {}", format_resolve_flags(data.how.resolve));
            });
            argf!(sf, "size: {}", data.size);

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
        syscalls::SYS_futex_waitv => {
            let data = unsafe { event.data.futex_waitv };

            arg!(sf, "waiters:");
            with_array!(sf, {
                let count = data.nr_waiters as usize;
                for i in 0..count {
                    let w = data.waiters[i];
                    arg!(sf, "waiter");
                    with_struct!(sf, {
                        argf!(sf, "uaddr: 0x{:x}", w.uaddr);
                        argf!(sf, "val: {}", w.val);
                        argf!(sf, "flags: {}", format_futex_waitv_flags(w.flags));
                    });
                }
            });

            argf!(sf, "nr_waiters: {}", data.nr_waiters);
            argf!(sf, "flags: {}", format_futex_waitv_flags(data.flags));

            arg!(sf, "timeout:");
            if data.has_timeout {
                format_timespec(&mut sf, data.timeout).await?;
            } else {
                raw!(sf, " NULL");
            }

            argf!(sf, "clockid: {}", format_clockid(data.clockid));

            if event.return_value > 0 {
                finish!(sf, event.return_value, b" (woken)");
            } else {
                finish!(sf, event.return_value);
            }
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
        syscalls::SYS_execveat => {
            use std::{ffi::OsString, os::unix::ffi::OsStringExt};
            let data = unsafe { event.data.execveat };

            // Format dirfd
            let dirfd_str = format_dirfd(data.dirfd);

            // Format pathname, showing ... if truncated
            let pathname = format_path(&data.pathname, data.pathname_truncated);

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

            // Format flags
            let flags_str = format_execveat_flags(data.flags);

            argf!(sf, "dirfd: {}", dirfd_str);
            argf!(sf, "pathname: {}", pathname);
            argf!(sf, "argv: [{}]", argv_str);
            argf!(sf, "envp: [{}]", envp_str);
            argf!(sf, "flags: {}", flags_str);

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
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_getdents => {
            let data = unsafe { event.data.getdents };

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
                        argf!(sf, "name: {}", format_path(&dirent.d_name, false));
                    });
                }
            });

            finish!(sf, event.return_value);
        }
        syscalls::SYS_semtimedop => {
            let data = unsafe { event.data.semtimedop };

            argf!(sf, "semid: {}", data.semid);
            arg!(sf, "sops:");

            with_array!(sf, {
                for sop in data.sops.iter().take(core::cmp::min(data.nsops, 4)) {
                    arg!(sf, "sembuf");
                    with_struct!(sf, {
                        argf!(sf, "sem_num: {}", sop.sem_num);
                        argf!(sf, "sem_op: {}", sop.sem_op);
                        argf!(sf, "sem_flg: 0x{:x}", sop.sem_flg);
                    });
                }
            });

            argf!(sf, "nsops: {}", data.nsops);

            if data.timeout_is_null != 0 {
                argf!(sf, "timeout: NULL");
            } else {
                argf!(
                    sf,
                    "timeout: {{tv_sec: {}, tv_nsec: {}}}",
                    data.timeout.seconds,
                    data.timeout.nanos
                );
            }

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_sendfile => {
            let data = unsafe { event.data.sendfile };

            argf!(sf, "out_fd: {}", data.out_fd);
            argf!(sf, "in_fd: {}", data.in_fd);

            if data.offset_is_null != 0 {
                argf!(sf, "offset: NULL");
            } else {
                argf!(sf, "offset: {}", data.offset);
            }

            argf!(sf, "count: {}", data.count);

            finish!(sf, event.return_value);
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
            format_iovec_array(
                &mut sf,
                &data.iovecs,
                &data.iov_lens,
                &data.iov_bufs,
                data.read_count,
                &IovecFormatOptions::for_address_only(),
            )
            .await?;
            argf!(sf, "iovcnt: {}", data.iovcnt);
            argf!(sf, "advice: {}", format_madvise_advice(data.advice));
            argf!(sf, "flags: {}", data.flags);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_process_vm_readv => {
            let data = unsafe { event.data.process_vm };

            argf!(sf, "pid: {}", data.pid);
            arg!(sf, "local_iov:");
            format_iovec_array(
                &mut sf,
                &data.local_iovecs,
                &data.local_iov_lens,
                &data.local_iov_bufs,
                data.local_read_count,
                &IovecFormatOptions::for_process_vm(),
            )
            .await?;
            argf!(sf, "liovcnt: {}", data.local_iovcnt);
            arg!(sf, "remote_iov:");
            format_iovec_array(
                &mut sf,
                &data.remote_iovecs,
                &data.remote_iov_lens,
                &[], // No buffers for remote iovecs
                data.remote_read_count,
                &IovecFormatOptions::for_address_only(),
            )
            .await?;
            argf!(sf, "riovcnt: {}", data.remote_iovcnt);
            argf!(sf, "flags: {}", data.flags);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_process_vm_writev => {
            let data = unsafe { event.data.process_vm };

            argf!(sf, "pid: {}", data.pid);
            arg!(sf, "local_iov:");
            format_iovec_array(
                &mut sf,
                &data.local_iovecs,
                &data.local_iov_lens,
                &data.local_iov_bufs,
                data.local_read_count,
                &IovecFormatOptions::for_process_vm(),
            )
            .await?;
            argf!(sf, "liovcnt: {}", data.local_iovcnt);
            arg!(sf, "remote_iov:");
            format_iovec_array(
                &mut sf,
                &data.remote_iovecs,
                &data.remote_iov_lens,
                &[], // No buffers for remote iovecs
                data.remote_read_count,
                &IovecFormatOptions::for_address_only(),
            )
            .await?;
            argf!(sf, "riovcnt: {}", data.remote_iovcnt);
            argf!(sf, "flags: {}", data.flags);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_mbind => {
            let data = unsafe { event.data.mbind };

            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "len: {}", data.len);
            argf!(sf, "mode: {}", format_mpol_mode(data.mode));
            argf!(
                sf,
                "nodemask: {}",
                format_nodemask(&data.nodemask, data.nodemask_read_count)
            );
            argf!(sf, "maxnode: {}", data.maxnode);
            argf!(sf, "flags: {}", format_mpol_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_get_mempolicy => {
            let data = unsafe { event.data.get_mempolicy };

            if data.mode_valid {
                argf!(sf, "mode: {}", format_mpol_mode(data.mode_out));
            } else {
                arg!(sf, "mode: NULL");
            }

            if data.nodemask_read_count > 0 {
                argf!(
                    sf,
                    "nodemask: {}",
                    format_nodemask(&data.nodemask_out, data.nodemask_read_count)
                );
            } else {
                arg!(sf, "nodemask: NULL");
            }
            argf!(sf, "maxnode: {}", data.maxnode);
            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "flags: {}", format_get_mempolicy_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_set_mempolicy => {
            let data = unsafe { event.data.set_mempolicy };

            argf!(sf, "mode: {}", format_mpol_mode(data.mode));
            argf!(
                sf,
                "nodemask: {}",
                format_nodemask(&data.nodemask, data.nodemask_read_count)
            );
            argf!(sf, "maxnode: {}", data.maxnode);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_set_mempolicy_home_node => {
            let data = unsafe { event.data.set_mempolicy_home_node };

            argf!(sf, "start: 0x{:x}", data.start);
            argf!(sf, "len: {}", data.len);
            argf!(sf, "home_node: {}", data.home_node);
            // Note: kernel requires flags == 0, reserved for future use
            argf!(sf, "flags: {}", data.flags);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_migrate_pages => {
            let data = unsafe { event.data.migrate_pages };

            argf!(sf, "pid: {}", data.pid);
            argf!(sf, "maxnode: {}", data.maxnode);
            argf!(
                sf,
                "old_nodes: {}",
                format_nodemask(&data.old_nodes, data.old_nodes_read_count)
            );
            argf!(
                sf,
                "new_nodes: {}",
                format_nodemask(&data.new_nodes, data.new_nodes_read_count)
            );

            finish!(sf, event.return_value);
        }
        syscalls::SYS_move_pages => {
            let data = unsafe { event.data.move_pages };

            argf!(sf, "pid: {}", data.pid);
            argf!(sf, "count: {}", data.count);

            if data.pages_read_count > 0 {
                let pages: Vec<String> = data.pages[..data.pages_read_count as usize]
                    .iter()
                    .map(|p| format!("0x{:x}", p))
                    .collect();

                if data.pages_read_count < data.count as u32 && data.count > 8 {
                    argf!(
                        sf,
                        "pages: [{}... (showing {} of {})]",
                        pages.join(", "),
                        data.pages_read_count,
                        data.count
                    );
                } else {
                    argf!(sf, "pages: [{}]", pages.join(", "));
                }
            } else {
                arg!(sf, "pages: NULL");
            }

            if data.nodes_read_count > 0 {
                let nodes: Vec<String> = data.nodes[..data.nodes_read_count as usize]
                    .iter()
                    .map(|n| n.to_string())
                    .collect();

                if data.nodes_read_count < data.count as u32 && data.count > 8 {
                    argf!(
                        sf,
                        "nodes: [{}... (showing {} of {})]",
                        nodes.join(", "),
                        data.nodes_read_count,
                        data.count
                    );
                } else {
                    argf!(sf, "nodes: [{}]", nodes.join(", "));
                }
            } else {
                arg!(sf, "nodes: NULL");
            }

            if data.status_read_count > 0 {
                let status: Vec<String> = data.status[..data.status_read_count as usize]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();

                if data.status_read_count < data.count as u32 && data.count > 8 {
                    argf!(
                        sf,
                        "status: [{}... (showing {} of {})]",
                        status.join(", "),
                        data.status_read_count,
                        data.count
                    );
                } else {
                    argf!(sf, "status: [{}]", status.join(", "));
                }
            } else {
                arg!(sf, "status: NULL");
            }
            argf!(sf, "flags: {}", format_mpol_flags(data.flags as u32));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_mincore => {
            let data = unsafe { event.data.mincore };

            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "length: {}", data.length);

            if data.vec_read_count > 0 {
                const PAGE_SIZE: u64 = 4096;
                let num_pages = data.length.div_ceil(PAGE_SIZE) as usize;
                let residency: Vec<String> = data.vec[..data.vec_read_count as usize]
                    .iter()
                    .map(|&b| (b & 1).to_string())
                    .collect();

                if data.vec_read_count < num_pages as u32 {
                    argf!(
                        sf,
                        "vec: [{}... (showing {} of {} pages)]",
                        residency.join(","),
                        data.vec_read_count,
                        num_pages
                    );
                } else {
                    argf!(sf, "vec: [{}]", residency.join(","));
                }
            } else {
                arg!(sf, "vec: NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_memfd_create => {
            let data = unsafe { event.data.memfd_create };

            let name = format_path(&data.name, false);

            argf!(sf, "name: {}", name);
            argf!(sf, "flags: {}", format_memfd_create_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_pkey_mprotect => {
            let data = unsafe { event.data.pkey_mprotect };

            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "len: {}", data.len);
            argf!(sf, "prot: {}", format_mmap_prot(data.prot));
            argf!(sf, "pkey: {}", data.pkey);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_mseal => {
            let data = unsafe { event.data.mseal };

            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "len: {}", data.len);
            argf!(sf, "flags: {}", format_mseal_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_remap_file_pages => {
            let data = unsafe { event.data.remap_file_pages };

            argf!(sf, "addr: 0x{:x}", data.addr);
            argf!(sf, "size: {}", data.size);
            argf!(sf, "prot: {}", format_mmap_prot(data.prot));
            argf!(sf, "pgoff: {}", data.pgoff);
            argf!(sf, "flags: {}", format_mmap_flags(data.flags));

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
        syscalls::SYS_statx => {
            let data = unsafe { event.data.statx };
            argf!(sf, "dirfd: {}", format_dirfd(data.dirfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "flags: 0x{:x}", data.flags);
            argf!(sf, "mask: 0x{:x}", data.mask);
            argf!(sf, "statxbuf: 0x{:x}", data.statxbuf);
            arg!(sf, "struct statx:");
            if event.return_value == 0 {
                with_struct!(sf, {
                    format_statx(&mut sf, &data.statx).await?;
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
        syscalls::SYS_faccessat | syscalls::SYS_faccessat2 => {
            let data = unsafe { event.data.faccessat };

            argf!(sf, "dirfd: {}", format_dirfd(data.dirfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "mode: {}", format_access_mode(data.mode));

            if event.syscall_nr == syscalls::SYS_faccessat2 {
                argf!(sf, "flags: {}", format_at_flags(data.flags));
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_fallocate => {
            let data = unsafe { event.data.fallocate };

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "mode: {}", format_fallocate_mode(data.mode));
            argf!(sf, "offset: {}", data.offset);
            argf!(sf, "size: {}", data.size);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_set_robust_list => {
            let data = unsafe { event.data.set_robust_list };

            argf!(sf, "head: 0x{:x}", data.head);
            argf!(sf, "len: {}", data.len);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_get_robust_list => {
            let data = unsafe { event.data.get_robust_list };

            argf!(sf, "pid: {}", data.pid);

            if event.return_value == 0 {
                argf!(sf, "head: 0x{:x}", data.head);
                argf!(sf, "len: {}", data.len);
            } else {
                arg!(sf, "head: (content unavailable)");
                arg!(sf, "len: (content unavailable)");
            }

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

            if data.has_set_data {
                argf!(
                    sf,
                    "set: {}",
                    format_sigset(&data.set_data, data.sigsetsize)
                );
            } else if data.set != 0 {
                argf!(sf, "set: 0x{:x}", data.set);
            } else {
                arg!(sf, "set: NULL");
            }

            if data.has_oldset_data {
                argf!(
                    sf,
                    "oldset: {}",
                    format_sigset(&data.oldset_data, data.sigsetsize)
                );
            } else if data.oldset != 0 {
                argf!(sf, "oldset: 0x{:x}", data.oldset);
            } else {
                arg!(sf, "oldset: NULL");
            }

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
        syscalls::SYS_rt_sigpending => {
            let data = unsafe { event.data.rt_sigpending };

            if data.has_set_data {
                argf!(
                    sf,
                    "set: {}",
                    format_sigset(&data.set_data, data.sigsetsize)
                );
            } else if data.set != 0 {
                argf!(sf, "set: 0x{:x}", data.set);
            } else {
                arg!(sf, "set: NULL");
            }
            argf!(sf, "sigsetsize: {}", data.sigsetsize);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_rt_sigqueueinfo => {
            let data = unsafe { event.data.rt_sigqueueinfo };

            argf!(sf, "tgid: {}", data.tgid);
            argf!(sf, "sig: {}", format_signal_number(data.sig));
            argf!(sf, "uinfo: 0x{:x}", data.uinfo);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_rt_sigsuspend => {
            let data = unsafe { event.data.rt_sigsuspend };

            if data.has_mask_data {
                argf!(
                    sf,
                    "mask: {}",
                    format_sigset(&data.mask_data, data.sigsetsize)
                );
            } else if data.mask != 0 {
                argf!(sf, "mask: 0x{:x}", data.mask);
            } else {
                arg!(sf, "mask: NULL");
            }
            argf!(sf, "sigsetsize: {}", data.sigsetsize);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_rt_sigtimedwait => {
            let data = unsafe { event.data.rt_sigtimedwait };

            if data.has_set_data {
                argf!(
                    sf,
                    "set: {}",
                    format_sigset(&data.set_data, data.sigsetsize)
                );
            } else if data.set != 0 {
                argf!(sf, "set: 0x{:x}", data.set);
            } else {
                arg!(sf, "set: NULL");
            }

            if data.info != 0 {
                argf!(sf, "info: 0x{:x}", data.info);
            } else {
                arg!(sf, "info: NULL");
            }

            if data.timeout != 0 {
                argf!(sf, "timeout: 0x{:x}", data.timeout);
            } else {
                arg!(sf, "timeout: NULL");
            }

            argf!(sf, "sigsetsize: {}", data.sigsetsize);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_rt_tgsigqueueinfo => {
            let data = unsafe { event.data.rt_tgsigqueueinfo };

            argf!(sf, "tgid: {}", data.tgid);
            argf!(sf, "tid: {}", data.tid);
            argf!(sf, "sig: {}", format_signal_number(data.sig));
            argf!(sf, "uinfo: 0x{:x}", data.uinfo);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_setrlimit => {
            let data = unsafe { event.data.rlimit };

            argf!(sf, "resource: {}", format_resource_type(data.resource));

            if data.has_limit {
                arg!(sf, "limit:");
                with_struct!(sf, {
                    format_rlimit(&mut sf, &data.limit).await?;
                });
            } else {
                arg!(sf, "limit: NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_getrlimit => {
            let data = unsafe { event.data.rlimit };

            argf!(sf, "resource: {}", format_resource_type(data.resource));

            arg!(sf, "limit:");
            if data.has_limit && event.return_value == 0 {
                with_struct!(sf, {
                    format_rlimit(&mut sf, &data.limit).await?;
                });
            } else if data.has_limit {
                raw!(sf, " (content unavailable)");
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_prlimit64 => {
            let data = unsafe { event.data.prlimit };

            argf!(sf, "pid: {}", data.pid);
            argf!(
                sf,
                "resource: {}",
                crate::format_helpers::format_resource_type(data.resource)
            );

            // Handle new_limit
            if data.has_new {
                arg!(sf, "new_limit:");
                with_struct!(sf, {
                    crate::format_helpers::format_rlimit(&mut sf, &data.new_limit).await?;
                });
            } else {
                arg!(sf, "new_limit: NULL");
            }

            // Handle old_limit
            arg!(sf, "old_limit:");
            if data.has_old && event.return_value == 0 {
                with_struct!(sf, {
                    crate::format_helpers::format_rlimit(&mut sf, &data.old_limit).await?;
                });
            } else if data.has_old {
                raw!(sf, " (content unavailable)");
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_kcmp => {
            let data = unsafe { event.data.kcmp };

            argf!(sf, "pid1: {}", data.pid1);
            argf!(sf, "pid2: {}", data.pid2);
            argf!(
                sf,
                "type: {}",
                crate::format_helpers::format_kcmp_type(data.type_)
            );
            argf!(sf, "idx1: {}", data.idx1);
            argf!(sf, "idx2: {}", data.idx2);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_getgroups => {
            let data = unsafe { event.data.getgroups };

            argf!(sf, "size: {}", data.size);

            if data.groups_read_count > 0 {
                let groups: Vec<String> = data.groups[..data.groups_read_count as usize]
                    .iter()
                    .map(|g| g.to_string())
                    .collect();

                if data.groups_read_count < event.return_value as u32
                    && event.return_value > pinchy_common::GROUP_ARRAY_CAP as i64
                {
                    argf!(
                        sf,
                        "list: [{}... (showing {} of {})]",
                        groups.join(", "),
                        data.groups_read_count,
                        event.return_value
                    );
                } else {
                    argf!(sf, "list: [{}]", groups.join(", "));
                }
            } else if data.size == 0 {
                arg!(sf, "list: NULL");
            } else {
                argf!(sf, "list: []");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_setgroups => {
            let data = unsafe { event.data.setgroups };

            argf!(sf, "size: {}", data.size);

            if data.groups_read_count > 0 {
                let groups: Vec<String> = data.groups[..data.groups_read_count as usize]
                    .iter()
                    .map(|g| g.to_string())
                    .collect();

                if data.groups_read_count < data.size as u32
                    && data.size > pinchy_common::GROUP_ARRAY_CAP
                {
                    argf!(
                        sf,
                        "list: [{}... (showing {} of {})]",
                        groups.join(", "),
                        data.groups_read_count,
                        data.size
                    );
                } else {
                    argf!(sf, "list: [{}]", groups.join(", "));
                }
            } else {
                argf!(sf, "list: []");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_getresuid => {
            let data = unsafe { event.data.getresuid };

            argf!(sf, "ruid: {}", data.ruid);
            argf!(sf, "euid: {}", data.euid);
            argf!(sf, "suid: {}", data.suid);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_getresgid => {
            let data = unsafe { event.data.getresgid };

            argf!(sf, "rgid: {}", data.rgid);
            argf!(sf, "egid: {}", data.egid);
            argf!(sf, "sgid: {}", data.sgid);

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
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_mknod => {
            let data = unsafe { event.data.mknod };

            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(
                sf,
                "mode: {} ({})",
                format_mode(data.mode),
                format_file_type_from_mode(data.mode)
            );
            argf!(sf, "dev: {}", format_dev(data.dev));

            finish!(sf, event.return_value);
        }

        syscalls::SYS_mknodat => {
            let data = unsafe { event.data.mknodat };

            argf!(sf, "dirfd: {}", format_dirfd(data.dirfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(
                sf,
                "mode: {} ({})",
                format_mode(data.mode),
                format_file_type_from_mode(data.mode)
            );
            argf!(sf, "dev: {}", format_dev(data.dev));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_pivot_root => {
            let data = unsafe { event.data.pivot_root };

            argf!(sf, "new_root: {}", format_path(&data.new_root, false));
            argf!(sf, "put_old: {}", format_path(&data.put_old, false));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_chroot => {
            let data = unsafe { event.data.chroot };

            argf!(sf, "path: {}", format_path(&data.path, false));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_open_tree => {
            let data = unsafe { event.data.open_tree };

            argf!(sf, "dfd: {}", format_dirfd(data.dfd));
            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "flags: {}", format_open_tree_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_mount => {
            let data = unsafe { event.data.mount };

            if data.source[0] != 0 {
                argf!(sf, "source: {}", format_path(&data.source, false));
            } else {
                arg!(sf, "source: NULL");
            }
            argf!(sf, "target: {}", format_path(&data.target, false));
            if data.filesystemtype[0] != 0 {
                argf!(
                    sf,
                    "filesystemtype: \"{}\"",
                    extract_cstring_with_truncation(&data.filesystemtype)
                );
            } else {
                arg!(sf, "filesystemtype: NULL");
            }
            argf!(sf, "mountflags: {}", format_mount_flags(data.mountflags));
            if data.data != 0 {
                argf!(sf, "data: 0x{:x}", data.data);
            } else {
                arg!(sf, "data: NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_umount2 => {
            let data = unsafe { event.data.umount2 };

            argf!(sf, "target: {}", format_path(&data.target, false));
            argf!(sf, "flags: {}", format_umount_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_mount_setattr => {
            let data = unsafe { event.data.mount_setattr };

            argf!(sf, "dfd: {}", format_dirfd(data.dfd));
            argf!(sf, "path: {}", format_path(&data.path, false));
            argf!(sf, "flags: {}", format_mount_setattr_flags(data.flags));

            if data.has_attr {
                arg!(sf, "mount_attr:");
                with_struct!(sf, {
                    argf!(
                        sf,
                        "attr_set: {}",
                        crate::format_helpers::format_mount_attr_flags(data.attr.attr_set)
                    );
                    argf!(
                        sf,
                        "attr_clr: {}",
                        crate::format_helpers::format_mount_attr_flags(data.attr.attr_clr)
                    );
                    argf!(
                        sf,
                        "propagation: {}",
                        crate::format_helpers::format_mount_attr_propagation(data.attr.propagation)
                    );
                    argf!(sf, "userns_fd: {}", data.attr.userns_fd);
                });
            } else {
                arg!(sf, "mount_attr: <unavailable>");
            }
            argf!(sf, "size: {}", data.size);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_move_mount => {
            let data = unsafe { event.data.move_mount };

            argf!(sf, "from_dfd: {}", format_dirfd(data.from_dfd));
            argf!(
                sf,
                "from_pathname: {}",
                format_path(&data.from_pathname, false)
            );
            argf!(sf, "to_dfd: {}", format_dirfd(data.to_dfd));
            argf!(sf, "to_pathname: {}", format_path(&data.to_pathname, false));
            argf!(sf, "flags: {}", format_move_mount_flags(data.flags));

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
        syscalls::SYS_sendto => {
            let data = unsafe { event.data.sendto };

            argf!(sf, "sockfd: {}", data.sockfd);

            if data.sent_len > 0 {
                let buf = &data.sent_data[..data.sent_len];
                let left_over = if data.size > buf.len() {
                    format!(" ... ({} more bytes)", data.size - buf.len())
                } else {
                    String::new()
                };
                argf!(sf, "buf: {}{}", format_bytes(buf), left_over);
            } else {
                argf!(sf, "buf: NULL");
            }

            argf!(sf, "size: {}", data.size);
            argf!(sf, "flags: {}", format_sendmsg_flags(data.flags));

            arg!(sf, "dest_addr:");
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
        syscalls::SYS_recvmmsg => {
            let data = unsafe { event.data.recvmmsg };

            argf!(sf, "sockfd: {}", data.sockfd);
            arg!(sf, "msgvec:");
            with_array!(sf, {
                for i in 0..data.msgs_count as usize {
                    with_struct!(sf, {
                        arg!(sf, "msg_hdr:");
                        with_struct!(sf, {
                            format_msghdr(&mut sf, &data.msgs[i].msg_hdr).await?;
                        });
                        argf!(sf, "msg_len: {}", data.msgs[i].msg_len);
                    });
                }
            });
            argf!(sf, "vlen: {}", data.vlen);
            argf!(sf, "flags: {}", format_recvmsg_flags(data.flags));

            if data.has_timeout {
                arg!(sf, "timeout:");
                with_struct!(sf, {
                    argf!(sf, "tv_sec: {}", data.timeout.seconds);
                    argf!(sf, "tv_nsec: {}", data.timeout.nanos);
                });
            } else {
                arg!(sf, "timeout: NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_sendmmsg => {
            let data = unsafe { event.data.sendmmsg };

            argf!(sf, "sockfd: {}", data.sockfd);
            arg!(sf, "msgvec:");
            with_array!(sf, {
                for i in 0..data.msgs_count as usize {
                    with_struct!(sf, {
                        arg!(sf, "msg_hdr:");
                        with_struct!(sf, {
                            format_msghdr(&mut sf, &data.msgs[i].msg_hdr).await?;
                        });
                        argf!(sf, "msg_len: {}", data.msgs[i].msg_len);
                    });
                }
            });
            argf!(sf, "vlen: {}", data.vlen);
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
        syscalls::SYS_socketpair => {
            let data = unsafe { event.data.socketpair };

            argf!(sf, "domain: {}", format_socket_domain(data.domain));
            argf!(sf, "type: {}", format_socket_type(data.type_));
            argf!(sf, "protocol: {}", data.protocol);

            // Show the resulting file descriptors only if successful
            if event.return_value == 0 {
                argf!(sf, "sv: [{}, {}]", data.sv[0], data.sv[1]);
            } else {
                arg!(sf, "sv: [?, ?]");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_getsockname => {
            let data = unsafe { event.data.getsockname };

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
        syscalls::SYS_getpeername => {
            let data = unsafe { event.data.getpeername };

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
        syscalls::SYS_setsockopt => {
            let data = unsafe { event.data.setsockopt };

            argf!(sf, "sockfd: {}", data.sockfd);
            argf!(sf, "level: {}", format_socket_level(data.level));
            argf!(
                sf,
                "optname: {}",
                format_socket_option(data.level, data.optname)
            );

            if data.optlen > 0 {
                let actual_len =
                    core::cmp::min(data.optlen as usize, pinchy_common::MEDIUM_READ_SIZE);
                argf!(sf, "optval: {}", format_bytes(&data.optval[..actual_len]));
            } else {
                arg!(sf, "optval: NULL");
            }

            argf!(sf, "optlen: {}", data.optlen);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_getsockopt => {
            let data = unsafe { event.data.getsockopt };

            argf!(sf, "sockfd: {}", data.sockfd);
            argf!(sf, "level: {}", format_socket_level(data.level));
            argf!(
                sf,
                "optname: {}",
                format_socket_option(data.level, data.optname)
            );

            if event.return_value >= 0 && data.optlen > 0 {
                let actual_len =
                    core::cmp::min(data.optlen as usize, pinchy_common::MEDIUM_READ_SIZE);
                argf!(sf, "optval: {}", format_bytes(&data.optval[..actual_len]));
            } else {
                arg!(sf, "optval: NULL");
            }

            argf!(sf, "optlen: {}", data.optlen);

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
        syscalls::SYS_waitid => {
            let data = unsafe { event.data.waitid };

            argf!(sf, "idtype: {}", format_waitid_idtype(data.idtype));

            // Format id based on idtype
            match data.idtype {
                0 => arg!(sf, "id: 0"),                   // P_ALL - id is ignored
                1 => argf!(sf, "id: {}", data.id as i32), // P_PID - show as signed PID
                2 => argf!(sf, "id: {}", data.id as i32), // P_PGID - show as signed PGID
                3 => argf!(sf, "id: {}", data.id),        // P_PIDFD - show as FD
                _ => argf!(sf, "id: {}", data.id),
            }

            arg!(sf, "infop:");
            if data.has_infop && event.return_value >= 0 {
                format_siginfo(&mut sf, &data.infop).await?;
            } else {
                raw!(sf, " NULL");
            }

            argf!(sf, "options: {}", format_wait_options(data.options));

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
                            crate::format_helpers::format_poll_events(data.fds[i].events)
                        );
                        argf!(
                            sf,
                            "revents: {}",
                            crate::format_helpers::format_poll_events(data.fds[i].revents)
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
            format_iovec_array(
                &mut sf,
                &data.iovecs,
                &data.iov_lens,
                &data.iov_bufs,
                data.read_count,
                &IovecFormatOptions::for_io_syscalls(),
            )
            .await?;
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
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_link => {
            let data = unsafe { event.data.link };
            argf!(sf, "oldpath: {}", format_path(&data.oldpath, false));
            argf!(sf, "newpath: {}", format_path(&data.newpath, false));
            finish!(sf, event.return_value);
        }
        syscalls::SYS_linkat => {
            let data = unsafe { event.data.linkat };
            argf!(sf, "olddirfd: {}", format_dirfd(data.olddirfd));
            argf!(sf, "oldpath: {}", format_path(&data.oldpath, false));
            argf!(sf, "newdirfd: {}", format_dirfd(data.newdirfd));
            argf!(sf, "newpath: {}", format_path(&data.newpath, false));
            argf!(sf, "flags: {}", format_at_flags(data.flags));
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
        syscalls::SYS_mq_open => {
            let data = unsafe { event.data.mq_open };

            argf!(sf, "name: 0x{:x}", data.name);
            argf!(sf, "flags: {}", format_mq_open_flags(data.flags));
            argf!(sf, "mode: {}", format_mode(data.mode));

            arg!(sf, "attr:");
            if data.has_attr {
                format_mq_attr(&mut sf, &data.attr).await?;
            } else {
                raw!(sf, " NULL");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_mq_unlink => {
            let data = unsafe { event.data.mq_unlink };

            argf!(sf, "name: 0x{:x}", data.name);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_mq_timedsend => {
            let data = unsafe { event.data.mq_timedsend };

            argf!(sf, "mqdes: {}", data.mqdes);
            argf!(sf, "msg_ptr: 0x{:x}", data.msg_ptr);
            argf!(sf, "msg_len: {}", data.msg_len);
            argf!(sf, "msg_prio: {}", data.msg_prio);
            argf!(sf, "abs_timeout: 0x{:x}", data.abs_timeout);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_mq_timedreceive => {
            let data = unsafe { event.data.mq_timedreceive };

            argf!(sf, "mqdes: {}", data.mqdes);
            argf!(sf, "msg_ptr: 0x{:x}", data.msg_ptr);
            argf!(sf, "msg_len: {}", data.msg_len);
            argf!(sf, "msg_prio: {}", data.msg_prio);
            argf!(sf, "abs_timeout: 0x{:x}", data.abs_timeout);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_mq_notify => {
            let data = unsafe { event.data.mq_notify };

            argf!(sf, "mqdes: {}", data.mqdes);
            argf!(sf, "sevp: 0x{:x}", data.sevp);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_mq_getsetattr => {
            let data = unsafe { event.data.mq_getsetattr };

            argf!(sf, "mqdes: {}", data.mqdes);

            arg!(sf, "newattr:");
            if data.has_newattr {
                format_mq_attr(&mut sf, &data.newattr).await?;
            } else {
                raw!(sf, " NULL");
            }

            arg!(sf, "oldattr:");
            if data.has_oldattr {
                format_mq_attr(&mut sf, &data.oldattr).await?;
            } else {
                raw!(sf, " NULL");
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
        syscalls::SYS_swapon => {
            let data = unsafe { event.data.swapon };

            argf!(sf, "pathname: {}", format_path(&data.pathname, false));
            argf!(sf, "flags: {}", format_swapon_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_swapoff => {
            let data = unsafe { event.data.swapoff };

            argf!(sf, "pathname: {}", format_path(&data.pathname, false));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_fstatfs => {
            let data = unsafe { event.data.fstatfs };

            argf!(sf, "fd: {}", data.fd);
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
        syscalls::SYS_fsopen => {
            let data = unsafe { event.data.fsopen };

            argf!(sf, "fsname: {}", format_path(&data.fsname, false));
            argf!(sf, "flags: {}", format_fsopen_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_fsconfig => {
            let data = unsafe { event.data.fsconfig };

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "cmd: {}", format_fsconfig_cmd(data.cmd));
            argf!(sf, "key: {}", format_path(&data.key, false));
            argf!(sf, "value: {}", format_path(&data.value, false));
            argf!(sf, "aux: {}", data.aux);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_fsmount => {
            let data = unsafe { event.data.fsmount };

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "flags: {}", format_fsmount_flags(data.flags));
            argf!(
                sf,
                "attr_flags: {}",
                format_fsmount_attr_flags(data.attr_flags)
            );

            finish!(sf, event.return_value);
        }
        syscalls::SYS_fspick => {
            let data = unsafe { event.data.fspick };

            argf!(sf, "dfd: {}", format_dirfd(data.dfd));
            argf!(sf, "path: {}", format_path(&data.path, false));
            argf!(sf, "flags: {}", format_fspick_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_init_module => {
            let data = unsafe { event.data.init_module };

            argf!(sf, "module_image: 0x{:x}", data.module_image);
            argf!(sf, "len: {}", data.len);
            argf!(
                sf,
                "param_values: {}",
                format_path(&data.param_values, false)
            );

            finish!(sf, event.return_value);
        }
        syscalls::SYS_finit_module => {
            let data = unsafe { event.data.finit_module };

            argf!(sf, "fd: {}", data.fd);
            argf!(
                sf,
                "param_values: {}",
                format_path(&data.param_values, false)
            );
            argf!(sf, "flags: {}", format_finit_module_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_delete_module => {
            let data = unsafe { event.data.delete_module };

            argf!(sf, "name: {}", format_path(&data.name, false));
            argf!(sf, "flags: {}", format_delete_module_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_sethostname => {
            let data = unsafe { event.data.sethostname };

            argf!(sf, "name: {}", format_path(&data.name, false));
            argf!(sf, "len: {}", data.len);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_setdomainname => {
            let data = unsafe { event.data.setdomainname };

            argf!(sf, "name: {}", format_path(&data.name, false));
            argf!(sf, "len: {}", data.len);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_io_uring_setup => {
            let data = unsafe { event.data.io_uring_setup };

            argf!(sf, "entries: {}", data.entries);
            argf!(sf, "params_ptr: 0x{:x}", data.params_ptr);

            if data.has_params {
                arg!(sf, "params:");
                with_struct!(sf, {
                    argf!(sf, "sq_entries: {}", data.params.sq_entries);
                    argf!(sf, "cq_entries: {}", data.params.cq_entries);
                    argf!(
                        sf,
                        "flags: {}",
                        format_io_uring_setup_flags(data.params.flags)
                    );
                    argf!(sf, "sq_thread_cpu: {}", data.params.sq_thread_cpu);
                    argf!(sf, "sq_thread_idle: {}", data.params.sq_thread_idle);
                    argf!(
                        sf,
                        "features: {}",
                        format_io_uring_features(data.params.features)
                    );
                    argf!(sf, "wq_fd: {}", data.params.wq_fd);
                });
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_io_uring_enter => {
            let data = unsafe { event.data.io_uring_enter };

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "to_submit: {}", data.to_submit);
            argf!(sf, "min_complete: {}", data.min_complete);
            argf!(sf, "flags: {}", format_io_uring_enter_flags(data.flags));
            argf!(sf, "sig: 0x{:x}", data.sig);
            argf!(sf, "sigsz: {}", data.sigsz);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_io_uring_register => {
            let data = unsafe { event.data.io_uring_register };

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "opcode: {}", format_io_uring_register_op(data.opcode));
            argf!(sf, "arg: 0x{:x}", data.arg);
            argf!(
                sf,
                "nr_args: {}",
                format_io_uring_register_nr_args(data.nr_args)
            );

            finish!(sf, event.return_value);
        }
        syscalls::SYS_io_setup => {
            let data = unsafe { event.data.io_setup };

            argf!(sf, "nr_events: {}", data.nr_events);
            argf!(sf, "ctx_idp: 0x{:x}", data.ctx_idp);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_io_destroy => {
            let data = unsafe { event.data.io_destroy };

            argf!(sf, "ctx_id: 0x{:x}", data.ctx_id);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_io_submit => {
            let data = unsafe { event.data.io_submit };

            argf!(sf, "ctx_id: 0x{:x}", data.ctx_id);
            argf!(sf, "nr: {}", data.nr);
            argf!(sf, "iocbpp: 0x{:x}", data.iocbpp);

            if data.iocb_count > 0 {
                arg!(sf, "iocbs:");
                with_array!(sf, {
                    for i in 0..data.iocb_count as usize {
                        let iocb = data.iocbs[i];
                        arg!(sf, "iocb");
                        with_struct!(sf, {
                            argf!(sf, "data: 0x{:x}", iocb.aio_data);
                            argf!(sf, "key: {}", iocb.aio_key);
                            argf!(sf, "rw_flags: {}", format_rwf_flags(iocb.aio_rw_flags));
                            argf!(sf, "lio_opcode: {}", format_iocb_cmd(iocb.aio_lio_opcode));
                            argf!(sf, "reqprio: {}", iocb.aio_reqprio);
                            argf!(sf, "fildes: {}", iocb.aio_fildes);
                            argf!(sf, "buf: 0x{:x}", iocb.aio_buf);
                            argf!(sf, "nbytes: {}", iocb.aio_nbytes);
                            argf!(sf, "offset: {}", iocb.aio_offset);
                            argf!(sf, "flags: {}", format_iocb_flags(iocb.aio_flags));
                            if iocb.aio_flags & aio_constants::IOCB_FLAG_RESFD != 0 {
                                argf!(sf, "resfd: {}", iocb.aio_resfd);
                            }
                        });
                    }
                });
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_io_cancel => {
            let data = unsafe { event.data.io_cancel };

            argf!(sf, "ctx_id: 0x{:x}", data.ctx_id);
            argf!(sf, "iocb: 0x{:x}", data.iocb);
            argf!(sf, "result: 0x{:x}", data.result);

            if data.has_result {
                arg!(sf, "result_event:");
                with_struct!(sf, {
                    argf!(sf, "data: 0x{:x}", data.result_event.data);
                    argf!(sf, "obj: 0x{:x}", data.result_event.obj);
                    argf!(sf, "res: {}", data.result_event.res);
                    argf!(sf, "res2: {}", data.result_event.res2);
                });
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_io_getevents => {
            let data = unsafe { event.data.io_getevents };

            argf!(sf, "ctx_id: 0x{:x}", data.ctx_id);
            argf!(sf, "min_nr: {}", data.min_nr);
            argf!(sf, "nr: {}", data.nr);
            argf!(sf, "events: 0x{:x}", data.events);

            if data.has_timeout {
                arg!(sf, "timeout:");
                format_timespec(&mut sf, data.timeout_data).await?;
            } else {
                argf!(sf, "timeout: NULL");
            }

            if data.event_count > 0 {
                arg!(sf, "events_returned:");
                with_array!(sf, {
                    for i in 0..data.event_count as usize {
                        let event = data.event_array[i];
                        arg!(sf, "event");
                        with_struct!(sf, {
                            argf!(sf, "data: 0x{:x}", event.data);
                            argf!(sf, "obj: 0x{:x}", event.obj);
                            argf!(sf, "res: {}", event.res);
                            argf!(sf, "res2: {}", event.res2);
                        });
                    }
                });
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_io_pgetevents => {
            let data = unsafe { event.data.io_pgetevents };

            argf!(sf, "ctx_id: 0x{:x}", data.ctx_id);
            argf!(sf, "min_nr: {}", data.min_nr);
            argf!(sf, "nr: {}", data.nr);
            argf!(sf, "events: 0x{:x}", data.events);

            if data.has_timeout {
                arg!(sf, "timeout:");
                format_timespec(&mut sf, data.timeout_data).await?;
            } else {
                argf!(sf, "timeout: NULL");
            }

            if data.has_usig {
                arg!(sf, "usig:");
                with_struct!(sf, {
                    argf!(sf, "sigmask: 0x{:x}", data.usig_data.sigmask);
                    argf!(sf, "sigsetsize: {}", data.usig_data.sigsetsize);
                    if data.usig_data.sigmask != 0 {
                        argf!(
                            sf,
                            "sigset: {}",
                            format_sigset(&data.sigset_data, data.usig_data.sigsetsize as usize)
                        );
                    }
                });
            } else {
                argf!(sf, "usig: NULL");
            }

            if data.event_count > 0 {
                arg!(sf, "events_returned:");
                with_array!(sf, {
                    for i in 0..data.event_count as usize {
                        let event = data.event_array[i];
                        arg!(sf, "event");
                        with_struct!(sf, {
                            argf!(sf, "data: 0x{:x}", event.data);
                            argf!(sf, "obj: 0x{:x}", event.obj);
                            argf!(sf, "res: {}", event.res);
                            argf!(sf, "res2: {}", event.res2);
                        });
                    }
                });
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_landlock_create_ruleset => {
            let data = unsafe { event.data.landlock_create_ruleset };

            argf!(sf, "attr: 0x{:x}", data.attr);
            argf!(sf, "size: {}", data.size);
            argf!(sf, "flags: {}", format_landlock_ruleset_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_landlock_add_rule => {
            let data = unsafe { event.data.landlock_add_rule };

            argf!(sf, "ruleset_fd: {}", data.ruleset_fd);
            argf!(
                sf,
                "rule_type: {}",
                format_landlock_rule_type(data.rule_type)
            );

            match data.rule_type {
                pinchy_common::LANDLOCK_RULE_PATH_BENEATH => {
                    let attr = unsafe { data.rule_attr_data.path_beneath };
                    argf!(sf, "parent_fd: {}", attr.parent_fd);
                    argf!(
                        sf,
                        "allowed_access: {}",
                        format_landlock_fs_access(attr.allowed_access)
                    );
                }
                pinchy_common::LANDLOCK_RULE_NET_PORT => {
                    let attr = unsafe { data.rule_attr_data.net_port };
                    argf!(sf, "port: {}", attr.port);
                    argf!(
                        sf,
                        "access_rights: {}",
                        format_landlock_net_access(attr.allowed_access)
                    );
                }
                _ => {
                    argf!(sf, "rule_attr: 0x{:x}", data.rule_attr);
                }
            }

            argf!(sf, "flags: {}", data.flags);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_landlock_restrict_self => {
            let data = unsafe { event.data.landlock_restrict_self };

            argf!(sf, "ruleset_fd: {}", data.ruleset_fd);
            argf!(sf, "flags: {}", data.flags);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_add_key => {
            let data = unsafe { event.data.add_key };

            let key_type = crate::format_helpers::extract_cstring_with_truncation(&data.key_type);
            let description =
                crate::format_helpers::extract_cstring_with_truncation(&data.description);

            argf!(sf, "type: \"{}\"", key_type);
            argf!(sf, "description: \"{}\"", description);

            if data.payload_len > 0 {
                let payload_bytes =
                    crate::format_helpers::format_bytes(&data.payload[..data.payload_len]);
                argf!(sf, "payload: {}", payload_bytes);
            } else {
                argf!(sf, "payload: (empty)");
            }

            argf!(
                sf,
                "keyring: {}",
                crate::format_helpers::format_key_spec_id(data.keyring)
            );

            finish!(sf, event.return_value);
        }
        syscalls::SYS_request_key => {
            let data = unsafe { event.data.request_key };

            let key_type = crate::format_helpers::extract_cstring_with_truncation(&data.key_type);
            let description =
                crate::format_helpers::extract_cstring_with_truncation(&data.description);

            argf!(sf, "type: \"{}\"", key_type);
            argf!(sf, "description: \"{}\"", description);

            if data.callout_info_len > 0 {
                let info = crate::format_helpers::extract_cstring_with_truncation(
                    &data.callout_info[..data.callout_info_len],
                );
                argf!(sf, "callout_info: \"{}\"", info);
            } else {
                argf!(sf, "callout_info: (null)");
            }

            argf!(
                sf,
                "dest_keyring: {}",
                crate::format_helpers::format_key_spec_id(data.dest_keyring)
            );

            finish!(sf, event.return_value);
        }
        syscalls::SYS_keyctl => {
            let data = unsafe { event.data.keyctl };

            let operation = data.operation;

            argf!(
                sf,
                "operation: {}",
                crate::format_helpers::format_keyctl_operation(operation)
            );

            let suffix: Option<&'static [u8]> = if event.return_value < 0 {
                Some(b" (error)")
            } else {
                let op_u32 = operation as u32;

                match op_u32 {
                    libc::KEYCTL_GET_KEYRING_ID
                    | libc::KEYCTL_JOIN_SESSION_KEYRING
                    | libc::KEYCTL_SEARCH
                    | libc::KEYCTL_GET_PERSISTENT
                    | libc::KEYCTL_ASSUME_AUTHORITY => Some(b" (key)"),
                    libc::KEYCTL_DESCRIBE
                    | libc::KEYCTL_READ
                    | libc::KEYCTL_GET_SECURITY
                    | libc::KEYCTL_DH_COMPUTE
                    | libc::KEYCTL_PKEY_QUERY
                    | libc::KEYCTL_PKEY_ENCRYPT
                    | libc::KEYCTL_PKEY_DECRYPT
                    | libc::KEYCTL_PKEY_SIGN
                    | libc::KEYCTL_PKEY_VERIFY
                    | libc::KEYCTL_CAPABILITIES => Some(b" (bytes)"),
                    _ => None,
                }
            };

            let op_u32 = operation as u32;

            match op_u32 {
                libc::KEYCTL_GET_KEYRING_ID => {
                    argf!(sf, "keyring: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "create: 0x{:x}", data.arg2);
                }
                libc::KEYCTL_JOIN_SESSION_KEYRING => {
                    argf!(sf, "name: 0x{:x}", data.arg1);
                }
                libc::KEYCTL_UPDATE => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "payload: 0x{:x}", data.arg2);
                    argf!(sf, "length: 0x{:x}", data.arg3);
                }
                libc::KEYCTL_REVOKE => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                }
                libc::KEYCTL_CHOWN => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "uid: 0x{:x}", data.arg2);
                    argf!(sf, "gid: 0x{:x}", data.arg3);
                }
                libc::KEYCTL_SETPERM => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "permissions: 0x{:x}", data.arg2);
                }
                libc::KEYCTL_DESCRIBE => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "buffer: 0x{:x}", data.arg2);
                    argf!(sf, "buflen: 0x{:x}", data.arg3);
                }
                libc::KEYCTL_CLEAR => {
                    argf!(sf, "keyring: {}", format_key_spec_id(data.arg1 as i32));
                }
                libc::KEYCTL_LINK | libc::KEYCTL_UNLINK => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "keyring: {}", format_key_spec_id(data.arg2 as i32));
                }
                libc::KEYCTL_SEARCH => {
                    argf!(sf, "keyring: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "type: 0x{:x}", data.arg2);
                    argf!(sf, "description: 0x{:x}", data.arg3);
                    argf!(sf, "dest_keyring: {}", format_key_spec_id(data.arg4 as i32));
                }
                libc::KEYCTL_READ => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "buffer: 0x{:x}", data.arg2);
                    argf!(sf, "buflen: 0x{:x}", data.arg3);
                }
                libc::KEYCTL_SET_REQKEY_KEYRING => {
                    argf!(
                        sf,
                        "reqkey_keyring: {}",
                        format_key_spec_id(data.arg1 as i32)
                    );
                }
                libc::KEYCTL_SET_TIMEOUT => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "timeout: 0x{:x}", data.arg2);
                }
                libc::KEYCTL_ASSUME_AUTHORITY => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                }
                libc::KEYCTL_GET_SECURITY => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "buffer: 0x{:x}", data.arg2);
                    argf!(sf, "buflen: 0x{:x}", data.arg3);
                }
                libc::KEYCTL_SESSION_TO_PARENT => {}
                libc::KEYCTL_REJECT => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "timeout: 0x{:x}", data.arg2);
                    argf!(sf, "error: -0x{:x}", data.arg3);
                }
                libc::KEYCTL_INSTANTIATE_IOV => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "iov: 0x{:x}", data.arg2);
                    argf!(sf, "iovlen: 0x{:x}", data.arg3);
                    argf!(sf, "keyring: {}", format_key_spec_id(data.arg4 as i32));
                }
                libc::KEYCTL_INVALIDATE => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                }
                libc::KEYCTL_GET_PERSISTENT => {
                    argf!(sf, "uid: 0x{:x}", data.arg1);
                    argf!(sf, "keyring: {}", format_key_spec_id(data.arg2 as i32));
                }
                libc::KEYCTL_DH_COMPUTE => {
                    argf!(sf, "params: 0x{:x}", data.arg1);
                    argf!(sf, "buffer: 0x{:x}", data.arg2);
                    argf!(sf, "buflen: 0x{:x}", data.arg3);
                }
                libc::KEYCTL_PKEY_QUERY
                | libc::KEYCTL_PKEY_ENCRYPT
                | libc::KEYCTL_PKEY_DECRYPT
                | libc::KEYCTL_PKEY_SIGN
                | libc::KEYCTL_PKEY_VERIFY => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "info: 0x{:x}", data.arg2);
                    argf!(sf, "buffer: 0x{:x}", data.arg3);
                    argf!(sf, "buflen: 0x{:x}", data.arg4);
                }
                libc::KEYCTL_RESTRICT_KEYRING => {
                    argf!(sf, "keyring: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "type: 0x{:x}", data.arg2);
                    argf!(sf, "restriction: 0x{:x}", data.arg3);
                }
                libc::KEYCTL_MOVE => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "from_keyring: {}", format_key_spec_id(data.arg2 as i32));
                    argf!(sf, "to_keyring: {}", format_key_spec_id(data.arg3 as i32));
                    argf!(sf, "flags: 0x{:x}", data.arg4);
                }
                libc::KEYCTL_CAPABILITIES => {
                    argf!(sf, "buffer: 0x{:x}", data.arg1);
                    argf!(sf, "buflen: 0x{:x}", data.arg2);
                }
                op_u32 if op_u32 == KEYCTL_WATCH_KEY => {
                    argf!(sf, "key: {}", format_key_spec_id(data.arg1 as i32));
                    argf!(sf, "watch_queue: 0x{:x}", data.arg2);
                    argf!(sf, "filter: 0x{:x}", data.arg3);
                    argf!(sf, "filter_len: 0x{:x}", data.arg4);
                }
                _ => {
                    argf!(sf, "arg1: 0x{:x}", data.arg1);
                    argf!(sf, "arg2: 0x{:x}", data.arg2);
                    argf!(sf, "arg3: 0x{:x}", data.arg3);
                    argf!(sf, "arg4: 0x{:x}", data.arg4);
                }
            }

            if let Some(suffix) = suffix {
                finish!(sf, event.return_value, suffix);
            } else {
                finish!(sf, event.return_value);
            }
        }
        syscalls::SYS_perf_event_open => {
            let data = unsafe { event.data.perf_event_open };

            arg!(sf, "attr:");
            format_perf_event_attr(&mut sf, &data.attr).await?;

            argf!(sf, "pid: {}", data.pid);
            argf!(sf, "cpu: {}", data.cpu);
            argf!(sf, "group_fd: {}", data.group_fd);
            argf!(
                sf,
                "flags: {}",
                crate::format_helpers::format_perf_event_open_flags(data.flags)
            );

            finish!(sf, event.return_value);
        }
        syscalls::SYS_bpf => {
            let data = unsafe { event.data.bpf };

            argf!(
                sf,
                "cmd: {}",
                crate::format_helpers::format_bpf_cmd(data.cmd)
            );

            match data.which_attr {
                1 => {
                    arg!(sf, "attr:");
                    with_struct!(sf, {
                        argf!(
                            sf,
                            "map_type: {}",
                            crate::format_helpers::format_bpf_map_type(
                                data.map_create_attr.map_type
                            )
                        );
                        argf!(sf, "key_size: {}", data.map_create_attr.key_size);
                        argf!(sf, "value_size: {}", data.map_create_attr.value_size);
                        argf!(sf, "max_entries: {}", data.map_create_attr.max_entries);
                    });
                }
                2 => {
                    let license_end = data
                        .license_str
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(data.license_str.len());
                    let license_str = std::str::from_utf8(&data.license_str[..license_end])
                        .unwrap_or("<invalid>");

                    arg!(sf, "attr:");
                    with_struct!(sf, {
                        argf!(
                            sf,
                            "prog_type: {}",
                            crate::format_helpers::format_bpf_prog_type(
                                data.prog_load_attr.prog_type
                            )
                        );
                        argf!(sf, "insn_cnt: {}", data.prog_load_attr.insn_cnt);
                        argf!(sf, "license: \"{}\"", license_str);
                    });
                }
                _ => {}
            }

            argf!(sf, "size: {}", data.size);

            // Some BPF commands return file descriptors on success
            let returns_fd = matches!(
                data.cmd,
                crate::format_helpers::bpf_constants::BPF_MAP_CREATE
                    | crate::format_helpers::bpf_constants::BPF_PROG_LOAD
                    | crate::format_helpers::bpf_constants::BPF_OBJ_GET
                    | crate::format_helpers::bpf_constants::BPF_PROG_GET_FD_BY_ID
                    | crate::format_helpers::bpf_constants::BPF_MAP_GET_FD_BY_ID
                    | crate::format_helpers::bpf_constants::BPF_BTF_GET_FD_BY_ID
                    | crate::format_helpers::bpf_constants::BPF_LINK_GET_FD_BY_ID
            );

            if returns_fd && event.return_value >= 0 {
                finish!(sf, event.return_value, b" (fd)");
            } else {
                finish!(sf, event.return_value);
            }
        }
        syscalls::SYS_syslog => {
            let data = unsafe { event.data.syslog };

            argf!(sf, "type: {}", format_syslog_type(data.type_));
            argf!(sf, "bufp: 0x{:x}", data.bufp);
            argf!(sf, "size: {}", data.size);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_ptrace => {
            let data = unsafe { event.data.ptrace };

            argf!(
                sf,
                "request: {}",
                crate::format_helpers::format_ptrace_request(data.request)
            );
            argf!(sf, "pid: {}", data.pid);

            // Context-aware formatting based on request type
            let request = data.request;

            if request == libc::PTRACE_CONT as i32
                || request == libc::PTRACE_SYSCALL as i32
                || request == libc::PTRACE_SINGLESTEP as i32
            {
                argf!(sf, "addr: 0x{:x}", data.addr);
                argf!(
                    sf,
                    "sig: {}",
                    crate::format_helpers::format_signal_number(data.data as i32)
                );
                finish!(sf, event.return_value);
            } else if request == libc::PTRACE_PEEKTEXT as i32
                || request == libc::PTRACE_PEEKDATA as i32
            {
                argf!(sf, "addr: 0x{:x}", data.addr);
                argf!(sf, "data: 0x{:x}", data.data);
                finish!(sf, event.return_value, b" (data ptr)");
            } else {
                argf!(sf, "addr: 0x{:x}", data.addr);
                argf!(sf, "data: 0x{:x}", data.data);
                finish!(sf, event.return_value);
            }
        }
        syscalls::SYS_seccomp => {
            let data = unsafe { event.data.seccomp };

            argf!(
                sf,
                "operation: {}",
                crate::format_helpers::format_seccomp_operation(data.operation)
            );
            argf!(
                sf,
                "flags: {}",
                crate::format_helpers::format_seccomp_flags(data.flags)
            );

            // Context-aware args formatting based on operation
            match data.operation {
                crate::format_helpers::seccomp_constants::SECCOMP_GET_ACTION_AVAIL => {
                    if data.args == 0 {
                        arg!(sf, "action: NULL");
                    } else if data.action_read_ok != 0 {
                        // Show the parsed action value only if read succeeded
                        argf!(
                            sf,
                            "action: {}",
                            crate::format_helpers::format_seccomp_action(data.action_avail)
                        );
                    } else {
                        // Read failed, show raw pointer
                        argf!(sf, "action: 0x{:x}", data.args);
                    }
                }
                crate::format_helpers::seccomp_constants::SECCOMP_SET_MODE_FILTER => {
                    if data.args == 0 {
                        arg!(sf, "prog: NULL");
                    } else if data.filter_len != 0 {
                        // Show the parsed filter length
                        argf!(
                            sf,
                            "prog: {{len: {}, filter: 0x{:x}}}",
                            data.filter_len,
                            data.args
                        );
                    } else {
                        argf!(sf, "prog: 0x{:x}", data.args);
                    }
                }
                crate::format_helpers::seccomp_constants::SECCOMP_GET_NOTIF_SIZES => {
                    if data.args == 0 {
                        arg!(sf, "sizes: NULL");
                    } else if data.notif_sizes[0] != 0
                        || data.notif_sizes[1] != 0
                        || data.notif_sizes[2] != 0
                    {
                        // Show the parsed notification sizes
                        argf!(
                            sf,
                            "sizes: {{notif: {}, resp: {}, data: {}}}",
                            data.notif_sizes[0],
                            data.notif_sizes[1],
                            data.notif_sizes[2]
                        );
                    } else {
                        argf!(sf, "sizes: 0x{:x}", data.args);
                    }
                }
                _ => {
                    // For other operations, show the raw args pointer
                    if data.args == 0 {
                        arg!(sf, "args: NULL");
                    } else {
                        argf!(sf, "args: 0x{:x}", data.args);
                    }
                }
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_restart_syscall => {
            let _data = unsafe { event.data.restart_syscall };

            finish!(sf, event.return_value);
        }
        syscalls::SYS_kexec_load => {
            let data = unsafe { event.data.kexec_load };

            argf!(sf, "entry: 0x{:x}", data.entry);
            argf!(sf, "nr_segments: {}", data.nr_segments);

            if data.segments_read > 0 {
                let segments: Vec<String> = data.parsed_segments[..data.segments_read as usize]
                    .iter()
                    .map(|seg| {
                        format!(
                            "{{buf: 0x{:x}, bufsz: {}, mem: 0x{:x}, memsz: {}}}",
                            seg.buf, seg.bufsz, seg.mem, seg.memsz
                        )
                    })
                    .collect();

                if data.segments_read < data.nr_segments
                    && data.nr_segments
                        > pinchy_common::kernel_types::KEXEC_SEGMENT_ARRAY_CAP as u64
                {
                    argf!(
                        sf,
                        "segments: [{}... (showing {} of {})]",
                        segments.join(", "),
                        data.segments_read,
                        data.nr_segments
                    );
                } else {
                    argf!(sf, "segments: [{}]", segments.join(", "));
                }
            } else if data.segments == 0 {
                arg!(sf, "segments: NULL");
            } else {
                argf!(sf, "segments: 0x{:x}", data.segments);
            }

            argf!(sf, "flags: {}", format_kexec_load_flags(data.flags));

            finish!(sf, event.return_value);
        }
        syscalls::SYS_fanotify_init => {
            let data = unsafe { event.data.fanotify_init };

            argf!(
                sf,
                "flags: {}",
                crate::format_helpers::format_fanotify_init_flags(data.flags)
            );
            argf!(
                sf,
                "event_f_flags: {}",
                crate::format_helpers::format_flags(data.event_f_flags as i32)
            );

            finish!(sf, event.return_value);
        }
        syscalls::SYS_fanotify_mark => {
            let data = unsafe { event.data.fanotify_mark };

            argf!(sf, "fanotify_fd: {}", data.fanotify_fd);
            argf!(
                sf,
                "flags: {}",
                crate::format_helpers::format_fanotify_mark_flags(data.flags)
            );
            argf!(
                sf,
                "mask: {}",
                crate::format_helpers::format_fanotify_mark_mask(data.mask)
            );
            argf!(
                sf,
                "dirfd: {}",
                crate::format_helpers::format_dirfd(data.dirfd)
            );

            let pathname = crate::format_helpers::extract_cstring_with_truncation(&data.pathname);
            if !pathname.is_empty() {
                argf!(sf, "pathname: \"{}\"", pathname);
            } else {
                argf!(sf, "pathname: (null)");
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_name_to_handle_at => {
            let data = unsafe { event.data.name_to_handle_at };

            argf!(
                sf,
                "dirfd: {}",
                crate::format_helpers::format_dirfd(data.dirfd)
            );

            let pathname = crate::format_helpers::extract_cstring_with_truncation(&data.pathname);
            if !pathname.is_empty() {
                argf!(sf, "pathname: \"{}\"", pathname);
            } else {
                argf!(sf, "pathname: (null)");
            }

            // Note: handle and mount_id are pointers to output parameters
            argf!(sf, "handle: 0x{:x}", data.handle);
            argf!(sf, "mount_id: 0x{:x}", data.mount_id);
            argf!(
                sf,
                "flags: {}",
                crate::format_helpers::format_at_flags(data.flags)
            );

            finish!(sf, event.return_value);
        }
        syscalls::SYS_open_by_handle_at => {
            let data = unsafe { event.data.open_by_handle_at };

            argf!(
                sf,
                "mount_fd: {}",
                crate::format_helpers::format_dirfd(data.mount_fd)
            );
            argf!(sf, "handle: 0x{:x}", data.handle);
            argf!(
                sf,
                "flags: {}",
                crate::format_helpers::format_flags(data.flags)
            );

            finish!(sf, event.return_value);
        }
        syscalls::SYS_copy_file_range => {
            let data = unsafe { event.data.copy_file_range };

            argf!(sf, "fd_in: {}", data.fd_in);

            if data.off_in_is_null != 0 {
                argf!(sf, "off_in: NULL");
            } else {
                argf!(sf, "off_in: {}", data.off_in);
            }

            argf!(sf, "fd_out: {}", data.fd_out);

            if data.off_out_is_null != 0 {
                argf!(sf, "off_out: NULL");
            } else {
                argf!(sf, "off_out: {}", data.off_out);
            }

            argf!(sf, "len: {}", data.len);
            argf!(sf, "flags: {}", data.flags);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_sync_file_range => {
            let data = unsafe { event.data.sync_file_range };

            argf!(sf, "fd: {}", data.fd);
            argf!(sf, "offset: {}", data.offset);
            argf!(sf, "nbytes: {}", data.nbytes);
            argf!(
                sf,
                "flags: {}",
                crate::format_helpers::format_sync_file_range_flags(data.flags)
            );

            finish!(sf, event.return_value);
        }
        syscalls::SYS_syncfs => {
            let data = unsafe { event.data.syncfs };

            argf!(sf, "fd: {}", data.fd);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_utimensat => {
            let data = unsafe { event.data.utimensat };

            argf!(
                sf,
                "dirfd: {}",
                crate::format_helpers::format_dirfd(data.dirfd)
            );

            let pathname = crate::format_helpers::extract_cstring_with_truncation(&data.pathname);

            if !pathname.is_empty() {
                argf!(sf, "pathname: \"{}\"", pathname);
            } else {
                argf!(sf, "pathname: (null)");
            }

            if data.times_is_null != 0 {
                argf!(sf, "times: NULL");
            } else {
                argf!(
                    sf,
                    "times: [{}, {}]",
                    crate::format_helpers::format_timespec_with_special(&data.times[0]),
                    crate::format_helpers::format_timespec_with_special(&data.times[1])
                );
            }

            argf!(
                sf,
                "flags: {}",
                crate::format_helpers::format_at_flags(data.flags)
            );

            finish!(sf, event.return_value);
        }
        syscalls::SYS_quotactl => {
            let data = unsafe { event.data.quotactl };

            argf!(
                sf,
                "op: {}",
                crate::format_helpers::format_quotactl_op(data.op)
            );
            argf!(sf, "special: {}", format_path(&data.special, false));
            argf!(sf, "id: {}", data.id);
            argf!(sf, "addr: 0x{:x}", data.addr);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_quotactl_fd => {
            let data = unsafe { event.data.quotactl_fd };

            argf!(sf, "fd: {}", data.fd);
            argf!(
                sf,
                "cmd: {}",
                crate::format_helpers::format_quotactl_op(data.cmd as i32)
            );
            argf!(sf, "id: {}", data.id);
            argf!(sf, "addr: 0x{:x}", data.addr);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_lookup_dcookie => {
            let data = unsafe { event.data.lookup_dcookie };

            argf!(sf, "cookie: {}", data.cookie);

            let buffer = format_path(&data.buffer, false);

            argf!(sf, "buffer: {}", buffer);
            argf!(sf, "size: {}", data.size);

            finish!(sf, event.return_value);
        }
        syscalls::SYS_nfsservctl => {
            let data = unsafe { event.data.nfsservctl };

            argf!(sf, "cmd: {}", data.cmd);
            argf!(sf, "argp: 0x{:x}", data.argp);
            argf!(sf, "resp: 0x{:x}", data.resp);

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_utime => {
            let data = unsafe { event.data.utime };

            let filename = format_path(&data.filename, false);

            argf!(sf, "filename: {}", filename);

            if data.times_is_null != 0 {
                argf!(sf, "times: NULL");
            } else {
                argf!(
                    sf,
                    "times: {{actime: {}, modtime: {}}}",
                    data.times.actime,
                    data.times.modtime
                );
            }

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_access => {
            let data = unsafe { event.data.access };

            let pathname = format_path(&data.pathname, false);

            argf!(sf, "pathname: {}", pathname);
            argf!(sf, "mode: {}", format_access_mode(data.mode));

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_chmod => {
            let data = unsafe { event.data.chmod };

            let pathname = format_path(&data.pathname, false);

            argf!(sf, "pathname: {}", pathname);
            argf!(sf, "mode: {}", format_mode(data.mode));

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_creat => {
            let data = unsafe { event.data.creat };

            let pathname = format_path(&data.pathname, false);

            argf!(sf, "pathname: {}", pathname);
            argf!(sf, "mode: {}", format_mode(data.mode));

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_mkdir => {
            let data = unsafe { event.data.mkdir };

            let pathname = format_path(&data.pathname, false);

            argf!(sf, "pathname: {}", pathname);
            argf!(sf, "mode: {}", format_mode(data.mode));

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_readlink => {
            let data = unsafe { event.data.readlink };

            let pathname = format_path(&data.pathname, false);
            let buf = format_path(&data.buf, false);

            argf!(sf, "pathname: {}", pathname);
            argf!(sf, "buf: {}", buf);
            argf!(sf, "bufsiz: {}", data.bufsiz);

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_stat => {
            let data = unsafe { event.data.stat };

            let pathname = format_path(&data.pathname, false);

            argf!(sf, "pathname: {}", pathname);
            arg!(sf, "statbuf:");
            format_stat(&mut sf, &data.statbuf).await?;

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_lstat => {
            let data = unsafe { event.data.lstat };

            let pathname = format_path(&data.pathname, false);

            argf!(sf, "pathname: {}", pathname);
            arg!(sf, "statbuf:");
            format_stat(&mut sf, &data.statbuf).await?;

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_utimes => {
            let data = unsafe { event.data.utimes };

            let filename = format_path(&data.filename, false);

            argf!(sf, "filename: {}", filename);

            if data.times_is_null != 0 {
                argf!(sf, "times: NULL");
            } else {
                argf!(
                    sf,
                    "times: [{{tv_sec: {}, tv_usec: {}}}, {{tv_sec: {}, tv_usec: {}}}]",
                    data.times[0].tv_sec,
                    data.times[0].tv_usec,
                    data.times[1].tv_sec,
                    data.times[1].tv_usec
                );
            }

            finish!(sf, event.return_value);
        }
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_futimesat => {
            let data = unsafe { event.data.futimesat };

            let pathname = format_path(&data.pathname, false);

            argf!(sf, "dirfd: {}", format_dirfd(data.dirfd));
            argf!(sf, "pathname: {}", pathname);

            if data.times_is_null != 0 {
                argf!(sf, "times: NULL");
            } else {
                argf!(
                    sf,
                    "times: [{{tv_sec: {}, tv_usec: {}}}, {{tv_sec: {}, tv_usec: {}}}]",
                    data.times[0].tv_sec,
                    data.times[0].tv_usec,
                    data.times[1].tv_sec,
                    data.times[1].tv_usec
                );
            }

            finish!(sf, event.return_value);
        }
        syscalls::SYS_close
        | syscalls::SYS_openat
        | syscalls::SYS_read
        | syscalls::SYS_lseek
        | syscalls::SYS_write
        | syscalls::SYS_pread64
        | syscalls::SYS_pwrite64
        | syscalls::SYS_readv
        | syscalls::SYS_writev
        | syscalls::SYS_preadv
        | syscalls::SYS_pwritev
        | syscalls::SYS_preadv2
        | syscalls::SYS_pwritev2 => {
            unreachable!();
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
