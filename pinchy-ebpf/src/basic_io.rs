// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_buf, bpf_probe_read_user},
    macros::tracepoint,
    programs::TracePointContext,
};
#[cfg(x86_64)]
use pinchy_common::kernel_types::Timeval;
use pinchy_common::{
    kernel_types::{EpollEvent, FdSet, Pollfd, Timespec},
    syscalls,
};

#[cfg(x86_64)]
use crate::util::read_timeval;
use crate::{
    data_mut,
    util::{
        get_args, get_return_value, get_syscall_nr, read_iovec_array, read_timespec, Entry, IovecOp,
    },
};

#[tracepoint]
pub fn syscall_exit_basic_io(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = get_syscall_nr(&ctx)?;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let mut entry = Entry::new(&ctx, syscall_nr)?;

        match syscall_nr {
            syscalls::SYS_openat => {
                let data = data_mut!(entry, openat);
                data.dfd = args[0] as i32;
                data.flags = args[2] as i32;
                data.mode = args[3] as u32;

                let pathname_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_buf(pathname_ptr as *const _, &mut data.pathname);
                }
            }
            syscalls::SYS_openat2 => {
                let data = data_mut!(entry, openat2);
                data.dfd = args[0] as i32;
                data.flags = args[2] as i32;
                data.mode = args[3] as u32;

                let pathname_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_buf(pathname_ptr as *const _, &mut data.pathname);
                }
            }
            syscalls::SYS_read => {
                let data = data_mut!(entry, read);
                data.fd = args[0] as i32;
                data.count = args[2];

                let buf_addr = args[1];
                if return_value > 0 {
                    let to_read = core::cmp::min(return_value as usize, data.buf.len());
                    unsafe {
                        let _ = bpf_probe_read_buf(buf_addr as *const _, &mut data.buf[..to_read]);
                    }
                }
            }
            syscalls::SYS_write => {
                let data = data_mut!(entry, write);
                data.fd = args[0] as i32;
                data.count = args[2];

                let buf_addr = args[1];
                if return_value > 0 {
                    let to_copy = core::cmp::min(return_value as usize, data.buf.len());
                    unsafe {
                        let _ = bpf_probe_read_buf(buf_addr as *const _, &mut data.buf[..to_copy]);
                    }
                }
            }
            syscalls::SYS_pread64 => {
                let data = data_mut!(entry, pread);
                data.fd = args[0] as i32;
                data.count = args[2];
                data.offset = args[3] as i64;

                let buf_addr = args[1];
                if return_value > 0 {
                    let to_read = core::cmp::min(return_value as usize, data.buf.len());
                    unsafe {
                        let _ = bpf_probe_read_buf(buf_addr as *const _, &mut data.buf[..to_read]);
                    }
                }
            }
            syscalls::SYS_pwrite64 => {
                let data = data_mut!(entry, pwrite);
                data.fd = args[0] as i32;
                data.count = args[2];
                data.offset = args[3] as i64;

                let buf_addr = args[1];
                if return_value > 0 {
                    let to_copy = core::cmp::min(return_value as usize, data.buf.len());
                    unsafe {
                        let _ = bpf_probe_read_buf(buf_addr as *const _, &mut data.buf[..to_copy]);
                    }
                }
            }
            syscalls::SYS_readv => {
                let data = data_mut!(entry, vector_io);
                data.fd = args[0] as i32;
                data.iovcnt = args[2] as usize;

                let iov_addr = args[1] as u64;
                read_iovec_array(
                    iov_addr,
                    data.iovcnt,
                    IovecOp::Read,
                    &mut data.iovecs,
                    &mut data.iov_lens,
                    Some(&mut data.iov_bufs),
                    &mut data.read_count,
                    return_value,
                );
            }
            syscalls::SYS_writev => {
                let data = data_mut!(entry, vector_io);
                data.fd = args[0] as i32;
                data.iovcnt = args[2] as usize;

                let iov_addr = args[1] as u64;
                read_iovec_array(
                    iov_addr,
                    data.iovcnt,
                    IovecOp::Write,
                    &mut data.iovecs,
                    &mut data.iov_lens,
                    Some(&mut data.iov_bufs),
                    &mut data.read_count,
                    return_value,
                );
            }
            syscalls::SYS_preadv => {
                let data = data_mut!(entry, vector_io);
                data.fd = args[0] as i32;
                data.iovcnt = args[2] as usize;
                data.offset = args[3] as i64;

                let iov_addr = args[1] as u64;
                read_iovec_array(
                    iov_addr,
                    data.iovcnt,
                    IovecOp::Read,
                    &mut data.iovecs,
                    &mut data.iov_lens,
                    Some(&mut data.iov_bufs),
                    &mut data.read_count,
                    return_value,
                );
            }
            syscalls::SYS_pwritev => {
                let data = data_mut!(entry, vector_io);
                data.fd = args[0] as i32;
                data.iovcnt = args[2] as usize;
                data.offset = args[3] as i64;

                let iov_addr = args[1] as u64;
                read_iovec_array(
                    iov_addr,
                    data.iovcnt,
                    IovecOp::Write,
                    &mut data.iovecs,
                    &mut data.iov_lens,
                    Some(&mut data.iov_bufs),
                    &mut data.read_count,
                    return_value,
                );
            }
            syscalls::SYS_preadv2 => {
                let data = data_mut!(entry, vector_io);
                data.fd = args[0] as i32;
                data.iovcnt = args[2] as usize;
                data.offset = args[3] as i64;
                data.flags = args[4] as u32;

                let iov_addr = args[1] as u64;
                read_iovec_array(
                    iov_addr,
                    data.iovcnt,
                    IovecOp::Read,
                    &mut data.iovecs,
                    &mut data.iov_lens,
                    Some(&mut data.iov_bufs),
                    &mut data.read_count,
                    return_value,
                );
            }
            syscalls::SYS_pwritev2 => {
                let data = data_mut!(entry, vector_io);
                data.fd = args[0] as i32;
                data.iovcnt = args[2] as usize;
                data.offset = args[3] as i64;
                data.flags = args[4] as u32;

                let iov_addr = args[1] as u64;
                read_iovec_array(
                    iov_addr,
                    data.iovcnt,
                    IovecOp::Write,
                    &mut data.iovecs,
                    &mut data.iov_lens,
                    Some(&mut data.iov_bufs),
                    &mut data.read_count,
                    return_value,
                );
            }
            syscalls::SYS_epoll_pwait => {
                let data = data_mut!(entry, epoll_pwait);
                data.epfd = args[0] as i32;
                data.max_events = args[2] as i32;
                data.timeout = args[3] as i32;

                let events_ptr = args[1] as *const EpollEvent;
                for (i, item) in data.events.iter_mut().enumerate() {
                    if i < return_value as usize {
                        unsafe {
                            let events_ptr = events_ptr.add(i);
                            if let Ok(evt) =
                                bpf_probe_read_user::<EpollEvent>(events_ptr as *const _)
                            {
                                *item = evt;
                            }
                        }
                    }
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_epoll_wait => {
                let data = data_mut!(entry, epoll_wait);
                data.epfd = args[0] as i32;
                data.max_events = args[2] as i32;
                data.timeout = args[3] as i32;

                let events_ptr = args[1] as *const EpollEvent;
                for (i, item) in data.events.iter_mut().enumerate() {
                    if i < return_value as usize {
                        unsafe {
                            let events_ptr = events_ptr.add(i);
                            if let Ok(evt) =
                                bpf_probe_read_user::<EpollEvent>(events_ptr as *const _)
                            {
                                *item = evt;
                            }
                        }
                    }
                }
            }
            syscalls::SYS_epoll_pwait2 => {
                let data = data_mut!(entry, epoll_pwait2);
                data.epfd = args[0] as i32;
                data.max_events = args[2] as i32;
                data.timeout = read_timespec(args[3] as *const Timespec);
                data.sigmask = args[4];
                data.sigsetsize = args[5];

                unsafe {
                    let events_ptr = args[1] as *const EpollEvent;
                    for (i, event) in data.events.iter_mut().enumerate() {
                        let event_ptr = events_ptr.add(i);
                        *event = bpf_probe_read_user(event_ptr).unwrap_or_default();
                    }
                }
            }
            syscalls::SYS_epoll_ctl => {
                let data = data_mut!(entry, epoll_ctl);
                data.epfd = args[0] as i32;
                data.op = args[1] as i32;
                data.fd = args[2] as i32;
                let event_ptr = args[3] as *const EpollEvent;
                if !event_ptr.is_null() {
                    data.event = unsafe { bpf_probe_read_user(event_ptr).unwrap_or_default() };
                }
            }
            syscalls::SYS_ppoll => {
                let data = data_mut!(entry, ppoll);
                data.nfds = args[1] as u32;
                data.timeout = read_timespec(args[2] as *const _);

                let fds_ptr = args[0] as *const Pollfd;
                for i in 0..data.fds.len() {
                    if i < data.nfds as usize {
                        unsafe {
                            let entry_ptr = fds_ptr.add(i);
                            if let Ok(pollfd) = bpf_probe_read_user::<Pollfd>(entry_ptr as *const _)
                            {
                                data.fds[i] = pollfd.fd;
                                data.events[i] = pollfd.events;
                                data.revents[i] = pollfd.revents;
                            }
                        }
                    }
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_poll => {
                let data = data_mut!(entry, poll);
                data.nfds = args[1] as u32;
                data.timeout = args[2] as i32;

                let mut fds_ptr = args[0] as *const Pollfd;
                let fds = &mut data.fds;

                // Only read pollfd array if pointer is valid and we have fds
                if !fds_ptr.is_null() && data.nfds > 0 {
                    let max_fds = core::cmp::min(data.nfds, 16) as usize;
                    for i in 0..max_fds {
                        fds_ptr = unsafe { fds_ptr.add(i) };

                        if fds_ptr.is_null() {
                            break;
                        }

                        if let Ok(pollfd) = unsafe { bpf_probe_read_user::<Pollfd>(fds_ptr) } {
                            fds[i] = pollfd;
                            data.actual_nfds += 1;
                        } else {
                            break;
                        }
                    }
                }
            }
            syscalls::SYS_pselect6 => {
                let data = data_mut!(entry, pselect6);
                data.nfds = args[0] as i32;

                let readfds_ptr = args[1] as *const u8;
                let writefds_ptr = args[2] as *const u8;
                let exceptfds_ptr = args[3] as *const u8;
                let timeout_ptr = args[4] as *const Timespec;
                let sigmask_ptr = args[5] as *const u8;

                read_fdset(&mut data.readfds, readfds_ptr, data.nfds);
                read_fdset(&mut data.writefds, writefds_ptr, data.nfds);
                read_fdset(&mut data.exceptfds, exceptfds_ptr, data.nfds);

                data.timeout = read_timespec(timeout_ptr);

                data.has_readfds = !readfds_ptr.is_null();
                data.has_writefds = !writefds_ptr.is_null();
                data.has_exceptfds = !exceptfds_ptr.is_null();
                data.has_timeout = !timeout_ptr.is_null();
                data.has_sigmask = !sigmask_ptr.is_null();
            }
            #[cfg(x86_64)]
            syscalls::SYS_select => {
                let data = data_mut!(entry, select);
                data.nfds = args[0] as i32;

                let readfds_ptr = args[1] as *const u8;
                let writefds_ptr = args[2] as *const u8;
                let exceptfds_ptr = args[3] as *const u8;
                let timeout_ptr = args[4] as *const Timeval;

                read_fdset(&mut data.readfds, readfds_ptr, data.nfds);
                read_fdset(&mut data.writefds, writefds_ptr, data.nfds);
                read_fdset(&mut data.exceptfds, exceptfds_ptr, data.nfds);

                data.timeout = if !timeout_ptr.is_null() {
                    read_timeval(timeout_ptr)
                } else {
                    Timeval::default()
                };

                data.has_readfds = !readfds_ptr.is_null();
                data.has_writefds = !writefds_ptr.is_null();
                data.has_exceptfds = !exceptfds_ptr.is_null();
                data.has_timeout = !timeout_ptr.is_null();
            }
            syscalls::SYS_pipe2 => {
                let data = data_mut!(entry, pipe2);
                data.flags = args[1] as i32;

                let pipefd_ptr = args[0] as *const i32;
                let mut pipefd_bytes = [0u8; core::mem::size_of::<[i32; 2]>()];
                unsafe {
                    let _ = bpf_probe_read_buf(pipefd_ptr as *const u8, &mut pipefd_bytes);
                }

                data.pipefd = unsafe {
                    core::mem::transmute::<[u8; core::mem::size_of::<[i32; 2]>()], [i32; 2]>(
                        pipefd_bytes,
                    )
                };
            }
            syscalls::SYS_splice => {
                let data = data_mut!(entry, splice);
                data.fd_in = args[0] as i32;
                data.off_in = args[1] as u64;
                data.fd_out = args[2] as i32;
                data.off_out = args[3] as u64;
                data.len = args[4] as usize;
                data.flags = args[5] as u32;
            }
            syscalls::SYS_tee => {
                let data = data_mut!(entry, tee);
                data.fd_in = args[0] as i32;
                data.fd_out = args[1] as i32;
                data.len = args[2] as usize;
                data.flags = args[3] as u32;
            }
            syscalls::SYS_vmsplice => {
                let data = data_mut!(entry, vmsplice);
                data.fd = args[0] as i32;
                data.iovcnt = args[2] as usize;
                data.flags = args[3] as u32;

                let iov_addr = args[1] as u64;
                read_iovec_array(
                    iov_addr,
                    data.iovcnt,
                    IovecOp::Write,
                    &mut data.iovecs,
                    &mut data.iov_lens,
                    Some(&mut data.iov_bufs),
                    &mut data.read_count,
                    return_value,
                );
            }
            _ => {
                entry.discard();
                return Ok(());
            }
        }

        entry.submit();
        Ok(())
    }

    if let Err(ret) = inner(ctx) {
        ret
    } else {
        0
    }
}

// Helper function to read fd_set from userspace as raw bytes
fn read_fdset(fdset: &mut FdSet, fd_set_ptr: *const u8, nfds: i32) {
    if fd_set_ptr.is_null() || nfds <= 0 {
        return;
    }

    // Calculate how many bytes we need to read to cover nfds file descriptors
    let bytes_needed = ((nfds + 7) / 8) as usize;
    let bytes_to_read = core::cmp::min(bytes_needed, fdset.bytes.len());

    unsafe {
        if bpf_probe_read_buf(fd_set_ptr, &mut fdset.bytes[..bytes_to_read]).is_ok() {
            fdset.len = bytes_to_read as u32;
        }
    }
}
