// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_user, bpf_probe_read_user_buf},
    macros::tracepoint,
    programs::TracePointContext,
};
#[cfg(x86_64)]
use pinchy_common::kernel_types::Timeval;
use pinchy_common::{
    kernel_types::{
        AioSigset, FdSet, IoCb, IoEvent, IoUringParams, OpenHow, Pollfd, Sigset, Timespec,
    },
    syscalls, LseekData, ReadData,
};

#[cfg(x86_64)]
use crate::util::read_timeval;
use crate::{
    data_mut,
    util::{
        get_args, get_return_value, get_syscall_nr, read_epoll_events, read_iovec_array,
        read_timespec, submit_compact_payload, Entry, IovecOp,
    },
};

#[tracepoint]
pub fn syscall_exit_basic_io(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = get_syscall_nr(&ctx)?;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_read => {
                submit_compact_payload::<ReadData, _>(
                    &ctx,
                    syscalls::SYS_read,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.count = args[2];

                        if return_value > 0 {
                            let to_read = core::cmp::min(return_value as usize, payload.buf.len());

                            unsafe {
                                let _ = bpf_probe_read_user_buf(
                                    args[1] as *const _,
                                    &mut payload.buf[..to_read],
                                );
                            }
                        }
                    },
                )?;

                return Ok(());
            }
            syscalls::SYS_lseek => {
                submit_compact_payload::<LseekData, _>(
                    &ctx,
                    syscalls::SYS_lseek,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.offset = args[1] as i64;
                        payload.whence = args[2] as i32;
                    },
                )?;

                return Ok(());
            }
            _ => {}
        }

        let mut entry = Entry::new(&ctx, syscall_nr)?;

        match syscall_nr {
            syscalls::SYS_openat => {
                let data = data_mut!(entry, openat);
                data.dfd = args[0] as i32;
                data.flags = args[2] as i32;
                data.mode = args[3] as u32;

                let pathname_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr as *const _, &mut data.pathname);
                }
            }
            syscalls::SYS_openat2 => {
                let data = data_mut!(entry, openat2);
                data.dfd = args[0] as i32;
                data.size = args[3];

                let pathname_ptr = args[1] as *const u8;
                let how_ptr = args[2] as *const OpenHow;

                // Read pathname
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }

                // Read struct open_how
                unsafe {
                    if let Ok(how) = bpf_probe_read_user(how_ptr) {
                        data.how = how;
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
                        let _ =
                            bpf_probe_read_user_buf(buf_addr as *const _, &mut data.buf[..to_copy]);
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
                        let _ =
                            bpf_probe_read_user_buf(buf_addr as *const _, &mut data.buf[..to_read]);
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
                        let _ =
                            bpf_probe_read_user_buf(buf_addr as *const _, &mut data.buf[..to_copy]);
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
                read_epoll_events(args[1] as *const _, return_value as usize, &mut data.events);
            }
            #[cfg(x86_64)]
            syscalls::SYS_epoll_wait => {
                let data = data_mut!(entry, epoll_wait);
                data.epfd = args[0] as i32;
                data.max_events = args[2] as i32;
                data.timeout = args[3] as i32;
                read_epoll_events(args[1] as *const _, return_value as usize, &mut data.events);
            }
            syscalls::SYS_epoll_pwait2 => {
                let data = data_mut!(entry, epoll_pwait2);
                data.epfd = args[0] as i32;
                data.max_events = args[2] as i32;
                data.timeout = read_timespec(args[3] as *const Timespec);
                data.sigmask = args[4];
                data.sigsetsize = args[5];
                read_epoll_events(args[1] as *const _, return_value as usize, &mut data.events);
            }
            syscalls::SYS_epoll_ctl => {
                let data = data_mut!(entry, epoll_ctl);
                data.epfd = args[0] as i32;
                data.op = args[1] as i32;
                data.fd = args[2] as i32;
                read_epoll_events(
                    args[3] as *const _,
                    1,
                    core::slice::from_mut(&mut data.event),
                );
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
                    let _ = bpf_probe_read_user_buf(pipefd_ptr as *const u8, &mut pipefd_bytes);
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
            syscalls::SYS_io_setup => {
                let data = data_mut!(entry, io_setup);
                data.nr_events = args[0] as u32;
                data.ctx_idp = args[1] as u64;
            }
            syscalls::SYS_io_destroy => {
                let data = data_mut!(entry, io_destroy);
                data.ctx_id = args[0] as u64;
            }
            syscalls::SYS_io_submit => {
                let data = data_mut!(entry, io_submit);
                data.ctx_id = args[0] as u64;
                data.nr = args[1] as i64;
                data.iocbpp = args[2] as u64;

                // Read bounded array of IOCBs
                let nr_to_read = if data.nr < 0 { 0 } else { data.nr as usize };
                let max_to_read = core::cmp::min(nr_to_read, data.iocbs.len());
                data.iocb_count = max_to_read as u32;

                if data.iocbpp != 0 && max_to_read > 0 {
                    // Read array of IOCB pointers
                    let iocb_ptrs_ptr = data.iocbpp as *const u64;
                    for i in 0..max_to_read {
                        unsafe {
                            if let Ok(iocb_ptr) = bpf_probe_read_user::<u64>(iocb_ptrs_ptr.add(i)) {
                                if iocb_ptr != 0 {
                                    if let Ok(iocb) =
                                        bpf_probe_read_user::<IoCb>(iocb_ptr as *const _)
                                    {
                                        data.iocbs[i] = iocb;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            syscalls::SYS_io_cancel => {
                let data = data_mut!(entry, io_cancel);
                data.ctx_id = args[0] as u64;
                data.iocb = args[1] as u64;
                data.result = args[2] as u64;

                // Try to read result event if pointer is valid and syscall succeeded
                data.has_result = data.result != 0 && return_value == 0;
                if data.has_result {
                    unsafe {
                        if let Ok(event) = bpf_probe_read_user::<IoEvent>(data.result as *const _) {
                            data.result_event = event;
                        } else {
                            data.has_result = false;
                        }
                    }
                }
            }
            syscalls::SYS_io_getevents => {
                let data = data_mut!(entry, io_getevents);
                data.ctx_id = args[0] as u64;
                data.min_nr = args[1] as i64;
                data.nr = args[2] as i64;
                data.events = args[3] as u64;
                data.timeout = args[4] as u64;

                // Read timeout if provided
                data.has_timeout = data.timeout != 0;
                if data.has_timeout {
                    data.timeout_data = read_timespec(data.timeout as *const _);
                }

                // Read bounded array of events if syscall succeeded
                if data.events != 0 && return_value > 0 {
                    let nr_events = return_value as usize;
                    let max_to_read = core::cmp::min(nr_events, data.event_array.len());
                    data.event_count = max_to_read as u32;

                    let events_ptr = data.events as *const IoEvent;
                    for i in 0..max_to_read {
                        unsafe {
                            if let Ok(event) = bpf_probe_read_user::<IoEvent>(events_ptr.add(i)) {
                                data.event_array[i] = event;
                            }
                        }
                    }
                }
            }
            syscalls::SYS_io_pgetevents => {
                let data = data_mut!(entry, io_pgetevents);
                data.ctx_id = args[0] as u64;
                data.min_nr = args[1] as i64;
                data.nr = args[2] as i64;
                data.events = args[3] as u64;
                data.timeout = args[4] as u64;
                data.usig = args[5] as u64;

                // Read timeout if provided
                data.has_timeout = data.timeout != 0;
                if data.has_timeout {
                    data.timeout_data = read_timespec(data.timeout as *const _);
                }

                // Read signal set info if provided
                data.has_usig = data.usig != 0;
                if data.has_usig {
                    unsafe {
                        if let Ok(aio_sigset) =
                            bpf_probe_read_user::<AioSigset>(data.usig as *const _)
                        {
                            data.usig_data = aio_sigset;

                            // Try to read the actual sigset if pointer is valid
                            if aio_sigset.sigmask != 0 && aio_sigset.sigsetsize <= 128 {
                                if let Ok(sigset) =
                                    bpf_probe_read_user::<Sigset>(aio_sigset.sigmask as *const _)
                                {
                                    data.sigset_data = sigset;
                                }
                            }
                        }
                    }
                }

                // Read bounded array of events if syscall succeeded
                if data.events != 0 && return_value > 0 {
                    let nr_events = return_value as usize;
                    let max_to_read = core::cmp::min(nr_events, data.event_array.len());
                    data.event_count = max_to_read as u32;

                    let events_ptr = data.events as *const IoEvent;
                    for i in 0..max_to_read {
                        unsafe {
                            if let Ok(event) = bpf_probe_read_user::<IoEvent>(events_ptr.add(i)) {
                                data.event_array[i] = event;
                            }
                        }
                    }
                }
            }
            syscalls::SYS_io_uring_setup => {
                let data = data_mut!(entry, io_uring_setup);
                data.entries = args[0] as u32;
                data.params_ptr = args[1] as u64;

                let params_ptr = args[1] as *const IoUringParams;
                if !params_ptr.is_null() {
                    unsafe {
                        if let Ok(params) = bpf_probe_read_user(params_ptr) {
                            data.params = params;
                            data.has_params = true;
                        }
                    }
                }
            }
            syscalls::SYS_io_uring_enter => {
                let data = data_mut!(entry, io_uring_enter);
                data.fd = args[0] as i32;
                data.to_submit = args[1] as u32;
                data.min_complete = args[2] as u32;
                data.flags = args[3] as u32;
                data.sig = args[4] as u64;
                data.sigsz = args[5] as usize;
            }
            syscalls::SYS_io_uring_register => {
                let data = data_mut!(entry, io_uring_register);
                data.fd = args[0] as i32;
                data.opcode = args[1] as u32;
                data.arg = args[2] as u64;
                data.nr_args = args[3] as u32;
            }
            #[cfg(x86_64)]
            syscalls::SYS_sendfile => {
                let data = data_mut!(entry, sendfile);

                data.out_fd = args[0] as i32;
                data.in_fd = args[1] as i32;
                data.count = args[3] as usize;

                let offset_ptr = args[2] as *const u64;

                if offset_ptr.is_null() {
                    data.offset_is_null = 1;
                } else {
                    data.offset_is_null = 0;
                    data.offset = unsafe { bpf_probe_read_user::<u64>(offset_ptr).unwrap_or(0) };
                }
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
        if bpf_probe_read_user_buf(fd_set_ptr, &mut fdset.bytes[..bytes_to_read]).is_ok() {
            fdset.len = bytes_to_read as u32;
        }
    }
}
