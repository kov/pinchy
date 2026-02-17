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
    syscalls, CloseData, EpollCtlData, EpollPWait2Data, EpollPWaitData, LseekData, OpenAt2Data,
    OpenAtData, Pipe2Data, PpollData, PreadData, Pselect6Data, PwriteData, ReadData, SpliceData,
    TeeData, VectorIOData, VmspliceData, WriteData,
};
#[cfg(x86_64)]
use pinchy_common::{PollData, SelectData, SendfileData};

#[cfg(x86_64)]
use crate::util::read_timeval;
use crate::util::{
    get_args, get_return_value, get_syscall_nr, read_epoll_events, read_iovec_array, read_timespec,
    submit_compact_payload, IovecOp,
};

#[tracepoint]
pub fn syscall_exit_basic_io(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = get_syscall_nr(&ctx)?;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_close => {
                submit_compact_payload::<CloseData, _>(
                    &ctx,
                    syscalls::SYS_close,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_openat => {
                submit_compact_payload::<OpenAtData, _>(
                    &ctx,
                    syscalls::SYS_openat,
                    return_value,
                    |payload| {
                        payload.dfd = args[0] as i32;
                        payload.flags = args[2] as i32;
                        payload.mode = args[3] as u32;

                        let pathname_ptr = args[1] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(
                                pathname_ptr as *const _,
                                &mut payload.pathname,
                            );
                        }
                    },
                )?;
            }
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
            }
            syscalls::SYS_write => {
                submit_compact_payload::<WriteData, _>(
                    &ctx,
                    syscalls::SYS_write,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.count = args[2];

                        let buf_addr = args[1];
                        if return_value > 0 {
                            let to_copy = core::cmp::min(return_value as usize, payload.buf.len());

                            unsafe {
                                let _ = bpf_probe_read_user_buf(
                                    buf_addr as *const _,
                                    &mut payload.buf[..to_copy],
                                );
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_pread64 => {
                submit_compact_payload::<PreadData, _>(
                    &ctx,
                    syscalls::SYS_pread64,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.count = args[2];
                        payload.offset = args[3] as i64;

                        let buf_addr = args[1];
                        if return_value > 0 {
                            let to_read = core::cmp::min(return_value as usize, payload.buf.len());

                            unsafe {
                                let _ = bpf_probe_read_user_buf(
                                    buf_addr as *const _,
                                    &mut payload.buf[..to_read],
                                );
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_pwrite64 => {
                submit_compact_payload::<PwriteData, _>(
                    &ctx,
                    syscalls::SYS_pwrite64,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.count = args[2];
                        payload.offset = args[3] as i64;

                        let buf_addr = args[1];
                        if return_value > 0 {
                            let to_copy = core::cmp::min(return_value as usize, payload.buf.len());

                            unsafe {
                                let _ = bpf_probe_read_user_buf(
                                    buf_addr as *const _,
                                    &mut payload.buf[..to_copy],
                                );
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_readv
            | syscalls::SYS_writev
            | syscalls::SYS_preadv
            | syscalls::SYS_pwritev
            | syscalls::SYS_preadv2
            | syscalls::SYS_pwritev2 => {
                submit_compact_payload::<VectorIOData, _>(
                    &ctx,
                    syscall_nr,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.iovcnt = args[2] as usize;

                        if syscall_nr == syscalls::SYS_preadv
                            || syscall_nr == syscalls::SYS_pwritev
                            || syscall_nr == syscalls::SYS_preadv2
                            || syscall_nr == syscalls::SYS_pwritev2
                        {
                            payload.offset = args[3] as i64;
                        }

                        if syscall_nr == syscalls::SYS_preadv2
                            || syscall_nr == syscalls::SYS_pwritev2
                        {
                            payload.flags = args[4] as u32;
                        }

                        let iov_addr = args[1] as u64;
                        let op = if syscall_nr == syscalls::SYS_readv
                            || syscall_nr == syscalls::SYS_preadv
                            || syscall_nr == syscalls::SYS_preadv2
                        {
                            IovecOp::Read
                        } else {
                            IovecOp::Write
                        };

                        read_iovec_array(
                            iov_addr,
                            payload.iovcnt,
                            op,
                            &mut payload.iovecs,
                            &mut payload.iov_lens,
                            Some(&mut payload.iov_bufs),
                            &mut payload.read_count,
                            return_value,
                        );
                    },
                )?;
            }
            syscalls::SYS_openat2 => {
                submit_compact_payload::<OpenAt2Data, _>(
                    &ctx,
                    syscalls::SYS_openat2,
                    return_value,
                    |payload| {
                        payload.dfd = args[0] as i32;
                        payload.size = args[3];

                        let pathname_ptr = args[1] as *const u8;
                        let how_ptr = args[2] as *const OpenHow;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(
                                pathname_ptr as *const _,
                                &mut payload.pathname,
                            );
                        }

                        unsafe {
                            if let Ok(how) = bpf_probe_read_user(how_ptr) {
                                payload.how = how;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_epoll_pwait => {
                submit_compact_payload::<EpollPWaitData, _>(
                    &ctx,
                    syscalls::SYS_epoll_pwait,
                    return_value,
                    |payload| {
                        payload.epfd = args[0] as i32;
                        payload.max_events = args[2] as i32;
                        payload.timeout = args[3] as i32;
                        read_epoll_events(
                            args[1] as *const _,
                            return_value as usize,
                            &mut payload.events,
                        );
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_epoll_wait => {
                submit_compact_payload::<EpollPWaitData, _>(
                    &ctx,
                    syscalls::SYS_epoll_wait,
                    return_value,
                    |payload| {
                        payload.epfd = args[0] as i32;
                        payload.max_events = args[2] as i32;
                        payload.timeout = args[3] as i32;
                        read_epoll_events(
                            args[1] as *const _,
                            return_value as usize,
                            &mut payload.events,
                        );
                    },
                )?;

                return Ok(());
            }
            syscalls::SYS_epoll_pwait2 => {
                submit_compact_payload::<EpollPWait2Data, _>(
                    &ctx,
                    syscalls::SYS_epoll_pwait2,
                    return_value,
                    |payload| {
                        payload.epfd = args[0] as i32;
                        payload.max_events = args[2] as i32;
                        payload.timeout = read_timespec(args[3] as *const Timespec);
                        payload.sigmask = args[4];
                        payload.sigsetsize = args[5];
                        read_epoll_events(
                            args[1] as *const _,
                            return_value as usize,
                            &mut payload.events,
                        );
                    },
                )?;
            }
            syscalls::SYS_epoll_ctl => {
                submit_compact_payload::<EpollCtlData, _>(
                    &ctx,
                    syscalls::SYS_epoll_ctl,
                    return_value,
                    |payload| {
                        payload.epfd = args[0] as i32;
                        payload.op = args[1] as i32;
                        payload.fd = args[2] as i32;
                        read_epoll_events(
                            args[3] as *const _,
                            1,
                            core::slice::from_mut(&mut payload.event),
                        );
                    },
                )?;
            }
            syscalls::SYS_ppoll => {
                submit_compact_payload::<PpollData, _>(
                    &ctx,
                    syscalls::SYS_ppoll,
                    return_value,
                    |payload| {
                        payload.nfds = args[1] as u32;
                        payload.timeout = read_timespec(args[2] as *const _);

                        let fds_ptr = args[0] as *const Pollfd;
                        for i in 0..payload.fds.len() {
                            if i < payload.nfds as usize {
                                unsafe {
                                    let entry_ptr = fds_ptr.add(i);
                                    if let Ok(pollfd) =
                                        bpf_probe_read_user::<Pollfd>(entry_ptr as *const _)
                                    {
                                        payload.fds[i] = pollfd.fd;
                                        payload.events[i] = pollfd.events;
                                        payload.revents[i] = pollfd.revents;
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_poll => {
                submit_compact_payload::<PollData, _>(
                    &ctx,
                    syscalls::SYS_poll,
                    return_value,
                    |payload| {
                        payload.nfds = args[1] as u32;
                        payload.timeout = args[2] as i32;

                        let mut fds_ptr = args[0] as *const Pollfd;
                        let fds = &mut payload.fds;

                        if !fds_ptr.is_null() && payload.nfds > 0 {
                            let max_fds = core::cmp::min(payload.nfds, 16) as usize;
                            for i in 0..max_fds {
                                fds_ptr = unsafe { fds_ptr.add(i) };

                                if fds_ptr.is_null() {
                                    break;
                                }

                                if let Ok(pollfd) =
                                    unsafe { bpf_probe_read_user::<Pollfd>(fds_ptr) }
                                {
                                    fds[i] = pollfd;
                                    payload.actual_nfds += 1;
                                } else {
                                    break;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_pselect6 => {
                submit_compact_payload::<Pselect6Data, _>(
                    &ctx,
                    syscalls::SYS_pselect6,
                    return_value,
                    |payload| {
                        payload.nfds = args[0] as i32;

                        let readfds_ptr = args[1] as *const u8;
                        let writefds_ptr = args[2] as *const u8;
                        let exceptfds_ptr = args[3] as *const u8;
                        let timeout_ptr = args[4] as *const Timespec;
                        let sigmask_ptr = args[5] as *const u8;

                        read_fdset(&mut payload.readfds, readfds_ptr, payload.nfds);
                        read_fdset(&mut payload.writefds, writefds_ptr, payload.nfds);
                        read_fdset(&mut payload.exceptfds, exceptfds_ptr, payload.nfds);

                        payload.timeout = read_timespec(timeout_ptr);

                        payload.has_readfds = !readfds_ptr.is_null();
                        payload.has_writefds = !writefds_ptr.is_null();
                        payload.has_exceptfds = !exceptfds_ptr.is_null();
                        payload.has_timeout = !timeout_ptr.is_null();
                        payload.has_sigmask = !sigmask_ptr.is_null();
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_select => {
                submit_compact_payload::<SelectData, _>(
                    &ctx,
                    syscalls::SYS_select,
                    return_value,
                    |payload| {
                        payload.nfds = args[0] as i32;

                        let readfds_ptr = args[1] as *const u8;
                        let writefds_ptr = args[2] as *const u8;
                        let exceptfds_ptr = args[3] as *const u8;
                        let timeout_ptr = args[4] as *const Timeval;

                        read_fdset(&mut payload.readfds, readfds_ptr, payload.nfds);
                        read_fdset(&mut payload.writefds, writefds_ptr, payload.nfds);
                        read_fdset(&mut payload.exceptfds, exceptfds_ptr, payload.nfds);

                        payload.timeout = if !timeout_ptr.is_null() {
                            read_timeval(timeout_ptr)
                        } else {
                            Timeval::default()
                        };

                        payload.has_readfds = !readfds_ptr.is_null();
                        payload.has_writefds = !writefds_ptr.is_null();
                        payload.has_exceptfds = !exceptfds_ptr.is_null();
                        payload.has_timeout = !timeout_ptr.is_null();
                    },
                )?;
            }
            syscalls::SYS_pipe2 => {
                submit_compact_payload::<Pipe2Data, _>(
                    &ctx,
                    syscalls::SYS_pipe2,
                    return_value,
                    |payload| {
                        payload.flags = args[1] as i32;

                        let pipefd_ptr = args[0] as *const i32;
                        let mut pipefd_bytes = [0u8; core::mem::size_of::<[i32; 2]>()];
                        unsafe {
                            let _ =
                                bpf_probe_read_user_buf(pipefd_ptr as *const u8, &mut pipefd_bytes);
                        }

                        payload.pipefd = unsafe {
                            core::mem::transmute::<[u8; core::mem::size_of::<[i32; 2]>()], [i32; 2]>(
                                pipefd_bytes,
                            )
                        };
                    },
                )?;
            }
            syscalls::SYS_splice => {
                submit_compact_payload::<SpliceData, _>(
                    &ctx,
                    syscalls::SYS_splice,
                    return_value,
                    |payload| {
                        payload.fd_in = args[0] as i32;
                        payload.off_in = args[1] as u64;
                        payload.fd_out = args[2] as i32;
                        payload.off_out = args[3] as u64;
                        payload.len = args[4] as usize;
                        payload.flags = args[5] as u32;
                    },
                )?;
            }
            syscalls::SYS_tee => {
                submit_compact_payload::<TeeData, _>(
                    &ctx,
                    syscalls::SYS_tee,
                    return_value,
                    |payload| {
                        payload.fd_in = args[0] as i32;
                        payload.fd_out = args[1] as i32;
                        payload.len = args[2] as usize;
                        payload.flags = args[3] as u32;
                    },
                )?;
            }
            syscalls::SYS_vmsplice => {
                submit_compact_payload::<VmspliceData, _>(
                    &ctx,
                    syscalls::SYS_vmsplice,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.iovcnt = args[2] as usize;
                        payload.flags = args[3] as u32;

                        let iov_addr = args[1] as u64;
                        read_iovec_array(
                            iov_addr,
                            payload.iovcnt,
                            IovecOp::Write,
                            &mut payload.iovecs,
                            &mut payload.iov_lens,
                            Some(&mut payload.iov_bufs),
                            &mut payload.read_count,
                            return_value,
                        );
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_sendfile => {
                submit_compact_payload::<SendfileData, _>(
                    &ctx,
                    syscalls::SYS_sendfile,
                    return_value,
                    |payload| {
                        payload.out_fd = args[0] as i32;
                        payload.in_fd = args[1] as i32;
                        payload.count = args[3] as usize;

                        let offset_ptr = args[2] as *const u64;

                        if offset_ptr.is_null() {
                            payload.offset_is_null = 1;
                        } else {
                            payload.offset_is_null = 0;
                            payload.offset =
                                unsafe { bpf_probe_read_user::<u64>(offset_ptr).unwrap_or(0) };
                        }
                    },
                )?;
            }
            syscalls::SYS_io_setup => {
                crate::util::submit_compact_payload::<pinchy_common::IoSetupData, _>(
                    &ctx,
                    syscalls::SYS_io_setup,
                    return_value,
                    |payload| {
                        payload.nr_events = args[0] as u32;
                        payload.ctx_idp = args[1] as u64;
                    },
                )?;
            }
            syscalls::SYS_io_destroy => {
                crate::util::submit_compact_payload::<pinchy_common::IoDestroyData, _>(
                    &ctx,
                    syscalls::SYS_io_destroy,
                    return_value,
                    |payload| {
                        payload.ctx_id = args[0] as u64;
                    },
                )?;
            }
            syscalls::SYS_io_submit => {
                crate::util::submit_compact_payload::<pinchy_common::IoSubmitData, _>(
                    &ctx,
                    syscalls::SYS_io_submit,
                    return_value,
                    |payload| {
                        payload.ctx_id = args[0] as u64;
                        payload.nr = args[1] as i64;
                        payload.iocbpp = args[2] as u64;

                        // Read bounded array of IOCBs
                        let nr_to_read = if payload.nr < 0 {
                            0
                        } else {
                            payload.nr as usize
                        };
                        let max_to_read = core::cmp::min(nr_to_read, payload.iocbs.len());
                        payload.iocb_count = max_to_read as u32;

                        if payload.iocbpp != 0 && max_to_read > 0 {
                            // Read array of IOCB pointers
                            let iocb_ptrs_ptr = payload.iocbpp as *const u64;
                            for i in 0..max_to_read {
                                unsafe {
                                    if let Ok(iocb_ptr) =
                                        bpf_probe_read_user::<u64>(iocb_ptrs_ptr.add(i))
                                    {
                                        if iocb_ptr != 0 {
                                            if let Ok(iocb) =
                                                bpf_probe_read_user::<IoCb>(iocb_ptr as *const _)
                                            {
                                                payload.iocbs[i] = iocb;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_io_cancel => {
                crate::util::submit_compact_payload::<pinchy_common::IoCancelData, _>(
                    &ctx,
                    syscalls::SYS_io_cancel,
                    return_value,
                    |payload| {
                        payload.ctx_id = args[0] as u64;
                        payload.iocb = args[1] as u64;
                        payload.result = args[2] as u64;

                        // Try to read result event if pointer is valid and syscall succeeded
                        payload.has_result = payload.result != 0 && return_value == 0;
                        if payload.has_result {
                            unsafe {
                                if let Ok(event) =
                                    bpf_probe_read_user::<IoEvent>(payload.result as *const _)
                                {
                                    payload.result_event = event;
                                } else {
                                    payload.has_result = false;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_io_getevents => {
                crate::util::submit_compact_payload::<pinchy_common::IoGeteventsData, _>(
                    &ctx,
                    syscalls::SYS_io_getevents,
                    return_value,
                    |payload| {
                        payload.ctx_id = args[0] as u64;
                        payload.min_nr = args[1] as i64;
                        payload.nr = args[2] as i64;
                        payload.events = args[3] as u64;
                        payload.timeout = args[4] as u64;

                        // Read timeout if provided
                        payload.has_timeout = payload.timeout != 0;
                        if payload.has_timeout {
                            payload.timeout_data = read_timespec(payload.timeout as *const _);
                        }

                        // Read bounded array of events if syscall succeeded
                        if payload.events != 0 && return_value > 0 {
                            let nr_events = return_value as usize;
                            let max_to_read = core::cmp::min(nr_events, payload.event_array.len());
                            payload.event_count = max_to_read as u32;

                            let events_ptr = payload.events as *const IoEvent;
                            for i in 0..max_to_read {
                                unsafe {
                                    if let Ok(event) =
                                        bpf_probe_read_user::<IoEvent>(events_ptr.add(i))
                                    {
                                        payload.event_array[i] = event;
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_io_pgetevents => {
                crate::util::submit_compact_payload::<pinchy_common::IoPgeteventsData, _>(
                    &ctx,
                    syscalls::SYS_io_pgetevents,
                    return_value,
                    |payload| {
                        payload.ctx_id = args[0] as u64;
                        payload.min_nr = args[1] as i64;
                        payload.nr = args[2] as i64;
                        payload.events = args[3] as u64;
                        payload.timeout = args[4] as u64;
                        payload.usig = args[5] as u64;

                        // Read timeout if provided
                        payload.has_timeout = payload.timeout != 0;
                        if payload.has_timeout {
                            payload.timeout_data = read_timespec(payload.timeout as *const _);
                        }

                        // Read signal set info if provided
                        payload.has_usig = payload.usig != 0;
                        if payload.has_usig {
                            unsafe {
                                if let Ok(aio_sigset) =
                                    bpf_probe_read_user::<AioSigset>(payload.usig as *const _)
                                {
                                    payload.usig_data = aio_sigset;

                                    // Try to read the actual sigset if pointer is valid
                                    if aio_sigset.sigmask != 0 && aio_sigset.sigsetsize <= 128 {
                                        if let Ok(sigset) = bpf_probe_read_user::<Sigset>(
                                            aio_sigset.sigmask as *const _,
                                        ) {
                                            payload.sigset_data = sigset;
                                        }
                                    }
                                }
                            }
                        }

                        // Read bounded array of events if syscall succeeded
                        if payload.events != 0 && return_value > 0 {
                            let nr_events = return_value as usize;
                            let max_to_read = core::cmp::min(nr_events, payload.event_array.len());
                            payload.event_count = max_to_read as u32;

                            let events_ptr = payload.events as *const IoEvent;
                            for i in 0..max_to_read {
                                unsafe {
                                    if let Ok(event) =
                                        bpf_probe_read_user::<IoEvent>(events_ptr.add(i))
                                    {
                                        payload.event_array[i] = event;
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_io_uring_setup => {
                crate::util::submit_compact_payload::<pinchy_common::IoUringSetupData, _>(
                    &ctx,
                    syscalls::SYS_io_uring_setup,
                    return_value,
                    |payload| {
                        payload.entries = args[0] as u32;
                        payload.params_ptr = args[1] as u64;

                        let params_ptr = args[1] as *const IoUringParams;
                        if !params_ptr.is_null() {
                            unsafe {
                                if let Ok(params) = bpf_probe_read_user(params_ptr) {
                                    payload.params = params;
                                    payload.has_params = true;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_io_uring_enter => {
                crate::util::submit_compact_payload::<pinchy_common::IoUringEnterData, _>(
                    &ctx,
                    syscalls::SYS_io_uring_enter,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.to_submit = args[1] as u32;
                        payload.min_complete = args[2] as u32;
                        payload.flags = args[3] as u32;
                        payload.sig = args[4] as u64;
                        payload.sigsz = args[5] as usize;
                    },
                )?;
            }
            syscalls::SYS_io_uring_register => {
                crate::util::submit_compact_payload::<pinchy_common::IoUringRegisterData, _>(
                    &ctx,
                    syscalls::SYS_io_uring_register,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.opcode = args[1] as u32;
                        payload.arg = args[2] as u64;
                        payload.nr_args = args[3] as u32;
                    },
                )?;
            }
            _ => {}
        }

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
