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
    syscalls::{
        SYS_epoll_pwait, SYS_fcntl, SYS_openat, SYS_pipe2, SYS_ppoll, SYS_pread64, SYS_preadv,
        SYS_preadv2, SYS_pwrite64, SYS_pwritev, SYS_pwritev2, SYS_read, SYS_readv, SYS_write,
        SYS_writev,
    },
    DATA_READ_SIZE,
};

#[cfg(x86_64)]
use crate::util::read_timeval;
use crate::{
    syscall_handler,
    util::{get_args, get_return_value, output_event, read_timespec, Entry},
};

#[tracepoint]
pub fn syscall_exit_openat(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_openat;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let dfd = args[0] as i32;
        let pathname_ptr = args[1] as *const u8;
        let flags = args[2] as i32;
        let mode = args[3] as u32;

        let mut pathname = [0u8; DATA_READ_SIZE];
        unsafe {
            let _ = bpf_probe_read_buf(pathname_ptr as *const _, &mut pathname);
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                openat: pinchy_common::OpenAtData {
                    dfd,
                    pathname,
                    flags,
                    mode,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_read(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_read;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let buf_addr = args[1];
        let count = args[2];

        let mut buf = [0u8; DATA_READ_SIZE];
        let to_read = core::cmp::min(return_value as usize, buf.len());
        unsafe {
            let _ = bpf_probe_read_buf(buf_addr as *const _, &mut buf[..to_read]);
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                read: pinchy_common::ReadData { fd, buf, count },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_fcntl(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_fcntl;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let cmd = args[1] as i32;
        let arg = args[2];

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                fcntl: pinchy_common::FcntlData { fd, cmd, arg },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_write(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_write;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let buf_addr = args[1];
        let count = args[2];

        let mut buf = [0u8; DATA_READ_SIZE];
        let to_copy = core::cmp::min(count as usize, buf.len());
        unsafe {
            let _ = bpf_probe_read_buf(buf_addr as *const _, &mut buf[..to_copy]);
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                write: pinchy_common::WriteData { fd, buf, count },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_pread64(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_pread64;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let buf_addr = args[1];
        let count = args[2];
        let offset = args[3] as i64;

        let mut buf = [0u8; DATA_READ_SIZE];
        let to_read = core::cmp::min(return_value as usize, buf.len());
        unsafe {
            let _ = bpf_probe_read_buf(buf_addr as *const _, &mut buf[..to_read]);
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                pread: pinchy_common::PreadData {
                    fd,
                    buf,
                    count,
                    offset,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_pwrite64(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_pwrite64;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let buf_addr = args[1];
        let count = args[2];
        let offset = args[3] as i64;

        let mut buf = [0u8; DATA_READ_SIZE];
        let to_copy = core::cmp::min(count as usize, buf.len());
        unsafe {
            let _ = bpf_probe_read_buf(buf_addr as *const _, &mut buf[..to_copy]);
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                pwrite: pinchy_common::PwriteData {
                    fd,
                    buf,
                    count,
                    offset,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_epoll_pwait(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_epoll_pwait;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let epfd = args[0] as i32;
        let events_ptr = args[1] as *const EpollEvent;
        let max_events = args[2] as i32;
        let timeout = args[3] as i32;

        let mut events = [EpollEvent::default(); 8];
        for (i, item) in events.iter_mut().enumerate() {
            if i < return_value as usize {
                unsafe {
                    let events_ptr = events_ptr.add(i);
                    if let Ok(evt) = bpf_probe_read_user::<EpollEvent>(events_ptr as *const _) {
                        *item = evt;
                    }
                }
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                epoll_pwait: pinchy_common::EpollPWaitData {
                    epfd,
                    events,
                    max_events,
                    timeout,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_ppoll(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_ppoll;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let nfds = args[1];
        let fds_ptr = args[0] as *const Pollfd;
        let mut fds = [0i32; 16];
        let mut events = [0i16; 16];
        let mut revents = [0i16; 16];
        for i in 0..fds.len() {
            if i < nfds {
                unsafe {
                    let entry_ptr = fds_ptr.add(i);
                    if let Ok(pollfd) = bpf_probe_read_user::<Pollfd>(entry_ptr as *const _) {
                        fds[i] = pollfd.fd;
                        events[i] = pollfd.events;
                        revents[i] = pollfd.revents;
                    }
                }
            }
        }
        let timeout = read_timespec(args[2] as *const _);

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                ppoll: pinchy_common::PpollData {
                    fds,
                    events,
                    revents,
                    nfds: nfds as u32,
                    timeout,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_pipe2(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_pipe2;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let pipefd_ptr = args[0] as *const i32;
        let flags = args[1] as i32;

        let mut pipefd_bytes = [0u8; core::mem::size_of::<[i32; 2]>()];
        unsafe {
            let _ = bpf_probe_read_buf(pipefd_ptr as *const u8, &mut pipefd_bytes);
        }

        let pipefd = unsafe {
            core::mem::transmute::<[u8; core::mem::size_of::<[i32; 2]>()], [i32; 2]>(pipefd_bytes)
        };

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                pipe2: pinchy_common::Pipe2Data { pipefd, flags },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

use crate::util::read_iovec_array;
#[tracepoint]
pub fn syscall_exit_readv(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_readv;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let iov_addr = args[1] as u64;
        let iovcnt = args[2] as usize;

        let (iovecs, iov_lens, iov_bufs, count) =
            read_iovec_array(iov_addr, iovcnt, true, return_value as usize);

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                vector_io: pinchy_common::VectorIOData {
                    fd,
                    iovecs,
                    iov_lens,
                    iov_bufs,
                    iovcnt: count,
                    offset: 0,
                    flags: 0,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_writev(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_writev;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let iov_addr = args[1] as u64;
        let iovcnt = args[2] as usize;

        let (iovecs, iov_lens, iov_bufs, count) = read_iovec_array(iov_addr, iovcnt, false, 0);

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                vector_io: pinchy_common::VectorIOData {
                    fd,
                    iovecs,
                    iov_lens,
                    iov_bufs,
                    iovcnt: count,
                    offset: 0,
                    flags: 0,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_preadv(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_preadv;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let iov_addr = args[1] as u64;
        let iovcnt = args[2] as usize;
        let offset = args[3] as i64;

        let (iovecs, iov_lens, iov_bufs, count) =
            read_iovec_array(iov_addr, iovcnt, true, return_value as usize);

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                vector_io: pinchy_common::VectorIOData {
                    fd,
                    iovecs,
                    iov_lens,
                    iov_bufs,
                    iovcnt: count,
                    offset,
                    flags: 0,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_pwritev(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_pwritev;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let iov_addr = args[1] as u64;
        let iovcnt = args[2] as usize;
        let offset = args[3] as i64;

        let (iovecs, iov_lens, iov_bufs, count) = read_iovec_array(iov_addr, iovcnt, false, 0);

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                vector_io: pinchy_common::VectorIOData {
                    fd,
                    iovecs,
                    iov_lens,
                    iov_bufs,
                    iovcnt: count,
                    offset,
                    flags: 0,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_preadv2(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_preadv2;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let iov_addr = args[1] as u64;
        let iovcnt = args[2] as usize;
        let offset = args[3] as i64;
        let flags = args[4] as u32;

        let (iovecs, iov_lens, iov_bufs, count) =
            read_iovec_array(iov_addr, iovcnt, true, return_value as usize);

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                vector_io: pinchy_common::VectorIOData {
                    fd,
                    iovecs,
                    iov_lens,
                    iov_bufs,
                    iovcnt: count,
                    offset,
                    flags,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_pwritev2(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_pwritev2;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let iov_addr = args[1] as u64;
        let iovcnt = args[2] as usize;
        let offset = args[3] as i64;
        let flags = args[4] as u32;

        let (iovecs, iov_lens, iov_bufs, count) = read_iovec_array(iov_addr, iovcnt, false, 0);

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                vector_io: pinchy_common::VectorIOData {
                    fd,
                    iovecs,
                    iov_lens,
                    iov_bufs,
                    iovcnt: count,
                    offset,
                    flags,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
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

syscall_handler!(pselect6, args, data, {
    data.nfds = args[0] as i32;

    let readfds_ptr = args[1] as *const u8;
    let writefds_ptr = args[2] as *const u8;
    let exceptfds_ptr = args[3] as *const u8;
    let timeout_ptr = args[4] as *const Timespec;
    let sigmask_ptr = args[5] as *const u8;

    read_fdset(&mut data.readfds, readfds_ptr, data.nfds);
    read_fdset(&mut data.writefds, writefds_ptr, data.nfds);
    read_fdset(&mut data.exceptfds, exceptfds_ptr, data.nfds);

    data.timeout = if !timeout_ptr.is_null() {
        read_timespec(timeout_ptr)
    } else {
        Timespec::default()
    };

    data.has_readfds = !readfds_ptr.is_null();
    data.has_writefds = !writefds_ptr.is_null();
    data.has_exceptfds = !exceptfds_ptr.is_null();
    data.has_timeout = !timeout_ptr.is_null();
    data.has_sigmask = !sigmask_ptr.is_null();
});

#[cfg(x86_64)]
syscall_handler!(select, args, data, {
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
});

#[cfg(x86_64)]
syscall_handler!(poll, args, data, {
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
});
