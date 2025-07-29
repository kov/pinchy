// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::helpers::{bpf_probe_read_buf, bpf_probe_read_user};
#[cfg(x86_64)]
use pinchy_common::kernel_types::Timeval;
use pinchy_common::kernel_types::{EpollEvent, FdSet, Pollfd, Timespec};

#[cfg(x86_64)]
use crate::util::read_timeval;
use crate::{
    syscall_handler,
    util::{read_iovec_array, read_timespec, IovecOp},
};

syscall_handler!(openat, openat, args, data, {
    data.dfd = args[0] as i32;
    data.flags = args[2] as i32;
    data.mode = args[3] as u32;

    let pathname_ptr = args[1] as *const u8;
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr as *const _, &mut data.pathname);
    }
});

syscall_handler!(read, read, args, data, return_value, {
    data.fd = args[0] as i32;
    data.count = args[2];

    let buf_addr = args[1];
    if return_value > 0 {
        let to_read = core::cmp::min(return_value as usize, data.buf.len());
        unsafe {
            let _ = bpf_probe_read_buf(buf_addr as *const _, &mut data.buf[..to_read]);
        }
    }
});

syscall_handler!(write, write, args, data, return_value, {
    data.fd = args[0] as i32;
    data.count = args[2];

    let buf_addr = args[1];
    if return_value > 0 {
        let to_copy = core::cmp::min(return_value as usize, data.buf.len());
        unsafe {
            let _ = bpf_probe_read_buf(buf_addr as *const _, &mut data.buf[..to_copy]);
        }
    }
});

syscall_handler!(pread64, pread, args, data, return_value, {
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
});

syscall_handler!(pwrite64, pwrite, args, data, return_value, {
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
});

syscall_handler!(epoll_pwait, epoll_pwait, args, data, return_value, {
    data.epfd = args[0] as i32;
    data.max_events = args[2] as i32;
    data.timeout = args[3] as i32;

    let events_ptr = args[1] as *const EpollEvent;
    for (i, item) in data.events.iter_mut().enumerate() {
        if i < return_value as usize {
            unsafe {
                let events_ptr = events_ptr.add(i);
                if let Ok(evt) = bpf_probe_read_user::<EpollEvent>(events_ptr as *const _) {
                    *item = evt;
                }
            }
        }
    }
});

#[cfg(x86_64)]
syscall_handler!(epoll_wait, epoll_wait, args, data, return_value, {
    data.epfd = args[0] as i32;
    data.max_events = args[2] as i32;
    data.timeout = args[3] as i32;

    let events_ptr = args[1] as *const EpollEvent;
    for (i, item) in data.events.iter_mut().enumerate() {
        if i < return_value as usize {
            unsafe {
                let events_ptr = events_ptr.add(i);
                if let Ok(evt) = bpf_probe_read_user::<EpollEvent>(events_ptr as *const _) {
                    *item = evt;
                }
            }
        }
    }
});

syscall_handler!(ppoll, args, data, {
    data.nfds = args[1] as u32;
    data.timeout = read_timespec(args[2] as *const _);

    let fds_ptr = args[0] as *const Pollfd;
    for i in 0..data.fds.len() {
        if i < data.nfds as usize {
            unsafe {
                let entry_ptr = fds_ptr.add(i);
                if let Ok(pollfd) = bpf_probe_read_user::<Pollfd>(entry_ptr as *const _) {
                    data.fds[i] = pollfd.fd;
                    data.events[i] = pollfd.events;
                    data.revents[i] = pollfd.revents;
                }
            }
        }
    }
});

syscall_handler!(pipe2, args, data, {
    data.flags = args[1] as i32;

    let pipefd_ptr = args[0] as *const i32;
    let mut pipefd_bytes = [0u8; core::mem::size_of::<[i32; 2]>()];
    unsafe {
        let _ = bpf_probe_read_buf(pipefd_ptr as *const u8, &mut pipefd_bytes);
    }

    data.pipefd = unsafe {
        core::mem::transmute::<[u8; core::mem::size_of::<[i32; 2]>()], [i32; 2]>(pipefd_bytes)
    };
});

syscall_handler!(readv, vector_io, args, data, return_value, {
    data.fd = args[0] as i32;
    data.iovcnt = args[2] as usize;

    let iov_addr = args[1] as u64;
    read_iovec_array(
        iov_addr,
        data.iovcnt,
        IovecOp::Read,
        &mut data.iovecs,
        &mut data.iov_lens,
        &mut data.iov_bufs,
        &mut data.read_count,
        return_value,
    );
});

syscall_handler!(writev, vector_io, args, data, return_value, {
    data.fd = args[0] as i32;
    data.iovcnt = args[2] as usize;

    let iov_addr = args[1] as u64;
    read_iovec_array(
        iov_addr,
        data.iovcnt,
        IovecOp::Write,
        &mut data.iovecs,
        &mut data.iov_lens,
        &mut data.iov_bufs,
        &mut data.read_count,
        return_value,
    );
});

syscall_handler!(preadv, vector_io, args, data, return_value, {
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
        &mut data.iov_bufs,
        &mut data.read_count,
        return_value,
    );
});

syscall_handler!(pwritev, vector_io, args, data, return_value, {
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
        &mut data.iov_bufs,
        &mut data.read_count,
        return_value,
    );
});

syscall_handler!(preadv2, vector_io, args, data, return_value, {
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
        &mut data.iov_bufs,
        &mut data.read_count,
        return_value,
    );
});

syscall_handler!(pwritev2, vector_io, args, data, return_value, {
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
        &mut data.iov_bufs,
        &mut data.read_count,
        return_value,
    );
});

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

    data.timeout = read_timespec(timeout_ptr);

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

syscall_handler!(epoll_pwait2, epoll_pwait2, args, data, {
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
});

syscall_handler!(epoll_ctl, args, data, {
    data.epfd = args[0] as i32;
    data.op = args[1] as i32;
    data.fd = args[2] as i32;
    let event_ptr = args[3] as *const EpollEvent;
    if !event_ptr.is_null() {
        data.event = unsafe { bpf_probe_read_user(event_ptr).unwrap_or_default() };
    }
});

syscall_handler!(splice, args, data, {
    data.fd_in = args[0] as i32;
    data.off_in = args[1] as u64;
    data.fd_out = args[2] as i32;
    data.off_out = args[3] as u64;
    data.len = args[4] as usize;
    data.flags = args[5] as u32;
});

syscall_handler!(tee, args, data, {
    data.fd_in = args[0] as i32;
    data.fd_out = args[1] as i32;
    data.len = args[2] as usize;
    data.flags = args[3] as u32;
});
