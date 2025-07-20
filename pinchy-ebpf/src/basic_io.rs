// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_buf, bpf_probe_read_user},
    macros::tracepoint,
    programs::TracePointContext,
};
use pinchy_common::{
    kernel_types::{EpollEvent, Pollfd},
    syscalls::{SYS_epoll_pwait, SYS_fcntl, SYS_openat, SYS_pipe2, SYS_ppoll, SYS_read, SYS_write},
    DATA_READ_SIZE,
};

use crate::util::{get_args, get_return_value, output_event, read_timespec};

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
