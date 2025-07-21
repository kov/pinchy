// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use pinchy_common::syscalls::{SYS_madvise, SYS_mmap, SYS_munmap};

use crate::util::{get_args, get_return_value, output_event};

#[tracepoint]
pub fn syscall_exit_mmap(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_mmap;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let addr = args[0];
        let length = args[1];
        let prot = args[2] as i32;
        let flags = args[3] as i32;
        let fd = args[4] as i32;
        let offset = args[5];

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                mmap: pinchy_common::MmapData {
                    addr,
                    length,
                    prot,
                    flags,
                    fd,
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
pub fn syscall_exit_munmap(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_munmap;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let addr = args[0];
        let length = args[1];

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                munmap: pinchy_common::MunmapData { addr, length },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_madvise(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_madvise;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let addr = args[0];
        let length = args[1];
        let advice = args[2] as i32;

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                madvise: pinchy_common::MadviseData {
                    addr,
                    length,
                    advice,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}
