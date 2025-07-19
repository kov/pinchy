// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use pinchy_common::kernel_types::Timespec;

use crate::util::{get_args, get_return_value, get_syscall_nr, output_event, read_timespec};

#[tracepoint]
pub fn syscall_exit_futex(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = get_syscall_nr(&ctx)?;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let uaddr = args[0];
        let op = args[1] as i32;
        let val = args[2] as u32;
        let timeout_ptr = args[3] as *const Timespec;
        let uaddr2 = args[4];
        let val3 = args[5] as u32;
        let timeout = if timeout_ptr.is_null() {
            unsafe { core::mem::zeroed() }
        } else {
            read_timespec(timeout_ptr)
        };

        let data = pinchy_common::SyscallEventData {
            futex: pinchy_common::FutexData {
                uaddr,
                op: op as u32,
                val,
                uaddr2,
                val3,
                timeout,
            },
        };

        output_event(&ctx, syscall_nr, return_value, data)
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(err) => err,
    }
}
