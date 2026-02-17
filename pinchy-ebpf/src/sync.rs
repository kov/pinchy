// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{helpers::bpf_probe_read_user, macros::tracepoint, programs::TracePointContext};
use pinchy_common::{
    kernel_types::{FutexWaitv, Timespec},
    syscalls,
};

use crate::util;

#[tracepoint]
pub fn syscall_exit_sync(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;
        let return_value = util::get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_futex => {
                crate::util::submit_compact_payload::<pinchy_common::FutexData, _>(
                    &ctx,
                    syscalls::SYS_futex,
                    return_value,
                    |payload| {
                        payload.uaddr = args[0];
                        payload.op = args[1] as u32;
                        payload.val = args[2] as u32;
                        payload.uaddr2 = args[4];
                        payload.val3 = args[5] as u32;

                        let timeout_ptr = args[3] as *const Timespec;
                        payload.timeout = crate::util::read_timespec(timeout_ptr);
                    },
                )?;
            }
            syscalls::SYS_futex_waitv => {
                crate::util::submit_compact_payload::<pinchy_common::FutexWaitvData, _>(
                    &ctx,
                    syscalls::SYS_futex_waitv,
                    return_value,
                    |payload| {
                        let waiters_ptr = args[0] as *const FutexWaitv;
                        payload.nr_waiters = args[1] as u32;
                        payload.flags = args[2] as u32;

                        let timeout_ptr = args[3] as *const Timespec;
                        payload.has_timeout = !timeout_ptr.is_null();
                        if payload.has_timeout {
                            payload.timeout = crate::util::read_timespec(timeout_ptr);
                        }

                        payload.clockid = args[4] as i32;

                        let count =
                            core::cmp::min(payload.nr_waiters as usize, payload.waiters.len());
                        for i in 0..count {
                            let ptr = unsafe { waiters_ptr.add(i) };
                            if let Ok(val) = unsafe { bpf_probe_read_user::<FutexWaitv>(ptr) } {
                                payload.waiters[i] = val;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_get_robust_list => {
                crate::util::submit_compact_payload::<pinchy_common::GetRobustListData, _>(
                    &ctx,
                    syscalls::SYS_get_robust_list,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;

                        let head_ptr = args[1] as *const usize;
                        let len_ptr = args[2] as *const usize;

                        payload.head =
                            unsafe { bpf_probe_read_user::<usize>(head_ptr) }.unwrap_or_default();
                        payload.len =
                            unsafe { bpf_probe_read_user::<usize>(len_ptr) }.unwrap_or_default();
                    },
                )?;
            }
            _ => {}
        }

        Ok(())
    }

    match inner(ctx) {
        Ok(()) => 0,
        Err(code) => code,
    }
}
