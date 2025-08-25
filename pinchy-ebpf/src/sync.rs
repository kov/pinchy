// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{helpers::bpf_probe_read_user, macros::tracepoint, programs::TracePointContext};
use pinchy_common::{
    kernel_types::{FutexWaitv, Timespec},
    syscalls,
};

use crate::{data_mut, util};

#[tracepoint]
pub fn syscall_exit_sync(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;

        let mut entry = util::Entry::new(&ctx, syscall_nr)?;

        match syscall_nr {
            syscalls::SYS_futex => {
                let data = data_mut!(entry, futex);
                data.uaddr = args[0];
                data.op = args[1] as u32;
                data.val = args[2] as u32;
                data.uaddr2 = args[4];
                data.val3 = args[5] as u32;

                let timeout_ptr = args[3] as *const Timespec;
                data.timeout = crate::util::read_timespec(timeout_ptr);
            }
            syscalls::SYS_futex_waitv => {
                let data = data_mut!(entry, futex_waitv);
                let waiters_ptr = args[0] as *const FutexWaitv;
                data.nr_waiters = args[1] as u32;
                data.flags = args[2] as u32;

                let timeout_ptr = args[3] as *const Timespec;
                data.has_timeout = !timeout_ptr.is_null();
                if data.has_timeout {
                    data.timeout = crate::util::read_timespec(timeout_ptr);
                }

                data.clockid = args[4] as i32;

                let count = core::cmp::min(data.nr_waiters as usize, data.waiters.len());
                for i in 0..count {
                    let ptr = unsafe { waiters_ptr.add(i) };
                    if let Ok(val) = unsafe { bpf_probe_read_user::<FutexWaitv>(ptr) } {
                        data.waiters[i] = val;
                    }
                }
            }
            syscalls::SYS_get_robust_list => {
                let data = data_mut!(entry, get_robust_list);
                data.pid = args[0] as i32;

                let head_ptr = args[1] as *const usize;
                let len_ptr = args[2] as *const usize;

                data.head = unsafe { bpf_probe_read_user::<usize>(head_ptr) }.unwrap_or_default();
                data.len = unsafe { bpf_probe_read_user::<usize>(len_ptr) }.unwrap_or_default();
            }

            _ => {
                entry.discard();
                return Ok(());
            }
        }

        entry.submit();
        Ok(())
    }

    match inner(ctx) {
        Ok(()) => 0,
        Err(code) => code,
    }
}
