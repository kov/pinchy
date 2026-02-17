// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_user, bpf_probe_read_user_buf},
    macros::tracepoint,
    programs::TracePointContext,
};
use pinchy_common::{
    kernel_types::{self, StackT},
    syscalls,
};

use crate::util;

#[tracepoint]
pub fn syscall_exit_signal(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;
        let return_value = util::get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_rt_sigprocmask => {
                crate::util::submit_compact_payload::<pinchy_common::RtSigprocmaskData, _>(
                    &ctx,
                    syscalls::SYS_rt_sigprocmask,
                    return_value,
                    |payload| {
                        payload.how = args[0] as i32;
                        payload.set = args[1];
                        payload.oldset = args[2];
                        payload.sigsetsize = args[3];

                        if let Some(set_data) = util::read_sigset(args[1] as *const _) {
                            payload.set_data = set_data;
                            payload.has_set_data = true;
                        }

                        if let Some(oldset_data) = util::read_sigset(args[2] as *const _) {
                            payload.oldset_data = oldset_data;
                            payload.has_oldset_data = true;
                        }
                    },
                )?;
            }
            syscalls::SYS_rt_sigpending => {
                crate::util::submit_compact_payload::<pinchy_common::RtSigpendingData, _>(
                    &ctx,
                    syscalls::SYS_rt_sigpending,
                    return_value,
                    |payload| {
                        payload.set = args[0];
                        payload.sigsetsize = args[1];

                        if let Some(set_data) = util::read_sigset(args[0] as *const _) {
                            payload.set_data = set_data;
                            payload.has_set_data = true;
                        }
                    },
                )?;
            }
            syscalls::SYS_rt_sigsuspend => {
                crate::util::submit_compact_payload::<pinchy_common::RtSigsuspendData, _>(
                    &ctx,
                    syscalls::SYS_rt_sigsuspend,
                    return_value,
                    |payload| {
                        payload.mask = args[0];
                        payload.sigsetsize = args[1];

                        if let Some(mask_data) = util::read_sigset(args[0] as *const _) {
                            payload.mask_data = mask_data;
                            payload.has_mask_data = true;
                        }
                    },
                )?;
            }
            syscalls::SYS_rt_sigtimedwait => {
                crate::util::submit_compact_payload::<pinchy_common::RtSigtimedwaitData, _>(
                    &ctx,
                    syscalls::SYS_rt_sigtimedwait,
                    return_value,
                    |payload| {
                        payload.set = args[0];
                        payload.info = args[1];
                        payload.timeout = args[2];
                        payload.sigsetsize = args[3];

                        if let Some(set_data) = util::read_sigset(args[0] as *const _) {
                            payload.set_data = set_data;
                            payload.has_set_data = true;
                        }
                    },
                )?;
            }
            syscalls::SYS_sigaltstack => {
                crate::util::submit_compact_payload::<pinchy_common::SigaltstackData, _>(
                    &ctx,
                    syscalls::SYS_sigaltstack,
                    return_value,
                    |payload| {
                        payload.ss_ptr = args[0];
                        payload.old_ss_ptr = args[1];

                        let ss_ptr = args[0] as *const u8;
                        if !ss_ptr.is_null() {
                            let buf = unsafe {
                                core::slice::from_raw_parts_mut(
                                    &mut payload.ss as *mut StackT as *mut u8,
                                    core::mem::size_of::<StackT>(),
                                )
                            };

                            let _ = unsafe { bpf_probe_read_user_buf(ss_ptr, buf) };
                            payload.has_ss = true;
                        }

                        let old_ss_ptr = args[1] as *const u8;

                        if !old_ss_ptr.is_null() {
                            let buf = unsafe {
                                core::slice::from_raw_parts_mut(
                                    &mut payload.old_ss as *mut StackT as *mut u8,
                                    core::mem::size_of::<StackT>(),
                                )
                            };

                            let _ = unsafe { bpf_probe_read_user_buf(old_ss_ptr, buf) };
                            payload.has_old_ss = true;
                        }
                    },
                )?;
            }

            #[cfg(x86_64)]
            syscalls::SYS_signalfd => {
                crate::util::submit_compact_payload::<pinchy_common::SignalfdData, _>(
                    &ctx,
                    syscalls::SYS_signalfd,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.flags = args[2] as i32;

                        let mask_ptr = args[1] as *const kernel_types::Sigset;
                        if !mask_ptr.is_null() {
                            unsafe {
                                payload.mask =
                                    bpf_probe_read_user::<kernel_types::Sigset>(mask_ptr)
                                        .unwrap_or_default();
                            }
                            payload.has_mask = true;
                        }
                    },
                )?;
            }
            syscalls::SYS_signalfd4 => {
                crate::util::submit_compact_payload::<pinchy_common::Signalfd4Data, _>(
                    &ctx,
                    syscalls::SYS_signalfd4,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.flags = args[2] as i32;

                        let mask_ptr = args[1] as *const kernel_types::Sigset;
                        if !mask_ptr.is_null() {
                            unsafe {
                                payload.mask =
                                    bpf_probe_read_user::<kernel_types::Sigset>(mask_ptr)
                                        .unwrap_or_default();
                            }
                            payload.has_mask = true;
                        }
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
