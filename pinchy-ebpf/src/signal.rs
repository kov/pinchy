// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_buf, bpf_probe_read_user},
    macros::tracepoint,
    programs::TracePointContext,
};
use pinchy_common::{
    kernel_types::{self, StackT},
    syscalls,
};

use crate::{data_mut, util};

#[tracepoint]
pub fn syscall_exit_signal(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;

        let mut entry = util::Entry::new(&ctx, syscall_nr)?;

        match syscall_nr {
            syscalls::SYS_rt_sigprocmask => {
                let data = data_mut!(entry, rt_sigprocmask);
                data.how = args[0] as i32;
                data.set = args[1];
                data.oldset = args[2];
                data.sigsetsize = args[3];

                if let Some(set_data) = util::read_sigset(args[1] as *const _) {
                    data.set_data = set_data;
                    data.has_set_data = true;
                }

                if let Some(oldset_data) = util::read_sigset(args[2] as *const _) {
                    data.oldset_data = oldset_data;
                    data.has_oldset_data = true;
                }
            }
            syscalls::SYS_rt_sigpending => {
                let data = data_mut!(entry, rt_sigpending);
                data.set = args[0];
                data.sigsetsize = args[1];

                if let Some(set_data) = util::read_sigset(args[0] as *const _) {
                    data.set_data = set_data;
                    data.has_set_data = true;
                }
            }
            syscalls::SYS_rt_sigsuspend => {
                let data = data_mut!(entry, rt_sigsuspend);
                data.mask = args[0];
                data.sigsetsize = args[1];

                if let Some(mask_data) = util::read_sigset(args[0] as *const _) {
                    data.mask_data = mask_data;
                    data.has_mask_data = true;
                }
            }
            syscalls::SYS_rt_sigtimedwait => {
                let data = data_mut!(entry, rt_sigtimedwait);
                data.set = args[0];
                data.info = args[1];
                data.timeout = args[2];
                data.sigsetsize = args[3];

                if let Some(set_data) = util::read_sigset(args[0] as *const _) {
                    data.set_data = set_data;
                    data.has_set_data = true;
                }
            }
            syscalls::SYS_sigaltstack => {
                let data = data_mut!(entry, sigaltstack);
                data.ss_ptr = args[0];
                data.old_ss_ptr = args[1];

                let ss_ptr = args[0] as *const u8;
                if !ss_ptr.is_null() {
                    let buf = unsafe {
                        core::slice::from_raw_parts_mut(
                            &mut data.ss as *mut StackT as *mut u8,
                            core::mem::size_of::<StackT>(),
                        )
                    };

                    let _ = unsafe { bpf_probe_read_buf(ss_ptr, buf) };
                    data.has_ss = true;
                }

                let old_ss_ptr = args[1] as *const u8;

                if !old_ss_ptr.is_null() {
                    let buf = unsafe {
                        core::slice::from_raw_parts_mut(
                            &mut data.old_ss as *mut StackT as *mut u8,
                            core::mem::size_of::<StackT>(),
                        )
                    };

                    let _ = unsafe { bpf_probe_read_buf(old_ss_ptr, buf) };
                    data.has_old_ss = true;
                }
            }

            #[cfg(x86_64)]
            syscalls::SYS_signalfd => {
                let data = data_mut!(entry, signalfd);
                data.fd = args[0] as i32;
                data.flags = args[2] as i32;

                let mask_ptr = args[1] as *const kernel_types::Sigset;
                if !mask_ptr.is_null() {
                    unsafe {
                        data.mask = bpf_probe_read_user::<kernel_types::Sigset>(mask_ptr)
                            .unwrap_or_default();
                    }
                    data.has_mask = true;
                }
            }
            syscalls::SYS_signalfd4 => {
                let data = data_mut!(entry, signalfd4);
                data.fd = args[0] as i32;
                data.flags = args[2] as i32;

                let mask_ptr = args[1] as *const kernel_types::Sigset;
                if !mask_ptr.is_null() {
                    unsafe {
                        data.mask = bpf_probe_read_user::<kernel_types::Sigset>(mask_ptr)
                            .unwrap_or_default();
                    }
                    data.has_mask = true;
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

    match inner(ctx) {
        Ok(()) => 0,
        Err(code) => code,
    }
}
