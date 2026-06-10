// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{helpers::bpf_probe_read_user, macros::tracepoint, programs::TracePointContext};
use pinchy_common::{kernel_types, syscalls};

use crate::util;

// Seccomp operation constants
const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
const SECCOMP_SET_MODE_FILTER: u32 = 1;
const SECCOMP_GET_NOTIF_SIZES: u32 = 3;

#[tracepoint]
pub fn syscall_exit_security(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;
        let return_value = util::get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_lsm_get_self_attr => {
                crate::util::submit_compact_payload::<pinchy_common::LsmGetSelfAttrData, _>(
                    &ctx,
                    syscalls::SYS_lsm_get_self_attr,
                    return_value,
                    |payload| {
                        payload.attr = args[0] as u32;
                        payload.ctx = args[1] as u64;
                        payload.flags = args[3] as u32;

                        let size_ptr = args[2] as *const u32;
                        if !size_ptr.is_null() {
                            if let Ok(size) =
                                unsafe { aya_ebpf::helpers::bpf_probe_read_user::<u32>(size_ptr) }
                            {
                                payload.size = size;
                                payload.has_size = true;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_lsm_list_modules => {
                crate::util::submit_compact_payload::<pinchy_common::LsmListModulesData, _>(
                    &ctx,
                    syscalls::SYS_lsm_list_modules,
                    return_value,
                    |payload| {
                        payload.flags = args[2] as u32;

                        let size_ptr = args[1] as *const u32;
                        if !size_ptr.is_null() {
                            if let Ok(size) =
                                unsafe { aya_ebpf::helpers::bpf_probe_read_user::<u32>(size_ptr) }
                            {
                                payload.size = size;
                                payload.has_size = true;
                            }
                        }

                        let ids_ptr = args[0] as *const u64;
                        if return_value > 0 && !ids_ptr.is_null() {
                            let count = core::cmp::min(return_value as usize, payload.ids.len());
                            for i in 0..count {
                                let ptr = unsafe { ids_ptr.add(i) };
                                if let Ok(id) =
                                    unsafe { aya_ebpf::helpers::bpf_probe_read_user::<u64>(ptr) }
                                {
                                    payload.ids[i] = id;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_ptrace => {
                crate::util::submit_compact_payload::<pinchy_common::PtraceData, _>(
                    &ctx,
                    syscalls::SYS_ptrace,
                    return_value,
                    |payload| {
                        payload.request = args[0] as i32;
                        payload.pid = args[1] as i32;
                        payload.addr = args[2] as u64;
                        payload.data = args[3] as u64;
                    },
                )?;
            }
            syscalls::SYS_seccomp => {
                crate::util::submit_compact_payload::<pinchy_common::SeccompData, _>(
                    &ctx,
                    syscalls::SYS_seccomp,
                    return_value,
                    |payload| {
                        payload.operation = args[0] as u32;
                        payload.flags = args[1] as u32;
                        payload.args = args[2] as u64;

                        // Parse args based on operation if not NULL
                        if payload.args != 0 {
                            match payload.operation {
                                SECCOMP_GET_ACTION_AVAIL => {
                                    // Read u32 action value
                                    if let Ok(action) =
                                        unsafe { bpf_probe_read_user(payload.args as *const u32) }
                                    {
                                        payload.action_avail = action;
                                        payload.action_read_ok = 1;
                                    }
                                }
                                SECCOMP_SET_MODE_FILTER => {
                                    // Read struct sock_fprog
                                    if let Ok(fprog) = unsafe {
                                        bpf_probe_read_user(
                                            payload.args as *const kernel_types::SockFprog,
                                        )
                                    } {
                                        payload.filter_len = fprog.len;
                                    }
                                }
                                SECCOMP_GET_NOTIF_SIZES => {
                                    // Read struct seccomp_notif_sizes
                                    if let Ok(sizes) = unsafe {
                                        bpf_probe_read_user(
                                            payload.args as *const kernel_types::SeccompNotifSizes,
                                        )
                                    } {
                                        payload.notif_sizes[0] = sizes.seccomp_notif;
                                        payload.notif_sizes[1] = sizes.seccomp_notif_resp;
                                        payload.notif_sizes[2] = sizes.seccomp_data;
                                    }
                                }
                                _ => {}
                            }
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
