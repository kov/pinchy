// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::bpf_probe_read_user, macros::tracepoint, programs::TracePointContext,
};
use pinchy_common::{kernel_types, syscalls};

use crate::{data_mut, util};

// Seccomp operation constants
const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
const SECCOMP_SET_MODE_FILTER: u32 = 1;
const SECCOMP_GET_NOTIF_SIZES: u32 = 3;

#[tracepoint]
pub fn syscall_exit_security(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;

        let mut entry = util::Entry::new(&ctx, syscall_nr)?;

        match syscall_nr {
            syscalls::SYS_ptrace => {
                let data = data_mut!(entry, ptrace);
                data.request = args[0] as i32;
                data.pid = args[1] as i32;
                data.addr = args[2] as u64;
                data.data = args[3] as u64;
            }
            syscalls::SYS_seccomp => {
                let data = data_mut!(entry, seccomp);
                data.operation = args[0] as u32;
                data.flags = args[1] as u32;
                data.args = args[2] as u64;

                // Parse args based on operation if not NULL
                if data.args != 0 {
                    match data.operation {
                        SECCOMP_GET_ACTION_AVAIL => {
                            // Read u32 action value
                            if let Ok(action) =
                                unsafe { bpf_probe_read_user(data.args as *const u32) }
                            {
                                data.action_avail = action;
                            }
                        }
                        SECCOMP_SET_MODE_FILTER => {
                            // Read struct sock_fprog
                            if let Ok(fprog) = unsafe {
                                bpf_probe_read_user(data.args as *const kernel_types::SockFprog)
                            } {
                                data.filter_len = fprog.len;
                            }
                        }
                        SECCOMP_GET_NOTIF_SIZES => {
                            // Read struct seccomp_notif_sizes
                            if let Ok(sizes) = unsafe {
                                bpf_probe_read_user(
                                    data.args as *const kernel_types::SeccompNotifSizes,
                                )
                            } {
                                data.notif_sizes[0] = sizes.seccomp_notif;
                                data.notif_sizes[1] = sizes.seccomp_notif_resp;
                                data.notif_sizes[2] = sizes.seccomp_data;
                            }
                        }
                        _ => {}
                    }
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
