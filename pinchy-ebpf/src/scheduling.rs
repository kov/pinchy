// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{helpers::bpf_probe_read_user, macros::tracepoint, programs::TracePointContext};
use pinchy_common::{
    kernel_types::{Rseq, RseqCs, SchedAttr, SchedParam},
    syscalls,
};

use crate::{data_mut, util};

#[tracepoint]
pub fn syscall_exit_scheduling(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;

        let mut entry = util::Entry::new(&ctx, syscall_nr)?;

        match syscall_nr {
            syscalls::SYS_rseq => {
                let data = data_mut!(entry, rseq);
                let rseq_ptr = args[0] as *const Rseq;
                data.rseq_ptr = rseq_ptr as u64;
                data.rseq_len = args[1] as u32;
                data.flags = args[2] as i32;
                data.signature = args[3] as u32;

                data.has_rseq = !rseq_ptr.is_null();
                if data.has_rseq {
                    if let Ok(val) = unsafe { bpf_probe_read_user::<Rseq>(rseq_ptr as *const _) } {
                        data.rseq = val;
                    }
                }

                data.has_rseq_cs = false;
                if data.has_rseq && data.rseq.rseq_cs != 0 {
                    let rseq_cs_ptr = data.rseq.rseq_cs as *const RseqCs;
                    if let Ok(val) = unsafe { bpf_probe_read_user::<RseqCs>(rseq_cs_ptr) } {
                        data.rseq_cs = val;
                        data.has_rseq_cs = true;
                    }
                }
            }
            syscalls::SYS_sched_setscheduler => {
                let data = data_mut!(entry, sched_setscheduler);
                data.pid = args[0] as i32;
                data.policy = args[1] as i32;

                let param_ptr = args[2] as *const SchedParam;
                data.has_param = !param_ptr.is_null();
                if data.has_param {
                    if let Ok(val) = unsafe { bpf_probe_read_user::<SchedParam>(param_ptr) } {
                        data.param = val;
                    }
                }
            }
            syscalls::SYS_sched_getaffinity => {
                let data = data_mut!(entry, sched_getaffinity);
                data.pid = args[0] as i32;
                data.cpusetsize = args[1];
                data.mask = args[2];
            }
            syscalls::SYS_sched_setaffinity => {
                let data = data_mut!(entry, sched_setaffinity);
                data.pid = args[0] as i32;
                data.cpusetsize = args[1];
                data.mask = args[2];
            }
            syscalls::SYS_sched_getparam => {
                let data = data_mut!(entry, sched_getparam);
                data.pid = args[0] as i32;

                let param_ptr = args[1] as *const SchedParam;
                data.has_param = !param_ptr.is_null();
                if data.has_param {
                    if let Ok(val) = unsafe { bpf_probe_read_user::<SchedParam>(param_ptr) } {
                        data.param = val;
                    }
                }
            }
            syscalls::SYS_sched_setparam => {
                let data = data_mut!(entry, sched_setparam);
                data.pid = args[0] as i32;

                let param_ptr = args[1] as *const SchedParam;
                data.has_param = !param_ptr.is_null();
                if data.has_param {
                    if let Ok(val) = unsafe { bpf_probe_read_user::<SchedParam>(param_ptr) } {
                        data.param = val;
                    }
                }
            }
            syscalls::SYS_sched_rr_get_interval => {
                let data = data_mut!(entry, sched_rr_get_interval);
                data.pid = args[0] as i32;
                data.interval = util::read_timespec(args[1] as *const _);
            }
            syscalls::SYS_sched_getattr => {
                let data = data_mut!(entry, sched_getattr);
                data.pid = args[0] as u32;
                let attr_ptr = args[1] as *const SchedAttr;
                data.size = args[2] as u32;
                data.flags = args[3] as u32;

                data.attr =
                    unsafe { bpf_probe_read_user::<SchedAttr>(attr_ptr).unwrap_or_default() };
            }
            syscalls::SYS_sched_setattr => {
                let data = data_mut!(entry, sched_setattr);
                data.pid = args[0] as u32;
                let attr_ptr = args[1] as *const SchedAttr;
                data.flags = args[2] as u32;

                data.attr =
                    unsafe { bpf_probe_read_user::<SchedAttr>(attr_ptr).unwrap_or_default() };
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
