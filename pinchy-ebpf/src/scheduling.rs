// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{helpers::bpf_probe_read_user, macros::tracepoint, programs::TracePointContext};
use pinchy_common::{
    kernel_types::{Rseq, RseqCs, SchedAttr, SchedParam},
    syscalls,
};

use crate::util;

#[tracepoint]
pub fn syscall_exit_scheduling(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;
        let return_value = util::get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_rseq => {
                crate::util::submit_compact_payload::<pinchy_common::RseqData, _>(
                    &ctx,
                    syscalls::SYS_rseq,
                    return_value,
                    |payload| {
                        let rseq_ptr = args[0] as *const Rseq;
                        payload.rseq_ptr = rseq_ptr as u64;
                        payload.rseq_len = args[1] as u32;
                        payload.flags = args[2] as i32;
                        payload.signature = args[3] as u32;

                        payload.has_rseq = !rseq_ptr.is_null();
                        if payload.has_rseq {
                            if let Ok(val) =
                                unsafe { bpf_probe_read_user::<Rseq>(rseq_ptr as *const _) }
                            {
                                payload.rseq = val;
                            }
                        }

                        payload.has_rseq_cs = false;
                        if payload.has_rseq && payload.rseq.rseq_cs != 0 {
                            let rseq_cs_ptr = payload.rseq.rseq_cs as *const RseqCs;
                            if let Ok(val) = unsafe { bpf_probe_read_user::<RseqCs>(rseq_cs_ptr) } {
                                payload.rseq_cs = val;
                                payload.has_rseq_cs = true;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_sched_setscheduler => {
                crate::util::submit_compact_payload::<pinchy_common::SchedSetschedulerData, _>(
                    &ctx,
                    syscalls::SYS_sched_setscheduler,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        payload.policy = args[1] as i32;

                        let param_ptr = args[2] as *const SchedParam;
                        payload.has_param = !param_ptr.is_null();
                        if payload.has_param {
                            if let Ok(val) = unsafe { bpf_probe_read_user::<SchedParam>(param_ptr) }
                            {
                                payload.param = val;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_sched_getaffinity => {
                crate::util::submit_compact_payload::<pinchy_common::SchedGetaffinityData, _>(
                    &ctx,
                    syscalls::SYS_sched_getaffinity,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        payload.cpusetsize = args[1];
                        payload.mask = args[2];
                    },
                )?;
            }
            syscalls::SYS_sched_setaffinity => {
                crate::util::submit_compact_payload::<pinchy_common::SchedSetaffinityData, _>(
                    &ctx,
                    syscalls::SYS_sched_setaffinity,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        payload.cpusetsize = args[1];
                        payload.mask = args[2];
                    },
                )?;
            }
            syscalls::SYS_sched_getparam => {
                crate::util::submit_compact_payload::<pinchy_common::SchedGetparamData, _>(
                    &ctx,
                    syscalls::SYS_sched_getparam,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;

                        let param_ptr = args[1] as *const SchedParam;
                        payload.has_param = !param_ptr.is_null();
                        if payload.has_param {
                            if let Ok(val) = unsafe { bpf_probe_read_user::<SchedParam>(param_ptr) }
                            {
                                payload.param = val;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_sched_setparam => {
                crate::util::submit_compact_payload::<pinchy_common::SchedSetparamData, _>(
                    &ctx,
                    syscalls::SYS_sched_setparam,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;

                        let param_ptr = args[1] as *const SchedParam;
                        payload.has_param = !param_ptr.is_null();
                        if payload.has_param {
                            if let Ok(val) = unsafe { bpf_probe_read_user::<SchedParam>(param_ptr) }
                            {
                                payload.param = val;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_sched_rr_get_interval => {
                crate::util::submit_compact_payload::<pinchy_common::SchedRrGetIntervalData, _>(
                    &ctx,
                    syscalls::SYS_sched_rr_get_interval,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        payload.interval = util::read_timespec(args[1] as *const _);
                    },
                )?;
            }
            syscalls::SYS_sched_getattr => {
                crate::util::submit_compact_payload::<pinchy_common::SchedGetattrData, _>(
                    &ctx,
                    syscalls::SYS_sched_getattr,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as u32;
                        let attr_ptr = args[1] as *const SchedAttr;
                        payload.size = args[2] as u32;
                        payload.flags = args[3] as u32;

                        payload.attr = unsafe {
                            bpf_probe_read_user::<SchedAttr>(attr_ptr).unwrap_or_default()
                        };
                    },
                )?;
            }
            syscalls::SYS_sched_setattr => {
                crate::util::submit_compact_payload::<pinchy_common::SchedSetattrData, _>(
                    &ctx,
                    syscalls::SYS_sched_setattr,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as u32;
                        let attr_ptr = args[1] as *const SchedAttr;
                        payload.flags = args[2] as u32;

                        payload.attr = unsafe {
                            bpf_probe_read_user::<SchedAttr>(attr_ptr).unwrap_or_default()
                        };
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
