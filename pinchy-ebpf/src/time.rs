// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{helpers::bpf_probe_read_user, macros::tracepoint, programs::TracePointContext};
use pinchy_common::{kernel_types::Timespec, syscalls, ClockTimeData};

use crate::util;

#[tracepoint]
pub fn syscall_exit_time(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;
        let return_value = util::get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_adjtimex => {
                crate::util::submit_compact_payload::<pinchy_common::AdjtimexData, _>(
                    &ctx,
                    syscalls::SYS_adjtimex,
                    return_value,
                    |payload| {
                        let timex_ptr = args[0] as *const pinchy_common::kernel_types::Timex;
                        if let Ok(val) = unsafe {
                            bpf_probe_read_user::<pinchy_common::kernel_types::Timex>(timex_ptr)
                        } {
                            payload.timex = val;
                        }
                    },
                )?;
            }
            syscalls::SYS_clock_adjtime => {
                crate::util::submit_compact_payload::<pinchy_common::ClockAdjtimeData, _>(
                    &ctx,
                    syscalls::SYS_clock_adjtime,
                    return_value,
                    |payload| {
                        payload.clockid = args[0] as i32;
                        let timex_ptr = args[1] as *const pinchy_common::kernel_types::Timex;
                        if let Ok(val) = unsafe {
                            bpf_probe_read_user::<pinchy_common::kernel_types::Timex>(timex_ptr)
                        } {
                            payload.timex = val;
                        }
                    },
                )?;
            }
            syscalls::SYS_clock_getres => {
                crate::util::submit_compact_payload::<pinchy_common::ClockTimeData, _>(
                    &ctx,
                    syscalls::SYS_clock_getres,
                    return_value,
                    |payload| {
                        read_clock_time(&args, payload);
                    },
                )?;
            }
            syscalls::SYS_clock_gettime => {
                crate::util::submit_compact_payload::<pinchy_common::ClockTimeData, _>(
                    &ctx,
                    syscalls::SYS_clock_gettime,
                    return_value,
                    |payload| {
                        read_clock_time(&args, payload);
                    },
                )?;
            }
            syscalls::SYS_clock_settime => {
                crate::util::submit_compact_payload::<pinchy_common::ClockTimeData, _>(
                    &ctx,
                    syscalls::SYS_clock_settime,
                    return_value,
                    |payload| {
                        read_clock_time(&args, payload);
                    },
                )?;
            }
            syscalls::SYS_timer_create => {
                crate::util::submit_compact_payload::<pinchy_common::TimerCreateData, _>(
                    &ctx,
                    syscalls::SYS_timer_create,
                    return_value,
                    |payload| {
                        payload.clockid = args[0] as i32;
                        let sevp_ptr = args[1] as *const pinchy_common::kernel_types::Sigevent;
                        if sevp_ptr.is_null() {
                            payload.has_sevp = false;
                        } else {
                            if let Ok(sevp) = unsafe { bpf_probe_read_user(sevp_ptr) } {
                                payload.sevp = sevp;
                                payload.has_sevp = true;
                            } else {
                                payload.has_sevp = false;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_timer_gettime => {
                crate::util::submit_compact_payload::<pinchy_common::TimerGettimeData, _>(
                    &ctx,
                    syscalls::SYS_timer_gettime,
                    return_value,
                    |payload| {
                        payload.timerid = args[0];
                        let curr_value_ptr =
                            args[1] as *const pinchy_common::kernel_types::Itimerspec;
                        if !curr_value_ptr.is_null() {
                            if let Ok(curr_value) = unsafe { bpf_probe_read_user(curr_value_ptr) } {
                                payload.curr_value = curr_value;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_timer_settime => {
                crate::util::submit_compact_payload::<pinchy_common::TimerSettimeData, _>(
                    &ctx,
                    syscalls::SYS_timer_settime,
                    return_value,
                    |payload| {
                        payload.timerid = args[0];
                        payload.flags = args[1] as i32;

                        let new_value_ptr =
                            args[2] as *const pinchy_common::kernel_types::Itimerspec;
                        if new_value_ptr.is_null() {
                            payload.has_new_value = false;
                        } else {
                            if let Ok(new_value) = unsafe { bpf_probe_read_user(new_value_ptr) } {
                                payload.new_value = new_value;
                                payload.has_new_value = true;
                            } else {
                                payload.has_new_value = false;
                            }
                        }

                        let old_value_ptr =
                            args[3] as *const pinchy_common::kernel_types::Itimerspec;
                        if old_value_ptr.is_null() {
                            payload.has_old_value = false;
                        } else {
                            if let Ok(old_value) = unsafe { bpf_probe_read_user(old_value_ptr) } {
                                payload.old_value = old_value;
                                payload.has_old_value = true;
                            } else {
                                payload.has_old_value = false;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_timerfd_create => {
                crate::util::submit_compact_payload::<pinchy_common::TimerfdCreateData, _>(
                    &ctx,
                    syscalls::SYS_timerfd_create,
                    return_value,
                    |payload| {
                        payload.clockid = args[0] as i32;
                        payload.flags = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_timerfd_gettime => {
                crate::util::submit_compact_payload::<pinchy_common::TimerfdGettimeData, _>(
                    &ctx,
                    syscalls::SYS_timerfd_gettime,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        let curr_value_ptr =
                            args[1] as *const pinchy_common::kernel_types::Itimerspec;
                        if let Ok(curr_value) = unsafe { bpf_probe_read_user(curr_value_ptr) } {
                            payload.curr_value = curr_value;
                        }
                    },
                )?;
            }
            syscalls::SYS_timerfd_settime => {
                crate::util::submit_compact_payload::<pinchy_common::TimerfdSettimeData, _>(
                    &ctx,
                    syscalls::SYS_timerfd_settime,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.flags = args[1] as i32;

                        let new_value_ptr =
                            args[2] as *const pinchy_common::kernel_types::Itimerspec;
                        if new_value_ptr.is_null() {
                            payload.has_new_value = false;
                        } else {
                            if let Ok(new_value) = unsafe { bpf_probe_read_user(new_value_ptr) } {
                                payload.new_value = new_value;
                                payload.has_new_value = true;
                            } else {
                                payload.has_new_value = false;
                            }
                        }

                        let old_value_ptr =
                            args[3] as *const pinchy_common::kernel_types::Itimerspec;
                        if old_value_ptr.is_null() {
                            payload.has_old_value = false;
                        } else {
                            if let Ok(old_value) = unsafe { bpf_probe_read_user(old_value_ptr) } {
                                payload.old_value = old_value;
                                payload.has_old_value = true;
                            } else {
                                payload.has_old_value = false;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_getitimer => {
                crate::util::submit_compact_payload::<pinchy_common::GetItimerData, _>(
                    &ctx,
                    syscalls::SYS_getitimer,
                    return_value,
                    |payload| {
                        payload.which = args[0] as i32;

                        let curr_value_ptr =
                            args[1] as *const pinchy_common::kernel_types::Itimerval;
                        if !curr_value_ptr.is_null() {
                            payload.curr_value = unsafe {
                                bpf_probe_read_user::<pinchy_common::kernel_types::Itimerval>(
                                    curr_value_ptr,
                                )
                            }
                            .unwrap_or_default();
                        }
                    },
                )?;
            }
            syscalls::SYS_setitimer => {
                crate::util::submit_compact_payload::<pinchy_common::SetItimerData, _>(
                    &ctx,
                    syscalls::SYS_setitimer,
                    return_value,
                    |payload| {
                        payload.which = args[0] as i32;

                        let new_value_ptr =
                            args[1] as *const pinchy_common::kernel_types::Itimerval;
                        if !new_value_ptr.is_null() {
                            payload.new_value = unsafe {
                                bpf_probe_read_user::<pinchy_common::kernel_types::Itimerval>(
                                    new_value_ptr,
                                )
                            }
                            .unwrap_or_default();
                        }

                        let old_value_ptr =
                            args[2] as *const pinchy_common::kernel_types::Itimerval;
                        payload.has_old_value = false;

                        if !old_value_ptr.is_null() {
                            if let Ok(val) = unsafe {
                                bpf_probe_read_user::<pinchy_common::kernel_types::Itimerval>(
                                    old_value_ptr,
                                )
                            } {
                                payload.old_value = val;
                                payload.has_old_value = true;
                            } else {
                                payload.has_old_value = false;
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

fn read_clock_time(args: &[usize], data: &mut ClockTimeData) {
    data.clockid = args[0] as i32;
    let tp_ptr = args[1] as *const Timespec;
    if tp_ptr.is_null() {
        data.has_tp = false;
    } else {
        data.tp = util::read_timespec(tp_ptr);
        data.has_tp = true;
    }
}
