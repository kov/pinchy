// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{helpers::bpf_probe_read_user, macros::tracepoint, programs::TracePointContext};
use pinchy_common::{kernel_types::Timespec, syscalls, ClockTimeData};

use crate::{data_mut, util};

#[tracepoint]
pub fn syscall_exit_time(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;

        let mut entry = util::Entry::new(&ctx, syscall_nr)?;

        match syscall_nr {
            syscalls::SYS_adjtimex => {
                let data = data_mut!(entry, adjtimex);
                let timex_ptr = args[0] as *const pinchy_common::kernel_types::Timex;
                if let Ok(val) =
                    unsafe { bpf_probe_read_user::<pinchy_common::kernel_types::Timex>(timex_ptr) }
                {
                    data.timex = val;
                }
            }
            syscalls::SYS_clock_adjtime => {
                let data = data_mut!(entry, clock_adjtime);
                data.clockid = args[0] as i32;
                let timex_ptr = args[1] as *const pinchy_common::kernel_types::Timex;
                if let Ok(val) =
                    unsafe { bpf_probe_read_user::<pinchy_common::kernel_types::Timex>(timex_ptr) }
                {
                    data.timex = val;
                }
            }
            syscalls::SYS_clock_getres => {
                let data = data_mut!(entry, clock_time);
                read_clock_time(&args, data);
            }
            syscalls::SYS_clock_gettime => {
                let data = data_mut!(entry, clock_time);
                read_clock_time(&args, data);
            }
            syscalls::SYS_clock_settime => {
                let data = data_mut!(entry, clock_time);
                read_clock_time(&args, data);
            }
            syscalls::SYS_timer_create => {
                let data = data_mut!(entry, timer_create);
                data.clockid = args[0] as i32;
                let sevp_ptr = args[1] as *const pinchy_common::kernel_types::Sigevent;
                if sevp_ptr.is_null() {
                    data.has_sevp = false;
                } else {
                    if let Ok(sevp) = unsafe { bpf_probe_read_user(sevp_ptr) } {
                        data.sevp = sevp;
                        data.has_sevp = true;
                    } else {
                        data.has_sevp = false;
                    }
                }
            }
            syscalls::SYS_timer_gettime => {
                let data = data_mut!(entry, timer_gettime);
                data.timerid = args[0];
                let curr_value_ptr = args[1] as *const pinchy_common::kernel_types::Itimerspec;
                if !curr_value_ptr.is_null() {
                    if let Ok(curr_value) = unsafe { bpf_probe_read_user(curr_value_ptr) } {
                        data.curr_value = curr_value;
                    }
                }
            }
            syscalls::SYS_timer_settime => {
                let data = data_mut!(entry, timer_settime);
                data.timerid = args[0];
                data.flags = args[1] as i32;

                let new_value_ptr = args[2] as *const pinchy_common::kernel_types::Itimerspec;
                if new_value_ptr.is_null() {
                    data.has_new_value = false;
                } else {
                    if let Ok(new_value) = unsafe { bpf_probe_read_user(new_value_ptr) } {
                        data.new_value = new_value;
                        data.has_new_value = true;
                    } else {
                        data.has_new_value = false;
                    }
                }

                let old_value_ptr = args[3] as *const pinchy_common::kernel_types::Itimerspec;
                if old_value_ptr.is_null() {
                    data.has_old_value = false;
                } else {
                    if let Ok(old_value) = unsafe { bpf_probe_read_user(old_value_ptr) } {
                        data.old_value = old_value;
                        data.has_old_value = true;
                    } else {
                        data.has_old_value = false;
                    }
                }
            }
            syscalls::SYS_timerfd_create => {
                let data = data_mut!(entry, timerfd_create);
                data.clockid = args[0] as i32;
                data.flags = args[1] as i32;
            }
            syscalls::SYS_timerfd_gettime => {
                let data = data_mut!(entry, timerfd_gettime);
                data.fd = args[0] as i32;
                let curr_value_ptr = args[1] as *const pinchy_common::kernel_types::Itimerspec;
                if let Ok(curr_value) = unsafe { bpf_probe_read_user(curr_value_ptr) } {
                    data.curr_value = curr_value;
                }
            }
            syscalls::SYS_timerfd_settime => {
                let data = data_mut!(entry, timerfd_settime);
                data.fd = args[0] as i32;
                data.flags = args[1] as i32;

                let new_value_ptr = args[2] as *const pinchy_common::kernel_types::Itimerspec;
                if new_value_ptr.is_null() {
                    data.has_new_value = false;
                } else {
                    if let Ok(new_value) = unsafe { bpf_probe_read_user(new_value_ptr) } {
                        data.new_value = new_value;
                        data.has_new_value = true;
                    } else {
                        data.has_new_value = false;
                    }
                }

                let old_value_ptr = args[3] as *const pinchy_common::kernel_types::Itimerspec;
                if old_value_ptr.is_null() {
                    data.has_old_value = false;
                } else {
                    if let Ok(old_value) = unsafe { bpf_probe_read_user(old_value_ptr) } {
                        data.old_value = old_value;
                        data.has_old_value = true;
                    } else {
                        data.has_old_value = false;
                    }
                }
            }
            syscalls::SYS_getitimer => {
                let data = data_mut!(entry, getitimer);
                data.which = args[0] as i32;

                let curr_value_ptr = args[1] as *const pinchy_common::kernel_types::Itimerval;
                if !curr_value_ptr.is_null() {
                    data.curr_value = unsafe {
                        bpf_probe_read_user::<pinchy_common::kernel_types::Itimerval>(
                            curr_value_ptr,
                        )
                    }
                    .unwrap_or_default();
                }
            }
            syscalls::SYS_setitimer => {
                let data = data_mut!(entry, setitimer);
                data.which = args[0] as i32;

                let new_value_ptr = args[1] as *const pinchy_common::kernel_types::Itimerval;
                if !new_value_ptr.is_null() {
                    data.new_value = unsafe {
                        bpf_probe_read_user::<pinchy_common::kernel_types::Itimerval>(new_value_ptr)
                    }
                    .unwrap_or_default();
                }

                let old_value_ptr = args[2] as *const pinchy_common::kernel_types::Itimerval;
                data.has_old_value = false;

                if !old_value_ptr.is_null() {
                    if let Ok(val) = unsafe {
                        bpf_probe_read_user::<pinchy_common::kernel_types::Itimerval>(old_value_ptr)
                    } {
                        data.old_value = val;
                        data.has_old_value = true;
                    } else {
                        data.has_old_value = false;
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
