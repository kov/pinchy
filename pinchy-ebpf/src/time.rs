// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::helpers::bpf_probe_read_user;
use pinchy_common::{kernel_types::Timespec, ClockTimeData};

use crate::{syscall_handler, util::read_timespec};

syscall_handler!(adjtimex, args, data, {
    let timex_ptr = args[0] as *const pinchy_common::kernel_types::Timex;
    if let Ok(val) = unsafe { bpf_probe_read_user::<pinchy_common::kernel_types::Timex>(timex_ptr) }
    {
        data.timex = val;
    }
});

syscall_handler!(clock_adjtime, args, data, {
    data.clockid = args[0] as i32;
    let timex_ptr = args[1] as *const pinchy_common::kernel_types::Timex;
    if let Ok(val) = unsafe { bpf_probe_read_user::<pinchy_common::kernel_types::Timex>(timex_ptr) }
    {
        data.timex = val;
    }
});

syscall_handler!(clock_getres, clock_time, args, data, {
    read_clock_time(&args, data);
});

syscall_handler!(clock_gettime, clock_time, args, data, {
    read_clock_time(&args, data);
});

syscall_handler!(clock_settime, clock_time, args, data, {
    read_clock_time(&args, data);
});

fn read_clock_time(args: &[usize], data: &mut ClockTimeData) {
    data.clockid = args[0] as i32;
    let tp_ptr = args[1] as *const Timespec;
    if tp_ptr.is_null() {
        data.has_tp = false;
    } else {
        data.tp = read_timespec(tp_ptr);
        data.has_tp = true;
    }
}

syscall_handler!(timer_create, timer_create, args, data, {
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
});

syscall_handler!(timer_gettime, timer_gettime, args, data, {
    data.timerid = args[0];
    let curr_value_ptr = args[1] as *const pinchy_common::kernel_types::Itimerspec;
    if !curr_value_ptr.is_null() {
        if let Ok(curr_value) = unsafe { bpf_probe_read_user(curr_value_ptr) } {
            data.curr_value = curr_value;
        }
    }
});

syscall_handler!(timer_settime, timer_settime, args, data, {
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
});
