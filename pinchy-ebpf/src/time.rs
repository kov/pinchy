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
