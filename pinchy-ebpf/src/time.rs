// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::helpers::bpf_probe_read_user;

use crate::syscall_handler;

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
