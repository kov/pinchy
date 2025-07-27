// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::kernel_types::Timespec;

use crate::syscall_handler;

syscall_handler!(futex, futex, args, data, {
    data.uaddr = args[0];
    data.op = args[1] as u32;
    data.val = args[2] as u32;
    data.uaddr2 = args[4];
    data.val3 = args[5] as u32;

    let timeout_ptr = args[3] as *const Timespec;
    data.timeout = crate::util::read_timespec(timeout_ptr);
});
