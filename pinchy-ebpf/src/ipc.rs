// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::helpers::bpf_probe_read_user;
use pinchy_common::kernel_types;

use crate::syscall_handler;

syscall_handler!(shmget, args, data, {
    data.key = args[0] as i32;
    data.size = args[1] as usize;
    data.shmflg = args[2] as i32;
});

syscall_handler!(shmat, args, data, {
    data.shmid = args[0] as i32;
    data.shmaddr = args[1];
    data.shmflg = args[2] as i32;
});

syscall_handler!(shmdt, args, data, {
    data.shmaddr = args[0];
});

syscall_handler!(shmctl, args, data, {
    data.shmid = args[0] as i32;
    data.cmd = args[1] as i32;

    let buf_ptr = args[2] as *const kernel_types::ShmidDs;
    if !buf_ptr.is_null() {
        data.has_buf = true;
        data.buf = unsafe {
            bpf_probe_read_user::<kernel_types::ShmidDs>(buf_ptr)
                .unwrap_or(kernel_types::ShmidDs::default())
        };
    } else {
        data.has_buf = false;
    }
});
