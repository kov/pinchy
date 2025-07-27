// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use crate::syscall_handler;

syscall_handler!(mmap, args, data, {
    data.addr = args[0];
    data.length = args[1];
    data.prot = args[2] as i32;
    data.flags = args[3] as i32;
    data.fd = args[4] as i32;
    data.offset = args[5];
});

syscall_handler!(munmap, args, data, {
    data.addr = args[0];
    data.length = args[1];
});

syscall_handler!(madvise, args, data, {
    data.addr = args[0];
    data.length = args[1];
    data.advice = args[2] as i32;
});
