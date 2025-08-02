// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use core::mem::size_of;

use aya_ebpf::helpers::bpf_probe_read_user;
use pinchy_common::kernel_types::Iovec;

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

syscall_handler!(process_madvise, args, data, {
    data.pidfd = args[0] as i32;
    data.iovcnt = args[2] as usize;
    data.advice = args[3] as i32;
    data.flags = args[4] as u32;
    data.read_count = core::cmp::min(data.iovcnt, pinchy_common::IOV_COUNT);

    let iov_addr = args[1] as u64;

    // Read only the iovec structures, not the buffer contents since these are addresses in another process
    for i in 0..data.read_count {
        let iov_ptr = (iov_addr as *const u8).wrapping_add(i * size_of::<Iovec>());

        let iov_base = unsafe {
            bpf_probe_read_user::<*const u8>(iov_ptr as *const _).unwrap_or(core::ptr::null())
        };

        if iov_base.is_null() {
            continue;
        }

        let iov_len =
            unsafe { bpf_probe_read_user::<u64>((iov_ptr as *const u64).add(1)).unwrap_or(0) };

        data.iovecs[i] = Iovec {
            iov_base: iov_base as u64,
            iov_len,
        };
        data.iov_lens[i] = iov_len as usize;
    }
});
