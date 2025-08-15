// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use crate::{
    syscall_handler,
    util::{read_iovec_array, IovecOp},
};

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

syscall_handler!(process_madvise, process_madvise, args, data, {
    data.pidfd = args[0] as i32;
    data.iovcnt = args[2] as usize;
    data.advice = args[3] as i32;
    data.flags = args[4] as u32;

    let iov_addr = args[1] as u64;
    read_iovec_array(
        iov_addr,
        data.iovcnt,
        IovecOp::AddressOnly, // Don't read buffer contents for madvise
        &mut data.iovecs,
        &mut data.iov_lens,
        None, // No buffer needed for AddressOnly
        &mut data.read_count,
        0, // return_value not relevant for AddressOnly
    );
});

syscall_handler!(process_vm_readv, process_vm, args, data, return_value, {
    data.pid = args[0] as i32;
    data.local_iovcnt = args[2] as usize;
    data.remote_iovcnt = args[4] as usize;
    data.flags = args[5] as u64;

    let local_addr = args[1] as u64;
    let remote_addr = args[3] as u64;

    // Read local iovec array (with buffer contents since it's readable by us)
    read_iovec_array(
        local_addr,
        data.local_iovcnt,
        IovecOp::Read,
        &mut data.local_iovecs,
        &mut data.local_iov_lens,
        Some(&mut data.local_iov_bufs),
        &mut data.local_read_count,
        return_value,
    );

    // Read remote iovec array (address-only since we can't read remote process memory)
    read_iovec_array(
        remote_addr,
        data.remote_iovcnt,
        IovecOp::AddressOnly,
        &mut data.remote_iovecs,
        &mut data.remote_iov_lens,
        None, // No buffer needed for AddressOnly
        &mut data.remote_read_count,
        return_value,
    );
});

syscall_handler!(process_vm_writev, process_vm, args, data, return_value, {
    data.pid = args[0] as i32;
    data.local_iovcnt = args[2] as usize;
    data.remote_iovcnt = args[4] as usize;
    data.flags = args[5] as u64;

    let local_addr = args[1] as u64;
    let remote_addr = args[3] as u64;

    // Read local iovec array (with buffer contents since it's readable by us)
    read_iovec_array(
        local_addr,
        data.local_iovcnt,
        IovecOp::Write,
        &mut data.local_iovecs,
        &mut data.local_iov_lens,
        Some(&mut data.local_iov_bufs),
        &mut data.local_read_count,
        return_value,
    );

    // Read remote iovec array (address-only since we can't read remote process memory)
    read_iovec_array(
        remote_addr,
        data.remote_iovcnt,
        IovecOp::AddressOnly,
        &mut data.remote_iovecs,
        &mut data.remote_iov_lens,
        None, // No buffer needed for AddressOnly
        &mut data.remote_read_count,
        return_value,
    );
});
