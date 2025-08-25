// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use pinchy_common::syscalls;

use crate::{
    data_mut,
    util::{get_args, get_return_value, get_syscall_nr, read_iovec_array, Entry, IovecOp},
};

#[tracepoint]
pub fn syscall_exit_memory(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = get_syscall_nr(&ctx)?;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let mut entry = Entry::new(&ctx, syscall_nr)?;

        match syscall_nr {
            syscalls::SYS_mmap => {
                let data = data_mut!(entry, mmap);
                data.addr = args[0];
                data.length = args[1];
                data.prot = args[2] as i32;
                data.flags = args[3] as i32;
                data.fd = args[4] as i32;
                data.offset = args[5];
            }
            syscalls::SYS_munmap => {
                let data = data_mut!(entry, munmap);
                data.addr = args[0];
                data.length = args[1];
            }
            syscalls::SYS_madvise => {
                let data = data_mut!(entry, madvise);
                data.addr = args[0];
                data.length = args[1];
                data.advice = args[2] as i32;
            }
            syscalls::SYS_process_madvise => {
                let data = data_mut!(entry, process_madvise);
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
            }
            syscalls::SYS_process_vm_readv => {
                let data = data_mut!(entry, process_vm);
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
            }
            syscalls::SYS_process_vm_writev => {
                let data = data_mut!(entry, process_vm);
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
        Err(e) => e,
    }
}
