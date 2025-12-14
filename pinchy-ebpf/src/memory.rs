// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{helpers::bpf_probe_read_user, macros::tracepoint, programs::TracePointContext};
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
            syscalls::SYS_mbind => {
                let data = data_mut!(entry, mbind);
                data.addr = args[0] as u64;
                data.len = args[1] as u64;
                data.mode = args[2] as i32;
                data.maxnode = args[4] as u64;
                data.flags = args[5] as u32;

                let nodemask_ptr = args[3] as *const u64;

                if !nodemask_ptr.is_null() && data.maxnode > 0 {
                    let max_longs = core::cmp::min(2, (data.maxnode + 63) / 64);

                    for i in 0..max_longs as usize {
                        if i >= 2 {
                            break;
                        }

                        unsafe {
                            let ptr = nodemask_ptr.add(i);

                            if let Ok(val) = bpf_probe_read_user(ptr) {
                                data.nodemask[i] = val;
                                data.nodemask_read_count += 1;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
            syscalls::SYS_get_mempolicy => {
                let data = data_mut!(entry, get_mempolicy);
                data.maxnode = args[2] as u64;
                data.addr = args[3] as u64;
                data.flags = args[4] as u64;

                if return_value >= 0 {
                    let mode_ptr = args[0] as *const i32;

                    if !mode_ptr.is_null() {
                        if let Ok(mode) = unsafe { bpf_probe_read_user(mode_ptr) } {
                            data.mode_out = mode;
                            data.mode_valid = true;
                        }
                    }

                    let nodemask_ptr = args[1] as *const u64;

                    if !nodemask_ptr.is_null() && data.maxnode > 0 {
                        let max_longs = core::cmp::min(2, (data.maxnode + 63) / 64);

                        for i in 0..max_longs as usize {
                            if i >= 2 {
                                break;
                            }

                            unsafe {
                                let ptr = nodemask_ptr.add(i);

                                if let Ok(val) = bpf_probe_read_user(ptr) {
                                    data.nodemask_out[i] = val;
                                    data.nodemask_read_count += 1;
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            syscalls::SYS_set_mempolicy => {
                let data = data_mut!(entry, set_mempolicy);
                data.mode = args[0] as i32;
                data.maxnode = args[2] as u64;

                let nodemask_ptr = args[1] as *const u64;

                if !nodemask_ptr.is_null() && data.maxnode > 0 {
                    let max_longs = core::cmp::min(2, (data.maxnode + 63) / 64);

                    for i in 0..max_longs as usize {
                        if i >= 2 {
                            break;
                        }

                        unsafe {
                            let ptr = nodemask_ptr.add(i);

                            if let Ok(val) = bpf_probe_read_user(ptr) {
                                data.nodemask[i] = val;
                                data.nodemask_read_count += 1;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
            syscalls::SYS_migrate_pages => {
                let data = data_mut!(entry, migrate_pages);
                data.pid = args[0] as i32;
                data.maxnode = args[1] as u64;

                let old_nodes_ptr = args[2] as *const u64;
                let new_nodes_ptr = args[3] as *const u64;

                if !old_nodes_ptr.is_null() && data.maxnode > 0 {
                    let max_longs = core::cmp::min(2, (data.maxnode + 63) / 64);

                    for i in 0..max_longs as usize {
                        if i >= 2 {
                            break;
                        }

                        unsafe {
                            let ptr = old_nodes_ptr.add(i);

                            if let Ok(val) = bpf_probe_read_user(ptr) {
                                data.old_nodes[i] = val;
                                data.old_nodes_read_count += 1;
                            } else {
                                break;
                            }
                        }
                    }
                }

                if !new_nodes_ptr.is_null() && data.maxnode > 0 {
                    let max_longs = core::cmp::min(2, (data.maxnode + 63) / 64);

                    for i in 0..max_longs as usize {
                        if i >= 2 {
                            break;
                        }

                        unsafe {
                            let ptr = new_nodes_ptr.add(i);

                            if let Ok(val) = bpf_probe_read_user(ptr) {
                                data.new_nodes[i] = val;
                                data.new_nodes_read_count += 1;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
            syscalls::SYS_move_pages => {
                let data = data_mut!(entry, move_pages);
                data.pid = args[0] as i32;
                data.count = args[1] as u64;
                data.flags = args[5] as i32;

                let pages_ptr = args[2] as *const *const core::ffi::c_void;
                let nodes_ptr = args[3] as *const i32;
                let status_ptr = args[4] as *const i32;

                let max_to_read = core::cmp::min(8, data.count as usize);

                if !pages_ptr.is_null() {
                    for i in 0..max_to_read {
                        unsafe {
                            let ptr = pages_ptr.add(i);

                            if let Ok(page_ptr) = bpf_probe_read_user(ptr) {
                                data.pages[i] = page_ptr as u64;
                                data.pages_read_count += 1;
                            } else {
                                break;
                            }
                        }
                    }
                }

                if !nodes_ptr.is_null() {
                    for i in 0..max_to_read {
                        unsafe {
                            let ptr = nodes_ptr.add(i);

                            if let Ok(node) = bpf_probe_read_user(ptr) {
                                data.nodes[i] = node;
                                data.nodes_read_count += 1;
                            } else {
                                break;
                            }
                        }
                    }
                }

                if !status_ptr.is_null() && return_value >= 0 {
                    for i in 0..max_to_read {
                        unsafe {
                            let ptr = status_ptr.add(i);

                            if let Ok(status) = bpf_probe_read_user(ptr) {
                                data.status[i] = status;
                                data.status_read_count += 1;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
            syscalls::SYS_mincore => {
                let data = data_mut!(entry, mincore);
                data.addr = args[0] as u64;
                data.length = args[1] as u64;

                if return_value >= 0 {
                    let vec_ptr = args[2] as *const u8;

                    if !vec_ptr.is_null() && data.length > 0 {
                        const PAGE_SIZE: u64 = 4096;
                        let num_pages = ((data.length + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
                        let max_to_read = core::cmp::min(32, num_pages);

                        for i in 0..max_to_read {
                            unsafe {
                                let ptr = vec_ptr.add(i);

                                if let Ok(byte) = bpf_probe_read_user(ptr) {
                                    data.vec[i] = byte;
                                    data.vec_read_count += 1;
                                } else {
                                    break;
                                }
                            }
                        }
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
        Err(e) => e,
    }
}
