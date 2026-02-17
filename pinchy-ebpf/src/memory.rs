// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{helpers::bpf_probe_read_user, macros::tracepoint, programs::TracePointContext};
use pinchy_common::syscalls;

use crate::util::{get_args, get_return_value, get_syscall_nr, read_iovec_array, IovecOp};

#[tracepoint]
pub fn syscall_exit_memory(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = get_syscall_nr(&ctx)?;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_mmap => {
                crate::util::submit_compact_payload::<pinchy_common::MmapData, _>(
                    &ctx,
                    syscalls::SYS_mmap,
                    return_value,
                    |payload| {
                        payload.addr = args[0];
                        payload.length = args[1];
                        payload.prot = args[2] as i32;
                        payload.flags = args[3] as i32;
                        payload.fd = args[4] as i32;
                        payload.offset = args[5];
                    },
                )?;
            }
            syscalls::SYS_munmap => {
                crate::util::submit_compact_payload::<pinchy_common::MunmapData, _>(
                    &ctx,
                    syscalls::SYS_munmap,
                    return_value,
                    |payload| {
                        payload.addr = args[0];
                        payload.length = args[1];
                    },
                )?;
            }
            syscalls::SYS_madvise => {
                crate::util::submit_compact_payload::<pinchy_common::MadviseData, _>(
                    &ctx,
                    syscalls::SYS_madvise,
                    return_value,
                    |payload| {
                        payload.addr = args[0];
                        payload.length = args[1];
                        payload.advice = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_process_madvise => {
                crate::util::submit_compact_payload::<pinchy_common::ProcessMadviseData, _>(
                    &ctx,
                    syscalls::SYS_process_madvise,
                    return_value,
                    |payload| {
                        payload.pidfd = args[0] as i32;
                        payload.iovcnt = args[2] as usize;
                        payload.advice = args[3] as i32;
                        payload.flags = args[4] as u32;

                        let iov_addr = args[1] as u64;
                        read_iovec_array(
                            iov_addr,
                            payload.iovcnt,
                            IovecOp::AddressOnly, // Don't read buffer contents for madvise
                            &mut payload.iovecs,
                            &mut payload.iov_lens,
                            None, // No buffer needed for AddressOnly
                            &mut payload.read_count,
                            0, // return_value not relevant for AddressOnly
                        );
                    },
                )?;
            }
            syscalls::SYS_process_vm_readv => {
                crate::util::submit_compact_payload::<pinchy_common::ProcessVmData, _>(
                    &ctx,
                    syscalls::SYS_process_vm_readv,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        payload.local_iovcnt = args[2] as usize;
                        payload.remote_iovcnt = args[4] as usize;
                        payload.flags = args[5] as u64;

                        let local_addr = args[1] as u64;
                        let remote_addr = args[3] as u64;

                        // Read local iovec array (with buffer contents since it's readable by us)
                        read_iovec_array(
                            local_addr,
                            payload.local_iovcnt,
                            IovecOp::Read,
                            &mut payload.local_iovecs,
                            &mut payload.local_iov_lens,
                            Some(&mut payload.local_iov_bufs),
                            &mut payload.local_read_count,
                            return_value,
                        );

                        // Read remote iovec array (address-only since we can't read remote process memory)
                        read_iovec_array(
                            remote_addr,
                            payload.remote_iovcnt,
                            IovecOp::AddressOnly,
                            &mut payload.remote_iovecs,
                            &mut payload.remote_iov_lens,
                            None, // No buffer needed for AddressOnly
                            &mut payload.remote_read_count,
                            return_value,
                        );
                    },
                )?;
            }
            syscalls::SYS_process_vm_writev => {
                crate::util::submit_compact_payload::<pinchy_common::ProcessVmData, _>(
                    &ctx,
                    syscalls::SYS_process_vm_writev,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        payload.local_iovcnt = args[2] as usize;
                        payload.remote_iovcnt = args[4] as usize;
                        payload.flags = args[5] as u64;

                        let local_addr = args[1] as u64;
                        let remote_addr = args[3] as u64;

                        // Read local iovec array (with buffer contents since it's readable by us)
                        read_iovec_array(
                            local_addr,
                            payload.local_iovcnt,
                            IovecOp::Write,
                            &mut payload.local_iovecs,
                            &mut payload.local_iov_lens,
                            Some(&mut payload.local_iov_bufs),
                            &mut payload.local_read_count,
                            return_value,
                        );

                        // Read remote iovec array (address-only since we can't read remote process memory)
                        read_iovec_array(
                            remote_addr,
                            payload.remote_iovcnt,
                            IovecOp::AddressOnly,
                            &mut payload.remote_iovecs,
                            &mut payload.remote_iov_lens,
                            None, // No buffer needed for AddressOnly
                            &mut payload.remote_read_count,
                            return_value,
                        );
                    },
                )?;
            }
            syscalls::SYS_mbind => {
                crate::util::submit_compact_payload::<pinchy_common::MbindData, _>(
                    &ctx,
                    syscalls::SYS_mbind,
                    return_value,
                    |payload| {
                        payload.addr = args[0] as u64;
                        payload.len = args[1] as u64;
                        payload.mode = args[2] as i32;
                        payload.maxnode = args[4] as u64;
                        payload.flags = args[5] as u32;

                        let nodemask_ptr = args[3] as *const u64;

                        if !nodemask_ptr.is_null() && payload.maxnode > 0 {
                            let max_longs = core::cmp::min(2, (payload.maxnode + 63) / 64);

                            for i in 0..max_longs as usize {
                                if i >= 2 {
                                    break;
                                }

                                unsafe {
                                    let ptr = nodemask_ptr.add(i);

                                    if let Ok(val) = bpf_probe_read_user(ptr) {
                                        payload.nodemask[i] = val;
                                        payload.nodemask_read_count += 1;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_get_mempolicy => {
                crate::util::submit_compact_payload::<pinchy_common::GetMempolicyData, _>(
                    &ctx,
                    syscalls::SYS_get_mempolicy,
                    return_value,
                    |payload| {
                        payload.maxnode = args[2] as u64;
                        payload.addr = args[3] as u64;
                        payload.flags = args[4] as u64;

                        if return_value >= 0 {
                            let mode_ptr = args[0] as *const i32;

                            if !mode_ptr.is_null() {
                                if let Ok(mode) = unsafe { bpf_probe_read_user(mode_ptr) } {
                                    payload.mode_out = mode;
                                    payload.mode_valid = true;
                                }
                            }

                            let nodemask_ptr = args[1] as *const u64;

                            if !nodemask_ptr.is_null() && payload.maxnode > 0 {
                                let max_longs = core::cmp::min(2, (payload.maxnode + 63) / 64);

                                for i in 0..max_longs as usize {
                                    if i >= 2 {
                                        break;
                                    }

                                    unsafe {
                                        let ptr = nodemask_ptr.add(i);

                                        if let Ok(val) = bpf_probe_read_user(ptr) {
                                            payload.nodemask_out[i] = val;
                                            payload.nodemask_read_count += 1;
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_set_mempolicy => {
                crate::util::submit_compact_payload::<pinchy_common::SetMempolicyData, _>(
                    &ctx,
                    syscalls::SYS_set_mempolicy,
                    return_value,
                    |payload| {
                        payload.mode = args[0] as i32;
                        payload.maxnode = args[2] as u64;

                        let nodemask_ptr = args[1] as *const u64;

                        if !nodemask_ptr.is_null() && payload.maxnode > 0 {
                            let max_longs = core::cmp::min(2, (payload.maxnode + 63) / 64);

                            for i in 0..max_longs as usize {
                                if i >= 2 {
                                    break;
                                }

                                unsafe {
                                    let ptr = nodemask_ptr.add(i);

                                    if let Ok(val) = bpf_probe_read_user(ptr) {
                                        payload.nodemask[i] = val;
                                        payload.nodemask_read_count += 1;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_migrate_pages => {
                crate::util::submit_compact_payload::<pinchy_common::MigratePagesData, _>(
                    &ctx,
                    syscalls::SYS_migrate_pages,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        payload.maxnode = args[1] as u64;

                        let old_nodes_ptr = args[2] as *const u64;
                        let new_nodes_ptr = args[3] as *const u64;

                        if !old_nodes_ptr.is_null() && payload.maxnode > 0 {
                            let max_longs = core::cmp::min(2, (payload.maxnode + 63) / 64);

                            for i in 0..max_longs as usize {
                                if i >= 2 {
                                    break;
                                }

                                unsafe {
                                    let ptr = old_nodes_ptr.add(i);

                                    if let Ok(val) = bpf_probe_read_user(ptr) {
                                        payload.old_nodes[i] = val;
                                        payload.old_nodes_read_count += 1;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }

                        if !new_nodes_ptr.is_null() && payload.maxnode > 0 {
                            let max_longs = core::cmp::min(2, (payload.maxnode + 63) / 64);

                            for i in 0..max_longs as usize {
                                if i >= 2 {
                                    break;
                                }

                                unsafe {
                                    let ptr = new_nodes_ptr.add(i);

                                    if let Ok(val) = bpf_probe_read_user(ptr) {
                                        payload.new_nodes[i] = val;
                                        payload.new_nodes_read_count += 1;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_move_pages => {
                crate::util::submit_compact_payload::<pinchy_common::MovePagesData, _>(
                    &ctx,
                    syscalls::SYS_move_pages,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        payload.count = args[1] as u64;
                        payload.flags = args[5] as i32;

                        let pages_ptr = args[2] as *const *const core::ffi::c_void;
                        let nodes_ptr = args[3] as *const i32;
                        let status_ptr = args[4] as *const i32;

                        let max_to_read = core::cmp::min(8, payload.count as usize);

                        if !pages_ptr.is_null() {
                            for i in 0..max_to_read {
                                unsafe {
                                    let ptr = pages_ptr.add(i);

                                    if let Ok(page_ptr) = bpf_probe_read_user(ptr) {
                                        payload.pages[i] = page_ptr as u64;
                                        payload.pages_read_count += 1;
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
                                        payload.nodes[i] = node;
                                        payload.nodes_read_count += 1;
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
                                        payload.status[i] = status;
                                        payload.status_read_count += 1;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_mincore => {
                crate::util::submit_compact_payload::<pinchy_common::MincoreData, _>(
                    &ctx,
                    syscalls::SYS_mincore,
                    return_value,
                    |payload| {
                        payload.addr = args[0] as u64;
                        payload.length = args[1] as u64;

                        if return_value >= 0 {
                            let vec_ptr = args[2] as *const u8;

                            if !vec_ptr.is_null() && payload.length > 0 {
                                const PAGE_SIZE: u64 = 4096;
                                let num_pages =
                                    ((payload.length + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
                                let max_to_read = core::cmp::min(32, num_pages);

                                for i in 0..max_to_read {
                                    unsafe {
                                        let ptr = vec_ptr.add(i);

                                        if let Ok(byte) = bpf_probe_read_user(ptr) {
                                            payload.vec[i] = byte;
                                            payload.vec_read_count += 1;
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_memfd_create => {
                crate::util::submit_compact_payload::<pinchy_common::MemfdCreateData, _>(
                    &ctx,
                    syscalls::SYS_memfd_create,
                    return_value,
                    |payload| {
                        payload.flags = args[1] as u32;

                        let name_ptr = args[0] as *const u8;

                        if !name_ptr.is_null() {
                            for i in 0..payload.name.len() {
                                unsafe {
                                    let ptr = name_ptr.add(i);

                                    if let Ok(byte) = bpf_probe_read_user(ptr) {
                                        payload.name[i] = byte;

                                        if byte == 0 {
                                            break;
                                        }
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_pkey_mprotect => {
                crate::util::submit_compact_payload::<pinchy_common::PkeyMprotectData, _>(
                    &ctx,
                    syscalls::SYS_pkey_mprotect,
                    return_value,
                    |payload| {
                        payload.addr = args[0] as u64;
                        payload.len = args[1] as u64;
                        payload.prot = args[2] as i32;
                        payload.pkey = args[3] as i32;
                    },
                )?;
            }
            syscalls::SYS_mseal => {
                crate::util::submit_compact_payload::<pinchy_common::MsealData, _>(
                    &ctx,
                    syscalls::SYS_mseal,
                    return_value,
                    |payload| {
                        payload.addr = args[0] as u64;
                        payload.len = args[1] as u64;
                        payload.flags = args[2] as u64;
                    },
                )?;
            }
            syscalls::SYS_remap_file_pages => {
                crate::util::submit_compact_payload::<pinchy_common::RemapFilePagesData, _>(
                    &ctx,
                    syscalls::SYS_remap_file_pages,
                    return_value,
                    |payload| {
                        payload.addr = args[0] as u64;
                        payload.size = args[1] as u64;
                        payload.prot = args[2] as i32;
                        payload.pgoff = args[3] as u64;
                        payload.flags = args[4] as i32;
                    },
                )?;
            }
            _ => {}
        }

        Ok(())
    }

    match inner(ctx) {
        Ok(()) => 0,
        Err(e) => e,
    }
}
