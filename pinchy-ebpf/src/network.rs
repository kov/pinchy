// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_buf, bpf_probe_read_user},
    macros::tracepoint,
    programs::TracePointContext,
};
use pinchy_common::syscalls::{SYS_accept4, SYS_recvmsg};

use crate::util::{get_args, get_return_value, output_event};

#[tracepoint]
pub fn syscall_exit_recvmsg(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_recvmsg;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let sockfd = args[0] as i32;
        let msg_ptr = args[1] as *const u8;
        let flags = args[2] as i32;

        let mut msghdr = pinchy_common::kernel_types::Msghdr::default();

        // Read the msghdr structure from userspace
        unsafe {
            // Read the basic msghdr structure fields
            if let Ok(msg_name_ptr) = bpf_probe_read_user::<u64>(msg_ptr as *const u64) {
                msghdr.msg_name = msg_name_ptr;
            }

            if let Ok(msg_namelen) = bpf_probe_read_user::<u32>(msg_ptr.add(8) as *const u32) {
                msghdr.msg_namelen = msg_namelen;
            }

            if let Ok(msg_iov_addr) = bpf_probe_read_user::<u64>(msg_ptr.add(16) as *const u64) {
                if let Ok(msg_iovlen) = bpf_probe_read_user::<u32>(msg_ptr.add(24) as *const u32) {
                    msghdr.msg_iovlen = msg_iovlen;

                    // Read the iovec array (up to MSG_IOV_COUNT entries)
                    if msg_iov_addr != 0 && msghdr.msg_iovlen > 0 {
                        let iov_count = core::cmp::min(
                            msghdr.msg_iovlen as usize,
                            pinchy_common::kernel_types::MSG_IOV_COUNT,
                        );

                        for i in 0..iov_count {
                            let iov_ptr = (msg_iov_addr as *const u8).add(i * 16);
                            let iov_base =
                                bpf_probe_read_user::<u64>(iov_ptr as *const u64).unwrap_or(0);
                            let iov_len =
                                bpf_probe_read_user::<u64>((iov_ptr as *const u64).add(1))
                                    .unwrap_or(0);

                            msghdr.msg_iov[i] =
                                pinchy_common::kernel_types::Iovec { iov_base, iov_len };
                        }
                    }
                }
            }

            if let Ok(msg_control) = bpf_probe_read_user::<u64>(msg_ptr.add(32) as *const u64) {
                msghdr.msg_control = msg_control;
            }

            if let Ok(msg_controllen) = bpf_probe_read_user::<u32>(msg_ptr.add(40) as *const u32) {
                msghdr.msg_controllen = msg_controllen;
            }

            if let Ok(msg_flags) = bpf_probe_read_user::<i32>(msg_ptr.add(48) as *const i32) {
                msghdr.msg_flags = msg_flags;
            }

            // Read the sockaddr if present and not null
            if msghdr.msg_name != 0 && msghdr.msg_namelen > 0 {
                if let Ok(sockaddr) = bpf_probe_read_user::<pinchy_common::kernel_types::Sockaddr>(
                    msghdr.msg_name as *const _,
                ) {
                    msghdr.name = sockaddr;
                    msghdr.has_name = true;
                }
            }

            // Read control message data if present (up to MSG_CONTROL_SIZE bytes)
            if msghdr.msg_control != 0 && msghdr.msg_controllen > 0 {
                let control_size = core::cmp::min(
                    msghdr.msg_controllen as usize,
                    pinchy_common::kernel_types::MSG_CONTROL_SIZE,
                );
                let _ = bpf_probe_read_buf(
                    msghdr.msg_control as *const u8,
                    &mut msghdr.control_data[..control_size],
                );
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                recvmsg: pinchy_common::RecvmsgData {
                    sockfd,
                    flags,
                    msghdr,
                },
            },
        )
    }

    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_accept4(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_accept4;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let sockfd = args[0] as i32;
        let addr_ptr = args[1] as *const u8;
        let addrlen_ptr = args[2] as *const u32;
        let flags = args[3] as i32;

        let mut addr = pinchy_common::kernel_types::Sockaddr::default();
        let mut addrlen = 0u32;
        let mut has_addr = false;

        unsafe {
            // Only read address data if the call was successful and addr_ptr is not null
            if return_value >= 0
                && addr_ptr != core::ptr::null()
                && addrlen_ptr != core::ptr::null()
            {
                if let Ok(len) = bpf_probe_read_user::<u32>(addrlen_ptr) {
                    addrlen = len;

                    if len > 0
                        && len
                            <= core::mem::size_of::<pinchy_common::kernel_types::Sockaddr>() as u32
                    {
                        if let Ok(sockaddr) = bpf_probe_read_user::<
                            pinchy_common::kernel_types::Sockaddr,
                        >(addr_ptr as *const _)
                        {
                            addr = sockaddr;
                            has_addr = true;
                        }
                    }
                }
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                accept4: pinchy_common::Accept4Data {
                    sockfd,
                    flags,
                    has_addr,
                    addr,
                    addrlen,
                },
            },
        )
    }

    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}
