// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_user, bpf_probe_read_user_buf},
    macros::tracepoint,
    programs::TracePointContext,
};
use pinchy_common::{kernel_types, syscalls};

use crate::util;

#[tracepoint]
pub fn syscall_exit_network(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;
        let return_value = util::get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_recvmsg => {
                crate::util::submit_compact_payload::<pinchy_common::RecvmsgData, _>(
                    &ctx,
                    syscalls::SYS_recvmsg,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.flags = args[2] as i32;
                        let msg_ptr = args[1] as *const u8;
                        parse_msghdr(
                            msg_ptr,
                            &mut payload.msghdr,
                            util::IovecOp::Read,
                            return_value,
                        );
                    },
                )?;
            }
            syscalls::SYS_sendmsg => {
                crate::util::submit_compact_payload::<pinchy_common::SendmsgData, _>(
                    &ctx,
                    syscalls::SYS_sendmsg,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.flags = args[2] as i32;
                        let msg_ptr = args[1] as *const u8;
                        parse_msghdr(msg_ptr, &mut payload.msghdr, util::IovecOp::Write, 0);
                    },
                )?;
            }
            syscalls::SYS_accept => {
                crate::util::submit_compact_payload::<pinchy_common::AcceptData, _>(
                    &ctx,
                    syscalls::SYS_accept,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.has_addr = false;
                        payload.addrlen = 0;
                        let addr_ptr = args[1] as *const u8;
                        let addrlen_ptr = args[2] as *const u32;
                        unsafe {
                            if return_value >= 0 && !addr_ptr.is_null() && !addrlen_ptr.is_null() {
                                if let Ok(len) = bpf_probe_read_user::<u32>(addrlen_ptr) {
                                    payload.addrlen = len;
                                    if len > 0
                                        && len
                                            <= core::mem::size_of::<kernel_types::Sockaddr>() as u32
                                    {
                                        if let Ok(sockaddr) =
                                            bpf_probe_read_user::<kernel_types::Sockaddr>(
                                                addr_ptr as *const _,
                                            )
                                        {
                                            payload.addr = sockaddr;
                                            payload.has_addr = true;
                                        }
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_accept4 => {
                crate::util::submit_compact_payload::<pinchy_common::Accept4Data, _>(
                    &ctx,
                    syscalls::SYS_accept4,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.flags = args[3] as i32;
                        payload.has_addr = false;
                        payload.addrlen = 0;
                        let addr_ptr = args[1] as *const u8;
                        let addrlen_ptr = args[2] as *const u32;
                        unsafe {
                            if return_value >= 0 && !addr_ptr.is_null() && !addrlen_ptr.is_null() {
                                if let Ok(len) = bpf_probe_read_user::<u32>(addrlen_ptr) {
                                    payload.addrlen = len;
                                    if len > 0
                                        && len
                                            <= core::mem::size_of::<kernel_types::Sockaddr>() as u32
                                    {
                                        if let Ok(sockaddr) =
                                            bpf_probe_read_user::<kernel_types::Sockaddr>(
                                                addr_ptr as *const _,
                                            )
                                        {
                                            payload.addr = sockaddr;
                                            payload.has_addr = true;
                                        }
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_recvfrom => {
                crate::util::submit_compact_payload::<pinchy_common::RecvfromData, _>(
                    &ctx,
                    syscalls::SYS_recvfrom,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.size = args[2] as usize;
                        payload.flags = args[3] as i32;
                        payload.has_addr = false;
                        payload.addrlen = 0;
                        payload.received_data = [0u8; pinchy_common::DATA_READ_SIZE];
                        payload.received_len = 0;
                        let buf_ptr = args[1] as *const u8;
                        let src_addr_ptr = args[4] as *const u8;
                        let addrlen_ptr = args[5] as *const u32;
                        unsafe {
                            if return_value >= 0
                                && !src_addr_ptr.is_null()
                                && !addrlen_ptr.is_null()
                            {
                                if let Ok(len) = bpf_probe_read_user::<u32>(addrlen_ptr) {
                                    payload.addrlen = len;
                                    if len > 0
                                        && len
                                            <= core::mem::size_of::<kernel_types::Sockaddr>() as u32
                                    {
                                        if let Ok(sockaddr) =
                                            bpf_probe_read_user::<kernel_types::Sockaddr>(
                                                src_addr_ptr as *const _,
                                            )
                                        {
                                            payload.addr = sockaddr;
                                            payload.has_addr = true;
                                        }
                                    }
                                }
                            }
                            if return_value > 0 && !buf_ptr.is_null() {
                                let read_size = core::cmp::min(
                                    return_value as usize,
                                    pinchy_common::DATA_READ_SIZE,
                                );
                                if read_size > 0 {
                                    let _ = bpf_probe_read_user_buf(
                                        buf_ptr,
                                        &mut payload.received_data[..read_size],
                                    );
                                    payload.received_len = read_size;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_sendto => {
                crate::util::submit_compact_payload::<pinchy_common::SendtoData, _>(
                    &ctx,
                    syscalls::SYS_sendto,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.size = args[2] as usize;
                        payload.flags = args[3] as i32;
                        payload.has_addr = false;
                        payload.addrlen = 0;
                        payload.sent_data = [0u8; pinchy_common::DATA_READ_SIZE];
                        payload.sent_len = 0;
                        let buf_ptr = args[1] as *const u8;
                        let dest_addr_ptr = args[4] as *const u8;
                        let addrlen = args[5] as u32;

                        unsafe {
                            if !dest_addr_ptr.is_null() && addrlen > 0 {
                                payload.addrlen = addrlen;
                                if addrlen <= core::mem::size_of::<kernel_types::Sockaddr>() as u32
                                {
                                    if let Ok(sockaddr) =
                                        bpf_probe_read_user::<kernel_types::Sockaddr>(
                                            dest_addr_ptr as *const _,
                                        )
                                    {
                                        payload.addr = sockaddr;
                                        payload.has_addr = true;
                                    }
                                }
                            }
                            if payload.size > 0 && !buf_ptr.is_null() {
                                let read_size =
                                    core::cmp::min(payload.size, pinchy_common::DATA_READ_SIZE);
                                if read_size > 0 {
                                    let _ = bpf_probe_read_user_buf(
                                        buf_ptr,
                                        &mut payload.sent_data[..read_size],
                                    );
                                    payload.sent_len = read_size;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_bind => {
                crate::util::submit_compact_payload::<pinchy_common::SockaddrData, _>(
                    &ctx,
                    syscalls::SYS_bind,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.addrlen = args[2] as u32;

                        let addr_ptr = args[1] as *const u8;
                        payload.addr = unsafe {
                            bpf_probe_read_user::<kernel_types::Sockaddr>(addr_ptr as *const _)
                                .unwrap_or(kernel_types::Sockaddr::default())
                        };
                    },
                )?;
            }
            syscalls::SYS_connect => {
                crate::util::submit_compact_payload::<pinchy_common::SockaddrData, _>(
                    &ctx,
                    syscalls::SYS_connect,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.addrlen = args[2] as u32;

                        let addr_ptr = args[1] as *const u8;
                        payload.addr = unsafe {
                            bpf_probe_read_user::<kernel_types::Sockaddr>(addr_ptr as *const _)
                                .unwrap_or(kernel_types::Sockaddr::default())
                        };
                    },
                )?;
            }
            syscalls::SYS_socketpair => {
                crate::util::submit_compact_payload::<pinchy_common::SocketpairData, _>(
                    &ctx,
                    syscalls::SYS_socketpair,
                    return_value,
                    |payload| {
                        payload.domain = args[0] as i32;
                        payload.type_ = args[1] as i32;
                        payload.protocol = args[2] as i32;
                        payload.sv = [0; 2];

                        let sv_ptr = args[3] as *const i32;
                        unsafe {
                            if return_value == 0 && !sv_ptr.is_null() {
                                if let Ok(fd0) = bpf_probe_read_user::<i32>(sv_ptr) {
                                    payload.sv[0] = fd0;
                                }
                                if let Ok(fd1) = bpf_probe_read_user::<i32>(sv_ptr.add(1)) {
                                    payload.sv[1] = fd1;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_getsockname => {
                crate::util::submit_compact_payload::<pinchy_common::GetSocknameData, _>(
                    &ctx,
                    syscalls::SYS_getsockname,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.has_addr = false;
                        payload.addrlen = 0;

                        let addr_ptr = args[1] as *const u8;
                        let addrlen_ptr = args[2] as *const u32;

                        unsafe {
                            if return_value == 0 && !addr_ptr.is_null() && !addrlen_ptr.is_null() {
                                if let Ok(len) = bpf_probe_read_user::<u32>(addrlen_ptr) {
                                    payload.addrlen = len;
                                    if len > 0
                                        && len
                                            <= core::mem::size_of::<kernel_types::Sockaddr>() as u32
                                    {
                                        if let Ok(sockaddr) =
                                            bpf_probe_read_user::<kernel_types::Sockaddr>(
                                                addr_ptr as *const _,
                                            )
                                        {
                                            payload.addr = sockaddr;
                                            payload.has_addr = true;
                                        }
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_getpeername => {
                crate::util::submit_compact_payload::<pinchy_common::GetpeernameData, _>(
                    &ctx,
                    syscalls::SYS_getpeername,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.has_addr = false;
                        payload.addrlen = 0;

                        let addr_ptr = args[1] as *const u8;
                        let addrlen_ptr = args[2] as *const u32;

                        unsafe {
                            if return_value == 0 && !addr_ptr.is_null() && !addrlen_ptr.is_null() {
                                if let Ok(len) = bpf_probe_read_user::<u32>(addrlen_ptr) {
                                    payload.addrlen = len;
                                    if len > 0
                                        && len
                                            <= core::mem::size_of::<kernel_types::Sockaddr>() as u32
                                    {
                                        if let Ok(sockaddr) =
                                            bpf_probe_read_user::<kernel_types::Sockaddr>(
                                                addr_ptr as *const _,
                                            )
                                        {
                                            payload.addr = sockaddr;
                                            payload.has_addr = true;
                                        }
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_setsockopt => {
                crate::util::submit_compact_payload::<pinchy_common::SetsockoptData, _>(
                    &ctx,
                    syscalls::SYS_setsockopt,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.level = args[1] as i32;
                        payload.optname = args[2] as i32;
                        payload.optlen = args[4] as u32;

                        let optval_ptr = args[3] as *const u8;
                        if !optval_ptr.is_null() && payload.optlen > 0 {
                            let read_size = core::cmp::min(
                                payload.optlen as usize,
                                pinchy_common::MEDIUM_READ_SIZE,
                            );
                            unsafe {
                                let _ = bpf_probe_read_user_buf(
                                    optval_ptr,
                                    &mut payload.optval[..read_size],
                                );
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_getsockopt => {
                crate::util::submit_compact_payload::<pinchy_common::GetsockoptData, _>(
                    &ctx,
                    syscalls::SYS_getsockopt,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.level = args[1] as i32;
                        payload.optname = args[2] as i32;

                        let optval_ptr = args[3] as *const u8;
                        let optlen_ptr = args[4] as *const u32;

                        if return_value == 0 && !optlen_ptr.is_null() {
                            unsafe {
                                if let Ok(len) = bpf_probe_read_user::<u32>(optlen_ptr) {
                                    payload.optlen = len;
                                    if !optval_ptr.is_null() && len > 0 {
                                        let read_size = core::cmp::min(
                                            payload.optlen as usize,
                                            pinchy_common::MEDIUM_READ_SIZE,
                                        );
                                        let _ = bpf_probe_read_user_buf(
                                            optval_ptr,
                                            &mut payload.optval[..read_size],
                                        );
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_recvmmsg => {
                crate::util::submit_compact_payload::<pinchy_common::RecvMmsgData, _>(
                    &ctx,
                    syscalls::SYS_recvmmsg,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.vlen = args[2] as u32;
                        payload.flags = args[3] as i32;

                        let msgvec_ptr = args[1] as *const u8;
                        let timeout_ptr = args[4] as *const u8;

                        // Read timeout if provided
                        payload.has_timeout = false;
                        if !timeout_ptr.is_null() {
                            unsafe {
                                if let Ok(timeout) =
                                    bpf_probe_read_user::<pinchy_common::kernel_types::Timespec>(
                                        timeout_ptr as *const _,
                                    )
                                {
                                    payload.timeout = timeout;
                                    payload.has_timeout = true;
                                }
                            }
                        }

                        // Read messages array
                        payload.msgs_count = 0;
                        if !msgvec_ptr.is_null() && payload.vlen > 0 {
                            let msg_count = core::cmp::min(
                                payload.vlen as usize,
                                pinchy_common::kernel_types::MMSGHDR_COUNT,
                            );

                            for i in 0..msg_count {
                                // Each mmsghdr is 64 bytes (56 bytes for msghdr + 4 bytes for msg_len + 4 bytes padding)
                                unsafe {
                                    let mmsghdr_ptr = msgvec_ptr.add(i * 64);

                                    // Parse the msghdr part first
                                    parse_msghdr(
                                        mmsghdr_ptr,
                                        &mut payload.msgs[i].msg_hdr,
                                        util::IovecOp::Read,
                                        return_value,
                                    );

                                    // Read msg_len (offset 56 in mmsghdr)
                                    if return_value > 0 {
                                        if let Ok(msg_len) = bpf_probe_read_user::<u32>(
                                            mmsghdr_ptr.add(56) as *const u32,
                                        ) {
                                            payload.msgs[i].msg_len = msg_len;
                                        }
                                    }
                                }
                            }
                            payload.msgs_count = msg_count as u32;
                        }
                    },
                )?;
            }
            syscalls::SYS_sendmmsg => {
                crate::util::submit_compact_payload::<pinchy_common::SendMmsgData, _>(
                    &ctx,
                    syscalls::SYS_sendmmsg,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.vlen = args[2] as u32;
                        payload.flags = args[3] as i32;

                        let msgvec_ptr = args[1] as *const u8;

                        // Read messages array
                        payload.msgs_count = 0;
                        if !msgvec_ptr.is_null() && payload.vlen > 0 {
                            let msg_count = core::cmp::min(
                                payload.vlen as usize,
                                pinchy_common::kernel_types::MMSGHDR_COUNT,
                            );

                            for i in 0..msg_count {
                                // Each mmsghdr is 64 bytes (56 bytes for msghdr + 4 bytes for msg_len + 4 bytes padding)
                                unsafe {
                                    let mmsghdr_ptr = msgvec_ptr.add(i * 64);

                                    // Parse the msghdr part first
                                    parse_msghdr(
                                        mmsghdr_ptr,
                                        &mut payload.msgs[i].msg_hdr,
                                        util::IovecOp::Write,
                                        0,
                                    );

                                    // For sendmmsg, msg_len is output-only and set by the kernel on success
                                    payload.msgs[i].msg_len = 0;
                                }
                            }
                            payload.msgs_count = msg_count as u32;
                        }
                    },
                )?;
            }
            _ => {}
        }

        Ok(())
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn parse_msghdr(
    msg_ptr: *const u8,
    msghdr: &mut kernel_types::Msghdr,
    op: util::IovecOp,
    return_value: i64,
) {
    if msg_ptr.is_null() {
        return;
    }

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

                // Read the iovec array using the shared helper
                if msg_iov_addr != 0 && msghdr.msg_iovlen > 0 {
                    let mut iov_lens = [0usize; pinchy_common::IOV_COUNT];
                    let mut read_count = 0;

                    util::read_iovec_array(
                        msg_iov_addr,
                        msghdr.msg_iovlen as usize,
                        op,
                        &mut msghdr.msg_iov, // MSG_IOV_COUNT == IOV_COUNT, so this works
                        &mut iov_lens,
                        None, // We don't need buffer contents for msghdr
                        &mut read_count,
                        return_value,
                    );
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
            if let Ok(sockaddr) =
                bpf_probe_read_user::<kernel_types::Sockaddr>(msghdr.msg_name as *const _)
            {
                msghdr.name = sockaddr;
                msghdr.has_name = true;
            }
        }

        // Read control message data if present (up to MSG_CONTROL_SIZE bytes)
        if msghdr.msg_control != 0 && msghdr.msg_controllen > 0 {
            let control_size = core::cmp::min(
                msghdr.msg_controllen as usize,
                kernel_types::MSG_CONTROL_SIZE,
            );
            let _ = bpf_probe_read_user_buf(
                msghdr.msg_control as *const u8,
                &mut msghdr.control_data[..control_size],
            );
        }
    }
}
