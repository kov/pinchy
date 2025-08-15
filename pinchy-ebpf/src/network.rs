// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::helpers::{bpf_probe_read_buf, bpf_probe_read_user};
use pinchy_common::kernel_types;

use crate::syscall_handler;

syscall_handler!(recvmsg, recvmsg, args, data, return_value, {
    data.sockfd = args[0] as i32;
    data.flags = args[2] as i32;
    let msg_ptr = args[1] as *const u8;
    parse_msghdr(
        msg_ptr,
        &mut data.msghdr,
        crate::util::IovecOp::Read,
        return_value,
    );
});

syscall_handler!(sendmsg, sendmsg, args, data, {
    data.sockfd = args[0] as i32;
    data.flags = args[2] as i32;
    let msg_ptr = args[1] as *const u8;
    parse_msghdr(msg_ptr, &mut data.msghdr, crate::util::IovecOp::Write, 0);
});

syscall_handler!(accept, accept, args, data, return_value, {
    data.sockfd = args[0] as i32;
    data.has_addr = false;
    data.addr = kernel_types::Sockaddr::default();
    data.addrlen = 0;
    let addr_ptr = args[1] as *const u8;
    let addrlen_ptr = args[2] as *const u32;
    unsafe {
        if return_value >= 0 && !addr_ptr.is_null() && !addrlen_ptr.is_null() {
            if let Ok(len) = bpf_probe_read_user::<u32>(addrlen_ptr) {
                data.addrlen = len;
                if len > 0 && len <= core::mem::size_of::<kernel_types::Sockaddr>() as u32 {
                    if let Ok(sockaddr) =
                        bpf_probe_read_user::<kernel_types::Sockaddr>(addr_ptr as *const _)
                    {
                        data.addr = sockaddr;
                        data.has_addr = true;
                    }
                }
            }
        }
    }
});

syscall_handler!(accept4, accept4, args, data, return_value, {
    data.sockfd = args[0] as i32;
    data.flags = args[3] as i32;
    data.has_addr = false;
    data.addr = kernel_types::Sockaddr::default();
    data.addrlen = 0;
    let addr_ptr = args[1] as *const u8;
    let addrlen_ptr = args[2] as *const u32;
    unsafe {
        if return_value >= 0 && !addr_ptr.is_null() && !addrlen_ptr.is_null() {
            if let Ok(len) = bpf_probe_read_user::<u32>(addrlen_ptr) {
                data.addrlen = len;
                if len > 0 && len <= core::mem::size_of::<kernel_types::Sockaddr>() as u32 {
                    if let Ok(sockaddr) =
                        bpf_probe_read_user::<kernel_types::Sockaddr>(addr_ptr as *const _)
                    {
                        data.addr = sockaddr;
                        data.has_addr = true;
                    }
                }
            }
        }
    }
});

syscall_handler!(recvfrom, recvfrom, args, data, return_value, {
    data.sockfd = args[0] as i32;
    data.size = args[2] as usize;
    data.flags = args[3] as i32;
    data.has_addr = false;
    data.addr = kernel_types::Sockaddr::default();
    data.addrlen = 0;
    data.received_data = [0u8; pinchy_common::DATA_READ_SIZE];
    data.received_len = 0;
    let buf_ptr = args[1] as *const u8;
    let src_addr_ptr = args[4] as *const u8;
    let addrlen_ptr = args[5] as *const u32;
    unsafe {
        if return_value >= 0 && !src_addr_ptr.is_null() && !addrlen_ptr.is_null() {
            if let Ok(len) = bpf_probe_read_user::<u32>(addrlen_ptr) {
                data.addrlen = len;
                if len > 0 && len <= core::mem::size_of::<kernel_types::Sockaddr>() as u32 {
                    if let Ok(sockaddr) =
                        bpf_probe_read_user::<kernel_types::Sockaddr>(src_addr_ptr as *const _)
                    {
                        data.addr = sockaddr;
                        data.has_addr = true;
                    }
                }
            }
        }
        if return_value > 0 && !buf_ptr.is_null() {
            let read_size = core::cmp::min(return_value as usize, pinchy_common::DATA_READ_SIZE);
            if read_size > 0 {
                let _ = bpf_probe_read_buf(buf_ptr, &mut data.received_data[..read_size]);
                data.received_len = read_size;
            }
        }
    }
});

syscall_handler!(sendto, sendto, args, data, {
    data.sockfd = args[0] as i32;
    data.size = args[2] as usize;
    data.flags = args[3] as i32;
    data.has_addr = false;
    data.addr = kernel_types::Sockaddr::default();
    data.addrlen = 0;
    data.sent_data = [0u8; pinchy_common::DATA_READ_SIZE];
    data.sent_len = 0;
    let buf_ptr = args[1] as *const u8;
    let dest_addr_ptr = args[4] as *const u8;
    let addrlen = args[5] as u32;

    unsafe {
        if !dest_addr_ptr.is_null() && addrlen > 0 {
            data.addrlen = addrlen;
            if addrlen <= core::mem::size_of::<kernel_types::Sockaddr>() as u32 {
                if let Ok(sockaddr) =
                    bpf_probe_read_user::<kernel_types::Sockaddr>(dest_addr_ptr as *const _)
                {
                    data.addr = sockaddr;
                    data.has_addr = true;
                }
            }
        }
        if data.size > 0 && !buf_ptr.is_null() {
            let read_size = core::cmp::min(data.size, pinchy_common::DATA_READ_SIZE);
            if read_size > 0 {
                let _ = bpf_probe_read_buf(buf_ptr, &mut data.sent_data[..read_size]);
                data.sent_len = read_size;
            }
        }
    }
});

syscall_handler!(bind, sockaddr, args, data, {
    data.sockfd = args[0] as i32;
    data.addrlen = args[2] as u32;

    let addr_ptr = args[1] as *const u8;
    data.addr = unsafe {
        bpf_probe_read_user::<kernel_types::Sockaddr>(addr_ptr as *const _)
            .unwrap_or(kernel_types::Sockaddr::default())
    };
});

syscall_handler!(connect, sockaddr, args, data, {
    data.sockfd = args[0] as i32;
    data.addrlen = args[2] as u32;

    let addr_ptr = args[1] as *const u8;
    data.addr = unsafe {
        bpf_probe_read_user::<kernel_types::Sockaddr>(addr_ptr as *const _)
            .unwrap_or(kernel_types::Sockaddr::default())
    };
});

syscall_handler!(socketpair, socketpair, args, data, return_value, {
    data.domain = args[0] as i32;
    data.type_ = args[1] as i32;
    data.protocol = args[2] as i32;
    data.sv = [0; 2];

    let sv_ptr = args[3] as *const i32;
    unsafe {
        if return_value == 0 && !sv_ptr.is_null() {
            if let Ok(fd0) = bpf_probe_read_user::<i32>(sv_ptr) {
                data.sv[0] = fd0;
            }
            if let Ok(fd1) = bpf_probe_read_user::<i32>(sv_ptr.add(1)) {
                data.sv[1] = fd1;
            }
        }
    }
});

syscall_handler!(getsockname, getsockname, args, data, return_value, {
    data.sockfd = args[0] as i32;
    data.has_addr = false;
    data.addr = kernel_types::Sockaddr::default();
    data.addrlen = 0;

    let addr_ptr = args[1] as *const u8;
    let addrlen_ptr = args[2] as *const u32;

    unsafe {
        if return_value == 0 && !addr_ptr.is_null() && !addrlen_ptr.is_null() {
            if let Ok(len) = bpf_probe_read_user::<u32>(addrlen_ptr) {
                data.addrlen = len;
                if len > 0 && len <= core::mem::size_of::<kernel_types::Sockaddr>() as u32 {
                    if let Ok(sockaddr) =
                        bpf_probe_read_user::<kernel_types::Sockaddr>(addr_ptr as *const _)
                    {
                        data.addr = sockaddr;
                        data.has_addr = true;
                    }
                }
            }
        }
    }
});

syscall_handler!(getpeername, getpeername, args, data, return_value, {
    data.sockfd = args[0] as i32;
    data.has_addr = false;
    data.addr = kernel_types::Sockaddr::default();
    data.addrlen = 0;

    let addr_ptr = args[1] as *const u8;
    let addrlen_ptr = args[2] as *const u32;

    unsafe {
        if return_value == 0 && !addr_ptr.is_null() && !addrlen_ptr.is_null() {
            if let Ok(len) = bpf_probe_read_user::<u32>(addrlen_ptr) {
                data.addrlen = len;
                if len > 0 && len <= core::mem::size_of::<kernel_types::Sockaddr>() as u32 {
                    if let Ok(sockaddr) =
                        bpf_probe_read_user::<kernel_types::Sockaddr>(addr_ptr as *const _)
                    {
                        data.addr = sockaddr;
                        data.has_addr = true;
                    }
                }
            }
        }
    }
});

#[inline(always)]
fn parse_msghdr(
    msg_ptr: *const u8,
    msghdr: &mut kernel_types::Msghdr,
    op: crate::util::IovecOp,
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

                    crate::util::read_iovec_array(
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
            let _ = bpf_probe_read_buf(
                msghdr.msg_control as *const u8,
                &mut msghdr.control_data[..control_size],
            );
        }
    }
}

syscall_handler!(setsockopt, setsockopt, args, data, {
    data.sockfd = args[0] as i32;
    data.level = args[1] as i32;
    data.optname = args[2] as i32;
    data.optlen = args[4] as u32;

    let optval_ptr = args[3] as *const u8;
    if !optval_ptr.is_null() && data.optlen > 0 {
        let read_size = core::cmp::min(data.optlen as usize, pinchy_common::MEDIUM_READ_SIZE);
        unsafe {
            let _ = bpf_probe_read_buf(optval_ptr, &mut data.optval[..read_size]);
        }
    }
});

syscall_handler!(getsockopt, getsockopt, args, data, return_value, {
    data.sockfd = args[0] as i32;
    data.level = args[1] as i32;
    data.optname = args[2] as i32;

    let optval_ptr = args[3] as *const u8;
    let optlen_ptr = args[4] as *const u32;

    if return_value == 0 && !optlen_ptr.is_null() {
        unsafe {
            if let Ok(len) = bpf_probe_read_user::<u32>(optlen_ptr) {
                data.optlen = len;
                if !optval_ptr.is_null() && len > 0 {
                    let read_size = core::cmp::min(len as usize, pinchy_common::MEDIUM_READ_SIZE);
                    let _ = bpf_probe_read_buf(optval_ptr, &mut data.optval[..read_size]);
                }
            }
        }
    }
});

syscall_handler!(recvmmsg, recvmmsg, args, data, return_value, {
    data.sockfd = args[0] as i32;
    data.vlen = args[2] as u32;
    data.flags = args[3] as i32;

    let msgvec_ptr = args[1] as *const u8;
    let timeout_ptr = args[4] as *const u8;

    // Read timeout if provided
    data.has_timeout = false;
    if !timeout_ptr.is_null() {
        unsafe {
            if let Ok(timeout) = bpf_probe_read_user::<pinchy_common::kernel_types::Timespec>(
                timeout_ptr as *const _,
            ) {
                data.timeout = timeout;
                data.has_timeout = true;
            }
        }
    }

    // Read messages array
    data.msgs_count = 0;
    if !msgvec_ptr.is_null() && data.vlen > 0 {
        let msg_count = core::cmp::min(
            data.vlen as usize,
            pinchy_common::kernel_types::MMSGHDR_COUNT,
        );

        for i in 0..msg_count {
            // Each mmsghdr is 64 bytes (56 bytes for msghdr + 4 bytes for msg_len + 4 bytes padding)
            unsafe {
                let mmsghdr_ptr = msgvec_ptr.add(i * 64);

                // Parse the msghdr part first
                parse_msghdr(
                    mmsghdr_ptr,
                    &mut data.msgs[i].msg_hdr,
                    crate::util::IovecOp::Read,
                    return_value,
                );

                // Read msg_len (offset 56 in mmsghdr)
                if return_value > 0 {
                    if let Ok(msg_len) =
                        bpf_probe_read_user::<u32>(mmsghdr_ptr.add(56) as *const u32)
                    {
                        data.msgs[i].msg_len = msg_len;
                    }
                }
            }
        }
        data.msgs_count = msg_count as u32;
    }
});

syscall_handler!(sendmmsg, sendmmsg, args, data, {
    data.sockfd = args[0] as i32;
    data.vlen = args[2] as u32;
    data.flags = args[3] as i32;

    let msgvec_ptr = args[1] as *const u8;

    // Read messages array
    data.msgs_count = 0;
    if !msgvec_ptr.is_null() && data.vlen > 0 {
        let msg_count = core::cmp::min(
            data.vlen as usize,
            pinchy_common::kernel_types::MMSGHDR_COUNT,
        );

        for i in 0..msg_count {
            // Each mmsghdr is 64 bytes (56 bytes for msghdr + 4 bytes for msg_len + 4 bytes padding)
            unsafe {
                let mmsghdr_ptr = msgvec_ptr.add(i * 64);

                // Parse the msghdr part first
                parse_msghdr(
                    mmsghdr_ptr,
                    &mut data.msgs[i].msg_hdr,
                    crate::util::IovecOp::Write,
                    0,
                );

                // For sendmmsg, msg_len is output-only and set by the kernel on success
                data.msgs[i].msg_len = 0;
            }
        }
        data.msgs_count = msg_count as u32;
    }
});
