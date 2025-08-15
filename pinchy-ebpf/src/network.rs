// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::helpers::{bpf_probe_read_buf, bpf_probe_read_user};
use pinchy_common::kernel_types;

use crate::syscall_handler;

syscall_handler!(recvmsg, recvmsg, args, data, {
    data.sockfd = args[0] as i32;
    data.flags = args[2] as i32;
    let msg_ptr = args[1] as *const u8;
    parse_msghdr(msg_ptr, &mut data.msghdr);
});

syscall_handler!(sendmsg, sendmsg, args, data, {
    data.sockfd = args[0] as i32;
    data.flags = args[2] as i32;
    let msg_ptr = args[1] as *const u8;
    parse_msghdr(msg_ptr, &mut data.msghdr);
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
fn parse_msghdr(msg_ptr: *const u8, msghdr: &mut kernel_types::Msghdr) {
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

                // Read the iovec array (up to MSG_IOV_COUNT entries)
                if msg_iov_addr != 0 && msghdr.msg_iovlen > 0 {
                    let iov_count =
                        core::cmp::min(msghdr.msg_iovlen as usize, kernel_types::MSG_IOV_COUNT);

                    for i in 0..iov_count {
                        let iov_ptr = (msg_iov_addr as *const u8).add(i * 16);
                        let iov_base =
                            bpf_probe_read_user::<u64>(iov_ptr as *const u64).unwrap_or(0);
                        let iov_len =
                            bpf_probe_read_user::<u64>((iov_ptr as *const u64).add(1)).unwrap_or(0);

                        msghdr.msg_iov[i] = kernel_types::Iovec { iov_base, iov_len };
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
