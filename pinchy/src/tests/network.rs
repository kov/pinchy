// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::pin::Pin;

use pinchy_common::{
    kernel_types::{Iovec, Msghdr, Sockaddr},
    syscalls::{SYS_accept4, SYS_recvmsg, SYS_sendmsg},
    Accept4Data, RecvmsgData, SendmsgData, SyscallEvent,
};

use crate::{
    events::handle_event,
    formatting::{Formatter, FormattingStyle},
};

#[tokio::test]
async fn parse_recvmsg() {
    // Test basic recvmsg with AF_INET socket
    let mut msghdr = Msghdr::default();

    // Set up a basic AF_INET sockaddr
    let mut sockaddr = Sockaddr {
        sa_family: libc::AF_INET as u16,
        ..Default::default()
    };

    sockaddr.sa_data[0] = 0x1f; // Port 8000 in network byte order (high byte)
    sockaddr.sa_data[1] = 0x40; // Port 8000 in network byte order (low byte)
    sockaddr.sa_data[2] = 127; // IP 127.0.0.1
    sockaddr.sa_data[3] = 0;
    sockaddr.sa_data[4] = 0;
    sockaddr.sa_data[5] = 1;

    msghdr.name = sockaddr;
    msghdr.has_name = true;
    msghdr.msg_name = 0x7fff12345678;
    msghdr.msg_namelen = 16;

    // Set up iovec entries
    msghdr.msg_iov[0] = Iovec {
        iov_base: 0x7fff87654321,
        iov_len: 1024,
    };
    msghdr.msg_iov[1] = Iovec {
        iov_base: 0x7fff11111111,
        iov_len: 512,
    };
    msghdr.msg_iovlen = 2;

    // Set up control message data
    msghdr.msg_control = 0x7fff99999999;
    msghdr.msg_controllen = 64;
    msghdr.control_data[0] = 0x01; // Some control data
    msghdr.control_data[1] = 0x02;
    msghdr.control_data[2] = 0x03;

    msghdr.msg_flags = libc::MSG_DONTWAIT;

    let event = SyscallEvent {
        syscall_nr: SYS_recvmsg,
        pid: 1234,
        tid: 1234,
        return_value: 1536, // Total bytes received
        data: pinchy_common::SyscallEventData {
            recvmsg: RecvmsgData {
                sockfd: 5,
                flags: libc::MSG_DONTWAIT,
                msghdr,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "1234 recvmsg(sockfd: 5, msg: {{ name: {{family: AF_INET, len: 16}}, iov: [  {{ base: 0x7fff87654321, len: 1024 }} {{ base: 0x7fff11111111, len: 512 }} ], iovlen: 2, control: {{ptr: 0x7fff99999999, len: 64}}, flags: 0x40 (MSG_DONTWAIT) }}, flags: 0x40 (MSG_DONTWAIT)) = 1536\n"
        )
    );
}

#[tokio::test]
async fn parse_sendmsg() {
    // Test basic sendmsg with AF_INET socket
    let mut msghdr = Msghdr::default();

    // Set up a basic AF_INET sockaddr
    let mut sockaddr = Sockaddr {
        sa_family: libc::AF_INET as u16,
        ..Default::default()
    };

    sockaddr.sa_data[0] = 0x1f; // Port 8000 in network byte order (high byte)
    sockaddr.sa_data[1] = 0x40; // Port 8000 in network byte order (low byte)
    sockaddr.sa_data[2] = 127; // IP 127.0.0.1
    sockaddr.sa_data[3] = 0;
    sockaddr.sa_data[4] = 0;
    sockaddr.sa_data[5] = 1;

    msghdr.name = sockaddr;
    msghdr.has_name = true;
    msghdr.msg_name = 0x7fff12345678;
    msghdr.msg_namelen = 16;

    // Set up iovec entries
    msghdr.msg_iov[0] = Iovec {
        iov_base: 0x7fff87654321,
        iov_len: 512,
    };
    msghdr.msg_iov[1] = Iovec {
        iov_base: 0x7fff11111111,
        iov_len: 256,
    };
    msghdr.msg_iovlen = 2;

    // Set up control message data
    msghdr.msg_control = 0x7fff99999999;
    msghdr.msg_controllen = 32;

    let event = SyscallEvent {
        syscall_nr: SYS_sendmsg,
        pid: 1234,
        tid: 5678,
        return_value: 768, // Total bytes sent (512 + 256)
        data: pinchy_common::SyscallEventData {
            sendmsg: SendmsgData {
                sockfd: 7,
                flags: libc::MSG_DONTWAIT,
                msghdr,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "5678 sendmsg(sockfd: 7, msg: {{ name: {{family: AF_INET, len: 16}}, iov: [  {{ base: 0x7fff87654321, len: 512 }} {{ base: 0x7fff11111111, len: 256 }} ], iovlen: 2, control: {{ptr: 0x7fff99999999, len: 32}}, flags: 0 }}, flags: 0x40 (MSG_DONTWAIT)) = 768\n"
        )
    );
}

#[tokio::test]
async fn parse_recvmsg_unix_socket() {
    // Test recvmsg with AF_UNIX socket (no address)
    let mut msghdr = Msghdr {
        has_name: false,
        msg_name: 0,
        msg_namelen: 0,
        ..Default::default()
    };

    // Single iovec
    msghdr.msg_iov[0] = Iovec {
        iov_base: 0x7fff12345678,
        iov_len: 256,
    };
    msghdr.msg_iovlen = 1;

    // No control messages
    msghdr.msg_control = 0;
    msghdr.msg_controllen = 0;
    msghdr.msg_flags = 0;

    let event = SyscallEvent {
        syscall_nr: SYS_recvmsg,
        pid: 999,
        tid: 999,
        return_value: 42,
        data: pinchy_common::SyscallEventData {
            recvmsg: RecvmsgData {
                sockfd: 7,
                flags: 0,
                msghdr,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "999 recvmsg(sockfd: 7, msg: {{ name: NULL, iov: [  {{ base: 0x7fff12345678, len: 256 }} ], iovlen: 1, control: NULL, flags: 0 }}, flags: 0) = 42\n"
        )
    );
}

#[tokio::test]
async fn parse_recvmsg_error() {
    // Test recvmsg returning an error
    let msghdr = Msghdr::default();

    let event = SyscallEvent {
        syscall_nr: SYS_recvmsg,
        pid: 555,
        tid: 555,
        return_value: -1, // Error
        data: pinchy_common::SyscallEventData {
            recvmsg: RecvmsgData {
                sockfd: 3,
                flags: libc::MSG_PEEK,
                msghdr,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "555 recvmsg(sockfd: 3, msg: {{ name: NULL, iov: NULL, iovlen: 0, control: NULL, flags: 0 }}, flags: 0x2 (MSG_PEEK)) = -1\n"
        )
    );
}

#[tokio::test]
async fn parse_accept4_success() {
    // Test accept4 with AF_INET address and flags
    let mut addr = Sockaddr {
        sa_family: libc::AF_INET as u16,
        ..Default::default()
    };

    addr.sa_data[0] = 0x00; // Port 80 in network byte order high byte
    addr.sa_data[1] = 0x50; // Port 80 in network byte order low byte
    addr.sa_data[2] = 192; // IP address 192.168.1.1
    addr.sa_data[3] = 168;
    addr.sa_data[4] = 1;
    addr.sa_data[5] = 1;

    let event = SyscallEvent {
        syscall_nr: SYS_accept4,
        pid: 1000,
        tid: 1234,
        return_value: 4,
        data: pinchy_common::SyscallEventData {
            accept4: Accept4Data {
                sockfd: 3,
                flags: libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                has_addr: true,
                addr,
                addrlen: 16,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "1234 accept4(sockfd: 3, addr: {{ family: AF_INET, addr: 192.168.1.1:80 }}, addrlen: 16, flags: 0x80800 (SOCK_CLOEXEC|SOCK_NONBLOCK)) = 4\n"
        )
    );
}

#[tokio::test]
async fn parse_accept4_null_addr() {
    // Test accept4 with NULL address
    let event = SyscallEvent {
        syscall_nr: SYS_accept4,
        pid: 1000,
        tid: 999,
        return_value: 5,
        data: pinchy_common::SyscallEventData {
            accept4: Accept4Data {
                sockfd: 3,
                flags: 0,
                has_addr: false,
                addr: Sockaddr::default(),
                addrlen: 0,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("999 accept4(sockfd: 3, addr: NULL, addrlen: 0, flags: 0) = 5\n")
    );
}

#[tokio::test]
async fn parse_accept4_error() {
    // Test accept4 returning an error
    let event = SyscallEvent {
        syscall_nr: SYS_accept4,
        pid: 1000,
        tid: 555,
        return_value: -1,
        data: pinchy_common::SyscallEventData {
            accept4: Accept4Data {
                sockfd: 8,
                flags: libc::SOCK_NONBLOCK,
                has_addr: false,
                addr: Sockaddr::default(),
                addrlen: 0,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "555 accept4(sockfd: 8, addr: NULL, addrlen: 0, flags: 0x800 (SOCK_NONBLOCK)) = -1\n"
        )
    );
}

#[tokio::test]
async fn test_accept4_unix_socket() {
    // Test accept4 with Unix domain socket
    let mut addr = Sockaddr {
        sa_family: libc::AF_UNIX as u16,
        ..Default::default()
    };

    let path = b"/tmp/test.soc"; // Shortened to fit within SOCKADDR_DATA_SIZE with null terminator
    addr.sa_data[..path.len()].copy_from_slice(path);
    // Add null terminator
    addr.sa_data[path.len()] = 0;

    let event = SyscallEvent {
        syscall_nr: SYS_accept4,
        pid: 1000,
        tid: 777,
        return_value: 6,
        data: pinchy_common::SyscallEventData {
            accept4: Accept4Data {
                sockfd: 4,
                flags: libc::SOCK_CLOEXEC,
                has_addr: true,
                addr,
                addrlen: 18,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "777 accept4(sockfd: 4, addr: {{ family: AF_UNIX, path: \"/tmp/test.soc\" }}, addrlen: 18, flags: 0x80000 (SOCK_CLOEXEC)) = 6\n"
        )
    );
}

#[tokio::test]
async fn test_accept4_ipv6_socket() {
    // Test accept4 with IPv6 socket
    let mut addr = Sockaddr {
        sa_family: libc::AF_INET6 as u16,
        ..Default::default()
    };

    // Set up sockaddr_in6: port (2 bytes) + flowinfo (4 bytes) + IPv6 address (16 bytes) + scope_id (4 bytes)
    let port: u16 = 8080;
    let port_bytes = port.to_be_bytes();
    addr.sa_data[0] = port_bytes[0];
    addr.sa_data[1] = port_bytes[1];

    // flowinfo (4 bytes) - set to 0
    addr.sa_data[2] = 0;
    addr.sa_data[3] = 0;
    addr.sa_data[4] = 0;
    addr.sa_data[5] = 0;

    // IPv6 address: ::1 (localhost) - 16 bytes, all zeros except last 2 bytes
    for i in 6..21 {
        addr.sa_data[i] = 0;
    }
    addr.sa_data[20] = 0;
    addr.sa_data[21] = 1; // ::1

    let event = SyscallEvent {
        syscall_nr: SYS_accept4,
        pid: 2000,
        tid: 2001,
        return_value: 7,
        data: pinchy_common::SyscallEventData {
            accept4: Accept4Data {
                sockfd: 6,
                flags: libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                has_addr: true,
                addr,
                addrlen: 28, // sizeof(sockaddr_in6)
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "2001 accept4(sockfd: 6, addr: {{ family: AF_INET6, addr: [0:0:0:0:0:0:0:1]:8080 }}, addrlen: 28, flags: 0x80800 (SOCK_CLOEXEC|SOCK_NONBLOCK)) = 7\n"
        )
    );
}

#[tokio::test]
async fn test_accept4_ipv6_full_address() {
    // Test accept4 with full IPv6 address
    let mut addr = Sockaddr {
        sa_family: libc::AF_INET6 as u16,
        ..Default::default()
    };

    // Port 443 (HTTPS)
    let port: u16 = 443;
    let port_bytes = port.to_be_bytes();
    addr.sa_data[0] = port_bytes[0];
    addr.sa_data[1] = port_bytes[1];

    // flowinfo = 0
    addr.sa_data[2] = 0;
    addr.sa_data[3] = 0;
    addr.sa_data[4] = 0;
    addr.sa_data[5] = 0;

    // IPv6 address: 2001:db8::1
    let ipv6_addr = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    addr.sa_data[6..22].copy_from_slice(&ipv6_addr);

    let event = SyscallEvent {
        syscall_nr: SYS_accept4,
        pid: 3000,
        tid: 3001,
        return_value: 8,
        data: pinchy_common::SyscallEventData {
            accept4: Accept4Data {
                sockfd: 7,
                flags: 0,
                has_addr: true,
                addr,
                addrlen: 28,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "3001 accept4(sockfd: 7, addr: {{ family: AF_INET6, addr: [2001:db8:0:0:0:0:0:1]:443 }}, addrlen: 28, flags: 0) = 8\n"
        )
    );
}

#[tokio::test]
async fn test_accept4_netlink_socket() {
    // Test accept4 with netlink socket
    let mut addr = Sockaddr {
        sa_family: libc::AF_NETLINK as u16,
        ..Default::default()
    };

    // sockaddr_nl: nl_pid (4 bytes) + nl_groups (4 bytes)
    let pid: u32 = 1234;
    let groups: u32 = 0x00000001; // RTMGRP_LINK

    let pid_bytes = pid.to_le_bytes();
    addr.sa_data[0] = pid_bytes[0];
    addr.sa_data[1] = pid_bytes[1];
    addr.sa_data[2] = pid_bytes[2];
    addr.sa_data[3] = pid_bytes[3];

    let groups_bytes = groups.to_le_bytes();
    addr.sa_data[4] = groups_bytes[0];
    addr.sa_data[5] = groups_bytes[1];
    addr.sa_data[6] = groups_bytes[2];
    addr.sa_data[7] = groups_bytes[3];

    let event = SyscallEvent {
        syscall_nr: SYS_accept4,
        pid: 4000,
        tid: 4001,
        return_value: 9,
        data: pinchy_common::SyscallEventData {
            accept4: Accept4Data {
                sockfd: 8,
                flags: libc::SOCK_CLOEXEC,
                has_addr: true,
                addr,
                addrlen: 12, // sizeof(sockaddr_nl)
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "4001 accept4(sockfd: 8, addr: {{ family: AF_NETLINK, pid: 1234, groups: 0x1 }}, addrlen: 12, flags: 0x80000 (SOCK_CLOEXEC)) = 9\n"
        )
    );
}

#[tokio::test]
async fn test_accept4_packet_socket() {
    // Test accept4 with packet socket (raw socket)
    let mut addr = Sockaddr {
        sa_family: libc::AF_PACKET as u16,
        ..Default::default()
    };

    // sockaddr_ll: protocol (2 bytes) + ifindex (4 bytes) + hatype (2 bytes) + pkttype (1 byte) + halen (1 byte) + addr (8 bytes)
    let protocol: u16 = 0x0800; // ETH_P_IP
    let ifindex: i32 = 2; // eth0
    let hatype: u16 = 1; // ARPHRD_ETHER
    let pkttype: u8 = 0; // PACKET_HOST
    let halen: u8 = 6; // Ethernet MAC address length
    let mac_addr: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

    let protocol_bytes = protocol.to_be_bytes();
    addr.sa_data[0] = protocol_bytes[0];
    addr.sa_data[1] = protocol_bytes[1];

    let ifindex_bytes = ifindex.to_le_bytes();
    addr.sa_data[2] = ifindex_bytes[0];
    addr.sa_data[3] = ifindex_bytes[1];
    addr.sa_data[4] = ifindex_bytes[2];
    addr.sa_data[5] = ifindex_bytes[3];

    let hatype_bytes = hatype.to_le_bytes();
    addr.sa_data[6] = hatype_bytes[0];
    addr.sa_data[7] = hatype_bytes[1];

    addr.sa_data[8] = pkttype;
    addr.sa_data[9] = halen;

    // MAC address
    addr.sa_data[10..16].copy_from_slice(&mac_addr);

    let event = SyscallEvent {
        syscall_nr: SYS_accept4,
        pid: 5000,
        tid: 5001,
        return_value: 10,
        data: pinchy_common::SyscallEventData {
            accept4: Accept4Data {
                sockfd: 9,
                flags: libc::SOCK_NONBLOCK,
                has_addr: true,
                addr,
                addrlen: 20, // sizeof(sockaddr_ll)
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "5001 accept4(sockfd: 9, addr: {{ family: AF_PACKET, protocol: 0x800, ifindex: 2, hatype: 1, pkttype: 0, addr: 00:11:22:33:44:55 }}, addrlen: 20, flags: 0x800 (SOCK_NONBLOCK)) = 10\n"
        )
    );
}

#[tokio::test]
async fn test_accept4_ipv6_with_larger_buffer() {
    // Test that IPv6 addresses are now properly captured with the larger buffer

    let mut addr = Sockaddr {
        sa_family: libc::AF_INET6 as u16,
        ..Default::default()
    };

    // Only provide port bytes, not enough for full IPv6 address
    addr.sa_data[0] = 0x1f; // Port 8000
    addr.sa_data[1] = 0x40;
    // No more data - but now with larger buffer it will show zeros

    let event = SyscallEvent {
        syscall_nr: SYS_accept4,
        pid: 6001,
        tid: 6001,
        return_value: 11,
        data: pinchy_common::SyscallEventData {
            accept4: Accept4Data {
                sockfd: 10,
                flags: 0,
                has_addr: true,
                addr,
                addrlen: 8, // Small addrlen, but we now have larger buffer
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "6001 accept4(sockfd: 10, addr: {{ family: AF_INET6, addr: [0:0:0:0:0:0:0:0]:8000 }}, addrlen: 8, flags: 0) = 11\n"
        )
    );
}

#[tokio::test]
async fn test_accept4_unknown_family() {
    // Test accept4 with unknown/unsupported address family
    let mut addr = Sockaddr {
        sa_family: 999, // unknown family
        ..Default::default()
    };

    addr.sa_data[0] = 0xde;
    addr.sa_data[1] = 0xad;
    addr.sa_data[2] = 0xbe;
    addr.sa_data[3] = 0xef;

    let event = SyscallEvent {
        syscall_nr: SYS_accept4,
        pid: 7000,
        tid: 7001,
        return_value: 12,
        data: pinchy_common::SyscallEventData {
            accept4: Accept4Data {
                sockfd: 11,
                flags: 0,
                has_addr: true,
                addr,
                addrlen: 8,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "7001 accept4(sockfd: 11, addr: {{ family: 999, data: de ad be ef  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0 }}, addrlen: 8, flags: 0) = 12\n"
        )
    );
}

#[tokio::test]
async fn parse_accept4_ipv6() {
    // Test accept4 with AF_INET6 address
    let mut addr = Sockaddr {
        sa_family: libc::AF_INET6 as u16,
        ..Default::default()
    };

    // Port 8080 in network byte order
    addr.sa_data[0] = 0x1f; // 8080 = 0x1f90
    addr.sa_data[1] = 0x90;
    // flowinfo = 0 (4 bytes, already zeroed)
    // IPv6 address 2001:db8::1
    addr.sa_data[6] = 0x20;
    addr.sa_data[7] = 0x01; // 2001
    addr.sa_data[8] = 0x0d;
    addr.sa_data[9] = 0xb8; // 0db8
                            // bytes 10-17 are zero (::)
    addr.sa_data[20] = 0x00;
    addr.sa_data[21] = 0x01; // ::1
                             // scope_id = 0 (4 bytes, already zeroed)

    let event = SyscallEvent {
        syscall_nr: SYS_accept4,
        pid: 2000,
        tid: 2234,
        return_value: 5,
        data: pinchy_common::SyscallEventData {
            accept4: Accept4Data {
                sockfd: 4,
                flags: libc::SOCK_CLOEXEC,
                has_addr: true,
                addr,
                addrlen: 28,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "2234 accept4(sockfd: 4, addr: {{ family: AF_INET6, addr: [2001:db8:0:0:0:0:0:1]:8080 }}, addrlen: 28, flags: 0x80000 (SOCK_CLOEXEC)) = 5\n"
        )
    );
}

#[tokio::test]
async fn parse_accept4_netlink() {
    // Test accept4 with AF_NETLINK address
    let mut addr = Sockaddr {
        sa_family: libc::AF_NETLINK as u16,
        ..Default::default()
    };

    // nl_pid = 1234 (little-endian)
    addr.sa_data[0] = 0xd2;
    addr.sa_data[1] = 0x04;
    addr.sa_data[2] = 0x00;
    addr.sa_data[3] = 0x00; // 1234
                            // nl_groups = 0x00000001 (little-endian)
    addr.sa_data[4] = 0x01;
    addr.sa_data[5] = 0x00;
    addr.sa_data[6] = 0x00;
    addr.sa_data[7] = 0x00; // 1

    let event = SyscallEvent {
        syscall_nr: SYS_accept4,
        pid: 3000,
        tid: 3234,
        return_value: 6,
        data: pinchy_common::SyscallEventData {
            accept4: Accept4Data {
                sockfd: 5,
                flags: 0,
                has_addr: true,
                addr,
                addrlen: 12,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "3234 accept4(sockfd: 5, addr: {{ family: AF_NETLINK, pid: 1234, groups: 0x1 }}, addrlen: 12, flags: 0) = 6\n"
        )
    );
}

#[tokio::test]
async fn parse_accept4_packet() {
    // Test accept4 with AF_PACKET address
    let mut addr = Sockaddr {
        sa_family: libc::AF_PACKET as u16,
        ..Default::default()
    };

    // protocol = 0x0800 (IPv4, big-endian)
    addr.sa_data[0] = 0x08;
    addr.sa_data[1] = 0x00;
    // ifindex = 2 (little-endian)
    addr.sa_data[2] = 0x02;
    addr.sa_data[3] = 0x00;
    addr.sa_data[4] = 0x00;
    addr.sa_data[5] = 0x00;
    // hatype = 1 (Ethernet, little-endian)
    addr.sa_data[6] = 0x01;
    addr.sa_data[7] = 0x00;
    // pkttype = 0 (host)
    addr.sa_data[8] = 0x00;
    // halen = 6 (MAC address length)
    addr.sa_data[9] = 0x06;
    // MAC address: aa:bb:cc:dd:ee:ff
    addr.sa_data[10] = 0xaa;
    addr.sa_data[11] = 0xbb;
    addr.sa_data[12] = 0xcc;
    addr.sa_data[13] = 0xdd;
    addr.sa_data[14] = 0xee;
    addr.sa_data[15] = 0xff;

    let event = SyscallEvent {
        syscall_nr: SYS_accept4,
        pid: 4000,
        tid: 4234,
        return_value: 7,
        data: pinchy_common::SyscallEventData {
            accept4: Accept4Data {
                sockfd: 6,
                flags: libc::SOCK_NONBLOCK,
                has_addr: true,
                addr,
                addrlen: 20,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "4234 accept4(sockfd: 6, addr: {{ family: AF_PACKET, protocol: 0x800, ifindex: 2, hatype: 1, pkttype: 0, addr: aa:bb:cc:dd:ee:ff }}, addrlen: 20, flags: 0x800 (SOCK_NONBLOCK)) = 7\n"
        )
    );
}
