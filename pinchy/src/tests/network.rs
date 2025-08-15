// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    kernel_types::{Iovec, Msghdr, Sockaddr},
    syscalls::{
        SYS_accept, SYS_accept4, SYS_bind, SYS_connect, SYS_getpeername, SYS_getsockname,
        SYS_getsockopt, SYS_listen, SYS_recvfrom, SYS_recvmsg, SYS_sendmsg, SYS_setsockopt,
        SYS_shutdown, SYS_socket, SYS_socketpair,
    },
    Accept4Data, AcceptData, GetSocknameData, GetpeernameData, GetsockoptData, ListenData,
    RecvfromData, RecvmsgData, SendmsgData, SetsockoptData, ShutdownData, SockaddrData, SocketData,
    SocketpairData, SyscallEvent, SyscallEventData,
};

use crate::syscall_test;

syscall_test!(
    parse_recvmsg,
    {
        let mut msghdr = Msghdr::default();
        let mut sockaddr = Sockaddr {
            sa_family: libc::AF_INET as u16,
            ..Default::default()
        };
        sockaddr.sa_data[0] = 0x1f;
        sockaddr.sa_data[1] = 0x40;
        sockaddr.sa_data[2] = 127;
        sockaddr.sa_data[3] = 0;
        sockaddr.sa_data[4] = 0;
        sockaddr.sa_data[5] = 1;
        msghdr.name = sockaddr;
        msghdr.has_name = true;
        msghdr.msg_name = 0x7fff12345678;
        msghdr.msg_namelen = 16;
        msghdr.msg_iov[0] = Iovec {
            iov_base: 0x7fff87654321,
            iov_len: 1024,
        };
        msghdr.msg_iov[1] = Iovec {
            iov_base: 0x7fff11111111,
            iov_len: 512,
        };
        msghdr.msg_iovlen = 2;
        msghdr.msg_control = 0x7fff99999999;
        msghdr.msg_controllen = 64;
        msghdr.control_data[0] = 0x01;
        msghdr.control_data[1] = 0x02;
        msghdr.control_data[2] = 0x03;
        msghdr.msg_flags = libc::MSG_DONTWAIT;
        SyscallEvent {
            syscall_nr: SYS_recvmsg,
            pid: 1234,
            tid: 1234,
            return_value: 1536,
            data: pinchy_common::SyscallEventData {
                recvmsg: RecvmsgData {
                    sockfd: 5,
                    flags: libc::MSG_DONTWAIT,
                    msghdr,
                },
            },
        }
    },
    "1234 recvmsg(sockfd: 5, msg: { name: {family: AF_INET, len: 16}, iov: [  { base: 0x7fff87654321, len: 1024 } { base: 0x7fff11111111, len: 512 } ], iovlen: 2, control: {ptr: 0x7fff99999999, len: 64}, flags: 0x40 (MSG_DONTWAIT) }, flags: 0x40 (MSG_DONTWAIT)) = 1536 (bytes)\n"
);

syscall_test!(
    parse_sendmsg,
    {
        let mut msghdr = Msghdr::default();
        let mut sockaddr = Sockaddr {
            sa_family: libc::AF_INET as u16,
            ..Default::default()
        };
        sockaddr.sa_data[0] = 0x1f;
        sockaddr.sa_data[1] = 0x40;
        sockaddr.sa_data[2] = 127;
        sockaddr.sa_data[3] = 0;
        sockaddr.sa_data[4] = 0;
        sockaddr.sa_data[5] = 1;
        msghdr.name = sockaddr;
        msghdr.has_name = true;
        msghdr.msg_name = 0x7fff12345678;
        msghdr.msg_namelen = 16;
        msghdr.msg_iov[0] = Iovec {
            iov_base: 0x7fff87654321,
            iov_len: 512,
        };
        msghdr.msg_iov[1] = Iovec {
            iov_base: 0x7fff11111111,
            iov_len: 256,
        };
        msghdr.msg_iovlen = 2;
        msghdr.msg_control = 0x7fff99999999;
        msghdr.msg_controllen = 32;
        SyscallEvent {
            syscall_nr: SYS_sendmsg,
            pid: 1234,
            tid: 5678,
            return_value: 768,
            data: pinchy_common::SyscallEventData {
                sendmsg: SendmsgData {
                    sockfd: 7,
                    flags: libc::MSG_DONTWAIT,
                    msghdr,
                },
            },
        }
    },
    "5678 sendmsg(sockfd: 7, msg: { name: {family: AF_INET, len: 16}, iov: [  { base: 0x7fff87654321, len: 512 } { base: 0x7fff11111111, len: 256 } ], iovlen: 2, control: {ptr: 0x7fff99999999, len: 32}, flags: 0 }, flags: 0x40 (MSG_DONTWAIT)) = 768 (bytes)\n"
);

syscall_test!(
    parse_recvmsg_unix_socket,
    {
        let mut msghdr = Msghdr {
            has_name: false,
            msg_name: 0,
            msg_namelen: 0,
            ..Default::default()
        };
        msghdr.msg_iov[0] = Iovec {
            iov_base: 0x7fff12345678,
            iov_len: 256,
        };
        msghdr.msg_iovlen = 1;
        msghdr.msg_control = 0;
        msghdr.msg_controllen = 0;
        msghdr.msg_flags = 0;
        SyscallEvent {
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
        }
    },
    "999 recvmsg(sockfd: 7, msg: { name: NULL, iov: [  { base: 0x7fff12345678, len: 256 } ], iovlen: 1, control: NULL, flags: 0 }, flags: 0) = 42 (bytes)\n"
);

syscall_test!(
    parse_recvmsg_error,
    {
        let msghdr = Msghdr::default();
        SyscallEvent {
            syscall_nr: SYS_recvmsg,
            pid: 555,
            tid: 555,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                recvmsg: RecvmsgData {
                    sockfd: 3,
                    flags: libc::MSG_PEEK,
                    msghdr,
                },
            },
        }
    },
    format!(
        "555 recvmsg(sockfd: 3, msg: {{ name: NULL, iov: NULL, iovlen: 0, control: NULL, flags: 0 }}, flags: 0x2 (MSG_PEEK)) = -1 (error)\n"
    )
);

syscall_test!(
    parse_accept_success,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_INET as u16,
            ..Default::default()
        };
        addr.sa_data[0] = 0x00;
        addr.sa_data[1] = 0x50;
        addr.sa_data[2] = 192;
        addr.sa_data[3] = 168;
        addr.sa_data[4] = 1;
        addr.sa_data[5] = 1;
        SyscallEvent {
            syscall_nr: SYS_accept,
            pid: 1000,
            tid: 1234,
            return_value: 4,
            data: pinchy_common::SyscallEventData {
                accept: AcceptData {
                    sockfd: 3,
                    has_addr: true,
                    addr,
                    addrlen: 16,
                },
            },
        }
    },
    format!(
        "1234 accept(sockfd: 3, addr: {{ family: AF_INET, addr: 192.168.1.1:80 }}, addrlen: 16) = 4 (fd)\n"
    )
);

syscall_test!(
    parse_accept_null_addr,
    {
        SyscallEvent {
            syscall_nr: SYS_accept,
            pid: 1000,
            tid: 999,
            return_value: 5,
            data: pinchy_common::SyscallEventData {
                accept: AcceptData {
                    sockfd: 3,
                    has_addr: false,
                    addr: Sockaddr::default(),
                    addrlen: 0,
                },
            },
        }
    },
    format!("999 accept(sockfd: 3, addr: NULL, addrlen: 0) = 5 (fd)\n")
);

syscall_test!(
    parse_accept4_success,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_INET as u16,
            ..Default::default()
        };
        addr.sa_data[0] = 0x00;
        addr.sa_data[1] = 0x50;
        addr.sa_data[2] = 192;
        addr.sa_data[3] = 168;
        addr.sa_data[4] = 1;
        addr.sa_data[5] = 1;
        SyscallEvent {
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
        }
    },
    format!(
        "1234 accept4(sockfd: 3, addr: {{ family: AF_INET, addr: 192.168.1.1:80 }}, addrlen: 16, flags: 0x80800 (SOCK_CLOEXEC|SOCK_NONBLOCK)) = 4 (fd)\n"
    )
);

syscall_test!(
    parse_accept4_null_addr,
    {
        SyscallEvent {
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
        }
    },
    format!("999 accept4(sockfd: 3, addr: NULL, addrlen: 0, flags: 0) = 5 (fd)\n")
);

syscall_test!(
    parse_accept4_error,
    {
        SyscallEvent {
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
        }
    },
    "555 accept4(sockfd: 8, addr: NULL, addrlen: 0, flags: 0x800 (SOCK_NONBLOCK)) = -1 (error)\n"
);

syscall_test!(
    test_accept4_unix_socket,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_UNIX as u16,
            ..Default::default()
        };
        let path = b"/tmp/test.soc";
        addr.sa_data[..path.len()].copy_from_slice(path);
        addr.sa_data[path.len()] = 0;
        SyscallEvent {
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
        }
    },
    format!(
        "777 accept4(sockfd: 4, addr: {{ family: AF_UNIX, path: \"/tmp/test.soc\" }}, addrlen: 18, flags: 0x80000 (SOCK_CLOEXEC)) = 6 (fd)\n"
    )
);

syscall_test!(
    test_accept4_ipv6_socket,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_INET6 as u16,
            ..Default::default()
        };
        let port: u16 = 8080;
        let port_bytes = port.to_be_bytes();
        addr.sa_data[0] = port_bytes[0];
        addr.sa_data[1] = port_bytes[1];
        addr.sa_data[2] = 0;
        addr.sa_data[3] = 0;
        addr.sa_data[4] = 0;
        addr.sa_data[5] = 0;
        for i in 6..21 {
            addr.sa_data[i] = 0;
        }
        addr.sa_data[20] = 0;
        addr.sa_data[21] = 1;
        SyscallEvent {
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
                    addrlen: 28,
                },
            },
        }
    },
    format!(
        "2001 accept4(sockfd: 6, addr: {{ family: AF_INET6, addr: [0:0:0:0:0:0:0:1]:8080 }}, addrlen: 28, flags: 0x80800 (SOCK_CLOEXEC|SOCK_NONBLOCK)) = 7 (fd)\n"
    )
);

syscall_test!(
    test_accept4_ipv6_full_address,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_INET6 as u16,
            ..Default::default()
        };
        let port: u16 = 443;
        let port_bytes = port.to_be_bytes();
        addr.sa_data[0] = port_bytes[0];
        addr.sa_data[1] = port_bytes[1];
        addr.sa_data[2] = 0;
        addr.sa_data[3] = 0;
        addr.sa_data[4] = 0;
        addr.sa_data[5] = 0;
        let ipv6_addr = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01,
        ];
        addr.sa_data[6..22].copy_from_slice(&ipv6_addr);
        SyscallEvent {
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
        }
    },
    format!(
        "3001 accept4(sockfd: 7, addr: {{ family: AF_INET6, addr: [2001:db8:0:0:0:0:0:1]:443 }}, addrlen: 28, flags: 0) = 8 (fd)\n"
    )
);

syscall_test!(
    test_accept4_netlink_socket,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_NETLINK as u16,
            ..Default::default()
        };
        let pid: u32 = 1234;
        let groups: u32 = 0x00000001;
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
        SyscallEvent {
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
                    addrlen: 12,
                },
            },
        }
    },
    format!(
        "4001 accept4(sockfd: 8, addr: {{ family: AF_NETLINK, pid: 1234, groups: 0x1 }}, addrlen: 12, flags: 0x80000 (SOCK_CLOEXEC)) = 9 (fd)\n"
    )
);

syscall_test!(
    test_accept4_packet_socket,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_PACKET as u16,
            ..Default::default()
        };
        let protocol: u16 = 0x0800;
        let ifindex: i32 = 2;
        let hatype: u16 = 1;
        let pkttype: u8 = 0;
        let halen: u8 = 6;
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
        addr.sa_data[10..16].copy_from_slice(&mac_addr);
        SyscallEvent {
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
                    addrlen: 20,
                },
            },
        }
    },
    format!(
        "5001 accept4(sockfd: 9, addr: {{ family: AF_PACKET, protocol: 0x800, ifindex: 2, hatype: 1, pkttype: 0, addr: 00:11:22:33:44:55 }}, addrlen: 20, flags: 0x800 (SOCK_NONBLOCK)) = 10 (fd)\n"
    )
);

syscall_test!(
    test_accept4_ipv6_with_larger_buffer,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_INET6 as u16,
            ..Default::default()
        };
        addr.sa_data[0] = 0x1f;
        addr.sa_data[1] = 0x40;
        SyscallEvent {
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
                    addrlen: 8,
                },
            },
        }
    },
    format!(
        "6001 accept4(sockfd: 10, addr: {{ family: AF_INET6, addr: [0:0:0:0:0:0:0:0]:8000 }}, addrlen: 8, flags: 0) = 11 (fd)\n"
    )
);

syscall_test!(
    test_accept4_unknown_family,
    {
        let mut addr = Sockaddr {
            sa_family: 999,
            ..Default::default()
        };
        addr.sa_data[0] = 0xde;
        addr.sa_data[1] = 0xad;
        addr.sa_data[2] = 0xbe;
        addr.sa_data[3] = 0xef;
        SyscallEvent {
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
        }
    },
    format!(
        "7001 accept4(sockfd: 11, addr: {{ family: 999, data: de ad be ef  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0 }}, addrlen: 8, flags: 0) = 12 (fd)\n"
    )
);

syscall_test!(
    parse_accept4_ipv6,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_INET6 as u16,
            ..Default::default()
        };
        addr.sa_data[0] = 0x1f;
        addr.sa_data[1] = 0x90;
        addr.sa_data[6] = 0x20;
        addr.sa_data[7] = 0x01;
        addr.sa_data[8] = 0x0d;
        addr.sa_data[9] = 0xb8;
        addr.sa_data[20] = 0x00;
        addr.sa_data[21] = 0x01;
        SyscallEvent {
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
        }
    },
    "2234 accept4(sockfd: 4, addr: { family: AF_INET6, addr: [2001:db8:0:0:0:0:0:1]:8080 }, addrlen: 28, flags: 0x80000 (SOCK_CLOEXEC)) = 5 (fd)\n"
);

syscall_test!(
    parse_accept4_netlink,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_NETLINK as u16,
            ..Default::default()
        };
        addr.sa_data[0] = 0xd2;
        addr.sa_data[1] = 0x04;
        addr.sa_data[4] = 0x01;
        SyscallEvent {
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
        }
    },
    format!(
        "3234 accept4(sockfd: 5, addr: {{ family: AF_NETLINK, pid: 1234, groups: 0x1 }}, addrlen: 12, flags: 0) = 6 (fd)\n"
    )
);

syscall_test!(
    parse_accept4_packet,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_PACKET as u16,
            ..Default::default()
        };
        addr.sa_data[0] = 0x08;
        addr.sa_data[1] = 0x00;
        addr.sa_data[2] = 0x02;
        addr.sa_data[3] = 0x00;
        addr.sa_data[6] = 0x01;
        addr.sa_data[9] = 0x06;
        addr.sa_data[10..16].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        SyscallEvent {
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
        }
    },
    "4234 accept4(sockfd: 6, addr: { family: AF_PACKET, protocol: 0x800, ifindex: 2, hatype: 1, pkttype: 0, addr: aa:bb:cc:dd:ee:ff }, addrlen: 20, flags: 0x800 (SOCK_NONBLOCK)) = 7 (fd)\n"
);

syscall_test!(
    test_recvfrom_with_address,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_INET as u16,
            ..Default::default()
        };
        addr.sa_data[0] = 0x01;
        addr.sa_data[1] = 0xbb;
        let mut received_data = [0u8; pinchy_common::DATA_READ_SIZE];
        received_data[..12].copy_from_slice(b"Hello world!");
        SyscallEvent {
            pid: 1234,
            tid: 1234,
            syscall_nr: SYS_recvfrom,
            return_value: 12,
            data: SyscallEventData {
                recvfrom: RecvfromData {
                    sockfd: 8,
                    size: 1024,
                    flags: libc::MSG_PEEK,
                    has_addr: true,
                    addr,
                    addrlen: 16,
                    received_data,
                    received_len: 12,
                },
            },
        }
    },
    "1234 recvfrom(sockfd: 8, buf: \"Hello world!\", size: 1024, flags: 0x2 (MSG_PEEK), src_addr: { family: AF_INET, addr: 0.0.0.0:443 }, addrlen: 16) = 12 (bytes)\n"
);

syscall_test!(
    test_recvfrom_without_address,
    {
        let mut received_data = [0u8; pinchy_common::DATA_READ_SIZE];
        received_data[..5].copy_from_slice(b"test!");
        SyscallEvent {
            pid: 5678,
            tid: 5678,
            syscall_nr: SYS_recvfrom,
            return_value: 5,
            data: SyscallEventData {
                recvfrom: RecvfromData {
                    sockfd: 3,
                    size: 512,
                    flags: 0,
                    has_addr: false,
                    addr: Sockaddr::default(),
                    addrlen: 0,
                    received_data,
                    received_len: 5,
                },
            },
        }
    },
    "5678 recvfrom(sockfd: 3, buf: \"test!\", size: 512, flags: 0, src_addr: NULL, addrlen: 0) = 5 (bytes)\n"
);

syscall_test!(
    test_recvfrom_failed,
    {
        SyscallEvent {
            pid: 9999,
            tid: 9999,
            syscall_nr: SYS_recvfrom,
            return_value: -1,
            data: SyscallEventData {
                recvfrom: RecvfromData {
                    sockfd: 4,
                    size: 256,
                    flags: libc::MSG_DONTWAIT,
                    has_addr: false,
                    addr: Sockaddr::default(),
                    addrlen: 0,
                    received_data: [0u8; pinchy_common::DATA_READ_SIZE],
                    received_len: 0,
                },
            },
        }
    },
    "9999 recvfrom(sockfd: 4, buf: NULL, size: 256, flags: 0x40 (MSG_DONTWAIT), src_addr: NULL, addrlen: 0) = -1 (error)\n"
);

syscall_test!(
    parse_bind_inet,
    {
        let mut sockaddr = Sockaddr {
            sa_family: libc::AF_INET as u16,
            ..Default::default()
        };
        sockaddr.sa_data[0] = 0x1f;
        sockaddr.sa_data[1] = 0x90;
        sockaddr.sa_data[2] = 0;
        sockaddr.sa_data[3] = 0;
        sockaddr.sa_data[4] = 0;
        sockaddr.sa_data[5] = 0;
        SyscallEvent {
            syscall_nr: SYS_bind,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: SyscallEventData {
                sockaddr: SockaddrData {
                    sockfd: 3,
                    addr: sockaddr,
                    addrlen: 16,
                },
            },
        }
    },
    "1234 bind(sockfd: 3, addr: { family: AF_INET, addr: 0.0.0.0:8080 }, addrlen: 16) = 0 (success)\n"
);

syscall_test!(
    parse_connect_inet,
    {
        let mut sockaddr = Sockaddr {
            sa_family: libc::AF_INET as u16,
            ..Default::default()
        };
        sockaddr.sa_data[0] = 0x1f;
        sockaddr.sa_data[1] = 0x90;
        sockaddr.sa_data[2] = 127;
        sockaddr.sa_data[3] = 0;
        sockaddr.sa_data[4] = 0;
        sockaddr.sa_data[5] = 1;
        SyscallEvent {
            syscall_nr: SYS_connect,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: SyscallEventData {
                sockaddr: SockaddrData {
                    sockfd: 4,
                    addr: sockaddr,
                    addrlen: 16,
                },
            },
        }
    },
    "1234 connect(sockfd: 4, addr: { family: AF_INET, addr: 127.0.0.1:8080 }, addrlen: 16) = 0 (success)\n"
);

syscall_test!(
    parse_bind_unix,
    {
        let mut sockaddr = Sockaddr {
            sa_family: libc::AF_UNIX as u16,
            ..Default::default()
        };
        let path = b"/tmp/test.sock";
        for (i, &byte) in path.iter().enumerate() {
            if i < sockaddr.sa_data.len() {
                sockaddr.sa_data[i] = byte;
            }
        }
        SyscallEvent {
            syscall_nr: SYS_bind,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: SyscallEventData {
                sockaddr: SockaddrData {
                    sockfd: 3,
                    addr: sockaddr,
                    addrlen: 2 + path.len() as u32,
                },
            },
        }
    },
    "1234 bind(sockfd: 3, addr: { family: AF_UNIX, path: \"/tmp/test.sock\" }, addrlen: 16) = 0 (success)\n"
);

syscall_test!(
    parse_connect_failed,
    {
        let mut sockaddr = Sockaddr {
            sa_family: libc::AF_INET as u16,
            ..Default::default()
        };
        sockaddr.sa_data[0] = 0x01;
        sockaddr.sa_data[1] = 0xbb;
        sockaddr.sa_data[2] = 192;
        sockaddr.sa_data[3] = 168;
        sockaddr.sa_data[4] = 1;
        sockaddr.sa_data[5] = 100;
        SyscallEvent {
            syscall_nr: SYS_connect,
            pid: 5678,
            tid: 5678,
            return_value: -1,
            data: SyscallEventData {
                sockaddr: SockaddrData {
                    sockfd: 5,
                    addr: sockaddr,
                    addrlen: 16,
                },
            },
        }
    },
    "5678 connect(sockfd: 5, addr: { family: AF_INET, addr: 192.168.1.100:443 }, addrlen: 16) = -1 (error)\n"
);

syscall_test!(
    parse_socket_inet,
    {
        SyscallEvent {
            syscall_nr: SYS_socket,
            pid: 1234,
            tid: 1234,
            return_value: 3,
            data: SyscallEventData {
                socket: SocketData {
                    domain: libc::AF_INET,
                    type_: libc::SOCK_STREAM,
                    protocol: 0,
                },
            },
        }
    },
    "1234 socket(domain: AF_INET, type: SOCK_STREAM, protocol: 0) = 3 (fd)\n"
);

syscall_test!(
    parse_socket_unix,
    {
        SyscallEvent {
            syscall_nr: SYS_socket,
            pid: 2345,
            tid: 2345,
            return_value: 4,
            data: SyscallEventData {
                socket: SocketData {
                    domain: libc::AF_UNIX,
                    type_: libc::SOCK_DGRAM,
                    protocol: 0,
                },
            },
        }
    },
    "2345 socket(domain: AF_UNIX, type: SOCK_DGRAM, protocol: 0) = 4 (fd)\n"
);

syscall_test!(
    parse_socket_failed,
    {
        SyscallEvent {
            syscall_nr: SYS_socket,
            pid: 9999,
            tid: 9999,
            return_value: -1,
            data: SyscallEventData {
                socket: SocketData {
                    domain: libc::AF_INET6,
                    type_: libc::SOCK_RAW,
                    protocol: libc::IPPROTO_ICMP,
                },
            },
        }
    },
    "9999 socket(domain: AF_INET6, type: SOCK_RAW, protocol: 1) = -1 (error)\n"
);

syscall_test!(
    parse_listen_success,
    {
        SyscallEvent {
            syscall_nr: SYS_listen,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: SyscallEventData {
                listen: ListenData {
                    sockfd: 3,
                    backlog: 128,
                },
            },
        }
    },
    "1234 listen(sockfd: 3, backlog: 128) = 0 (success)\n"
);

syscall_test!(
    parse_listen_failed,
    {
        SyscallEvent {
            syscall_nr: SYS_listen,
            pid: 5678,
            tid: 5678,
            return_value: -1,
            data: SyscallEventData {
                listen: ListenData {
                    sockfd: 7,
                    backlog: 50,
                },
            },
        }
    },
    "5678 listen(sockfd: 7, backlog: 50) = -1 (error)\n"
);

syscall_test!(
    parse_shutdown_read,
    {
        SyscallEvent {
            syscall_nr: SYS_shutdown,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: SyscallEventData {
                shutdown: ShutdownData {
                    sockfd: 3,
                    how: libc::SHUT_RD,
                },
            },
        }
    },
    "1234 shutdown(sockfd: 3, how: SHUT_RD) = 0 (success)\n"
);

syscall_test!(
    parse_shutdown_rdwr,
    {
        SyscallEvent {
            syscall_nr: SYS_shutdown,
            pid: 2345,
            tid: 2345,
            return_value: 0,
            data: SyscallEventData {
                shutdown: ShutdownData {
                    sockfd: 5,
                    how: libc::SHUT_RDWR,
                },
            },
        }
    },
    "2345 shutdown(sockfd: 5, how: SHUT_RDWR) = 0 (success)\n"
);

syscall_test!(
    parse_shutdown_failed,
    {
        SyscallEvent {
            syscall_nr: SYS_shutdown,
            pid: 9999,
            tid: 9999,
            return_value: -1,
            data: SyscallEventData {
                shutdown: ShutdownData {
                    sockfd: 10,
                    how: libc::SHUT_WR,
                },
            },
        }
    },
    "9999 shutdown(sockfd: 10, how: SHUT_WR) = -1 (error)\n"
);

syscall_test!(
    parse_socketpair_success,
    {
        SyscallEvent {
            syscall_nr: SYS_socketpair,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: SyscallEventData {
                socketpair: SocketpairData {
                    domain: libc::AF_UNIX,
                    type_: libc::SOCK_STREAM,
                    protocol: 0,
                    sv: [5, 6],
                },
            },
        }
    },
    "1234 socketpair(domain: AF_UNIX, type: SOCK_STREAM, protocol: 0, sv: [5, 6]) = 0 (success)\n"
);

syscall_test!(
    parse_socketpair_with_flags,
    {
        SyscallEvent {
            syscall_nr: SYS_socketpair,
            pid: 2345,
            tid: 2345,
            return_value: 0,
            data: SyscallEventData {
                socketpair: SocketpairData {
                    domain: libc::AF_UNIX,
                    type_: libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    protocol: 0,
                    sv: [7, 8],
                },
            },
        }
    },
    "2345 socketpair(domain: AF_UNIX, type: SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, protocol: 0, sv: [7, 8]) = 0 (success)\n"
);

syscall_test!(
    parse_socketpair_failed,
    {
        SyscallEvent {
            syscall_nr: SYS_socketpair,
            pid: 9999,
            tid: 9999,
            return_value: -1,
            data: SyscallEventData {
                socketpair: SocketpairData {
                    domain: libc::AF_INET,
                    type_: libc::SOCK_STREAM,
                    protocol: 0,
                    sv: [0, 0],
                },
            },
        }
    },
    "9999 socketpair(domain: AF_INET, type: SOCK_STREAM, protocol: 0, sv: [?, ?]) = -1 (error)\n"
);

syscall_test!(
    parse_getsockname_inet_success,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_INET as u16,
            ..Default::default()
        };
        addr.sa_data[0] = 0x1f;
        addr.sa_data[1] = 0x90;
        addr.sa_data[2] = 127;
        addr.sa_data[3] = 0;
        addr.sa_data[4] = 0;
        addr.sa_data[5] = 1;
        SyscallEvent {
            syscall_nr: SYS_getsockname,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: SyscallEventData {
                getsockname: GetSocknameData {
                    sockfd: 4,
                    has_addr: true,
                    addr,
                    addrlen: 16,
                },
            },
        }
    },
    "1234 getsockname(sockfd: 4, addr: { family: AF_INET, addr: 127.0.0.1:8080 }, addrlen: 16) = 0 (success)\n"
);

syscall_test!(
    parse_getsockname_unix_success,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_UNIX as u16,
            ..Default::default()
        };
        let path = b"/tmp/test.sock";
        addr.sa_data[..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: SYS_getsockname,
            pid: 2345,
            tid: 2345,
            return_value: 0,
            data: SyscallEventData {
                getsockname: GetSocknameData {
                    sockfd: 5,
                    has_addr: true,
                    addr,
                    addrlen: 2 + path.len() as u32,
                },
            },
        }
    },
    "2345 getsockname(sockfd: 5, addr: { family: AF_UNIX, path: \"/tmp/test.sock\" }, addrlen: 16) = 0 (success)\n"
);

syscall_test!(
    parse_getsockname_null_addr,
    {
        SyscallEvent {
            syscall_nr: SYS_getsockname,
            pid: 3456,
            tid: 3456,
            return_value: 0,
            data: SyscallEventData {
                getsockname: GetSocknameData {
                    sockfd: 7,
                    has_addr: false,
                    addr: Sockaddr::default(),
                    addrlen: 0,
                },
            },
        }
    },
    "3456 getsockname(sockfd: 7, addr: NULL, addrlen: 0) = 0 (success)\n"
);

syscall_test!(
    parse_getsockname_failed,
    {
        SyscallEvent {
            syscall_nr: SYS_getsockname,
            pid: 9999,
            tid: 9999,
            return_value: -1,
            data: SyscallEventData {
                getsockname: GetSocknameData {
                    sockfd: 8,
                    has_addr: false,
                    addr: Sockaddr::default(),
                    addrlen: 0,
                },
            },
        }
    },
    "9999 getsockname(sockfd: 8, addr: NULL, addrlen: 0) = -1 (error)\n"
);

syscall_test!(
    parse_getpeername_inet_success,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_INET as u16,
            ..Default::default()
        };
        addr.sa_data[0] = 0x01;
        addr.sa_data[1] = 0xbb;
        addr.sa_data[2] = 192;
        addr.sa_data[3] = 168;
        addr.sa_data[4] = 1;
        addr.sa_data[5] = 100;
        SyscallEvent {
            syscall_nr: SYS_getpeername,
            pid: 4567,
            tid: 4567,
            return_value: 0,
            data: SyscallEventData {
                getpeername: GetpeernameData {
                    sockfd: 6,
                    has_addr: true,
                    addr,
                    addrlen: 16,
                },
            },
        }
    },
    "4567 getpeername(sockfd: 6, addr: { family: AF_INET, addr: 192.168.1.100:443 }, addrlen: 16) = 0 (success)\n"
);

syscall_test!(
    parse_getpeername_ipv6_success,
    {
        let mut addr = Sockaddr {
            sa_family: libc::AF_INET6 as u16,
            ..Default::default()
        };
        addr.sa_data[0] = 0x1f;
        addr.sa_data[1] = 0x40;
        addr.sa_data[6] = 0x20;
        addr.sa_data[7] = 0x01;
        addr.sa_data[8] = 0x0d;
        addr.sa_data[9] = 0xb8;
        addr.sa_data[20] = 0x00;
        addr.sa_data[21] = 0x01;
        SyscallEvent {
            syscall_nr: SYS_getpeername,
            pid: 5678,
            tid: 5678,
            return_value: 0,
            data: SyscallEventData {
                getpeername: GetpeernameData {
                    sockfd: 9,
                    has_addr: true,
                    addr,
                    addrlen: 28,
                },
            },
        }
    },
    "5678 getpeername(sockfd: 9, addr: { family: AF_INET6, addr: [2001:db8:0:0:0:0:0:1]:8000 }, addrlen: 28) = 0 (success)\n"
);

syscall_test!(
    parse_getpeername_null_addr,
    {
        SyscallEvent {
            syscall_nr: SYS_getpeername,
            pid: 6789,
            tid: 6789,
            return_value: 0,
            data: SyscallEventData {
                getpeername: GetpeernameData {
                    sockfd: 10,
                    has_addr: false,
                    addr: Sockaddr::default(),
                    addrlen: 0,
                },
            },
        }
    },
    "6789 getpeername(sockfd: 10, addr: NULL, addrlen: 0) = 0 (success)\n"
);

syscall_test!(
    parse_getpeername_failed,
    {
        SyscallEvent {
            syscall_nr: SYS_getpeername,
            pid: 8888,
            tid: 8888,
            return_value: -1,
            data: SyscallEventData {
                getpeername: GetpeernameData {
                    sockfd: 11,
                    has_addr: false,
                    addr: Sockaddr::default(),
                    addrlen: 0,
                },
            },
        }
    },
    "8888 getpeername(sockfd: 11, addr: NULL, addrlen: 0) = -1 (error)\n"
);

syscall_test!(
    parse_setsockopt_so_reuseaddr,
    {
        let mut optval = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        optval[0] = 1; // Enable SO_REUSEADDR
        optval[1] = 0;
        optval[2] = 0;
        optval[3] = 0;

        SyscallEvent {
            syscall_nr: SYS_setsockopt,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: SyscallEventData {
                setsockopt: SetsockoptData {
                    sockfd: 5,
                    level: libc::SOL_SOCKET,
                    optname: libc::SO_REUSEADDR,
                    optval,
                    optlen: 4,
                },
            },
        }
    },
    r#"1234 setsockopt(sockfd: 5, level: SOL_SOCKET, optname: SO_REUSEADDR, optval: "\u{1}\0\0\0", optlen: 4) = 0 (success)
"#
);

syscall_test!(
    parse_setsockopt_tcp_nodelay,
    {
        let mut optval = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        optval[0] = 1; // Enable TCP_NODELAY
        optval[1] = 0;
        optval[2] = 0;
        optval[3] = 0;

        SyscallEvent {
            syscall_nr: SYS_setsockopt,
            pid: 2345,
            tid: 2345,
            return_value: 0,
            data: SyscallEventData {
                setsockopt: SetsockoptData {
                    sockfd: 8,
                    level: libc::IPPROTO_TCP,
                    optname: libc::TCP_NODELAY,
                    optval,
                    optlen: 4,
                },
            },
        }
    },
    r#"2345 setsockopt(sockfd: 8, level: IPPROTO_TCP, optname: TCP_NODELAY, optval: "\u{1}\0\0\0", optlen: 4) = 0 (success)
"#
);

syscall_test!(
    parse_setsockopt_zero_length,
    {
        SyscallEvent {
            syscall_nr: SYS_setsockopt,
            pid: 3456,
            tid: 3456,
            return_value: 0,
            data: SyscallEventData {
                setsockopt: SetsockoptData {
                    sockfd: 10,
                    level: libc::SOL_SOCKET,
                    optname: libc::SO_KEEPALIVE,
                    optval: [0u8; pinchy_common::MEDIUM_READ_SIZE],
                    optlen: 0,
                },
            },
        }
    },
    "3456 setsockopt(sockfd: 10, level: SOL_SOCKET, optname: SO_KEEPALIVE, optval: NULL, optlen: 0) = 0 (success)\n"
);

syscall_test!(
    parse_getsockopt_so_error,
    {
        let mut optval = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        optval[0] = 0; // No error
        optval[1] = 0;
        optval[2] = 0;
        optval[3] = 0;

        SyscallEvent {
            syscall_nr: SYS_getsockopt,
            pid: 4567,
            tid: 4567,
            return_value: 0,
            data: SyscallEventData {
                getsockopt: GetsockoptData {
                    sockfd: 7,
                    level: libc::SOL_SOCKET,
                    optname: libc::SO_ERROR,
                    optval,
                    optlen: 4,
                },
            },
        }
    },
    r#"4567 getsockopt(sockfd: 7, level: SOL_SOCKET, optname: SO_ERROR, optval: "\0\0\0\0", optlen: 4) = 0 (success)
"#
);

syscall_test!(
    parse_getsockopt_failed,
    {
        SyscallEvent {
            syscall_nr: SYS_getsockopt,
            pid: 5678,
            tid: 5678,
            return_value: -1,
            data: SyscallEventData {
                getsockopt: GetsockoptData {
                    sockfd: 9,
                    level: libc::SOL_SOCKET,
                    optname: libc::SO_TYPE,
                    optval: [0u8; pinchy_common::MEDIUM_READ_SIZE],
                    optlen: 0,
                },
            },
        }
    },
    "5678 getsockopt(sockfd: 9, level: SOL_SOCKET, optname: SO_TYPE, optval: NULL, optlen: 0) = -1 (error)\n"
);
