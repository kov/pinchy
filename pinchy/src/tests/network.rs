// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::pin::Pin;

use pinchy_common::{
    kernel_types::{Iovec, Msghdr, Sockaddr},
    syscalls::SYS_recvmsg,
    RecvmsgData, SyscallEvent,
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
