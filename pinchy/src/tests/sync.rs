// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::pin::Pin;

use pinchy_common::{
    kernel_types::Timespec,
    syscalls::{SYS_futex, SYS_set_robust_list, SYS_set_tid_address},
    FutexData, SetRobustListData, SetTidAddressData, SyscallEvent,
};

use crate::{
    events::handle_event,
    formatting::{Formatter, FormattingStyle},
};

#[tokio::test]
async fn parse_futex() {
    let event = SyscallEvent {
        syscall_nr: SYS_futex,
        pid: 22,
        tid: 22,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            futex: FutexData {
                uaddr: 0xbeef,
                op: 10,
                val: 11,
                uaddr2: 0xbeef2,
                val3: 12,
                timeout: Timespec {
                    seconds: 13,
                    nanos: 14,
                },
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
            "22 futex(uaddr: 0xbeef, op: 10, val: 11, uaddr2: 0xbeef2, val3: 12, timeout: {{ secs: 13, nanos: 14 }}) = 0\n"
        )
    );
}

#[tokio::test]
async fn parse_set_robust_list() {
    let event = SyscallEvent {
        syscall_nr: SYS_set_robust_list,
        pid: 1234,
        tid: 1234,
        return_value: 0, // Success
        data: pinchy_common::SyscallEventData {
            set_robust_list: SetRobustListData {
                head: 0x7f1234560000, // Robust list head address
                len: 24,              // Standard size for 64-bit systems
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("1234 set_robust_list(head: 0x7f1234560000, len: 24) = 0\n")
    );

    // Test with an error
    let event = SyscallEvent {
        syscall_nr: SYS_set_robust_list,
        pid: 1234,
        tid: 1234,
        return_value: -22, // -EINVAL
        data: pinchy_common::SyscallEventData {
            set_robust_list: SetRobustListData {
                head: 0x7f1234560000,
                len: 0, // Invalid size, which would trigger EINVAL
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1234 set_robust_list(head: 0x7f1234560000, len: 0) = -22 (error)\n"
    );
}

#[tokio::test]
async fn parse_set_tid_address() {
    // Test with a non-NULL address
    let event = SyscallEvent {
        syscall_nr: SYS_set_tid_address,
        pid: 5678,
        tid: 5678,
        return_value: 5678, // Returns the thread ID
        data: pinchy_common::SyscallEventData {
            set_tid_address: SetTidAddressData {
                tidptr: 0x7f1234560000, // Address to store the thread ID
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("5678 set_tid_address(tidptr: 0x7f1234560000) = 5678\n")
    );

    // Test with NULL address
    let event = SyscallEvent {
        syscall_nr: SYS_set_tid_address,
        pid: 5678,
        tid: 5678,
        return_value: 5678, // Returns the thread ID
        data: pinchy_common::SyscallEventData {
            set_tid_address: SetTidAddressData {
                tidptr: 0, // NULL address
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("5678 set_tid_address(tidptr: 0x0) = 5678\n")
    );
}
