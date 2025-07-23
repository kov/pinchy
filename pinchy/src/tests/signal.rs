// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::pin::Pin;

use pinchy_common::{
    syscalls::{SYS_rt_sigaction, SYS_rt_sigprocmask},
    RtSigactionData, RtSigprocmaskData, SyscallEvent,
};

use crate::{
    events::handle_event,
    formatting::{Formatter, FormattingStyle},
};

#[tokio::test]
async fn parse_rt_sigprocmask() {
    // Test with SIG_BLOCK and both set and oldset pointers
    let event = SyscallEvent {
        syscall_nr: SYS_rt_sigprocmask,
        pid: 1234,
        tid: 1234,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            rt_sigprocmask: RtSigprocmaskData {
                how: libc::SIG_BLOCK,
                set: 0x7fff12345678,
                oldset: 0x7fff87654321,
                sigsetsize: 8,
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
            "1234 rt_sigprocmask(how: SIG_BLOCK, set: 0x7fff12345678, oldset: 0x7fff87654321, sigsetsize: 8) = 0\n"
        )
    );
}

#[tokio::test]
async fn parse_rt_sigprocmask_null_set() {
    // Test with SIG_SETMASK and NULL set pointer
    let event = SyscallEvent {
        syscall_nr: SYS_rt_sigprocmask,
        pid: 5678,
        tid: 5678,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            rt_sigprocmask: RtSigprocmaskData {
                how: libc::SIG_SETMASK,
                set: 0,
                oldset: 0x7fff11223344,
                sigsetsize: 8,
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
            "5678 rt_sigprocmask(how: SIG_SETMASK, set: 0x0, oldset: 0x7fff11223344, sigsetsize: 8) = 0\n"
        )
    );
}

#[tokio::test]
async fn parse_rt_sigprocmask_unblock() {
    // Test with SIG_UNBLOCK and NULL oldset pointer
    let event = SyscallEvent {
        syscall_nr: SYS_rt_sigprocmask,
        pid: 9999,
        tid: 9999,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            rt_sigprocmask: RtSigprocmaskData {
                how: libc::SIG_UNBLOCK,
                set: 0x7fffaabbccdd,
                oldset: 0,
                sigsetsize: 8,
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
            "9999 rt_sigprocmask(how: SIG_UNBLOCK, set: 0x7fffaabbccdd, oldset: 0x0, sigsetsize: 8) = 0\n"
        )
    );
}

#[tokio::test]
async fn parse_rt_sigaction() {
    // Test with SIGTERM and both act and oldact pointers
    let event = SyscallEvent {
        syscall_nr: SYS_rt_sigaction,
        pid: 2468,
        tid: 2468,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            rt_sigaction: RtSigactionData {
                signum: libc::SIGTERM,
                act: 0x7fff12345678,
                oldact: 0x7fff87654321,
                sigsetsize: 8,
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
            "2468 rt_sigaction(signum: SIGTERM, act: 0x7fff12345678, oldact: 0x7fff87654321, sigsetsize: 8) = 0\n"
        )
    );
}

#[tokio::test]
async fn parse_rt_sigaction_null_act() {
    // Test with SIGUSR1 and NULL act pointer (just querying current action)
    let event = SyscallEvent {
        syscall_nr: SYS_rt_sigaction,
        pid: 1357,
        tid: 1357,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            rt_sigaction: RtSigactionData {
                signum: libc::SIGUSR1,
                act: 0,
                oldact: 0x7fff11223344,
                sigsetsize: 8,
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
            "1357 rt_sigaction(signum: SIGUSR1, act: 0x0, oldact: 0x7fff11223344, sigsetsize: 8) = 0\n"
        )
    );
}

#[tokio::test]
async fn parse_rt_sigaction_realtime_signal() {
    // Test with real-time signal
    let event = SyscallEvent {
        syscall_nr: SYS_rt_sigaction,
        pid: 8642,
        tid: 8642,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            rt_sigaction: RtSigactionData {
                signum: 35, // SIGRT1
                act: 0x7fffaabbccdd,
                oldact: 0,
                sigsetsize: 8,
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
            "8642 rt_sigaction(signum: SIGRT1, act: 0x7fffaabbccdd, oldact: 0x0, sigsetsize: 8) = 0\n"
        )
    );
}

#[tokio::test]
async fn parse_tkill() {
    let event = SyscallEvent {
        syscall_nr: pinchy_common::syscalls::SYS_tkill,
        pid: 1234,
        tid: 1234,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            tkill: pinchy_common::TkillData {
                pid: 5678,
                signal: libc::SIGTERM,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1234 tkill(pid: 5678, sig: SIGTERM) = 0\n"
    );
}

#[tokio::test]
async fn parse_tkill_with_sigusr1() {
    let event = SyscallEvent {
        syscall_nr: pinchy_common::syscalls::SYS_tkill,
        pid: 9999,
        tid: 9999,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            tkill: pinchy_common::TkillData {
                pid: 1111,
                signal: libc::SIGUSR1,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "9999 tkill(pid: 1111, sig: SIGUSR1) = 0\n"
    );
}

#[tokio::test]
async fn parse_tgkill() {
    let event = SyscallEvent {
        syscall_nr: pinchy_common::syscalls::SYS_tgkill,
        pid: 2468,
        tid: 2468,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            tgkill: pinchy_common::TgkillData {
                tgid: 1357,
                pid: 2468,
                signal: libc::SIGKILL,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "2468 tgkill(tgid: 1357, pid: 2468, sig: SIGKILL) = 0\n"
    );
}

#[tokio::test]
async fn parse_tgkill_error() {
    let event = SyscallEvent {
        syscall_nr: pinchy_common::syscalls::SYS_tgkill,
        pid: 1111,
        tid: 1111,
        return_value: -3, // ESRCH
        data: pinchy_common::SyscallEventData {
            tgkill: pinchy_common::TgkillData {
                tgid: 9999,
                pid: 8888,
                signal: libc::SIGTERM,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1111 tgkill(tgid: 9999, pid: 8888, sig: SIGTERM) = -3 (error)\n"
    );
}
