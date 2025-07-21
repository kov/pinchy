// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::pin::Pin;

use pinchy_common::{
    syscalls::{SYS_brk, SYS_madvise, SYS_mmap, SYS_mprotect},
    SyscallEvent,
};

use crate::{
    events::handle_event,
    formatting::{Formatter, FormattingStyle},
};

#[tokio::test]
async fn parse_mmap() {
    use pinchy_common::MmapData;

    let event = SyscallEvent {
        syscall_nr: SYS_mmap,
        pid: 66,
        tid: 66,
        return_value: 0x7f1234567000, // A typical memory address returned by mmap
        data: pinchy_common::SyscallEventData {
            mmap: MmapData {
                addr: 0,
                length: 4096,
                prot: libc::PROT_READ | libc::PROT_WRITE,
                flags: libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                fd: -1,
                offset: 0,
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
            "66 mmap(addr: 0x0, length: 4096, prot: 0x3 (PROT_READ|PROT_WRITE), flags: 0x22 (MAP_PRIVATE|MAP_ANONYMOUS), fd: -1, offset: 0x0) = 0x7f1234567000\n"
        )
    );

    // Test with error return
    let event_error = SyscallEvent {
        syscall_nr: SYS_mmap,
        pid: 66,
        tid: 66,
        return_value: -1, // Error
        data: pinchy_common::SyscallEventData {
            mmap: MmapData {
                addr: 0x7f0000000000,
                length: 8192,
                prot: libc::PROT_EXEC,
                flags: libc::MAP_SHARED,
                fd: 5,
                offset: 4096,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event_error, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "66 mmap(addr: 0x7f0000000000, length: 8192, prot: 0x4 (PROT_EXEC), flags: 0x1 (MAP_SHARED), fd: 5, offset: 0x1000) = -1 (error)\n"
        )
    );
}

#[tokio::test]
async fn test_munmap() {
    use std::pin::Pin;

    use pinchy_common::{syscalls::SYS_munmap, MunmapData, SyscallEvent, SyscallEventData};

    use crate::formatting::{Formatter, FormattingStyle};

    let mut event = SyscallEvent {
        syscall_nr: SYS_munmap,
        pid: 123,
        tid: 123,
        return_value: 0, // Success
        data: SyscallEventData {
            munmap: MunmapData {
                addr: 0xffff8a9c2000,
                length: 57344,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("123 munmap(addr: 0xffff8a9c2000, length: 57344) = 0\n")
    );

    // Test with error return
    event.return_value = -1;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("123 munmap(addr: 0xffff8a9c2000, length: 57344) = -1\n")
    );
}

#[tokio::test]
async fn parse_mprotect() {
    use pinchy_common::MprotectData;

    let event = SyscallEvent {
        syscall_nr: SYS_mprotect,
        pid: 77,
        tid: 77,
        return_value: 0, // Success
        data: pinchy_common::SyscallEventData {
            mprotect: MprotectData {
                addr: 0x7f5678901000,
                length: 8192,
                prot: libc::PROT_READ | libc::PROT_EXEC,
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
            "77 mprotect(addr: 0x7f5678901000, length: 8192, prot: 0x5 (PROT_READ|PROT_EXEC)) = 0\n"
        )
    );

    // Test with error return value
    let event_error = SyscallEvent {
        syscall_nr: SYS_mprotect,
        pid: 77,
        tid: 77,
        return_value: -22, // EINVAL
        data: pinchy_common::SyscallEventData {
            mprotect: MprotectData {
                addr: 0x1000, // Invalid address (not page-aligned)
                length: 4096,
                prot: libc::PROT_WRITE,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event_error, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("77 mprotect(addr: 0x1000, length: 4096, prot: 0x2 (PROT_WRITE)) = -22\n")
    );
}

#[tokio::test]
async fn parse_brk() {
    use pinchy_common::BrkData;

    // Test with a new program break address
    let event = SyscallEvent {
        syscall_nr: SYS_brk,
        pid: 888,
        tid: 888,
        return_value: 0x7f1234570000, // New program break
        data: pinchy_common::SyscallEventData {
            brk: BrkData {
                addr: 0x7f1234560000, // Requested address
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("888 brk(addr: 0x7f1234560000) = 0x7f1234570000\n")
    );

    // Test with NULL address - used to get the current program break
    let event = SyscallEvent {
        syscall_nr: SYS_brk,
        pid: 888,
        tid: 888,
        return_value: 0x7f1234500000, // Current program break
        data: pinchy_common::SyscallEventData {
            brk: BrkData {
                addr: 0, // NULL address (get current brk)
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("888 brk(addr: 0x0) = 0x7f1234500000\n")
    );
}

#[tokio::test]
async fn parse_madvise() {
    use pinchy_common::MadviseData;

    let event = SyscallEvent {
        syscall_nr: SYS_madvise,
        pid: 123,
        tid: 123,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            madvise: MadviseData {
                addr: 0x7f1234567000,
                length: 4096,
                advice: 4, // MADV_DONTNEED
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("123 madvise(addr: 0x7f1234567000, length: 4096, advice: MADV_DONTNEED (4)) = 0\n")
    );

    // Test with error return
    let event_error = SyscallEvent {
        syscall_nr: SYS_madvise,
        pid: 456,
        tid: 456,
        return_value: -1, // Error
        data: pinchy_common::SyscallEventData {
            madvise: MadviseData {
                addr: 0x0, // Invalid address
                length: 4096,
                advice: 3, // MADV_WILLNEED
            },
        },
    };

    let mut output_error: Vec<u8> = vec![];
    let pin_output_error = unsafe { Pin::new_unchecked(&mut output_error) };
    let formatter_error = Formatter::new(pin_output_error, FormattingStyle::OneLine);

    handle_event(&event_error, formatter_error).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output_error),
        format!("456 madvise(addr: 0x0, length: 4096, advice: MADV_WILLNEED (3)) = -1\n")
    );

    // Test with unknown advice value
    let event_unknown = SyscallEvent {
        syscall_nr: SYS_madvise,
        pid: 789,
        tid: 789,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            madvise: MadviseData {
                addr: 0x7f1234567000,
                length: 8192,
                advice: 999, // Unknown advice value
            },
        },
    };

    let mut output_unknown: Vec<u8> = vec![];
    let pin_output_unknown = unsafe { Pin::new_unchecked(&mut output_unknown) };
    let formatter_unknown = Formatter::new(pin_output_unknown, FormattingStyle::OneLine);

    handle_event(&event_unknown, formatter_unknown)
        .await
        .unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output_unknown),
        format!("789 madvise(addr: 0x7f1234567000, length: 8192, advice: UNKNOWN (999)) = 0\n")
    );
}
