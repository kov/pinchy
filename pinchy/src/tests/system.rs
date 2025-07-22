// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#[tokio::test]
async fn parse_rt_sigreturn() {
    use pinchy_common::RtSigreturnData;

    let event = SyscallEvent {
        syscall_nr: pinchy_common::syscalls::SYS_rt_sigreturn,
        pid: 123,
        tid: 123,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            rt_sigreturn: RtSigreturnData {},
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(String::from_utf8_lossy(&output), "123 rt_sigreturn() = 0\n");
}
use std::pin::Pin;

use pinchy_common::{
    kernel_types::Utsname,
    syscalls::{SYS_getrandom, SYS_ioctl, SYS_uname},
    IoctlData, SyscallEvent, UnameData,
};

use crate::{
    events::handle_event,
    formatting::{Formatter, FormattingStyle},
};

#[tokio::test]
async fn parse_ioctl() {
    let event = SyscallEvent {
        syscall_nr: SYS_ioctl,
        pid: 22,
        tid: 22,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            ioctl: IoctlData {
                fd: 4,
                request: 0x4332,
                arg: 0x0,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("22 ioctl(fd: 4, request: (0x4332) SNDRV_COMPRESS_START::sound, arg: 0x0) = 0\n")
    );
}

#[tokio::test]
async fn parse_getrandom() {
    use pinchy_common::GetrandomData;

    // Test successful getrandom call
    let mut event = SyscallEvent {
        syscall_nr: SYS_getrandom,
        pid: 555,
        tid: 555,
        return_value: 32, // Number of bytes written
        data: pinchy_common::SyscallEventData {
            getrandom: GetrandomData {
                buf: 0x7f5678901000, // Buffer address
                buflen: 32,
                flags: 0, // No flags
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x0) = 32\n")
    );

    // Test with GRND_RANDOM flag
    event.data.getrandom.flags = libc::GRND_RANDOM;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x2 (GRND_RANDOM)) = 32\n")
    );

    // Test with GRND_RANDOM flag
    event.data.getrandom.flags = libc::GRND_NONBLOCK;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x1 (GRND_NONBLOCK)) = 32\n"
        )
    );

    // Test with combined flags
    unsafe { event.data.getrandom.flags |= libc::GRND_RANDOM };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x3 (GRND_NONBLOCK|GRND_RANDOM)) = 32\n"
        )
    );

    // Test error case (would happen if entropy pool not initialized yet)
    event.return_value = -11;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x3 (GRND_NONBLOCK|GRND_RANDOM)) = -11 (error)\n"
    );
}

#[tokio::test]
async fn parse_uname() {
    // Create a mock utsname with typical Linux system information
    let mut utsname = Utsname::default();

    // Simulate typical system info (strings will be null-terminated)
    let sysname = b"Linux";
    let nodename = b"jabuticaba";
    let release = b"6.15.4-200.fc42.aarch64";
    let version = b"#1 SMP PREEMPT_DYNAMIC";
    let machine = b"aarch64";
    let domainname = b"(none)";

    utsname.sysname[..sysname.len()].copy_from_slice(sysname);
    utsname.nodename[..nodename.len()].copy_from_slice(nodename);
    utsname.release[..release.len()].copy_from_slice(release);
    utsname.version[..version.len()].copy_from_slice(version);
    utsname.machine[..machine.len()].copy_from_slice(machine);
    utsname.domainname[..domainname.len()].copy_from_slice(domainname);

    let event = SyscallEvent {
        syscall_nr: SYS_uname,
        pid: 1234,
        tid: 1234,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            uname: UnameData { utsname },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1234 uname(struct utsname: { sysname: \"Linux\", nodename: \"jabuticaba\", release: \"6.15.4-200.fc42.aarch64\", version: \"#1 SMP PREEMPT_DYNAMIC\", machine: \"aarch64\", domainname: \"(none)\" }) = 0\n"
    );
}

#[tokio::test]
async fn parse_uname_truncated() {
    // Test with a very long version string that gets truncated
    let mut utsname = Utsname::default();

    let sysname = b"Linux";
    let nodename = b"jabuticaba";
    let release = b"6.15.4-200.fc42.aarch64";
    let version = b"#1 SMP PREEMPT_DYNAMIC Fri Jun 27 15:55:20 UTC 2025 aarch64 GNU/L";
    let machine = b"aarch64";
    let domainname = b"(none)";

    utsname.sysname[..sysname.len()].copy_from_slice(sysname);
    utsname.nodename[..nodename.len()].copy_from_slice(nodename);
    utsname.release[..release.len()].copy_from_slice(release);
    utsname.version.copy_from_slice(version);
    utsname.machine[..machine.len()].copy_from_slice(machine);
    utsname.domainname[..domainname.len()].copy_from_slice(domainname);

    let event = SyscallEvent {
        syscall_nr: SYS_uname,
        pid: 1234,
        tid: 1234,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            uname: UnameData { utsname },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1234 uname(struct utsname: { sysname: \"Linux\", nodename: \"jabuticaba\", release: \"6.15.4-200.fc42.aarch64\", version: \"#1 SMP PREEMPT_DYNAMIC Fri Jun 27 15:55:20 UTC 2025 aarch64 GNU/L ... (truncated)\", machine: \"aarch64\", domainname: \"(none)\" }) = 0\n"
    );
}

#[tokio::test]
async fn parse_exit_group() {
    use pinchy_common::ExitGroupData;

    let event = SyscallEvent {
        syscall_nr: pinchy_common::syscalls::SYS_exit_group,
        pid: 123,
        tid: 123,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            exit_group: ExitGroupData { status: 42 },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "123 exit_group(status: 42) = 0\n"
    );
}
