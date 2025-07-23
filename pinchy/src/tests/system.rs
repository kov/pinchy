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
    syscalls::{
        SYS_getrandom, SYS_gettimeofday, SYS_ioctl, SYS_ioprio_get, SYS_ioprio_set,
        SYS_personality, SYS_settimeofday, SYS_sync, SYS_sysinfo, SYS_times, SYS_umask, SYS_uname,
        SYS_vhangup,
    },
    GettimeofdayData, IoctlData, IoprioGetData, IoprioSetData, PersonalityData, SettimeofdayData,
    SyncData, SyscallEvent, SysinfoData, TimesData, UmaskData, UnameData, VhangupData,
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

#[tokio::test]
async fn test_sync() {
    let event = SyscallEvent {
        syscall_nr: SYS_sync,
        pid: 123,
        tid: 123,
        return_value: 0,
        data: pinchy_common::SyscallEventData { sync: SyncData },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "123 sync() = 0 (success)\n"
    );
}

#[tokio::test]
async fn test_umask() {
    let event = SyscallEvent {
        syscall_nr: SYS_umask,
        pid: 123,
        tid: 123,
        return_value: 0o022, // previous mask
        data: pinchy_common::SyscallEventData {
            umask: UmaskData { mask: 0o027 }, // new mask
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "123 umask(mask: 0o27) = 18\n"
    );
}

#[tokio::test]
async fn test_vhangup() {
    let event = SyscallEvent {
        syscall_nr: SYS_vhangup,
        pid: 123,
        tid: 123,
        return_value: 0, // success
        data: pinchy_common::SyscallEventData {
            vhangup: VhangupData,
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "123 vhangup() = 0 (success)\n"
    );
}

#[tokio::test]
async fn test_ioprio_get() {
    let event = SyscallEvent {
        syscall_nr: SYS_ioprio_get,
        pid: 123,
        tid: 123,
        return_value: 4, // I/O priority value
        data: pinchy_common::SyscallEventData {
            ioprio_get: IoprioGetData { which: 1, who: 0 }, // IOPRIO_WHO_PROCESS, current process
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "123 ioprio_get(which: 1, who: 0) = 4\n"
    );
}

#[tokio::test]
async fn test_ioprio_set() {
    let event = SyscallEvent {
        syscall_nr: SYS_ioprio_set,
        pid: 123,
        tid: 123,
        return_value: 0, // success
        data: pinchy_common::SyscallEventData {
            ioprio_set: IoprioSetData {
                which: 1,
                who: 0,
                ioprio: 4,
            }, // IOPRIO_WHO_PROCESS, current process, priority 4
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "123 ioprio_set(which: 1, who: 0, ioprio: 4) = 0 (success)\n"
    );
}

#[tokio::test]
async fn test_personality() {
    let event = SyscallEvent {
        syscall_nr: SYS_personality,
        pid: 1001,
        tid: 1001,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            personality: PersonalityData { persona: 0x200 },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1001 personality(persona: 0x200) = 0 (success)\n"
    );
}

#[tokio::test]
async fn test_sysinfo() {
    use pinchy_common::kernel_types::Sysinfo;

    let event = SyscallEvent {
        syscall_nr: SYS_sysinfo,
        pid: 1001,
        tid: 1001,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            sysinfo: SysinfoData {
                info: Sysinfo {
                    uptime: 3600,              // 1 hour uptime
                    loads: [1024, 2048, 3072], // Load averages (scaled by 65536)
                    totalram: 16777216,        // 16 GB in KB (assuming mem_unit=1024)
                    freeram: 8388608,          // 8 GB free
                    sharedram: 1048576,        // 1 GB shared
                    bufferram: 524288,         // 512 MB buffers
                    totalswap: 4194304,        // 4 GB swap
                    freeswap: 4194304,         // 4 GB free swap
                    procs: 150,                // 150 processes
                    totalhigh: 0,              // No high memory
                    freehigh: 0,               // No high memory
                    mem_unit: 1024,            // 1 KB memory units
                },
                has_info: true,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1001 sysinfo(info: { uptime: 3600 seconds, loads: [1024, 2048, 3072], totalram: 16384 MB, freeram: 8192 MB, sharedram: 1024 MB, bufferram: 512 MB, totalswap: 4096 MB, freeswap: 4096 MB, procs: 150, mem_unit: 1024 bytes }) = 0 (success)\n"
    );
}

#[tokio::test]
async fn test_times() {
    use pinchy_common::kernel_types::Tms;

    let event = SyscallEvent {
        syscall_nr: SYS_times,
        pid: 1001,
        tid: 1001,
        return_value: 123456, // Clock ticks since boot
        data: pinchy_common::SyscallEventData {
            times: TimesData {
                buf: Tms {
                    tms_utime: 1234, // User CPU time in ticks
                    tms_stime: 5678, // System CPU time in ticks
                    tms_cutime: 100, // Children user CPU time
                    tms_cstime: 200, // Children system CPU time
                },
                has_buf: true,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1001 times(buf: { tms_utime: 1234 ticks, tms_stime: 5678 ticks, tms_cutime: 100 ticks, tms_cstime: 200 ticks }) = 123456\n"
    );
}

#[tokio::test]
async fn test_gettimeofday() {
    use pinchy_common::kernel_types::{Timeval, Timezone};

    let event = SyscallEvent {
        syscall_nr: SYS_gettimeofday,
        pid: 1001,
        tid: 1001,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            gettimeofday: GettimeofdayData {
                tv: Timeval {
                    tv_sec: 1672531200, // 2023-01-01 00:00:00 UTC
                    tv_usec: 123456,
                },
                tz: Timezone {
                    tz_minuteswest: 480, // PST (8 hours west)
                    tz_dsttime: 0,
                },
                has_tv: true,
                has_tz: true,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1001 gettimeofday(tv: { tv_sec: 1672531200, tv_usec: 123456 }, tz: { tz_minuteswest: 480, tz_dsttime: 0 }) = 0 (success)\n"
    );
}

#[tokio::test]
async fn test_settimeofday() {
    use pinchy_common::kernel_types::{Timeval, Timezone};

    let event = SyscallEvent {
        syscall_nr: SYS_settimeofday,
        pid: 1001,
        tid: 1001,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            settimeofday: SettimeofdayData {
                tv: Timeval {
                    tv_sec: 1672531200, // 2023-01-01 00:00:00 UTC
                    tv_usec: 123456,
                },
                tz: Timezone::default(), // tz is NULL (0x0)
                has_tv: true,
                has_tz: false,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1001 settimeofday(tv: { tv_sec: 1672531200, tv_usec: 123456 }, tz: NULL) = 0 (success)\n"
    );
}

#[tokio::test]
async fn parse_setfsuid() {
    let event = SyscallEvent {
        syscall_nr: pinchy_common::syscalls::SYS_setfsuid,
        pid: 1234,
        tid: 1234,
        return_value: 1000, // Previous fsuid
        data: pinchy_common::SyscallEventData {
            setfsuid: pinchy_common::SetfsuidData { uid: 1001 },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1234 setfsuid(uid: 1001) = 1000\n"
    );
}

#[tokio::test]
async fn parse_setfsuid_root() {
    let event = SyscallEvent {
        syscall_nr: pinchy_common::syscalls::SYS_setfsuid,
        pid: 5678,
        tid: 5678,
        return_value: 1001, // Previous fsuid
        data: pinchy_common::SyscallEventData {
            setfsuid: pinchy_common::SetfsuidData { uid: 0 },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "5678 setfsuid(uid: 0) = 1001\n"
    );
}

#[tokio::test]
async fn parse_setfsgid() {
    let event = SyscallEvent {
        syscall_nr: pinchy_common::syscalls::SYS_setfsgid,
        pid: 2468,
        tid: 2468,
        return_value: 1000, // Previous fsgid
        data: pinchy_common::SyscallEventData {
            setfsgid: pinchy_common::SetfsgidData { gid: 1001 },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "2468 setfsgid(gid: 1001) = 1000\n"
    );
}

#[tokio::test]
async fn parse_setfsgid_root() {
    let event = SyscallEvent {
        syscall_nr: pinchy_common::syscalls::SYS_setfsgid,
        pid: 9999,
        tid: 9999,
        return_value: 1001, // Previous fsgid
        data: pinchy_common::SyscallEventData {
            setfsgid: pinchy_common::SetfsgidData { gid: 0 },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "9999 setfsgid(gid: 0) = 1001\n"
    );
}
