// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    kernel_types::{CapUserData, CapUserHeader, Rlimit, Utsname},
    syscalls::{
        SYS_capget, SYS_capset, SYS_clock_nanosleep, SYS_getcpu, SYS_getrandom, SYS_gettimeofday,
        SYS_ioctl, SYS_ioprio_get, SYS_ioprio_set, SYS_nanosleep, SYS_personality, SYS_reboot,
        SYS_settimeofday, SYS_sync, SYS_sysinfo, SYS_times, SYS_umask, SYS_uname, SYS_vhangup,
    },
    CapsetgetData, ClockNanosleepData, ExitGroupData, GetcpuData, GetrandomData, GettimeofdayData,
    IoctlData, IoprioGetData, IoprioSetData, NanosleepData, PersonalityData, RebootData,
    RtSigreturnData, SettimeofdayData, SyncData, SyscallEvent, SyscallEventData, SysinfoData,
    TimesData, UmaskData, UnameData, VhangupData,
};

use crate::syscall_test;

syscall_test!(
    parse_rt_sigreturn,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_rt_sigreturn,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rt_sigreturn: RtSigreturnData {},
            },
        }
    },
    "123 rt_sigreturn() = 0\n"
);

syscall_test!(
    reboot_restart_success,
    {
        SyscallEvent {
            syscall_nr: SYS_reboot,
            pid: 999,
            tid: 999,
            return_value: 0,
            data: SyscallEventData {
                reboot: RebootData {
                    magic1: libc::LINUX_REBOOT_MAGIC1,
                    magic2: libc::LINUX_REBOOT_MAGIC2,
                    cmd: libc::LINUX_REBOOT_CMD_RESTART,
                    arg: 0,
                    has_restart2: false,
                    restart2: [0; pinchy_common::DATA_READ_SIZE],
                },
            },
        }
    },
    "999 reboot(magic1: 0xfee1dead (LINUX_REBOOT_MAGIC1), magic2: 0x28121969 (LINUX_REBOOT_MAGIC2), cmd: LINUX_REBOOT_CMD_RESTART (19088743), arg: 0x0) = 0 (success)\n"
);

syscall_test!(
    reboot_restart2_with_string,
    {
        let mut buf = [0u8; pinchy_common::DATA_READ_SIZE];
        let s = b"firmware";
        buf[..s.len()].copy_from_slice(s);

        SyscallEvent {
            syscall_nr: SYS_reboot,
            pid: 777,
            tid: 777,
            return_value: 0,
            data: SyscallEventData {
                reboot: RebootData {
                    magic1: libc::LINUX_REBOOT_MAGIC1,
                    magic2: libc::LINUX_REBOOT_MAGIC2,
                    cmd: libc::LINUX_REBOOT_CMD_RESTART2,
                    arg: 0xdeadbeef,
                    has_restart2: true,
                    restart2: buf,
                },
            },
        }
    },
    "777 reboot(magic1: 0xfee1dead (LINUX_REBOOT_MAGIC1), magic2: 0x28121969 (LINUX_REBOOT_MAGIC2), cmd: LINUX_REBOOT_CMD_RESTART2 (-1582119980), arg: 0xdeadbeef, restart2: \"firmware\") = 0 (success)\n"
);

syscall_test!(
    reboot_error,
    {
        SyscallEvent {
            syscall_nr: SYS_reboot,
            pid: 42,
            tid: 42,
            return_value: -22,
            data: SyscallEventData {
                reboot: RebootData {
                    magic1: libc::LINUX_REBOOT_MAGIC1,
                    magic2: libc::LINUX_REBOOT_MAGIC2,
                    cmd: libc::LINUX_REBOOT_CMD_HALT,
                    arg: 0,
                    has_restart2: false,
                    restart2: [0; pinchy_common::DATA_READ_SIZE],
                },
            },
        }
    },
    "42 reboot(magic1: 0xfee1dead (LINUX_REBOOT_MAGIC1), magic2: 0x28121969 (LINUX_REBOOT_MAGIC2), cmd: LINUX_REBOOT_CMD_HALT (-839974621), arg: 0x0) = -22 (error)\n"
);

syscall_test!(
    parse_ioctl,
    {
        SyscallEvent {
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
        }
    },
    "22 ioctl(fd: 4, request: (0x4332) SNDRV_COMPRESS_START::sound, arg: 0x0) = 0 (success)\n"
);

syscall_test!(
    parse_getrandom_success,
    {
        SyscallEvent {
            syscall_nr: SYS_getrandom,
            pid: 555,
            tid: 555,
            return_value: 32,
            data: pinchy_common::SyscallEventData {
                getrandom: GetrandomData {
                    buf: 0x7f5678901000,
                    buflen: 32,
                    flags: 0,
                },
            },
        }
    },
    "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x0) = 32\n"
);

syscall_test!(
    parse_getrandom_grnd_random,
    {
        SyscallEvent {
            syscall_nr: SYS_getrandom,
            pid: 555,
            tid: 555,
            return_value: 32,
            data: pinchy_common::SyscallEventData {
                getrandom: GetrandomData {
                    buf: 0x7f5678901000,
                    buflen: 32,
                    flags: libc::GRND_RANDOM,
                },
            },
        }
    },
    "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x2 (GRND_RANDOM)) = 32\n"
);

syscall_test!(
    parse_getrandom_grnd_nonblock,
    {
        SyscallEvent {
            syscall_nr: SYS_getrandom,
            pid: 555,
            tid: 555,
            return_value: 32,
            data: pinchy_common::SyscallEventData {
                getrandom: GetrandomData {
                    buf: 0x7f5678901000,
                    buflen: 32,
                    flags: libc::GRND_NONBLOCK,
                },
            },
        }
    },
    "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x1 (GRND_NONBLOCK)) = 32\n"
);

syscall_test!(
    parse_getrandom_combined_flags,
    {
        SyscallEvent {
            syscall_nr: SYS_getrandom,
            pid: 555,
            tid: 555,
            return_value: 32,
            data: pinchy_common::SyscallEventData {
                getrandom: GetrandomData {
                    buf: 0x7f5678901000,
                    buflen: 32,
                    flags: libc::GRND_RANDOM | libc::GRND_NONBLOCK,
                },
            },
        }
    },
    "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x3 (GRND_NONBLOCK|GRND_RANDOM)) = 32\n"
);

syscall_test!(
    parse_getrandom_error,
    {
        SyscallEvent {
            syscall_nr: SYS_getrandom,
            pid: 555,
            tid: 555,
            return_value: -11,
            data: pinchy_common::SyscallEventData {
                getrandom: GetrandomData {
                    buf: 0x7f5678901000,
                    buflen: 32,
                    flags: libc::GRND_RANDOM|libc::GRND_NONBLOCK,
                },
            },
        }
    },
    "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x3 (GRND_NONBLOCK|GRND_RANDOM)) = -11 (error)\n"
);

syscall_test!(
    parse_uname,
    {
        let mut utsname = Utsname::default();

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

        SyscallEvent {
            syscall_nr: SYS_uname,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                uname: UnameData { utsname },
            },
        }
    },
    "1234 uname(struct utsname: { sysname: \"Linux\", nodename: \"jabuticaba\", release: \"6.15.4-200.fc42.aarch64\", version: \"#1 SMP PREEMPT_DYNAMIC\", machine: \"aarch64\", domainname: \"(none)\" }) = 0 (success)\n"
);

syscall_test!(
    parse_uname_truncated,
    {
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

        SyscallEvent {
            syscall_nr: SYS_uname,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                uname: UnameData { utsname },
            },
        }
    },
    "1234 uname(struct utsname: { sysname: \"Linux\", nodename: \"jabuticaba\", release: \"6.15.4-200.fc42.aarch64\", version: \"#1 SMP PREEMPT_DYNAMIC Fri Jun 27 15:55:20 UTC 2025 aarch64 GNU/L ... (truncated)\", machine: \"aarch64\", domainname: \"(none)\" }) = 0 (success)\n"
);

syscall_test!(
    parse_exit_group,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_exit_group,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                exit_group: ExitGroupData { status: 42 },
            },
        }
    },
    "123 exit_group(status: 42) = 0 (success)\n"
);

syscall_test!(
    test_sync,
    {
        SyscallEvent {
            syscall_nr: SYS_sync,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData { sync: SyncData },
        }
    },
    "123 sync() = 0 (success)\n"
);

syscall_test!(
    test_umask,
    {
        SyscallEvent {
            syscall_nr: SYS_umask,
            pid: 123,
            tid: 123,
            return_value: 0o022, // previous mask
            data: pinchy_common::SyscallEventData {
                umask: UmaskData { mask: 0o027 }, // new mask
            },
        }
    },
    "123 umask(mask: 0o27) = 18\n"
);

syscall_test!(
    test_vhangup,
    {
        SyscallEvent {
            syscall_nr: SYS_vhangup,
            pid: 123,
            tid: 123,
            return_value: 0, // success
            data: pinchy_common::SyscallEventData {
                vhangup: VhangupData,
            },
        }
    },
    "123 vhangup() = 0 (success)\n"
);

syscall_test!(
    test_ioprio_get,
    {
        SyscallEvent {
            syscall_nr: SYS_ioprio_get,
            pid: 123,
            tid: 123,
            return_value: 4, // I/O priority value
            data: pinchy_common::SyscallEventData {
                ioprio_get: IoprioGetData { which: 1, who: 0 }, // IOPRIO_WHO_PROCESS, current process
            },
        }
    },
    "123 ioprio_get(which: 1, who: 0) = 4\n"
);

syscall_test!(
    test_ioprio_set,
    {
        SyscallEvent {
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
        }
    },
    "123 ioprio_set(which: 1, who: 0, ioprio: 4) = 0 (success)\n"
);

syscall_test!(
    test_personality,
    {
        SyscallEvent {
            syscall_nr: SYS_personality,
            pid: 1001,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                personality: PersonalityData { persona: 0x200 },
            },
        }
    },
    "1001 personality(persona: 0x200) = 0 (success)\n"
);

syscall_test!(
    test_sysinfo,
    {
        use pinchy_common::kernel_types::Sysinfo;

        SyscallEvent {
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
        }
    },
    "1001 sysinfo(info: { uptime: 3600 seconds, loads: [1024, 2048, 3072], totalram: 16384 MB, freeram: 8192 MB, sharedram: 1024 MB, bufferram: 512 MB, totalswap: 4096 MB, freeswap: 4096 MB, procs: 150, mem_unit: 1024 bytes }) = 0 (success)\n"
);

syscall_test!(
    test_times,
    {
        use pinchy_common::kernel_types::Tms;

        SyscallEvent {
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
        }
    },
    "1001 times(buf: { tms_utime: 1234 ticks, tms_stime: 5678 ticks, tms_cutime: 100 ticks, tms_cstime: 200 ticks }) = 123456\n"
);

syscall_test!(
    test_gettimeofday,
    {
        use pinchy_common::kernel_types::{Timeval, Timezone};

        SyscallEvent {
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
        }
    },
    "1001 gettimeofday(tv: { tv_sec: 1672531200, tv_usec: 123456 }, tz: { tz_minuteswest: 480, tz_dsttime: 0 }) = 0 (success)\n"
);

syscall_test!(
    test_settimeofday,
    {
        use pinchy_common::kernel_types::{Timeval, Timezone};

        SyscallEvent {
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
        }
    },
    "1001 settimeofday(tv: { tv_sec: 1672531200, tv_usec: 123456 }, tz: NULL) = 0 (success)\n"
);

syscall_test!(
    parse_setfsuid,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_setfsuid,
            pid: 1234,
            tid: 1234,
            return_value: 1000, // Previous fsuid
            data: pinchy_common::SyscallEventData {
                setfsuid: pinchy_common::SetfsuidData { uid: 1001 },
            },
        }
    },
    "1234 setfsuid(uid: 1001) = 1000\n"
);

syscall_test!(
    parse_setfsuid_root,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_setfsuid,
            pid: 5678,
            tid: 5678,
            return_value: 1001, // Previous fsuid
            data: pinchy_common::SyscallEventData {
                setfsuid: pinchy_common::SetfsuidData { uid: 0 },
            },
        }
    },
    "5678 setfsuid(uid: 0) = 1001\n"
);

syscall_test!(
    parse_setfsgid,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_setfsgid,
            pid: 2468,
            tid: 2468,
            return_value: 1000, // Previous fsgid
            data: pinchy_common::SyscallEventData {
                setfsgid: pinchy_common::SetfsgidData { gid: 1001 },
            },
        }
    },
    "2468 setfsgid(gid: 1001) = 1000\n"
);

syscall_test!(
    parse_setfsgid_root,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_setfsgid,
            pid: 9999,
            tid: 9999,
            return_value: 1001, // Previous fsgid
            data: pinchy_common::SyscallEventData {
                setfsgid: pinchy_common::SetfsgidData { gid: 0 },
            },
        }
    },
    "9999 setfsgid(gid: 0) = 1001\n"
);

syscall_test!(
    test_nanosleep_success,
    {
        use pinchy_common::kernel_types::Timespec;

        SyscallEvent {
            syscall_nr: SYS_nanosleep,
            pid: 1234,
            tid: 1234,
            return_value: 0, // Success
            data: pinchy_common::SyscallEventData {
                nanosleep: NanosleepData {
                    req: Timespec {
                        seconds: 2,
                        nanos: 500_000_000, // 2.5 seconds
                    },
                    rem: Timespec::default(), // Not used when successful
                    has_rem: false,
                },
            },
        }
    },
    "1234 nanosleep(req: { secs: 2, nanos: 500000000 }, rem: NULL) = 0 (success)\n"
);

syscall_test!(
    test_nanosleep_interrupted,
    {
        use pinchy_common::kernel_types::Timespec;

        SyscallEvent {
            syscall_nr: SYS_nanosleep,
            pid: 5678,
            tid: 5678,
            return_value: -4, // EINTR (interrupted)
            data: pinchy_common::SyscallEventData {
                nanosleep: NanosleepData {
                    req: Timespec {
                        seconds: 10,
                        nanos: 0, // 10 seconds requested
                    },
                    rem: Timespec {
                        seconds: 7,
                        nanos: 250_000_000, // 7.25 seconds remaining
                    },
                    has_rem: true,
                },
            },
        }
    },
    "5678 nanosleep(req: { secs: 10, nanos: 0 }, rem: { secs: 7, nanos: 250000000 }) = -4 (error)\n"
);

syscall_test!(
    test_nanosleep_zero_time,
    {
        use pinchy_common::kernel_types::Timespec;

        SyscallEvent {
            syscall_nr: SYS_nanosleep,
            pid: 9999,
            tid: 9999,
            return_value: 0, // Success (immediately returns)
            data: pinchy_common::SyscallEventData {
                nanosleep: NanosleepData {
                    req: Timespec {
                        seconds: 0,
                        nanos: 0, // Zero sleep time
                    },
                    rem: Timespec::default(),
                    has_rem: false,
                },
            },
        }
    },
    "9999 nanosleep(req: { secs: 0, nanos: 0 }, rem: NULL) = 0 (success)\n"
);

syscall_test!(
    test_clock_nanosleep_realtime_success,
    {
        use pinchy_common::kernel_types::Timespec;

        SyscallEvent {
            syscall_nr: SYS_clock_nanosleep,
            pid: 1234,
            tid: 1234,
            return_value: 0, // Success
            data: pinchy_common::SyscallEventData {
                clock_nanosleep: ClockNanosleepData {
                    clockid: libc::CLOCK_REALTIME,
                    flags: 0, // Relative sleep
                    req: Timespec {
                        seconds: 2,
                        nanos: 500_000_000, // 2.5 seconds
                    },
                    rem: Timespec::default(), // Not used when successful
                    has_rem: false,
                },
            },
        }
    },
    "1234 clock_nanosleep(clockid: CLOCK_REALTIME, flags: 0, req: { secs: 2, nanos: 500000000 }, rem: NULL) = 0 (success)\n"
);

syscall_test!(
    test_clock_nanosleep_monotonic_interrupted,
    {
        use pinchy_common::kernel_types::Timespec;

        SyscallEvent {
            syscall_nr: SYS_clock_nanosleep,
            pid: 5678,
            tid: 5678,
            return_value: -4, // EINTR (interrupted)
            data: pinchy_common::SyscallEventData {
                clock_nanosleep: ClockNanosleepData {
                    clockid: libc::CLOCK_MONOTONIC,
                    flags: 0, // Relative sleep
                    req: Timespec {
                        seconds: 10,
                        nanos: 0, // 10 seconds requested
                    },
                    rem: Timespec {
                        seconds: 7,
                        nanos: 250_000_000, // 7.25 seconds remaining
                    },
                    has_rem: true,
                },
            },
        }
    },
    "5678 clock_nanosleep(clockid: CLOCK_MONOTONIC, flags: 0, req: { secs: 10, nanos: 0 }, rem: { secs: 7, nanos: 250000000 }) = -4 (error)\n"
);

syscall_test!(
    test_clock_nanosleep_absolute_time,
    {
        use pinchy_common::kernel_types::Timespec;

        SyscallEvent {
            syscall_nr: SYS_clock_nanosleep,
            pid: 9999,
            tid: 9999,
            return_value: 0, // Success
            data: pinchy_common::SyscallEventData {
                clock_nanosleep: ClockNanosleepData {
                    clockid: libc::CLOCK_REALTIME,
                    flags: libc::TIMER_ABSTIME, // Absolute time
                    req: Timespec {
                        seconds: 1_700_000_000, // Some future absolute time
                        nanos: 123_456_789,
                    },
                    rem: Timespec::default(), // Not used for absolute time
                    has_rem: false,
                },
            },
        }
    },
    "9999 clock_nanosleep(clockid: CLOCK_REALTIME, flags: TIMER_ABSTIME, req: { secs: 1700000000, nanos: 123456789 }, rem: NULL) = 0 (success)\n"
);

syscall_test!(
    parse_getcpu_all,
    {
        SyscallEvent {
            syscall_nr: SYS_getcpu,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: SyscallEventData {
                getcpu: GetcpuData {
                    cpu: 11,
                    has_cpu: true,
                    node: 5,
                    has_node: true,
                    tcache: 0xdeadbeef,
                },
            },
        }
    },
    "1001 getcpu(cpu: 11, node: 5, tcache: 0xdeadbeef) = 0 (success)\n"
);

syscall_test!(
    parse_getcpu_null,
    {
        SyscallEvent {
            syscall_nr: SYS_getcpu,
            pid: 1002,
            tid: 1002,
            return_value: 0,
            data: SyscallEventData {
                getcpu: GetcpuData {
                    cpu: 0,
                    has_cpu: false,
                    node: 0,
                    has_node: false,
                    tcache: 0x1f1b2e,
                },
            },
        }
    },
    "1002 getcpu(cpu: NULL, node: NULL, tcache: 0x1f1b2e) = 0 (success)\n"
);

syscall_test!(
    parse_capget_v3_all_caps,
    {
        SyscallEvent {
            syscall_nr: SYS_capget,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: SyscallEventData {
                capsetget: CapsetgetData {
                    header: CapUserHeader {
                        version: pinchy_common::kernel_types::LINUX_CAPABILITY_VERSION_3,
                        pid: 0,
                    },
                    data_count: 3,
                    data: [
                        CapUserData {
                            effective: 0xFFFFFFFF,
                            permitted: 0xFFFFFFFF,
                            inheritable: 0xFFFFFFFF,
                        },
                        CapUserData {
                            effective: 0x0,
                            permitted: 0x0,
                            inheritable: 0x0,
                        },
                        CapUserData {
                            effective: 0x1,
                            permitted: 0x2,
                            inheritable: 0x4,
                        },
                    ],
                },
            },
        }
    },
    "1234 capget(header: { version: 0x20080522, pid: 0 }, data: [ cap_data { effective: 0xffffffff, permitted: 0xffffffff, inheritable: 0xffffffff }, cap_data { effective: 0x0, permitted: 0x0, inheritable: 0x0 }, cap_data { effective: 0x1, permitted: 0x2, inheritable: 0x4 } ] (effective: CAP_CHOWN|CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH|CAP_FOWNER|CAP_FSETID|CAP_KILL|CAP_SETGID|CAP_SETUID|CAP_SETPCAP|CAP_LINUX_IMMUTABLE|CAP_NET_BIND_SERVICE|CAP_NET_BROADCAST|CAP_NET_ADMIN|CAP_NET_RAW|CAP_IPC_LOCK|CAP_IPC_OWNER|CAP_SYS_MODULE|CAP_SYS_RAWIO|CAP_SYS_CHROOT|CAP_SYS_PTRACE|CAP_SYS_PACCT|CAP_SYS_ADMIN|CAP_SYS_BOOT|CAP_SYS_NICE|CAP_SYS_RESOURCE|CAP_SYS_TIME|CAP_SYS_TTY_CONFIG|CAP_MKNOD|CAP_LEASE|CAP_AUDIT_WRITE|CAP_AUDIT_CONTROL|CAP_SETFCAP, permitted: CAP_CHOWN|CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH|CAP_FOWNER|CAP_FSETID|CAP_KILL|CAP_SETGID|CAP_SETUID|CAP_SETPCAP|CAP_LINUX_IMMUTABLE|CAP_NET_BIND_SERVICE|CAP_NET_BROADCAST|CAP_NET_ADMIN|CAP_NET_RAW|CAP_IPC_LOCK|CAP_IPC_OWNER|CAP_SYS_MODULE|CAP_SYS_RAWIO|CAP_SYS_CHROOT|CAP_SYS_PTRACE|CAP_SYS_PACCT|CAP_SYS_ADMIN|CAP_SYS_BOOT|CAP_SYS_NICE|CAP_SYS_RESOURCE|CAP_SYS_TIME|CAP_SYS_TTY_CONFIG|CAP_MKNOD|CAP_LEASE|CAP_AUDIT_WRITE|CAP_AUDIT_CONTROL|CAP_SETFCAP, inheritable: CAP_CHOWN|CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH|CAP_FOWNER|CAP_FSETID|CAP_KILL|CAP_SETGID|CAP_SETUID|CAP_SETPCAP|CAP_LINUX_IMMUTABLE|CAP_NET_BIND_SERVICE|CAP_NET_BROADCAST|CAP_NET_ADMIN|CAP_NET_RAW|CAP_IPC_LOCK|CAP_IPC_OWNER|CAP_SYS_MODULE|CAP_SYS_RAWIO|CAP_SYS_CHROOT|CAP_SYS_PTRACE|CAP_SYS_PACCT|CAP_SYS_ADMIN|CAP_SYS_BOOT|CAP_SYS_NICE|CAP_SYS_RESOURCE|CAP_SYS_TIME|CAP_SYS_TTY_CONFIG|CAP_MKNOD|CAP_LEASE|CAP_AUDIT_WRITE|CAP_AUDIT_CONTROL|CAP_SETFCAP) = 0 (success)\n"
);

syscall_test!(
    parse_capset_v1_some_caps,
    {
        SyscallEvent {
            syscall_nr: SYS_capset,
            pid: 4321,
            tid: 4321,
            return_value: 0,
            data: SyscallEventData {
                capsetget: CapsetgetData {
                    header: CapUserHeader {
                        version: pinchy_common::kernel_types::LINUX_CAPABILITY_VERSION_1,
                        pid: 4321,
                    },
                    data_count: 1,
                    data: [
                        CapUserData {
                            effective: 0x5,
                            permitted: 0xA,
                            inheritable: 0x0,
                        },
                        CapUserData::default(),
                        CapUserData::default(),
                    ],
                },
            },
        }
    },
    "4321 capset(header: { version: 0x19980330, pid: 4321 }, data: [ cap_data { effective: 0x5, permitted: 0xa, inheritable: 0x0 } ] (effective: CAP_CHOWN|CAP_DAC_READ_SEARCH, permitted: CAP_DAC_OVERRIDE|CAP_FOWNER, inheritable: 0) = 0 (success)\n"
);

syscall_test!(
    parse_capget_v2_none,
    {
        SyscallEvent {
            syscall_nr: SYS_capget,
            pid: 111,
            tid: 111,
            return_value: 0,
            data: SyscallEventData {
                capsetget: CapsetgetData {
                    header: CapUserHeader {
                        version: pinchy_common::kernel_types::LINUX_CAPABILITY_VERSION_2,
                        pid: 111,
                    },
                    data_count: 2,
                    data: [
                        CapUserData::default(),
                        CapUserData::default(),
                        CapUserData::default(),
                    ],
                },
            },
        }
    },
    "111 capget(header: { version: 0x20071026, pid: 111 }, data: [ cap_data { effective: 0x0, permitted: 0x0, inheritable: 0x0 }, cap_data { effective: 0x0, permitted: 0x0, inheritable: 0x0 } ] (effective: 0, permitted: 0, inheritable: 0) = 0 (success)\n"
);

syscall_test!(
    parse_setrlimit_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_setrlimit,
            pid: 100,
            tid: 100,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rlimit: pinchy_common::RlimitData {
                    resource: libc::RLIMIT_NOFILE as i32,
                    has_limit: true,
                    limit: Rlimit {
                        rlim_cur: 1024,
                        rlim_max: 4096,
                    },
                },
            },
        }
    },
    "100 setrlimit(resource: RLIMIT_NOFILE, limit: { rlim_cur: 1024, rlim_max: 4096 }) = 0 (success)\n"
);

syscall_test!(
    parse_setrlimit_null,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_setrlimit,
            pid: 101,
            tid: 101,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                rlimit: pinchy_common::RlimitData {
                    resource: libc::RLIMIT_NOFILE as i32,
                    has_limit: false,
                    limit: pinchy_common::kernel_types::Rlimit::default(),
                },
            },
        }
    },
    "101 setrlimit(resource: RLIMIT_NOFILE, limit: NULL) = -1 (error)\n"
);

syscall_test!(
    parse_getrlimit_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_getrlimit,
            pid: 200,
            tid: 200,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rlimit: pinchy_common::RlimitData {
                    resource: libc::RLIMIT_STACK as i32,
                    has_limit: true,
                    limit: Rlimit {
                        rlim_cur: 8192,
                        rlim_max: 16384,
                    },
                },
            },
        }
    },
    "200 getrlimit(resource: RLIMIT_STACK, limit: { rlim_cur: 8192, rlim_max: 16384 }) = 0 (success)\n"
);

syscall_test!(
    parse_getrlimit_error,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_getrlimit,
            pid: 201,
            tid: 201,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                rlimit: pinchy_common::RlimitData {
                    resource: libc::RLIMIT_STACK as i32,
                    has_limit: true,
                    limit: pinchy_common::kernel_types::Rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    },
                },
            },
        }
    },
    "201 getrlimit(resource: RLIMIT_STACK, limit: (content unavailable)) = -1 (error)\n"
);

syscall_test!(
    parse_getrlimit_null,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_getrlimit,
            pid: 202,
            tid: 202,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                rlimit: pinchy_common::RlimitData {
                    resource: libc::RLIMIT_STACK as i32,
                    has_limit: false,
                    limit: pinchy_common::kernel_types::Rlimit::default(),
                },
            },
        }
    },
    "202 getrlimit(resource: RLIMIT_STACK, limit: NULL) = -1 (error)\n"
);
