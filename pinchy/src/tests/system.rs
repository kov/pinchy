// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    kernel_types::{CapUserData, CapUserHeader, LandlockRuleAttrUnion, Rlimit, Utsname},
    syscalls::{
        SYS_add_key, SYS_bpf, SYS_capget, SYS_capset, SYS_clock_nanosleep, SYS_delete_module,
        SYS_finit_module, SYS_getcpu, SYS_getrandom, SYS_gettimeofday, SYS_init_module, SYS_ioctl,
        SYS_ioprio_get, SYS_ioprio_set, SYS_kexec_load, SYS_keyctl, SYS_landlock_add_rule,
        SYS_landlock_create_ruleset, SYS_landlock_restrict_self, SYS_nanosleep,
        SYS_perf_event_open, SYS_personality, SYS_reboot, SYS_request_key, SYS_restart_syscall,
        SYS_setdomainname, SYS_sethostname, SYS_settimeofday, SYS_sync, SYS_sysinfo, SYS_syslog,
        SYS_times, SYS_umask, SYS_uname, SYS_vhangup,
    },
    AddKeyData, BpfData, CapsetgetData, ClockNanosleepData, DeleteModuleData, ExitGroupData,
    FinitModuleData, GetcpuData, GetrandomData, GettimeofdayData, InitModuleData, IoctlData,
    IoprioGetData, IoprioSetData, KexecLoadData, KeyctlData, LandlockAddRuleData,
    LandlockCreateRulesetData, LandlockRestrictSelfData, NanosleepData, PerfEventOpenData,
    PersonalityData, RebootData, RequestKeyData, RestartSyscallData, RtSigreturnData,
    SetdomainnameData, SethostnameData, SettimeofdayData, SyncData, SyscallEvent, SyscallEventData,
    SysinfoData, SyslogData, TimesData, UmaskData, UnameData, VhangupData,
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

syscall_test!(
    parse_init_module_success,
    {
        let mut param_values = [0u8; pinchy_common::DATA_READ_SIZE];
        let params = b"param1=value1 param2=value2\0";
        param_values[..params.len()].copy_from_slice(params);

        SyscallEvent {
            syscall_nr: SYS_init_module,
            pid: 1000,
            tid: 1000,
            return_value: 0,
            data: SyscallEventData {
                init_module: InitModuleData {
                    module_image: 0x7f8000001000,
                    len: 65536,
                    param_values,
                },
            },
        }
    },
    "1000 init_module(module_image: 0x7f8000001000, len: 65536, param_values: \"param1=value1 param2=value2\") = 0 (success)\n"
);

syscall_test!(
    parse_init_module_error,
    {
        let param_values = [0u8; pinchy_common::DATA_READ_SIZE]; // empty params

        SyscallEvent {
            syscall_nr: SYS_init_module,
            pid: 1001,
            tid: 1001,
            return_value: -17, // EEXIST - module already exists
            data: SyscallEventData {
                init_module: InitModuleData {
                    module_image: 0x7f8000002000,
                    len: 32768,
                    param_values,
                },
            },
        }
    },
    "1001 init_module(module_image: 0x7f8000002000, len: 32768, param_values: \"\") = -17 (error)\n"
);

syscall_test!(
    parse_finit_module_success,
    {
        let mut param_values = [0u8; pinchy_common::DATA_READ_SIZE];
        let params = b"debug=1\0";
        param_values[..params.len()].copy_from_slice(params);

        SyscallEvent {
            syscall_nr: SYS_finit_module,
            pid: 2000,
            tid: 2000,
            return_value: 0,
            data: SyscallEventData {
                finit_module: FinitModuleData {
                    fd: 5,
                    param_values,
                    flags: 0,
                },
            },
        }
    },
    "2000 finit_module(fd: 5, param_values: \"debug=1\", flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_finit_module_with_flags,
    {
        let mut param_values = [0u8; pinchy_common::DATA_READ_SIZE];
        let params = b"verbose=1 force=1\0";
        param_values[..params.len()].copy_from_slice(params);

        SyscallEvent {
            syscall_nr: SYS_finit_module,
            pid: 2001,
            tid: 2001,
            return_value: 0,
            data: SyscallEventData {
                finit_module: FinitModuleData {
                    fd: 8,
                    param_values,
                    flags: libc::MODULE_INIT_IGNORE_MODVERSIONS
                        | libc::MODULE_INIT_IGNORE_VERMAGIC,
                },
            },
        }
    },
    "2001 finit_module(fd: 8, param_values: \"verbose=1 force=1\", flags: 0x3 (MODULE_INIT_IGNORE_MODVERSIONS|MODULE_INIT_IGNORE_VERMAGIC)) = 0 (success)\n"
);

syscall_test!(
    parse_finit_module_error,
    {
        let param_values = [0u8; pinchy_common::DATA_READ_SIZE]; // empty params

        SyscallEvent {
            syscall_nr: SYS_finit_module,
            pid: 2002,
            tid: 2002,
            return_value: -2, // ENOENT - no such file
            data: SyscallEventData {
                finit_module: FinitModuleData {
                    fd: -1, // bad fd
                    param_values,
                    flags: 0,
                },
            },
        }
    },
    "2002 finit_module(fd: -1, param_values: \"\", flags: 0) = -2 (error)\n"
);

syscall_test!(
    parse_delete_module_success,
    {
        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let module_name = b"test_module\0";
        name[..module_name.len()].copy_from_slice(module_name);

        SyscallEvent {
            syscall_nr: SYS_delete_module,
            pid: 3000,
            tid: 3000,
            return_value: 0,
            data: SyscallEventData {
                delete_module: DeleteModuleData { name, flags: 0 },
            },
        }
    },
    "3000 delete_module(name: \"test_module\", flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_delete_module_force,
    {
        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let module_name = b"problematic_module\0";
        name[..module_name.len()].copy_from_slice(module_name);

        SyscallEvent {
            syscall_nr: SYS_delete_module,
            pid: 3001,
            tid: 3001,
            return_value: 0,
            data: SyscallEventData {
                delete_module: DeleteModuleData {
                    name,
                    flags: libc::O_TRUNC | libc::O_NONBLOCK,
                },
            },
        }
    },
    "3001 delete_module(name: \"problematic_module\", flags: 0xa00 (O_NONBLOCK|O_TRUNC)) = 0 (success)\n"
);

syscall_test!(
    parse_delete_module_error,
    {
        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let module_name = b"nonexistent_module\0";
        name[..module_name.len()].copy_from_slice(module_name);

        SyscallEvent {
            syscall_nr: SYS_delete_module,
            pid: 3002,
            tid: 3002,
            return_value: -2, // ENOENT - module not found
            data: SyscallEventData {
                delete_module: DeleteModuleData { name, flags: 0 },
            },
        }
    },
    "3002 delete_module(name: \"nonexistent_module\", flags: 0) = -2 (error)\n"
);

syscall_test!(
    parse_sethostname_success,
    {
        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let hostname = b"myhostname\0";
        name[..hostname.len()].copy_from_slice(hostname);

        SyscallEvent {
            syscall_nr: SYS_sethostname,
            pid: 4000,
            tid: 4000,
            return_value: 0,
            data: SyscallEventData {
                sethostname: SethostnameData {
                    name,
                    len: 10, // "myhostname"
                },
            },
        }
    },
    "4000 sethostname(name: \"myhostname\", len: 10) = 0 (success)\n"
);

syscall_test!(
    parse_sethostname_error,
    {
        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let hostname = b"verylonghostname\0";
        name[..hostname.len()].copy_from_slice(hostname);

        SyscallEvent {
            syscall_nr: SYS_sethostname,
            pid: 4001,
            tid: 4001,
            return_value: -22, // EINVAL - name too long
            data: SyscallEventData {
                sethostname: SethostnameData { name, len: 16 },
            },
        }
    },
    "4001 sethostname(name: \"verylonghostname\", len: 16) = -22 (error)\n"
);

syscall_test!(
    parse_setdomainname_success,
    {
        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let domainname = b"mydomain.com\0";
        name[..domainname.len()].copy_from_slice(domainname);

        SyscallEvent {
            syscall_nr: SYS_setdomainname,
            pid: 5000,
            tid: 5000,
            return_value: 0,
            data: SyscallEventData {
                setdomainname: SetdomainnameData {
                    name,
                    len: 12, // "mydomain.com"
                },
            },
        }
    },
    "5000 setdomainname(name: \"mydomain.com\", len: 12) = 0 (success)\n"
);

syscall_test!(
    parse_setdomainname_error,
    {
        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let domainname = b"veryverylongdomainname.example.org\0";
        name[..domainname.len()].copy_from_slice(domainname);

        SyscallEvent {
            syscall_nr: SYS_setdomainname,
            pid: 5001,
            tid: 5001,
            return_value: -1, // EPERM - no permission
            data: SyscallEventData {
                setdomainname: SetdomainnameData { name, len: 34 },
            },
        }
    },
    "5001 setdomainname(name: \"veryverylongdomainname.example.org\", len: 34) = -1 (error)\n"
);

syscall_test!(
    parse_landlock_create_ruleset_success,
    {
        SyscallEvent {
            syscall_nr: SYS_landlock_create_ruleset,
            pid: 6000,
            tid: 6000,
            return_value: 3,
            data: SyscallEventData {
                landlock_create_ruleset: LandlockCreateRulesetData {
                    attr: 0xdeadbeef,
                    size: 16,
                    flags: 0,
                },
            },
        }
    },
    "6000 landlock_create_ruleset(attr: 0xdeadbeef, size: 16, flags: 0) = 3 (fd)\n"
);

syscall_test!(
    parse_landlock_create_ruleset_with_flags,
    {
        SyscallEvent {
            syscall_nr: SYS_landlock_create_ruleset,
            pid: 6001,
            tid: 6001,
            return_value: 4,
            data: SyscallEventData {
                landlock_create_ruleset: LandlockCreateRulesetData {
                    attr: 0xcafebabe,
                    size: 24,
                    flags: pinchy_common::LANDLOCK_CREATE_RULESET_VERSION,
                },
            },
        }
    },
    "6001 landlock_create_ruleset(attr: 0xcafebabe, size: 24, flags: 0x1 (LANDLOCK_CREATE_RULESET_VERSION)) = 4 (fd)\n"
);

syscall_test!(
    parse_landlock_add_rule_path_beneath,
    {
        SyscallEvent {
            syscall_nr: SYS_landlock_add_rule,
            pid: 6002,
            tid: 6002,
            return_value: 0,
            data: SyscallEventData {
                landlock_add_rule: LandlockAddRuleData {
                    ruleset_fd: 3,
                    rule_type: pinchy_common::LANDLOCK_RULE_PATH_BENEATH,
                    rule_attr: 0x7fff12345678,
                    flags: 0,
                    rule_attr_data: LandlockRuleAttrUnion {
                        path_beneath: pinchy_common::kernel_types::LandlockPathBeneathAttr {
                            allowed_access: pinchy_common::LANDLOCK_ACCESS_FS_EXECUTE
                                | pinchy_common::LANDLOCK_ACCESS_FS_WRITE_FILE
                                | pinchy_common::LANDLOCK_ACCESS_FS_READ_FILE
                                | pinchy_common::LANDLOCK_ACCESS_FS_READ_DIR
                                | pinchy_common::LANDLOCK_ACCESS_FS_REMOVE_DIR
                                | pinchy_common::LANDLOCK_ACCESS_FS_REMOVE_FILE,
                            parent_fd: 4,
                        },
                    },
                },
            },
        }
    },
    "6002 landlock_add_rule(ruleset_fd: 3, rule_type: LANDLOCK_RULE_PATH_BENEATH, parent_fd: 4, allowed_access: 0x3f (EXECUTE|WRITE_FILE|READ_FILE|READ_DIR|REMOVE_DIR|REMOVE_FILE), flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_landlock_add_rule_net_port,
    {
        SyscallEvent {
            syscall_nr: SYS_landlock_add_rule,
            pid: 6003,
            tid: 6003,
            return_value: 0,
            data: SyscallEventData {
                landlock_add_rule: LandlockAddRuleData {
                    ruleset_fd: 4,
                    rule_type: pinchy_common::LANDLOCK_RULE_NET_PORT,
                    rule_attr: 0x7fff87654321,
                    flags: 0,
                    rule_attr_data: LandlockRuleAttrUnion {
                        net_port: pinchy_common::kernel_types::LandlockNetPortAttr {
                            allowed_access: pinchy_common::LANDLOCK_ACCESS_NET_BIND_TCP
                                | pinchy_common::LANDLOCK_ACCESS_NET_CONNECT_TCP,
                            port: 8080,
                        },
                    },
                },
            },
        }
    },
    "6003 landlock_add_rule(ruleset_fd: 4, rule_type: LANDLOCK_RULE_NET_PORT, port: 8080, access_rights: 0x3 (BIND_TCP|CONNECT_TCP), flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_landlock_add_rule_error,
    {
        SyscallEvent {
            syscall_nr: SYS_landlock_add_rule,
            pid: 6004,
            tid: 6004,
            return_value: -9, // EBADF - bad file descriptor
            data: SyscallEventData {
                landlock_add_rule: LandlockAddRuleData {
                    ruleset_fd: 999,
                    rule_type: pinchy_common::LANDLOCK_RULE_PATH_BENEATH,
                    rule_attr: 0,
                    flags: 0,
                    rule_attr_data: LandlockRuleAttrUnion {
                        path_beneath: pinchy_common::kernel_types::LandlockPathBeneathAttr::default(),
                    },
                },
            },
        }
    },
    "6004 landlock_add_rule(ruleset_fd: 999, rule_type: LANDLOCK_RULE_PATH_BENEATH, parent_fd: 0, allowed_access: 0, flags: 0) = -9 (error)\n"
);

syscall_test!(
    parse_landlock_restrict_self_success,
    {
        SyscallEvent {
            syscall_nr: SYS_landlock_restrict_self,
            pid: 6005,
            tid: 6005,
            return_value: 0,
            data: SyscallEventData {
                landlock_restrict_self: LandlockRestrictSelfData {
                    ruleset_fd: 3,
                    flags: 0,
                },
            },
        }
    },
    "6005 landlock_restrict_self(ruleset_fd: 3, flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_landlock_restrict_self_error,
    {
        SyscallEvent {
            syscall_nr: SYS_landlock_restrict_self,
            pid: 6006,
            tid: 6006,
            return_value: -22, // EINVAL - invalid argument
            data: SyscallEventData {
                landlock_restrict_self: LandlockRestrictSelfData {
                    ruleset_fd: -1,
                    flags: 0,
                },
            },
        }
    },
    "6006 landlock_restrict_self(ruleset_fd: -1, flags: 0) = -22 (error)\n"
);
syscall_test!(
    parse_add_key_user_type,
    {
        let mut key_type_buf = [0u8; pinchy_common::SMALLISH_READ_SIZE];
        let mut desc_buf = [0u8; pinchy_common::LARGER_READ_SIZE];
        let mut payload_buf = [0u8; pinchy_common::MEDIUM_READ_SIZE];

        let key_type = b"user\0";
        let description = b"my_secret_key\0";
        let payload_data = b"super_secret_data";
        let payload = b"super_secret_data\0";

        key_type_buf[..key_type.len()].copy_from_slice(key_type);
        desc_buf[..description.len()].copy_from_slice(description);
        payload_buf[..payload.len()].copy_from_slice(payload);

        SyscallEvent {
            syscall_nr: SYS_add_key,
            pid: 7000,
            tid: 7000,
            return_value: 512000001,
            data: SyscallEventData {
                add_key: AddKeyData {
                    key_type: key_type_buf,
                    description: desc_buf,
                    payload: payload_buf,
                    payload_len: payload_data.len(),
                    keyring: libc::KEY_SPEC_SESSION_KEYRING,
                },
            },
        }
    },
    "7000 add_key(type: \"user\", description: \"my_secret_key\", payload: \"super_secret_data\", keyring: KEY_SPEC_SESSION_KEYRING) = 512000001\n"
);

syscall_test!(
    parse_add_key_empty_payload,
    {
        let mut key_type_buf = [0u8; pinchy_common::SMALLISH_READ_SIZE];
        let mut desc_buf = [0u8; pinchy_common::LARGER_READ_SIZE];
        let payload_buf = [0u8; pinchy_common::MEDIUM_READ_SIZE];

        let key_type = b"keyring\0";
        let description = b"temp_keyring\0";

        key_type_buf[..key_type.len()].copy_from_slice(key_type);
        desc_buf[..description.len()].copy_from_slice(description);

        SyscallEvent {
            syscall_nr: SYS_add_key,
            pid: 7001,
            tid: 7001,
            return_value: 512000002,
            data: SyscallEventData {
                add_key: AddKeyData {
                    key_type: key_type_buf,
                    description: desc_buf,
                    payload: payload_buf,
                    payload_len: 0,
                    keyring: libc::KEY_SPEC_PROCESS_KEYRING,
                },
            },
        }
    },
    "7001 add_key(type: \"keyring\", description: \"temp_keyring\", payload: (empty), keyring: KEY_SPEC_PROCESS_KEYRING) = 512000002\n"
);

syscall_test!(
    parse_add_key_error,
    {
        let mut key_type_buf = [0u8; pinchy_common::SMALLISH_READ_SIZE];
        let desc_buf = [0u8; pinchy_common::LARGER_READ_SIZE];
        let payload_buf = [0u8; pinchy_common::MEDIUM_READ_SIZE];

        let key_type = b"unknown\0";
        key_type_buf[..key_type.len()].copy_from_slice(key_type);

        SyscallEvent {
            syscall_nr: SYS_add_key,
            pid: 7002,
            tid: 7002,
            return_value: -22, // EINVAL
            data: SyscallEventData {
                add_key: AddKeyData {
                    key_type: key_type_buf,
                    description: desc_buf,
                    payload: payload_buf,
                    payload_len: 0,
                    keyring: libc::KEY_SPEC_THREAD_KEYRING,
                },
            },
        }
    },
    "7002 add_key(type: \"unknown\", description: \"\", payload: (empty), keyring: KEY_SPEC_THREAD_KEYRING) = -22 (error)\n"
);

syscall_test!(
    parse_request_key_success,
    {
        let mut key_type_buf = [0u8; pinchy_common::SMALLISH_READ_SIZE];
        let mut desc_buf = [0u8; pinchy_common::LARGER_READ_SIZE];
        let mut info_buf = [0u8; pinchy_common::MEDIUM_READ_SIZE];

        let key_type = b"user\0";
        let description = b"api_token\0";
        let callout_info = b"service:web\0";

        key_type_buf[..key_type.len()].copy_from_slice(key_type);
        desc_buf[..description.len()].copy_from_slice(description);
        info_buf[..callout_info.len()].copy_from_slice(callout_info);

        SyscallEvent {
            syscall_nr: SYS_request_key,
            pid: 7010,
            tid: 7010,
            return_value: 512000010,
            data: SyscallEventData {
                request_key: RequestKeyData {
                    key_type: key_type_buf,
                    description: desc_buf,
                    callout_info: info_buf,
                    callout_info_len: callout_info.len(),
                    dest_keyring: libc::KEY_SPEC_SESSION_KEYRING,
                },
            },
        }
    },
    "7010 request_key(type: \"user\", description: \"api_token\", callout_info: \"service:web\", dest_keyring: KEY_SPEC_SESSION_KEYRING) = 512000010\n"
);

syscall_test!(
    parse_request_key_no_callout,
    {
        let mut key_type_buf = [0u8; pinchy_common::SMALLISH_READ_SIZE];
        let mut desc_buf = [0u8; pinchy_common::LARGER_READ_SIZE];
        let info_buf = [0u8; pinchy_common::MEDIUM_READ_SIZE];

        let key_type = b"user\0";
        let description = b"password\0";

        key_type_buf[..key_type.len()].copy_from_slice(key_type);
        desc_buf[..description.len()].copy_from_slice(description);

        SyscallEvent {
            syscall_nr: SYS_request_key,
            pid: 7011,
            tid: 7011,
            return_value: 512000011,
            data: SyscallEventData {
                request_key: RequestKeyData {
                    key_type: key_type_buf,
                    description: desc_buf,
                    callout_info: info_buf,
                    callout_info_len: 0,
                    dest_keyring: 0,
                },
            },
        }
    },
    "7011 request_key(type: \"user\", description: \"password\", callout_info: (null), dest_keyring: 0) = 512000011\n"
);

syscall_test!(
    parse_keyctl_get_keyring_id,
    {
        SyscallEvent {
            syscall_nr: SYS_keyctl,
            pid: 7020,
            tid: 7020,
            return_value: 512000020,
            data: SyscallEventData {
                keyctl: KeyctlData {
                    operation: libc::KEYCTL_GET_KEYRING_ID as i32,
                    arg1: libc::KEY_SPEC_SESSION_KEYRING as u64,
                    arg2: 0,
                    arg3: 0,
                    arg4: 0,
                },
            },
        }
    },
    "7020 keyctl(operation: GET_KEYRING_ID, keyring: KEY_SPEC_SESSION_KEYRING, create: 0x0) = 512000020 (key)\n"
);

syscall_test!(
    parse_keyctl_update,
    {
        SyscallEvent {
            syscall_nr: SYS_keyctl,
            pid: 7021,
            tid: 7021,
            return_value: 0,
            data: SyscallEventData {
                keyctl: KeyctlData {
                    operation: libc::KEYCTL_UPDATE as i32,
                    arg1: 512000001, // key_id
                    arg2: 0xdeadbeef, // payload pointer
                    arg3: 32,        // size
                    arg4: 0,
                },
            },
        }
    },
    "7021 keyctl(operation: UPDATE, key: 512000001, payload: 0xdeadbeef, length: 0x20) = 0 (success)\n"
);

syscall_test!(
    parse_keyctl_revoke,
    {
        SyscallEvent {
            syscall_nr: SYS_keyctl,
            pid: 7022,
            tid: 7022,
            return_value: 0,
            data: SyscallEventData {
                keyctl: KeyctlData {
                    operation: libc::KEYCTL_REVOKE as i32,
                    arg1: 512000001,
                    arg2: 0,
                    arg3: 0,
                    arg4: 0,
                },
            },
        }
    },
    "7022 keyctl(operation: REVOKE, key: 512000001) = 0 (success)\n"
);

syscall_test!(
    parse_keyctl_search,
    {
        SyscallEvent {
            syscall_nr: SYS_keyctl,
            pid: 7023,
            tid: 7023,
            return_value: 512000023,
            data: SyscallEventData {
                keyctl: KeyctlData {
                    operation: libc::KEYCTL_SEARCH as i32,
                    arg1: libc::KEY_SPEC_SESSION_KEYRING as u64,
                    arg2: 0xaabbccdd,
                    arg3: 0xddeeffaa,
                    arg4: libc::KEY_SPEC_PROCESS_KEYRING as u64,
                },
            },
        }
    },
    "7023 keyctl(operation: SEARCH, keyring: KEY_SPEC_SESSION_KEYRING, type: 0xaabbccdd, description: 0xddeeffaa, dest_keyring: KEY_SPEC_PROCESS_KEYRING) = 512000023 (key)\n"
);

// Import constants from format_helpers
use crate::format_helpers::{bpf_constants, perf_constants};

syscall_test!(
    parse_perf_event_open_success,
    {
        SyscallEvent {
            syscall_nr: SYS_perf_event_open,
            pid: 8000,
            tid: 8000,
            return_value: 3,
            data: SyscallEventData {
                perf_event_open: PerfEventOpenData {
                    attr: pinchy_common::kernel_types::PerfEventAttr {
                        type_: 0, // PERF_TYPE_HARDWARE
                        config: 0,
                        sample_period: 4000,
                        ..Default::default()
                    },
                    pid: 1234,
                    cpu: 0,
                    group_fd: -1,
                    flags: 0,
                },
            },
        }
    },
    "8000 perf_event_open(attr: { type: PERF_TYPE_HARDWARE, size: 0, config: 0x0, sample_period: 4000 }, pid: 1234, cpu: 0, group_fd: -1, flags: 0) = 3 (fd)\n"
);

syscall_test!(
    parse_perf_event_open_with_flags,
    {
        SyscallEvent {
            syscall_nr: SYS_perf_event_open,
            pid: 8001,
            tid: 8001,
            return_value: 4,
            data: SyscallEventData {
                perf_event_open: PerfEventOpenData {
                    attr: pinchy_common::kernel_types::PerfEventAttr {
                        type_: 1, // PERF_TYPE_SOFTWARE
                        config: 0x9, // PERF_COUNT_SW_CPU_CLOCK
                        sample_period: 1000000,
                        ..Default::default()
                    },
                    pid: -1,
                    cpu: 2,
                    group_fd: 3,
                    flags: perf_constants::PERF_FLAG_FD_CLOEXEC
                        | perf_constants::PERF_FLAG_FD_NO_GROUP,
                },
            },
        }
    },
    "8001 perf_event_open(attr: { type: PERF_TYPE_SOFTWARE, size: 0, config: 0x9, sample_period: 1000000 }, pid: -1, cpu: 2, group_fd: 3, flags: 0x9 (FD_NO_GROUP|FD_CLOEXEC)) = 4 (fd)\n"
);

syscall_test!(
    parse_perf_event_open_error,
    {
        SyscallEvent {
            syscall_nr: SYS_perf_event_open,
            pid: 8002,
            tid: 8002,
            return_value: -22,
            data: SyscallEventData {
                perf_event_open: PerfEventOpenData {
                    attr: Default::default(),
                    pid: 0,
                    cpu: -1,
                    group_fd: -1,
                    flags: 0,
                },
            },
        }
    },
    "8002 perf_event_open(attr: { type: PERF_TYPE_HARDWARE, size: 0, config: 0x0, sample_period: 0 }, pid: 0, cpu: -1, group_fd: -1, flags: 0) = -22 (error)\n"
);

syscall_test!(
    parse_bpf_map_create,
    {
        SyscallEvent {
            syscall_nr: SYS_bpf,
            pid: 8100,
            tid: 8100,
            return_value: 3,
            data: SyscallEventData {
                bpf: BpfData {
                    cmd: bpf_constants::BPF_MAP_CREATE,
                    size: 72,
                    which_attr: 1,
                    map_create_attr: pinchy_common::kernel_types::BpfMapCreateAttr {
                        map_type: 1, // BPF_MAP_TYPE_HASH
                        key_size: 4,
                        value_size: 8,
                        max_entries: 1024,
                        ..Default::default()
                    },
                    prog_load_attr: Default::default(),
                },
            },
        }
    },
    "8100 bpf(cmd: BPF_MAP_CREATE, attr: { map_type: BPF_MAP_TYPE_HASH, key_size: 4, value_size: 8, max_entries: 1024 }, size: 72) = 3 (fd)\n"
);

syscall_test!(
    parse_bpf_prog_load,
    {
        SyscallEvent {
            syscall_nr: SYS_bpf,
            pid: 8101,
            tid: 8101,
            return_value: 4,
            data: SyscallEventData {
                bpf: BpfData {
                    cmd: bpf_constants::BPF_PROG_LOAD,
                    size: 128,
                    which_attr: 2,
                    map_create_attr: Default::default(),
                    prog_load_attr: pinchy_common::kernel_types::BpfProgLoadAttr {
                        prog_type: 1, // BPF_PROG_TYPE_SOCKET_FILTER
                        insn_cnt: 10,
                        license: {
                            let mut arr = [0u8; 32];
                            arr[0] = b'G';
                            arr[1] = b'P';
                            arr[2] = b'L';
                            arr
                        },
                    },
                },
            },
        }
    },
    "8101 bpf(cmd: BPF_PROG_LOAD, attr: { prog_type: BPF_PROG_TYPE_SOCKET_FILTER, insn_cnt: 10, license: \"GPL\" }, size: 128) = 4 (fd)\n"
);

syscall_test!(
    parse_bpf_error,
    {
        SyscallEvent {
            syscall_nr: SYS_bpf,
            pid: 8102,
            tid: 8102,
            return_value: -1,
            data: SyscallEventData {
                bpf: BpfData {
                    cmd: bpf_constants::BPF_PROG_LOAD,
                    size: 0,
                    which_attr: 0,
                    map_create_attr: Default::default(),
                    prog_load_attr: Default::default(),
                },
            },
        }
    },
    "8102 bpf(cmd: BPF_PROG_LOAD, size: 0) = -1 (error)\n"
);

syscall_test!(
    parse_syslog_read_all,
    {
        SyscallEvent {
            syscall_nr: SYS_syslog,
            pid: 9100,
            tid: 9100,
            return_value: 4096,
            data: SyscallEventData {
                syslog: SyslogData {
                    type_: crate::format_helpers::syslog_constants::SYSLOG_ACTION_READ_ALL,
                    bufp: 0x7fff12345678,
                    size: 8192,
                },
            },
        }
    },
    "9100 syslog(type: SYSLOG_ACTION_READ_ALL, bufp: 0x7fff12345678, size: 8192) = 4096\n"
);

syscall_test!(
    parse_syslog_size_buffer,
    {
        SyscallEvent {
            syscall_nr: SYS_syslog,
            pid: 9101,
            tid: 9101,
            return_value: 262144,
            data: SyscallEventData {
                syslog: SyslogData {
                    type_: crate::format_helpers::syslog_constants::SYSLOG_ACTION_SIZE_BUFFER,
                    bufp: 0,
                    size: 0,
                },
            },
        }
    },
    "9101 syslog(type: SYSLOG_ACTION_SIZE_BUFFER, bufp: 0x0, size: 0) = 262144\n"
);

syscall_test!(
    parse_syslog_error,
    {
        SyscallEvent {
            syscall_nr: SYS_syslog,
            pid: 9102,
            tid: 9102,
            return_value: -1,
            data: SyscallEventData {
                syslog: SyslogData {
                    type_: crate::format_helpers::syslog_constants::SYSLOG_ACTION_READ,
                    bufp: 0,
                    size: 0,
                },
            },
        }
    },
    "9102 syslog(type: SYSLOG_ACTION_READ, bufp: 0x0, size: 0) = -1 (error)\n"
);

syscall_test!(
    parse_restart_syscall,
    {
        SyscallEvent {
            syscall_nr: SYS_restart_syscall,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: SyscallEventData {
                restart_syscall: RestartSyscallData::default(),
            },
        }
    },
    "123 restart_syscall() = 0 (success)\n"
);

syscall_test!(
    parse_kexec_load_basic,
    {
        SyscallEvent {
            syscall_nr: SYS_kexec_load,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: SyscallEventData {
                kexec_load: KexecLoadData {
                    entry: 0x80000000,
                    nr_segments: 4,
                    segments: 0x7fff0000,
                    flags: 0,
                    segments_read: 0,
                    parsed_segments: Default::default(),
                },
            },
        }
    },
    "123 kexec_load(entry: 0x80000000, nr_segments: 4, segments: 0x7fff0000, flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_kexec_load_on_crash,
    {
        SyscallEvent {
            syscall_nr: SYS_kexec_load,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: SyscallEventData {
                kexec_load: KexecLoadData {
                    entry: 0x80000000,
                    nr_segments: 2,
                    segments: 0x7fff0000,
                    flags: crate::format_helpers::kexec_constants::KEXEC_ON_CRASH,
                    segments_read: 0,
                    parsed_segments: Default::default(),
                },
            },
        }
    },
    "123 kexec_load(entry: 0x80000000, nr_segments: 2, segments: 0x7fff0000, flags: 0x1 (KEXEC_ON_CRASH)) = 0 (success)\n"
);

syscall_test!(
    parse_kexec_load_with_arch,
    {
        SyscallEvent {
            syscall_nr: SYS_kexec_load,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: SyscallEventData {
                kexec_load: KexecLoadData {
                    entry: 0x80000000,
                    nr_segments: 3,
                    segments: 0x7fff0000,
                    flags: crate::format_helpers::kexec_constants::KEXEC_ON_CRASH
                        | crate::format_helpers::kexec_constants::KEXEC_ARCH_X86_64,
                    segments_read: 0,
                    parsed_segments: Default::default(),
                },
            },
        }
    },
    "123 kexec_load(entry: 0x80000000, nr_segments: 3, segments: 0x7fff0000, flags: 0x3e0001 (KEXEC_ON_CRASH|KEXEC_ARCH_X86_64)) = 0 (success)\n"
);

syscall_test!(
    parse_kexec_load_with_segments,
    {
        use pinchy_common::kernel_types::KexecSegment;

        let mut parsed_segments = [KexecSegment::default(); 16];
        parsed_segments[0] = KexecSegment {
            buf: 0x1000,
            bufsz: 4096,
            mem: 0x100000,
            memsz: 4096,
        };
        parsed_segments[1] = KexecSegment {
            buf: 0x2000,
            bufsz: 8192,
            mem: 0x200000,
            memsz: 8192,
        };

        SyscallEvent {
            syscall_nr: SYS_kexec_load,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: SyscallEventData {
                kexec_load: KexecLoadData {
                    entry: 0x80000000,
                    nr_segments: 2,
                    segments: 0x7fff0000,
                    flags: 0,
                    segments_read: 2,
                    parsed_segments,
                },
            },
        }
    },
    "123 kexec_load(entry: 0x80000000, nr_segments: 2, segments: [{buf: 0x1000, bufsz: 4096, mem: 0x100000, memsz: 4096}, {buf: 0x2000, bufsz: 8192, mem: 0x200000, memsz: 8192}], flags: 0) = 0 (success)\n"
);
