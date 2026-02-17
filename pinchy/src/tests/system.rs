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
    SetdomainnameData, SethostnameData, SettimeofdayData, SyncData, SysinfoData, SyslogData,
    TimesData, UmaskData, UnameData, VhangupData,
};

use crate::syscall_test;

syscall_test!(
    parse_rt_sigreturn,
    {
        let data = RtSigreturnData {};

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_rt_sigreturn,
            123,
            0,
            &data,
        )
    },
    "123 rt_sigreturn() = 0\n"
);

syscall_test!(
    reboot_restart_success,
    {
        let data = RebootData {
                    magic1: libc::LINUX_REBOOT_MAGIC1,
                    magic2: libc::LINUX_REBOOT_MAGIC2,
                    cmd: libc::LINUX_REBOOT_CMD_RESTART,
                    arg: 0,
                    has_restart2: false,
                    restart2: [0; pinchy_common::DATA_READ_SIZE],
                };

        crate::tests::make_compact_test_data(SYS_reboot, 999, 0, &data)
    },
    "999 reboot(magic1: 0xfee1dead (LINUX_REBOOT_MAGIC1), magic2: 0x28121969 (LINUX_REBOOT_MAGIC2), cmd: LINUX_REBOOT_CMD_RESTART (19088743), arg: 0x0) = 0 (success)\n"
);

syscall_test!(
    reboot_restart2_with_string,
    {

        let mut buf = [0u8; pinchy_common::DATA_READ_SIZE];
        let s = b"firmware";
        buf[..s.len()].copy_from_slice(s);

        let data = RebootData {
                    magic1: libc::LINUX_REBOOT_MAGIC1,
                    magic2: libc::LINUX_REBOOT_MAGIC2,
                    cmd: libc::LINUX_REBOOT_CMD_RESTART2,
                    arg: 0xdeadbeef,
                    has_restart2: true,
                    restart2: buf,
                };

        crate::tests::make_compact_test_data(SYS_reboot, 777, 0, &data)
    },
    "777 reboot(magic1: 0xfee1dead (LINUX_REBOOT_MAGIC1), magic2: 0x28121969 (LINUX_REBOOT_MAGIC2), cmd: LINUX_REBOOT_CMD_RESTART2 (-1582119980), arg: 0xdeadbeef, restart2: \"firmware\") = 0 (success)\n"
);

syscall_test!(
    reboot_error,
    {
        let data = RebootData {
                    magic1: libc::LINUX_REBOOT_MAGIC1,
                    magic2: libc::LINUX_REBOOT_MAGIC2,
                    cmd: libc::LINUX_REBOOT_CMD_HALT,
                    arg: 0,
                    has_restart2: false,
                    restart2: [0; pinchy_common::DATA_READ_SIZE],
                };

        crate::tests::make_compact_test_data(SYS_reboot, 42, -22, &data)
    },
    "42 reboot(magic1: 0xfee1dead (LINUX_REBOOT_MAGIC1), magic2: 0x28121969 (LINUX_REBOOT_MAGIC2), cmd: LINUX_REBOOT_CMD_HALT (-839974621), arg: 0x0) = -22 (error)\n"
);

syscall_test!(
    parse_ioctl,
    {
        let data = IoctlData {
            fd: 4,
            request: 0x4332,
            arg: 0x0,
        };

        crate::tests::make_compact_test_data(SYS_ioctl, 22, 0, &data)
    },
    "22 ioctl(fd: 4, request: (0x4332) SNDRV_COMPRESS_START::sound, arg: 0x0) = 0 (success)\n"
);

syscall_test!(
    parse_getrandom_success,
    {
        let data = GetrandomData {
            buf: 0x7f5678901000,
            buflen: 32,
            flags: 0,
        };

        crate::tests::make_compact_test_data(SYS_getrandom, 555, 32, &data)
    },
    "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x0) = 32\n"
);

syscall_test!(
    parse_getrandom_grnd_random,
    {
        let data = GetrandomData {
            buf: 0x7f5678901000,
            buflen: 32,
            flags: libc::GRND_RANDOM,
        };

        crate::tests::make_compact_test_data(SYS_getrandom, 555, 32, &data)
    },
    "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x2 (GRND_RANDOM)) = 32\n"
);

syscall_test!(
    parse_getrandom_grnd_nonblock,
    {
        let data = GetrandomData {
            buf: 0x7f5678901000,
            buflen: 32,
            flags: libc::GRND_NONBLOCK,
        };

        crate::tests::make_compact_test_data(SYS_getrandom, 555, 32, &data)
    },
    "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x1 (GRND_NONBLOCK)) = 32\n"
);

syscall_test!(
    parse_getrandom_combined_flags,
    {
        let data = GetrandomData {
            buf: 0x7f5678901000,
            buflen: 32,
            flags: libc::GRND_RANDOM | libc::GRND_NONBLOCK,
        };

        crate::tests::make_compact_test_data(SYS_getrandom, 555, 32, &data)
    },
    "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x3 (GRND_NONBLOCK|GRND_RANDOM)) = 32\n"
);

syscall_test!(
    parse_getrandom_error,
    {
        let data = GetrandomData {
                    buf: 0x7f5678901000,
                    buflen: 32,
                    flags: libc::GRND_RANDOM|libc::GRND_NONBLOCK,
                };

        crate::tests::make_compact_test_data(SYS_getrandom, 555, -11, &data)
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

        let data = UnameData { utsname };

        crate::tests::make_compact_test_data(SYS_uname, 1234, 0, &data)
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

        let data = UnameData { utsname };

        crate::tests::make_compact_test_data(SYS_uname, 1234, 0, &data)
    },
    "1234 uname(struct utsname: { sysname: \"Linux\", nodename: \"jabuticaba\", release: \"6.15.4-200.fc42.aarch64\", version: \"#1 SMP PREEMPT_DYNAMIC Fri Jun 27 15:55:20 UTC 2025 aarch64 GNU/L ... (truncated)\", machine: \"aarch64\", domainname: \"(none)\" }) = 0 (success)\n"
);

syscall_test!(
    parse_exit_group,
    {
        let data = ExitGroupData { status: 42 };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_exit_group, 123, 0, &data)
    },
    "123 exit_group(status: 42) = 0 (success)\n"
);

syscall_test!(
    test_sync,
    {
        let data = SyncData;

        crate::tests::make_compact_test_data(SYS_sync, 123, 0, &data)
    },
    "123 sync() = 0 (success)\n"
);

syscall_test!(
    test_umask,
    {
        let data = UmaskData { mask: 0o027 };

        crate::tests::make_compact_test_data(SYS_umask, 123, 0o022, &data)
    },
    "123 umask(mask: 0o27) = 18\n"
);

syscall_test!(
    test_vhangup,
    {
        let data = VhangupData;

        crate::tests::make_compact_test_data(SYS_vhangup, 123, 0, &data)
    },
    "123 vhangup() = 0 (success)\n"
);

syscall_test!(
    test_ioprio_get,
    {
        let data = IoprioGetData { which: 1, who: 0 };

        crate::tests::make_compact_test_data(SYS_ioprio_get, 123, 4, &data)
    },
    "123 ioprio_get(which: 1, who: 0) = 4\n"
);

syscall_test!(
    test_ioprio_set,
    {
        let data = IoprioSetData {
            which: 1,
            who: 0,
            ioprio: 4,
        };

        crate::tests::make_compact_test_data(SYS_ioprio_set, 123, 0, &data)
    },
    "123 ioprio_set(which: 1, who: 0, ioprio: 4) = 0 (success)\n"
);

syscall_test!(
    test_personality,
    {
        let data = PersonalityData { persona: 0x200 };

        crate::tests::make_compact_test_data(SYS_personality, 1001, 0, &data)
    },
    "1001 personality(persona: 0x200) = 0 (success)\n"
);

syscall_test!(
    test_sysinfo,
    {

        use pinchy_common::kernel_types::Sysinfo;

        let data = SysinfoData {
                    info: Sysinfo {
                        uptime: 3600,
                        loads: [1024, 2048, 3072],
                        totalram: 16777216,
                        freeram: 8388608,
                        sharedram: 1048576,
                        bufferram: 524288,
                        totalswap: 4194304,
                        freeswap: 4194304,
                        procs: 150,
                        totalhigh: 0,
                        freehigh: 0,
                        mem_unit: 1024,
                    },
                    has_info: true,
                };

        crate::tests::make_compact_test_data(SYS_sysinfo, 1001, 0, &data)
    },
    "1001 sysinfo(info: { uptime: 3600 seconds, loads: [1024, 2048, 3072], totalram: 16384 MB, freeram: 8192 MB, sharedram: 1024 MB, bufferram: 512 MB, totalswap: 4096 MB, freeswap: 4096 MB, procs: 150, mem_unit: 1024 bytes }) = 0 (success)\n"
);

syscall_test!(
    test_times,
    {

        use pinchy_common::kernel_types::Tms;

        let data = TimesData {
                    buf: Tms {
                        tms_utime: 1234,
                        tms_stime: 5678,
                        tms_cutime: 100,
                        tms_cstime: 200,
                    },
                    has_buf: true,
                };

        crate::tests::make_compact_test_data(SYS_times, 1001, 123456, &data)
    },
    "1001 times(buf: { tms_utime: 1234 ticks, tms_stime: 5678 ticks, tms_cutime: 100 ticks, tms_cstime: 200 ticks }) = 123456\n"
);

syscall_test!(
    test_gettimeofday,
    {

        use pinchy_common::kernel_types::{Timeval, Timezone};

        let data = GettimeofdayData {
                    tv: Timeval {
                        tv_sec: 1672531200,
                        tv_usec: 123456,
                    },
                    tz: Timezone {
                        tz_minuteswest: 480,
                        tz_dsttime: 0,
                    },
                    has_tv: true,
                    has_tz: true,
                };

        crate::tests::make_compact_test_data(SYS_gettimeofday, 1001, 0, &data)
    },
    "1001 gettimeofday(tv: { tv_sec: 1672531200, tv_usec: 123456 }, tz: { tz_minuteswest: 480, tz_dsttime: 0 }) = 0 (success)\n"
);

syscall_test!(
    test_settimeofday,
    {
        use pinchy_common::kernel_types::{Timeval, Timezone};

        let data = SettimeofdayData {
            tv: Timeval {
                tv_sec: 1672531200,
                tv_usec: 123456,
            },
            tz: Timezone::default(),
            has_tv: true,
            has_tz: false,
        };

        crate::tests::make_compact_test_data(SYS_settimeofday, 1001, 0, &data)
    },
    "1001 settimeofday(tv: { tv_sec: 1672531200, tv_usec: 123456 }, tz: NULL) = 0 (success)\n"
);

syscall_test!(
    parse_setfsuid,
    {
        let data = pinchy_common::SetfsuidData { uid: 1001 };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_setfsuid,
            1234,
            1000,
            &data,
        )
    },
    "1234 setfsuid(uid: 1001) = 1000\n"
);

syscall_test!(
    parse_setfsuid_root,
    {
        let data = pinchy_common::SetfsuidData { uid: 0 };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_setfsuid,
            5678,
            1001,
            &data,
        )
    },
    "5678 setfsuid(uid: 0) = 1001\n"
);

syscall_test!(
    parse_setfsgid,
    {
        let data = pinchy_common::SetfsgidData { gid: 1001 };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_setfsgid,
            2468,
            1000,
            &data,
        )
    },
    "2468 setfsgid(gid: 1001) = 1000\n"
);

syscall_test!(
    parse_setfsgid_root,
    {
        let data = pinchy_common::SetfsgidData { gid: 0 };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_setfsgid,
            9999,
            1001,
            &data,
        )
    },
    "9999 setfsgid(gid: 0) = 1001\n"
);

syscall_test!(
    test_nanosleep_success,
    {
        use pinchy_common::kernel_types::Timespec;

        let data = NanosleepData {
            req: Timespec {
                seconds: 2,
                nanos: 500_000_000,
            },
            rem: Timespec::default(),
            has_rem: false,
        };

        crate::tests::make_compact_test_data(SYS_nanosleep, 1234, 0, &data)
    },
    "1234 nanosleep(req: { secs: 2, nanos: 500000000 }, rem: NULL) = 0 (success)\n"
);

syscall_test!(
    test_nanosleep_interrupted,
    {

        use pinchy_common::kernel_types::Timespec;

        let data = NanosleepData {
                    req: Timespec {
                        seconds: 10,
                        nanos: 0,
                    },
                    rem: Timespec {
                        seconds: 7,
                        nanos: 250_000_000,
                    },
                    has_rem: true,
                };

        crate::tests::make_compact_test_data(SYS_nanosleep, 5678, -4, &data)
    },
    "5678 nanosleep(req: { secs: 10, nanos: 0 }, rem: { secs: 7, nanos: 250000000 }) = -4 (error)\n"
);

syscall_test!(
    test_nanosleep_zero_time,
    {
        use pinchy_common::kernel_types::Timespec;

        let data = NanosleepData {
            req: Timespec {
                seconds: 0,
                nanos: 0,
            },
            rem: Timespec::default(),
            has_rem: false,
        };

        crate::tests::make_compact_test_data(SYS_nanosleep, 9999, 0, &data)
    },
    "9999 nanosleep(req: { secs: 0, nanos: 0 }, rem: NULL) = 0 (success)\n"
);

syscall_test!(
    test_clock_nanosleep_realtime_success,
    {

        use pinchy_common::kernel_types::Timespec;

        let data = ClockNanosleepData {
                    clockid: libc::CLOCK_REALTIME,
                    flags: 0,
                    req: Timespec {
                        seconds: 2,
                        nanos: 500_000_000,
                    },
                    rem: Timespec::default(),
                    has_rem: false,
                };

        crate::tests::make_compact_test_data(SYS_clock_nanosleep, 1234, 0, &data)
    },
    "1234 clock_nanosleep(clockid: CLOCK_REALTIME, flags: 0, req: { secs: 2, nanos: 500000000 }, rem: NULL) = 0 (success)\n"
);

syscall_test!(
    test_clock_nanosleep_monotonic_interrupted,
    {

        use pinchy_common::kernel_types::Timespec;

        let data = ClockNanosleepData {
                    clockid: libc::CLOCK_MONOTONIC,
                    flags: 0,
                    req: Timespec {
                        seconds: 10,
                        nanos: 0,
                    },
                    rem: Timespec {
                        seconds: 7,
                        nanos: 250_000_000,
                    },
                    has_rem: true,
                };

        crate::tests::make_compact_test_data(SYS_clock_nanosleep, 5678, -4, &data)
    },
    "5678 clock_nanosleep(clockid: CLOCK_MONOTONIC, flags: 0, req: { secs: 10, nanos: 0 }, rem: { secs: 7, nanos: 250000000 }) = -4 (error)\n"
);

syscall_test!(
    test_clock_nanosleep_absolute_time,
    {

        use pinchy_common::kernel_types::Timespec;

        let data = ClockNanosleepData {
                    clockid: libc::CLOCK_REALTIME,
                    flags: libc::TIMER_ABSTIME,
                    req: Timespec {
                        seconds: 1_700_000_000,
                        nanos: 123_456_789,
                    },
                    rem: Timespec::default(),
                    has_rem: false,
                };

        crate::tests::make_compact_test_data(SYS_clock_nanosleep, 9999, 0, &data)
    },
    "9999 clock_nanosleep(clockid: CLOCK_REALTIME, flags: TIMER_ABSTIME, req: { secs: 1700000000, nanos: 123456789 }, rem: NULL) = 0 (success)\n"
);

syscall_test!(
    parse_getcpu_all,
    {
        let data = GetcpuData {
            cpu: 11,
            has_cpu: true,
            node: 5,
            has_node: true,
            tcache: 0xdeadbeef,
        };

        crate::tests::make_compact_test_data(SYS_getcpu, 1001, 0, &data)
    },
    "1001 getcpu(cpu: 11, node: 5, tcache: 0xdeadbeef) = 0 (success)\n"
);

syscall_test!(
    parse_getcpu_null,
    {
        let data = GetcpuData {
            cpu: 0,
            has_cpu: false,
            node: 0,
            has_node: false,
            tcache: 0x1f1b2e,
        };

        crate::tests::make_compact_test_data(SYS_getcpu, 1002, 0, &data)
    },
    "1002 getcpu(cpu: NULL, node: NULL, tcache: 0x1f1b2e) = 0 (success)\n"
);

syscall_test!(
    parse_capget_v3_all_caps,
    {
        let data = CapsetgetData {
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
                };

        crate::tests::make_compact_test_data(SYS_capget, 1234, 0, &data)
    },
    "1234 capget(header: { version: 0x20080522, pid: 0 }, data: [ cap_data { effective: 0xffffffff, permitted: 0xffffffff, inheritable: 0xffffffff }, cap_data { effective: 0x0, permitted: 0x0, inheritable: 0x0 }, cap_data { effective: 0x1, permitted: 0x2, inheritable: 0x4 } ] (effective: CAP_CHOWN|CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH|CAP_FOWNER|CAP_FSETID|CAP_KILL|CAP_SETGID|CAP_SETUID|CAP_SETPCAP|CAP_LINUX_IMMUTABLE|CAP_NET_BIND_SERVICE|CAP_NET_BROADCAST|CAP_NET_ADMIN|CAP_NET_RAW|CAP_IPC_LOCK|CAP_IPC_OWNER|CAP_SYS_MODULE|CAP_SYS_RAWIO|CAP_SYS_CHROOT|CAP_SYS_PTRACE|CAP_SYS_PACCT|CAP_SYS_ADMIN|CAP_SYS_BOOT|CAP_SYS_NICE|CAP_SYS_RESOURCE|CAP_SYS_TIME|CAP_SYS_TTY_CONFIG|CAP_MKNOD|CAP_LEASE|CAP_AUDIT_WRITE|CAP_AUDIT_CONTROL|CAP_SETFCAP, permitted: CAP_CHOWN|CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH|CAP_FOWNER|CAP_FSETID|CAP_KILL|CAP_SETGID|CAP_SETUID|CAP_SETPCAP|CAP_LINUX_IMMUTABLE|CAP_NET_BIND_SERVICE|CAP_NET_BROADCAST|CAP_NET_ADMIN|CAP_NET_RAW|CAP_IPC_LOCK|CAP_IPC_OWNER|CAP_SYS_MODULE|CAP_SYS_RAWIO|CAP_SYS_CHROOT|CAP_SYS_PTRACE|CAP_SYS_PACCT|CAP_SYS_ADMIN|CAP_SYS_BOOT|CAP_SYS_NICE|CAP_SYS_RESOURCE|CAP_SYS_TIME|CAP_SYS_TTY_CONFIG|CAP_MKNOD|CAP_LEASE|CAP_AUDIT_WRITE|CAP_AUDIT_CONTROL|CAP_SETFCAP, inheritable: CAP_CHOWN|CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH|CAP_FOWNER|CAP_FSETID|CAP_KILL|CAP_SETGID|CAP_SETUID|CAP_SETPCAP|CAP_LINUX_IMMUTABLE|CAP_NET_BIND_SERVICE|CAP_NET_BROADCAST|CAP_NET_ADMIN|CAP_NET_RAW|CAP_IPC_LOCK|CAP_IPC_OWNER|CAP_SYS_MODULE|CAP_SYS_RAWIO|CAP_SYS_CHROOT|CAP_SYS_PTRACE|CAP_SYS_PACCT|CAP_SYS_ADMIN|CAP_SYS_BOOT|CAP_SYS_NICE|CAP_SYS_RESOURCE|CAP_SYS_TIME|CAP_SYS_TTY_CONFIG|CAP_MKNOD|CAP_LEASE|CAP_AUDIT_WRITE|CAP_AUDIT_CONTROL|CAP_SETFCAP) = 0 (success)\n"
);

syscall_test!(
    parse_capset_v1_some_caps,
    {
        let data = CapsetgetData {
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
                };

        crate::tests::make_compact_test_data(SYS_capset, 4321, 0, &data)
    },
    "4321 capset(header: { version: 0x19980330, pid: 4321 }, data: [ cap_data { effective: 0x5, permitted: 0xa, inheritable: 0x0 } ] (effective: CAP_CHOWN|CAP_DAC_READ_SEARCH, permitted: CAP_DAC_OVERRIDE|CAP_FOWNER, inheritable: 0) = 0 (success)\n"
);

syscall_test!(
    parse_capget_v2_none,
    {
        let data = CapsetgetData {
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
                };

        crate::tests::make_compact_test_data(SYS_capget, 111, 0, &data)
    },
    "111 capget(header: { version: 0x20071026, pid: 111 }, data: [ cap_data { effective: 0x0, permitted: 0x0, inheritable: 0x0 }, cap_data { effective: 0x0, permitted: 0x0, inheritable: 0x0 } ] (effective: 0, permitted: 0, inheritable: 0) = 0 (success)\n"
);

syscall_test!(
    parse_setrlimit_success,
    {
        let data = pinchy_common::RlimitData {
                    resource: libc::RLIMIT_NOFILE as i32,
                    has_limit: true,
                    limit: Rlimit {
                        rlim_cur: 1024,
                        rlim_max: 4096,
                    },
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_setrlimit, 100, 0, &data)
    },
    "100 setrlimit(resource: RLIMIT_NOFILE, limit: { rlim_cur: 1024, rlim_max: 4096 }) = 0 (success)\n"
);

syscall_test!(
    parse_setrlimit_null,
    {
        let data = pinchy_common::RlimitData {
            resource: libc::RLIMIT_NOFILE as i32,
            has_limit: false,
            limit: pinchy_common::kernel_types::Rlimit::default(),
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_setrlimit, 101, -1, &data)
    },
    "101 setrlimit(resource: RLIMIT_NOFILE, limit: NULL) = -1 (error)\n"
);

syscall_test!(
    parse_getrlimit_success,
    {
        let data = pinchy_common::RlimitData {
                    resource: libc::RLIMIT_STACK as i32,
                    has_limit: true,
                    limit: Rlimit {
                        rlim_cur: 8192,
                        rlim_max: 16384,
                    },
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_getrlimit, 200, 0, &data)
    },
    "200 getrlimit(resource: RLIMIT_STACK, limit: { rlim_cur: 8192, rlim_max: 16384 }) = 0 (success)\n"
);

syscall_test!(
    parse_getrlimit_error,
    {
        let data = pinchy_common::RlimitData {
            resource: libc::RLIMIT_STACK as i32,
            has_limit: true,
            limit: pinchy_common::kernel_types::Rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            },
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_getrlimit, 201, -1, &data)
    },
    "201 getrlimit(resource: RLIMIT_STACK, limit: (content unavailable)) = -1 (error)\n"
);

syscall_test!(
    parse_getrlimit_null,
    {
        let data = pinchy_common::RlimitData {
            resource: libc::RLIMIT_STACK as i32,
            has_limit: false,
            limit: pinchy_common::kernel_types::Rlimit::default(),
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_getrlimit, 202, -1, &data)
    },
    "202 getrlimit(resource: RLIMIT_STACK, limit: NULL) = -1 (error)\n"
);

syscall_test!(
    parse_init_module_success,
    {

        let mut param_values = [0u8; pinchy_common::DATA_READ_SIZE];
        let params = b"param1=value1 param2=value2\0";
        param_values[..params.len()].copy_from_slice(params);

        let data = InitModuleData {
                    module_image: 0x7f8000001000,
                    len: 65536,
                    param_values,
                };

        crate::tests::make_compact_test_data(SYS_init_module, 1000, 0, &data)
    },
    "1000 init_module(module_image: 0x7f8000001000, len: 65536, param_values: \"param1=value1 param2=value2\") = 0 (success)\n"
);

syscall_test!(
    parse_init_module_error,
    {

        let param_values = [0u8; pinchy_common::DATA_READ_SIZE]; // empty params

        let data = InitModuleData {
                    module_image: 0x7f8000002000,
                    len: 32768,
                    param_values,
                };

        crate::tests::make_compact_test_data(SYS_init_module, 1001, -17, &data)
    },
    "1001 init_module(module_image: 0x7f8000002000, len: 32768, param_values: \"\") = -17 (error)\n"
);

syscall_test!(
    parse_finit_module_success,
    {
        let mut param_values = [0u8; pinchy_common::DATA_READ_SIZE];
        let params = b"debug=1\0";
        param_values[..params.len()].copy_from_slice(params);

        let data = FinitModuleData {
            fd: 5,
            param_values,
            flags: 0,
        };

        crate::tests::make_compact_test_data(SYS_finit_module, 2000, 0, &data)
    },
    "2000 finit_module(fd: 5, param_values: \"debug=1\", flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_finit_module_with_flags,
    {

        let mut param_values = [0u8; pinchy_common::DATA_READ_SIZE];
        let params = b"verbose=1 force=1\0";
        param_values[..params.len()].copy_from_slice(params);

        let data = FinitModuleData {
                    fd: 8,
                    param_values,
                    flags: libc::MODULE_INIT_IGNORE_MODVERSIONS
                        | libc::MODULE_INIT_IGNORE_VERMAGIC,
                };

        crate::tests::make_compact_test_data(SYS_finit_module, 2001, 0, &data)
    },
    "2001 finit_module(fd: 8, param_values: \"verbose=1 force=1\", flags: 0x3 (MODULE_INIT_IGNORE_MODVERSIONS|MODULE_INIT_IGNORE_VERMAGIC)) = 0 (success)\n"
);

syscall_test!(
    parse_finit_module_error,
    {
        let param_values = [0u8; pinchy_common::DATA_READ_SIZE]; // empty params

        let data = FinitModuleData {
            fd: -1,
            param_values,
            flags: 0,
        };

        crate::tests::make_compact_test_data(SYS_finit_module, 2002, -2, &data)
    },
    "2002 finit_module(fd: -1, param_values: \"\", flags: 0) = -2 (error)\n"
);

syscall_test!(
    parse_delete_module_success,
    {
        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let module_name = b"test_module\0";
        name[..module_name.len()].copy_from_slice(module_name);

        let data = DeleteModuleData { name, flags: 0 };

        crate::tests::make_compact_test_data(SYS_delete_module, 3000, 0, &data)
    },
    "3000 delete_module(name: \"test_module\", flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_delete_module_force,
    {

        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let module_name = b"problematic_module\0";
        name[..module_name.len()].copy_from_slice(module_name);

        let data = DeleteModuleData {
                    name,
                    flags: libc::O_TRUNC | libc::O_NONBLOCK,
                };

        crate::tests::make_compact_test_data(SYS_delete_module, 3001, 0, &data)
    },
    "3001 delete_module(name: \"problematic_module\", flags: 0xa00 (O_NONBLOCK|O_TRUNC)) = 0 (success)\n"
);

syscall_test!(
    parse_delete_module_error,
    {
        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let module_name = b"nonexistent_module\0";
        name[..module_name.len()].copy_from_slice(module_name);

        let data = DeleteModuleData { name, flags: 0 };

        crate::tests::make_compact_test_data(SYS_delete_module, 3002, -2, &data)
    },
    "3002 delete_module(name: \"nonexistent_module\", flags: 0) = -2 (error)\n"
);

syscall_test!(
    parse_sethostname_success,
    {
        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let hostname = b"myhostname\0";
        name[..hostname.len()].copy_from_slice(hostname);

        let data = SethostnameData { name, len: 10 };

        crate::tests::make_compact_test_data(SYS_sethostname, 4000, 0, &data)
    },
    "4000 sethostname(name: \"myhostname\", len: 10) = 0 (success)\n"
);

syscall_test!(
    parse_sethostname_error,
    {
        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let hostname = b"verylonghostname\0";
        name[..hostname.len()].copy_from_slice(hostname);

        let data = SethostnameData { name, len: 16 };

        crate::tests::make_compact_test_data(SYS_sethostname, 4001, -22, &data)
    },
    "4001 sethostname(name: \"verylonghostname\", len: 16) = -22 (error)\n"
);

syscall_test!(
    parse_setdomainname_success,
    {
        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let domainname = b"mydomain.com\0";
        name[..domainname.len()].copy_from_slice(domainname);

        let data = SetdomainnameData { name, len: 12 };

        crate::tests::make_compact_test_data(SYS_setdomainname, 5000, 0, &data)
    },
    "5000 setdomainname(name: \"mydomain.com\", len: 12) = 0 (success)\n"
);

syscall_test!(
    parse_setdomainname_error,
    {
        let mut name = [0u8; pinchy_common::MEDIUM_READ_SIZE];
        let domainname = b"veryverylongdomainname.example.org\0";
        name[..domainname.len()].copy_from_slice(domainname);

        let data = SetdomainnameData { name, len: 34 };

        crate::tests::make_compact_test_data(SYS_setdomainname, 5001, -1, &data)
    },
    "5001 setdomainname(name: \"veryverylongdomainname.example.org\", len: 34) = -1 (error)\n"
);

syscall_test!(
    parse_landlock_create_ruleset_success,
    {
        let data = LandlockCreateRulesetData {
            attr: 0xdeadbeef,
            size: 16,
            flags: 0,
        };

        crate::tests::make_compact_test_data(SYS_landlock_create_ruleset, 6000, 3, &data)
    },
    "6000 landlock_create_ruleset(attr: 0xdeadbeef, size: 16, flags: 0) = 3 (fd)\n"
);

syscall_test!(
    parse_landlock_create_ruleset_with_flags,
    {
        let data = LandlockCreateRulesetData {
                    attr: 0xcafebabe,
                    size: 24,
                    flags: pinchy_common::LANDLOCK_CREATE_RULESET_VERSION,
                };

        crate::tests::make_compact_test_data(SYS_landlock_create_ruleset, 6001, 4, &data)
    },
    "6001 landlock_create_ruleset(attr: 0xcafebabe, size: 24, flags: 0x1 (LANDLOCK_CREATE_RULESET_VERSION)) = 4 (fd)\n"
);

syscall_test!(
    parse_landlock_add_rule_path_beneath,
    {
        let data = LandlockAddRuleData {
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
                };

        crate::tests::make_compact_test_data(SYS_landlock_add_rule, 6002, 0, &data)
    },
    "6002 landlock_add_rule(ruleset_fd: 3, rule_type: LANDLOCK_RULE_PATH_BENEATH, parent_fd: 4, allowed_access: 0x3f (EXECUTE|WRITE_FILE|READ_FILE|READ_DIR|REMOVE_DIR|REMOVE_FILE), flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_landlock_add_rule_net_port,
    {
        let data = LandlockAddRuleData {
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
                };

        crate::tests::make_compact_test_data(SYS_landlock_add_rule, 6003, 0, &data)
    },
    "6003 landlock_add_rule(ruleset_fd: 4, rule_type: LANDLOCK_RULE_NET_PORT, port: 8080, access_rights: 0x3 (BIND_TCP|CONNECT_TCP), flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_landlock_add_rule_error,
    {
        let data = LandlockAddRuleData {
                    ruleset_fd: 999,
                    rule_type: pinchy_common::LANDLOCK_RULE_PATH_BENEATH,
                    rule_attr: 0,
                    flags: 0,
                    rule_attr_data: LandlockRuleAttrUnion {
                        path_beneath: pinchy_common::kernel_types::LandlockPathBeneathAttr::default(),
                    },
                };

        crate::tests::make_compact_test_data(SYS_landlock_add_rule, 6004, -9, &data)
    },
    "6004 landlock_add_rule(ruleset_fd: 999, rule_type: LANDLOCK_RULE_PATH_BENEATH, parent_fd: 0, allowed_access: 0, flags: 0) = -9 (error)\n"
);

syscall_test!(
    parse_landlock_restrict_self_success,
    {
        let data = LandlockRestrictSelfData {
            ruleset_fd: 3,
            flags: 0,
        };

        crate::tests::make_compact_test_data(SYS_landlock_restrict_self, 6005, 0, &data)
    },
    "6005 landlock_restrict_self(ruleset_fd: 3, flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_landlock_restrict_self_error,
    {
        let data = LandlockRestrictSelfData {
            ruleset_fd: -1,
            flags: 0,
        };

        crate::tests::make_compact_test_data(SYS_landlock_restrict_self, 6006, -22, &data)
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

        let data = AddKeyData {
                    key_type: key_type_buf,
                    description: desc_buf,
                    payload: payload_buf,
                    payload_len: payload_data.len(),
                    keyring: libc::KEY_SPEC_SESSION_KEYRING,
                };

        crate::tests::make_compact_test_data(SYS_add_key, 7000, 512000001, &data)
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

        let data = AddKeyData {
                    key_type: key_type_buf,
                    description: desc_buf,
                    payload: payload_buf,
                    payload_len: 0,
                    keyring: libc::KEY_SPEC_PROCESS_KEYRING,
                };

        crate::tests::make_compact_test_data(SYS_add_key, 7001, 512000002, &data)
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

        let data = AddKeyData {
                    key_type: key_type_buf,
                    description: desc_buf,
                    payload: payload_buf,
                    payload_len: 0,
                    keyring: libc::KEY_SPEC_THREAD_KEYRING,
                };

        crate::tests::make_compact_test_data(SYS_add_key, 7002, -22, &data)
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

        let data = RequestKeyData {
                    key_type: key_type_buf,
                    description: desc_buf,
                    callout_info: info_buf,
                    callout_info_len: callout_info.len(),
                    dest_keyring: libc::KEY_SPEC_SESSION_KEYRING,
                };

        crate::tests::make_compact_test_data(SYS_request_key, 7010, 512000010, &data)
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

        let data = RequestKeyData {
                    key_type: key_type_buf,
                    description: desc_buf,
                    callout_info: info_buf,
                    callout_info_len: 0,
                    dest_keyring: 0,
                };

        crate::tests::make_compact_test_data(SYS_request_key, 7011, 512000011, &data)
    },
    "7011 request_key(type: \"user\", description: \"password\", callout_info: (null), dest_keyring: 0) = 512000011\n"
);

syscall_test!(
    parse_keyctl_get_keyring_id,
    {
        let data = KeyctlData {
                    operation: libc::KEYCTL_GET_KEYRING_ID as i32,
                    arg1: libc::KEY_SPEC_SESSION_KEYRING as u64,
                    arg2: 0,
                    arg3: 0,
                    arg4: 0,
                };

        crate::tests::make_compact_test_data(SYS_keyctl, 7020, 512000020, &data)
    },
    "7020 keyctl(operation: GET_KEYRING_ID, keyring: KEY_SPEC_SESSION_KEYRING, create: 0x0) = 512000020 (key)\n"
);

syscall_test!(
    parse_keyctl_update,
    {
        let data = KeyctlData {
                    operation: libc::KEYCTL_UPDATE as i32,
                    arg1: 512000001,
                    arg2: 0xdeadbeef,
                    arg3: 32,
                    arg4: 0,
                };

        crate::tests::make_compact_test_data(SYS_keyctl, 7021, 0, &data)
    },
    "7021 keyctl(operation: UPDATE, key: 512000001, payload: 0xdeadbeef, length: 0x20) = 0 (success)\n"
);

syscall_test!(
    parse_keyctl_revoke,
    {
        let data = KeyctlData {
            operation: libc::KEYCTL_REVOKE as i32,
            arg1: 512000001,
            arg2: 0,
            arg3: 0,
            arg4: 0,
        };

        crate::tests::make_compact_test_data(SYS_keyctl, 7022, 0, &data)
    },
    "7022 keyctl(operation: REVOKE, key: 512000001) = 0 (success)\n"
);

syscall_test!(
    parse_keyctl_search,
    {
        let data = KeyctlData {
                    operation: libc::KEYCTL_SEARCH as i32,
                    arg1: libc::KEY_SPEC_SESSION_KEYRING as u64,
                    arg2: 0xaabbccdd,
                    arg3: 0xddeeffaa,
                    arg4: libc::KEY_SPEC_PROCESS_KEYRING as u64,
                };

        crate::tests::make_compact_test_data(SYS_keyctl, 7023, 512000023, &data)
    },
    "7023 keyctl(operation: SEARCH, keyring: KEY_SPEC_SESSION_KEYRING, type: 0xaabbccdd, description: 0xddeeffaa, dest_keyring: KEY_SPEC_PROCESS_KEYRING) = 512000023 (key)\n"
);

// Import constants from format_helpers
use crate::format_helpers::{bpf_constants, perf_constants};

syscall_test!(
    parse_perf_event_open_success,
    {
        let data = PerfEventOpenData {
                    attr: pinchy_common::kernel_types::PerfEventAttr {
                        type_: perf_constants::PERF_TYPE_HARDWARE,
                        config: 0,
                        sample_period: 4000,
                        ..Default::default()
                    },
                    pid: 1234,
                    cpu: 0,
                    group_fd: -1,
                    flags: 0,
                };

        crate::tests::make_compact_test_data(SYS_perf_event_open, 8000, 3, &data)
    },
    "8000 perf_event_open(attr: { type: PERF_TYPE_HARDWARE, size: 0, config: 0x0, sample_period: 4000 }, pid: 1234, cpu: 0, group_fd: -1, flags: 0) = 3 (fd)\n"
);

syscall_test!(
    parse_perf_event_open_with_flags,
    {
        let data = PerfEventOpenData {
                    attr: pinchy_common::kernel_types::PerfEventAttr {
                        type_: perf_constants::PERF_TYPE_SOFTWARE,
                        config: perf_constants::PERF_COUNT_SW_CPU_CLOCK,
                        sample_period: 1000000,
                        ..Default::default()
                    },
                    pid: -1,
                    cpu: 2,
                    group_fd: 3,
                    flags: perf_constants::PERF_FLAG_FD_CLOEXEC
                        | perf_constants::PERF_FLAG_FD_NO_GROUP,
                };

        crate::tests::make_compact_test_data(SYS_perf_event_open, 8001, 4, &data)
    },
    "8001 perf_event_open(attr: { type: PERF_TYPE_SOFTWARE, size: 0, config: 0x0, sample_period: 1000000 }, pid: -1, cpu: 2, group_fd: 3, flags: 0x9 (FD_NO_GROUP|FD_CLOEXEC)) = 4 (fd)\n"
);

syscall_test!(
    parse_perf_event_open_error,
    {
        let data = PerfEventOpenData {
                    attr: Default::default(),
                    pid: 0,
                    cpu: -1,
                    group_fd: -1,
                    flags: 0,
                };

        crate::tests::make_compact_test_data(SYS_perf_event_open, 8002, -22, &data)
    },
    "8002 perf_event_open(attr: { type: PERF_TYPE_HARDWARE, size: 0, config: 0x0, sample_period: 0 }, pid: 0, cpu: -1, group_fd: -1, flags: 0) = -22 (error)\n"
);

syscall_test!(
    parse_bpf_map_create,
    {
        let data = BpfData {
                    cmd: bpf_constants::BPF_MAP_CREATE,
                    size: 72,
                    which_attr: 1,
                    map_create_attr: pinchy_common::kernel_types::BpfMapCreateAttr {
                        map_type: bpf_constants::BPF_MAP_TYPE_HASH,
                        key_size: 4,
                        value_size: 8,
                        max_entries: 1024,
                        ..Default::default()
                    },
                    prog_load_attr: Default::default(),
                    license_str: Default::default(),
                };

        crate::tests::make_compact_test_data(SYS_bpf, 8100, 3, &data)
    },
    "8100 bpf(cmd: BPF_MAP_CREATE, attr: { map_type: BPF_MAP_TYPE_HASH, key_size: 4, value_size: 8, max_entries: 1024 }, size: 72) = 3 (fd)\n"
);

syscall_test!(
    parse_bpf_prog_load,
    {

        let mut license_str = [0u8; 32];
        license_str[0] = b'G';
        license_str[1] = b'P';
        license_str[2] = b'L';

        let data = BpfData {
                    cmd: bpf_constants::BPF_PROG_LOAD,
                    size: 128,
                    which_attr: 2,
                    map_create_attr: Default::default(),
                    prog_load_attr: pinchy_common::kernel_types::BpfProgLoadAttr {
                        prog_type: bpf_constants::BPF_PROG_TYPE_SOCKET_FILTER,
                        insn_cnt: 10,
                        license: 0x4141414141414141,
                    },
                    license_str,
                };

        crate::tests::make_compact_test_data(SYS_bpf, 8101, 4, &data)
    },
    "8101 bpf(cmd: BPF_PROG_LOAD, attr: { prog_type: BPF_PROG_TYPE_SOCKET_FILTER, insn_cnt: 10, license: \"GPL\" }, size: 128) = 4 (fd)\n"
);

syscall_test!(
    parse_bpf_error,
    {
        let data = BpfData {
            cmd: bpf_constants::BPF_PROG_LOAD,
            size: 0,
            which_attr: 0,
            map_create_attr: Default::default(),
            prog_load_attr: Default::default(),
            license_str: Default::default(),
        };

        crate::tests::make_compact_test_data(SYS_bpf, 8102, -1, &data)
    },
    "8102 bpf(cmd: BPF_PROG_LOAD, size: 0) = -1 (error)\n"
);

syscall_test!(
    parse_syslog_read_all,
    {
        let data = SyslogData {
            type_: crate::format_helpers::syslog_constants::SYSLOG_ACTION_READ_ALL,
            bufp: 0x7fff12345678,
            size: 8192,
        };

        crate::tests::make_compact_test_data(SYS_syslog, 9100, 4096, &data)
    },
    "9100 syslog(type: SYSLOG_ACTION_READ_ALL, bufp: 0x7fff12345678, size: 8192) = 4096\n"
);

syscall_test!(
    parse_syslog_size_buffer,
    {
        let data = SyslogData {
            type_: crate::format_helpers::syslog_constants::SYSLOG_ACTION_SIZE_BUFFER,
            bufp: 0,
            size: 0,
        };

        crate::tests::make_compact_test_data(SYS_syslog, 9101, 262144, &data)
    },
    "9101 syslog(type: SYSLOG_ACTION_SIZE_BUFFER, bufp: 0x0, size: 0) = 262144\n"
);

syscall_test!(
    parse_syslog_error,
    {
        let data = SyslogData {
            type_: crate::format_helpers::syslog_constants::SYSLOG_ACTION_READ,
            bufp: 0,
            size: 0,
        };

        crate::tests::make_compact_test_data(SYS_syslog, 9102, -1, &data)
    },
    "9102 syslog(type: SYSLOG_ACTION_READ, bufp: 0x0, size: 0) = -1 (error)\n"
);

syscall_test!(
    parse_restart_syscall,
    {
        let data = RestartSyscallData::default();

        crate::tests::make_compact_test_data(SYS_restart_syscall, 123, 0, &data)
    },
    "123 restart_syscall() = 0 (success)\n"
);

syscall_test!(
    parse_kexec_load_basic,
    {
        let data = KexecLoadData {
                    entry: 0x80000000,
                    nr_segments: 4,
                    segments: 0x7fff0000,
                    flags: 0,
                    segments_read: 0,
                    parsed_segments: Default::default(),
                };

        crate::tests::make_compact_test_data(SYS_kexec_load, 123, 0, &data)
    },
    "123 kexec_load(entry: 0x80000000, nr_segments: 4, segments: 0x7fff0000, flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_kexec_load_on_crash,
    {
        let data = KexecLoadData {
                    entry: 0x80000000,
                    nr_segments: 2,
                    segments: 0x7fff0000,
                    flags: crate::format_helpers::kexec_constants::KEXEC_ON_CRASH,
                    segments_read: 0,
                    parsed_segments: Default::default(),
                };

        crate::tests::make_compact_test_data(SYS_kexec_load, 123, 0, &data)
    },
    "123 kexec_load(entry: 0x80000000, nr_segments: 2, segments: 0x7fff0000, flags: 0x1 (KEXEC_ON_CRASH)) = 0 (success)\n"
);

syscall_test!(
    parse_kexec_load_with_arch,
    {
        let data = KexecLoadData {
                    entry: 0x80000000,
                    nr_segments: 3,
                    segments: 0x7fff0000,
                    flags: crate::format_helpers::kexec_constants::KEXEC_ON_CRASH
                        | crate::format_helpers::kexec_constants::KEXEC_ARCH_X86_64,
                    segments_read: 0,
                    parsed_segments: Default::default(),
                };

        crate::tests::make_compact_test_data(SYS_kexec_load, 123, 0, &data)
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

        let data = KexecLoadData {
                    entry: 0x80000000,
                    nr_segments: 2,
                    segments: 0x7fff0000,
                    flags: 0,
                    segments_read: 2,
                    parsed_segments,
                };

        crate::tests::make_compact_test_data(SYS_kexec_load, 123, 0, &data)
    },
    "123 kexec_load(entry: 0x80000000, nr_segments: 2, segments: [{buf: 0x1000, bufsz: 4096, mem: 0x100000, memsz: 4096}, {buf: 0x2000, bufsz: 8192, mem: 0x200000, memsz: 8192}], flags: 0) = 0 (success)\n"
);
