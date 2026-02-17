// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#[cfg(target_arch = "x86_64")]
use pinchy_common::syscalls::{SYS_fork, SYS_getpgrp, SYS_vfork};
use pinchy_common::{
    kernel_types::CloneArgs,
    syscalls::{
        SYS_clone3, SYS_execve, SYS_execveat, SYS_getegid, SYS_geteuid, SYS_getgid, SYS_getgroups,
        SYS_getpgid, SYS_getpid, SYS_getppid, SYS_getresgid, SYS_getresuid, SYS_getsid, SYS_gettid,
        SYS_getuid, SYS_kcmp, SYS_pidfd_getfd, SYS_pidfd_open, SYS_prctl, SYS_set_tid_address,
        SYS_setgid, SYS_setgroups, SYS_setns, SYS_setpgid, SYS_setregid, SYS_setresgid,
        SYS_setresuid, SYS_setreuid, SYS_setsid, SYS_setuid, SYS_unshare,
    },
    Clone3Data, ExecveData, ExecveatData, GenericSyscallData, GetegidData, GeteuidData, GetgidData,
    GetgroupsData, GetpgidData, GetpidData, GetppidData, GetresgidData, GetresuidData, GetsidData,
    GettidData, GetuidData, KcmpData, PidfdOpenData, SetTidAddressData, SetgidData, SetgroupsData,
    SetnsData, SetpgidData, SetregidData, SetresgidData, SetresuidData, SetreuidData, SetsidData,
    SetuidData, UnshareData, SMALL_READ_SIZE,
};
#[cfg(target_arch = "x86_64")]
use pinchy_common::{ForkData, GetpgrpData, VforkData};

use crate::{format_helpers::kcmp_constants, syscall_test};

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_getpgrp,
    {
        let data = GetpgrpData;

        crate::tests::make_compact_test_data(SYS_getpgrp, 1001, 1001, &data)
    },
    "1001 getpgrp() = 1001 (pid)\n"
);

syscall_test!(
    parse_execve,
    {
        let mut data = ExecveData {
            filename: [0u8; SMALL_READ_SIZE * 4],
            filename_truncated: false,
            argv: [[0u8; SMALL_READ_SIZE]; 4],
            argv_len: [0u16; 4],
            argc: 0,
            envp: [[0u8; SMALL_READ_SIZE]; 2],
            envp_len: [0u16; 2],
            envc: 0,
        };

        let filename = c"/bin/find".to_bytes_with_nul();
        data.filename[..filename.len()].copy_from_slice(filename);

        let argv = [
            c"/etc".to_bytes_with_nul(),
            c"-name".to_bytes_with_nul(),
            c"org.pinc".to_bytes(),
        ];
        data.argv[0][..argv[0].len()].copy_from_slice(argv[0]);
        data.argv_len[0] = argv[0].len() as u16;

        data.argv[1][..argv[1].len()].copy_from_slice(argv[1]);
        data.argv_len[1] = argv[1].len() as u16;

        data.argv[2][..argv[2].len()].copy_from_slice(argv[2]);
        data.argv_len[2] = argv[2].len() as u16;

        data.argc = 3;

        let envp = [c"HOME=/ro".to_bytes(), c"WAYLAND=".to_bytes()];
        data.envp[0][..SMALL_READ_SIZE].copy_from_slice(&envp[0][..SMALL_READ_SIZE]);
        data.envp_len[0] = envp[0].len() as u16;

        data.envp[1][..SMALL_READ_SIZE].copy_from_slice(&envp[1][..SMALL_READ_SIZE]);
        data.envp_len[1] = envp[1].len() as u16;

        data.envc = 30;

        crate::tests::make_compact_test_data(SYS_execve, 22, 0, &data)
    },
    "22 execve(filename: \"/bin/find\", argv: [/etc\0, -name\0, org.pinc], envp: [HOME=/ro, WAYLAND=, ... (28 more)]) = 0 (success)\n"
);

syscall_test!(
    parse_execveat,
    {
        let mut data = ExecveatData {
            dirfd: libc::AT_FDCWD,
            pathname: [0u8; SMALL_READ_SIZE * 4],
            pathname_truncated: false,
            argv: [[0u8; SMALL_READ_SIZE]; 4],
            argv_len: [0u16; 4],
            argc: 0,
            envp: [[0u8; SMALL_READ_SIZE]; 2],
            envp_len: [0u16; 2],
            envc: 0,
            flags: libc::AT_EMPTY_PATH,
        };

        let pathname = c"/bin/ls".to_bytes_with_nul();
        data.pathname[..pathname.len()].copy_from_slice(pathname);

        let argv = [
            c"/bin/ls".to_bytes_with_nul(),
            c"-la".to_bytes_with_nul(),
        ];
        data.argv[0][..argv[0].len()].copy_from_slice(argv[0]);
        data.argv_len[0] = argv[0].len() as u16;

        data.argv[1][..argv[1].len()].copy_from_slice(argv[1]);
        data.argv_len[1] = argv[1].len() as u16;

        data.argc = 2;

        let envp = [c"PATH=/u".to_bytes(), c"USER=te".to_bytes()];
        data.envp[0][..envp[0].len()].copy_from_slice(envp[0]);
        data.envp_len[0] = envp[0].len() as u16;

        data.envp[1][..envp[1].len()].copy_from_slice(envp[1]);
        data.envp_len[1] = envp[1].len() as u16;

        data.envc = 5;

        crate::tests::make_compact_test_data(SYS_execveat, 23, 0, &data)
    },
    "23 execveat(dirfd: AT_FDCWD, pathname: \"/bin/ls\", argv: [/bin/ls\0, -la\0], envp: [PATH=/u, USER=te, ... (3 more)], flags: 0x1000 (AT_EMPTY_PATH)) = 0 (success)\n"
);

syscall_test!(
    parse_prctl,
    {
        let data = GenericSyscallData {
            args: [libc::PR_SET_NAME as usize, 0x7fffffff0000, 0, 0, 0, 0],
        };

        crate::tests::make_compact_test_data(SYS_prctl, 999, 0, &data)
    },
    "999 prctl(PR_SET_NAME, 0x7fffffff0000) = 0 (success)\n"
);

syscall_test!(
    parse_set_tid_address,
    {
        let data = SetTidAddressData {
            tidptr: 0x7f1234560000,
        };

        crate::tests::make_compact_test_data(SYS_set_tid_address, 5678, 5678, &data)
    },
    "5678 set_tid_address(tidptr: 0x7f1234560000) = 5678\n"
);

syscall_test!(
    test_getpid,
    {
        let data = GetpidData;

        crate::tests::make_compact_test_data(SYS_getpid, 1234, 1234, &data)
    },
    "1234 getpid() = 1234 (pid)\n"
);

syscall_test!(
    test_gettid,
    {
        let data = GettidData;

        crate::tests::make_compact_test_data(SYS_gettid, 5678, 5678, &data)
    },
    "5678 gettid() = 5678 (pid)\n"
);

syscall_test!(
    test_getuid,
    {
        let data = GetuidData;

        crate::tests::make_compact_test_data(SYS_getuid, 1234, 1000, &data)
    },
    "1234 getuid() = 1000 (id)\n"
);

syscall_test!(
    test_geteuid,
    {
        let data = GeteuidData;

        crate::tests::make_compact_test_data(SYS_geteuid, 1234, 1000, &data)
    },
    "1234 geteuid() = 1000 (id)\n"
);

syscall_test!(
    test_getgid,
    {
        let data = GetgidData;

        crate::tests::make_compact_test_data(SYS_getgid, 1234, 1000, &data)
    },
    "1234 getgid() = 1000 (id)\n"
);

syscall_test!(
    test_getegid,
    {
        let data = GetegidData;

        crate::tests::make_compact_test_data(SYS_getegid, 1234, 1000, &data)
    },
    "1234 getegid() = 1000 (id)\n"
);

syscall_test!(
    test_getppid,
    {
        let data = GetppidData;

        crate::tests::make_compact_test_data(SYS_getppid, 1234, 987, &data)
    },
    "1234 getppid() = 987 (pid)\n"
);

syscall_test!(
    parse_prlimit64_new_and_old,
    {

        use pinchy_common::{
            kernel_types::Rlimit, syscalls::SYS_prlimit64, PrlimitData, };

        let data = PrlimitData {
                    pid: 1234,
                    resource: 7,
                    has_old: true,
                    has_new: true,
                    old_limit: Rlimit {
                        rlim_cur: 1024,
                        rlim_max: 4096,
                    },
                    new_limit: Rlimit {
                        rlim_cur: 2048,
                        rlim_max: 4096,
                    },
                };

        crate::tests::make_compact_test_data(SYS_prlimit64, 9876, 0, &data)
    },
    "9876 prlimit64(pid: 1234, resource: RLIMIT_NOFILE, new_limit: { rlim_cur: 2048, rlim_max: 4096 }, old_limit: { rlim_cur: 1024, rlim_max: 4096 }) = 0 (success)\n"
);

syscall_test!(
    parse_prlimit64_old_only,
    {

        use pinchy_common::{
            kernel_types::Rlimit, syscalls::SYS_prlimit64, PrlimitData, };

        let data = PrlimitData {
                    pid: 0,
                    resource: 3,
                    has_old: true,
                    has_new: false,
                    old_limit: Rlimit {
                        rlim_cur: 8 * 1024 * 1024,
                        rlim_max: u64::MAX,
                    },
                    new_limit: Rlimit::default(),
                };

        crate::tests::make_compact_test_data(SYS_prlimit64, 9876, 0, &data)
    },
    "9876 prlimit64(pid: 0, resource: RLIMIT_STACK, new_limit: NULL, old_limit: { rlim_cur: 8388608, rlim_max: RLIM_INFINITY }) = 0 (success)\n"
);

syscall_test!(
    parse_prlimit64_new_only_error,
    {

        use pinchy_common::{
            kernel_types::Rlimit, syscalls::SYS_prlimit64, PrlimitData, };

        let data = PrlimitData {
                    pid: 5678,
                    resource: 9,
                    has_old: false,
                    has_new: true,
                    old_limit: Rlimit::default(),
                    new_limit: Rlimit {
                        rlim_cur: 4 * 1024 * 1024 * 1024,
                        rlim_max: 8 * 1024 * 1024 * 1024,
                    },
                };

        crate::tests::make_compact_test_data(SYS_prlimit64, 9876, -1, &data)
    },
    "9876 prlimit64(pid: 5678, resource: RLIMIT_AS, new_limit: { rlim_cur: 4294967296, rlim_max: 8589934592 }, old_limit: NULL) = -1 (error)\n"
);

syscall_test!(
    parse_fchdir,
    {
        use pinchy_common::{syscalls::SYS_fchdir, FchdirData};

        let data = FchdirData { fd: 5 };

        crate::tests::make_compact_test_data(SYS_fchdir, 42, 0, &data)
    },
    "42 fchdir(fd: 5) = 0 (success)\n"
);

syscall_test!(
    test_wait4_successful,
    {

        use pinchy_common::{
            kernel_types::Rusage, syscalls::SYS_wait4, Wait4Data,
        };

        let data = Wait4Data {
                    pid: -1,
                    wstatus: 0,
                    options: libc::WNOHANG | libc::WUNTRACED,
                    has_rusage: true,
                    rusage: Rusage {
                        ru_utime: pinchy_common::kernel_types::Timeval {
                            tv_sec: 0,
                            tv_usec: 123456,
                        },
                        ru_stime: pinchy_common::kernel_types::Timeval {
                            tv_sec: 0,
                            tv_usec: 78910,
                        },
                        ru_maxrss: 1024,
                        ru_minflt: 100,
                        ru_majflt: 5,
                        ..Default::default()
                    },
                };

        crate::tests::make_compact_test_data(SYS_wait4, 1001, 1234, &data)
    },
    "1001 wait4(pid: -1, wstatus: {WIFEXITED(s) && WEXITSTATUS(s) == 0}, options: WNOHANG|WUNTRACED|WSTOPPED, rusage: { ru_utime: { tv_sec: 0, tv_usec: 123456 }, ru_stime: { tv_sec: 0, tv_usec: 78910 }, ru_maxrss: 1024, ru_ixrss: 0, ru_idrss: 0, ru_isrss: 0, ru_minflt: 100, ru_majflt: 5, ru_nswap: 0, ru_inblock: 0, ru_oublock: 0, ru_msgsnd: 0, ru_msgrcv: 0, ru_nsignals: 0, ru_nvcsw: 0, ru_nivcsw: 0 }) = 1234\n"
);

syscall_test!(
    test_wait4_no_rusage,
    {

        use pinchy_common::{
            syscalls::SYS_wait4, Wait4Data,
        };

        let data = Wait4Data {
                    pid: 1234,
                    wstatus: 9 << 8,
                    options: 0,
                    has_rusage: false,
                    rusage: Default::default(),
                };

        crate::tests::make_compact_test_data(SYS_wait4, 2001, 5678, &data)
    },
    "2001 wait4(pid: 1234, wstatus: {WIFEXITED(s) && WEXITSTATUS(s) == 9}, options: 0, rusage: NULL) = 5678\n"
);

syscall_test!(
    test_waitid_successful,
    {

        use pinchy_common::{
            kernel_types::Siginfo, syscalls::SYS_waitid, WaitidData,
        };

        let data = WaitidData {
                    idtype: libc::P_PID,
                    id: 1234,
                    infop: Siginfo {
                        si_signo: libc::SIGCHLD,
                        si_errno: 0,
                        si_code: 1,
                        si_pid: 1234,
                        si_uid: 1000,
                        si_status: 0,
                        ..Default::default()
                    },
                    options: libc::WEXITED,
                    has_infop: true,
                };

        crate::tests::make_compact_test_data(SYS_waitid, 4001, 0, &data)
    },
    "4001 waitid(idtype: P_PID, id: 1234, infop: { signo: 17, errno: 0, code: 1, trapno: 0, pid: 1234, uid: 1000, status: 0, utime: 0, stime: 0, value: 0x0, int: 0, ptr: 0x0, overrun: 0, timerid: 0, addr: 0x0, band: 0, fd: 0, addr_lsb: 0, lower: 0x0, upper: 0x0, pkey: 0, call_addr: 0x0, syscall: 0, arch: 0 }, options: WEXITED) = 0 (success)\n"
);

syscall_test!(
    test_waitid_p_all,
    {

        use pinchy_common::{
            kernel_types::Siginfo, syscalls::SYS_waitid, WaitidData,
        };

        let data = WaitidData {
                    idtype: libc::P_ALL,
                    id: 0,
                    infop: Siginfo {
                        si_signo: libc::SIGCHLD,
                        si_errno: 0,
                        si_code: 2,
                        si_pid: 5678,
                        si_uid: 0,
                        si_status: 9,
                        ..Default::default()
                    },
                    options: libc::WNOHANG | libc::WEXITED,
                    has_infop: true,
                };

        crate::tests::make_compact_test_data(SYS_waitid, 5001, 0, &data)
    },
    "5001 waitid(idtype: P_ALL, id: 0, infop: { signo: 17, errno: 0, code: 2, trapno: 0, pid: 5678, uid: 0, status: 9, utime: 0, stime: 0, value: 0x0, int: 0, ptr: 0x0, overrun: 0, timerid: 0, addr: 0x0, band: 0, fd: 0, addr_lsb: 0, lower: 0x0, upper: 0x0, pkey: 0, call_addr: 0x0, syscall: 0, arch: 0 }, options: WNOHANG|WEXITED) = 0 (success)\n"
);

syscall_test!(
    test_waitid_failed,
    {
        use pinchy_common::{syscalls::SYS_waitid, WaitidData};

        let data = WaitidData {
            idtype: libc::P_PID,
            id: 9999,
            infop: Default::default(),
            options: libc::WEXITED,
            has_infop: false,
        };

        crate::tests::make_compact_test_data(SYS_waitid, 6001, -1, &data)
    },
    "6001 waitid(idtype: P_PID, id: 9999, infop: NULL, options: WEXITED) = -1 (error)\n"
);

syscall_test!(
    test_getrusage_self,
    {

        use pinchy_common::{
            kernel_types::Rusage, syscalls::SYS_getrusage, GetrusageData,
        };

        let data = GetrusageData {
                    who: libc::RUSAGE_SELF,
                    rusage: Rusage {
                        ru_utime: pinchy_common::kernel_types::Timeval {
                            tv_sec: 1,
                            tv_usec: 250000,
                        },
                        ru_stime: pinchy_common::kernel_types::Timeval {
                            tv_sec: 0,
                            tv_usec: 150000,
                        },
                        ru_maxrss: 2048,
                        ru_minflt: 200,
                        ru_majflt: 10,
                        ru_nvcsw: 50,
                        ru_nivcsw: 5,
                        ..Default::default()
                    },
                };

        crate::tests::make_compact_test_data(SYS_getrusage, 3001, 0, &data)
    },
    "3001 getrusage(who: RUSAGE_SELF, rusage: { ru_utime: { tv_sec: 1, tv_usec: 250000 }, ru_stime: { tv_sec: 0, tv_usec: 150000 }, ru_maxrss: 2048, ru_ixrss: 0, ru_idrss: 0, ru_isrss: 0, ru_minflt: 200, ru_majflt: 10, ru_nswap: 0, ru_inblock: 0, ru_oublock: 0, ru_msgsnd: 0, ru_msgrcv: 0, ru_nsignals: 0, ru_nvcsw: 50, ru_nivcsw: 5 }) = 0 (success)\n"
);

syscall_test!(
    test_getrusage_children,
    {

        use pinchy_common::{
            kernel_types::Rusage, syscalls::SYS_getrusage, GetrusageData,
        };

        let data = GetrusageData {
                    who: libc::RUSAGE_CHILDREN,
                    rusage: Rusage {
                        ru_utime: pinchy_common::kernel_types::Timeval {
                            tv_sec: 5,
                            tv_usec: 750000,
                        },
                        ru_stime: pinchy_common::kernel_types::Timeval {
                            tv_sec: 2,
                            tv_usec: 500000,
                        },
                        ru_maxrss: 4096,
                        ru_inblock: 100,
                        ru_oublock: 50,
                        ..Default::default()
                    },
                };

        crate::tests::make_compact_test_data(SYS_getrusage, 4001, 0, &data)
    },
    "4001 getrusage(who: RUSAGE_CHILDREN, rusage: { ru_utime: { tv_sec: 5, tv_usec: 750000 }, ru_stime: { tv_sec: 2, tv_usec: 500000 }, ru_maxrss: 4096, ru_ixrss: 0, ru_idrss: 0, ru_isrss: 0, ru_minflt: 0, ru_majflt: 0, ru_nswap: 0, ru_inblock: 100, ru_oublock: 50, ru_msgsnd: 0, ru_msgrcv: 0, ru_nsignals: 0, ru_nvcsw: 0, ru_nivcsw: 0 }) = 0 (success)\n"
);

syscall_test!(
    test_getrusage_error,
    {
        use pinchy_common::{syscalls::SYS_getrusage, GetrusageData};

        let data = GetrusageData {
            who: 999,
            rusage: Default::default(),
        };

        crate::tests::make_compact_test_data(SYS_getrusage, 5001, -22, &data)
    },
    "5001 getrusage(who: UNKNOWN, rusage: NULL) = -22 (error)\n"
);

syscall_test!(
    test_clone3,
    {
        let data = Clone3Data {
                    cl_args: CloneArgs {
                        flags: 0x11200,
                        pidfd: 0,
                        child_tid: 0x7fff12345678,
                        parent_tid: 0x7fff87654321,
                        exit_signal: 17,
                        stack: 0x7fff00001000,
                        stack_size: 8192,
                        tls: 0x7fff00002000,
                        set_tid: 0,
                        set_tid_size: 0,
                        cgroup: 0,
                    },
                    size: 88,
                    set_tid_count: 0,
                    set_tid_array: [0; pinchy_common::CLONE_SET_TID_MAX],
                };

        crate::tests::make_compact_test_data(SYS_clone3, 1001, 1234, &data)
    },
    "1001 clone3(cl_args: { flags: 0x11200 (CLONE_FS|CLONE_PIDFD|CLONE_THREAD), pidfd: 0x0, child_tid: 0x7fff12345678, parent_tid: 0x7fff87654321, exit_signal: 17, stack: 0x7fff00001000, stack_size: 8192, tls: 0x7fff00002000 }, size: 88) = 1234 (pid)\n"
);

syscall_test!(
    test_clone3_with_set_tid,
    {

        use pinchy_common::{
            kernel_types::CloneArgs, syscalls::SYS_clone3, Clone3Data,
        };

        let data = Clone3Data {
                    cl_args: CloneArgs {
                        flags: 0x11200,
                        pidfd: 0,
                        child_tid: 0x7fff12345678,
                        parent_tid: 0x7fff87654321,
                        exit_signal: 17,
                        stack: 0x7fff00001000,
                        stack_size: 8192,
                        tls: 0x7fff00002000,
                        set_tid: 0x7fff00003000,
                        set_tid_size: 3,
                        cgroup: 0,
                    },
                    size: 88,
                    set_tid_count: 3,
                    set_tid_array: [7, 42, 31496, 0, 0, 0, 0, 0],
                };

        crate::tests::make_compact_test_data(SYS_clone3, 1001, 1234, &data)
    },
    "1001 clone3(cl_args: { flags: 0x11200 (CLONE_FS|CLONE_PIDFD|CLONE_THREAD), pidfd: 0x0, child_tid: 0x7fff12345678, parent_tid: 0x7fff87654321, exit_signal: 17, stack: 0x7fff00001000, stack_size: 8192, tls: 0x7fff00002000, set_tid: [ 7, 42, 31496 ], set_tid_size: 3 }, size: 88) = 1234 (pid)\n"
);

syscall_test!(
    test_clone,
    {

        use pinchy_common::{
            CloneData, syscalls::SYS_clone, };

        let data = CloneData {
                    flags: libc::CLONE_FS as u64 | libc::CLONE_THREAD as u64 | libc::CLONE_VM as u64,
                    stack: 0x7fff00001000,
                    parent_tid: 41,
                    child_tid: 42,
                    tls: 0x7fff00002000,
                };

        crate::tests::make_compact_test_data(SYS_clone, 1001, 4321, &data)
    },
    "1001 clone(flags: 0x10300 (CLONE_VM|CLONE_FS|CLONE_THREAD), stack: 0x7fff00001000, parent_tid: 41, child_tid: 42, tls: 0x7fff00002000) = 4321 (pid)\n"
);

syscall_test!(
    test_setuid,
    {
        let data = SetuidData { uid: 1001 };

        crate::tests::make_compact_test_data(SYS_setuid, 1001, 0, &data)
    },
    "1001 setuid(uid: 1001) = 0 (success)\n"
);

syscall_test!(
    test_setgid,
    {
        let data = SetgidData { gid: 1001 };

        crate::tests::make_compact_test_data(SYS_setgid, 1001, 0, &data)
    },
    "1001 setgid(gid: 1001) = 0 (success)\n"
);

syscall_test!(
    test_setsid,
    {
        let data = SetsidData;

        crate::tests::make_compact_test_data(SYS_setsid, 1001, 1001, &data)
    },
    "1001 setsid() = 1001 (pid)\n"
);

syscall_test!(
    test_getpgid,
    {
        let data = GetpgidData { pid: 0 };

        crate::tests::make_compact_test_data(SYS_getpgid, 1001, 1234, &data)
    },
    "1001 getpgid(pid: 0) = 1234 (pid)\n"
);

syscall_test!(
    test_getsid,
    {
        let data = GetsidData { pid: 1234 };

        crate::tests::make_compact_test_data(SYS_getsid, 1001, 5678, &data)
    },
    "1001 getsid(pid: 1234) = 5678 (pid)\n"
);

syscall_test!(
    test_setpgid,
    {
        let data = SetpgidData {
            pid: 1234,
            pgid: 5678,
        };

        crate::tests::make_compact_test_data(SYS_setpgid, 1001, 0, &data)
    },
    "1001 setpgid(pid: 1234, pgid: 5678) = 0 (success)\n"
);

syscall_test!(
    test_setreuid,
    {
        let data = SetreuidData {
            ruid: 1001,
            euid: 1002,
        };

        crate::tests::make_compact_test_data(SYS_setreuid, 1001, 0, &data)
    },
    "1001 setreuid(ruid: 1001, euid: 1002) = 0 (success)\n"
);

syscall_test!(
    test_setregid,
    {
        let data = SetregidData {
            rgid: 1001,
            egid: 1002,
        };

        crate::tests::make_compact_test_data(SYS_setregid, 1001, 0, &data)
    },
    "1001 setregid(rgid: 1001, egid: 1002) = 0 (success)\n"
);

syscall_test!(
    test_setresuid,
    {
        let data = SetresuidData {
            ruid: 1001,
            euid: 1002,
            suid: 1003,
        };

        crate::tests::make_compact_test_data(SYS_setresuid, 1001, 0, &data)
    },
    "1001 setresuid(ruid: 1001, euid: 1002, suid: 1003) = 0 (success)\n"
);

syscall_test!(
    test_setresgid,
    {
        let data = SetresgidData {
            rgid: 1001,
            egid: 1002,
            sgid: 1003,
        };

        crate::tests::make_compact_test_data(SYS_setresgid, 1001, 0, &data)
    },
    "1001 setresgid(rgid: 1001, egid: 1002, sgid: 1003) = 0 (success)\n"
);

syscall_test!(
    parse_pidfd_open,
    {
        let data = PidfdOpenData {
            pid: 12345,
            flags: 0,
        };

        crate::tests::make_compact_test_data(SYS_pidfd_open, 123, 5, &data)
    },
    "123 pidfd_open(pid: 12345, flags: 0x0) = 5 (fd)\n"
);

syscall_test!(
    test_pidfd_send_signal,
    {
        let data = pinchy_common::PidfdSendSignalData {
                    pidfd: 5,
                    sig: libc::SIGKILL,
                    info: pinchy_common::kernel_types::Siginfo {
                        si_signo: 0,
                        si_errno: 0,
                        si_code: 0,
                        si_trapno: 0,
                        si_pid: 0,
                        si_uid: 0,
                        si_status: 0,
                        si_utime: 0,
                        si_stime: 0,
                        si_value: 0,
                        si_int: 0,
                        si_ptr: 0,
                        si_overrun: 0,
                        si_timerid: 0,
                        si_addr: 0,
                        si_band: 0,
                        si_fd: 0,
                        si_addr_lsb: 0,
                        si_lower: 0,
                        si_upper: 0,
                        si_pkey: 0,
                        si_call_addr: 0,
                        si_syscall: 0,
                        si_arch: 0,
                    },
                    info_ptr: 0x7fffdeadbeef,
                    flags: 0,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_pidfd_send_signal, 42, 0, &data)
    },
    "42 pidfd_send_signal(pidfd: 5, sig: SIGKILL, siginfo: { signo: 0, errno: 0, code: 0, trapno: 0, pid: 0, uid: 0, status: 0, utime: 0, stime: 0, value: 0x0, int: 0, ptr: 0x0, overrun: 0, timerid: 0, addr: 0x0, band: 0, fd: 0, addr_lsb: 0, lower: 0x0, upper: 0x0, pkey: 0, call_addr: 0x0, syscall: 0, arch: 0 }, flags: 0x0) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_alarm,
    {
        use pinchy_common::{syscalls::SYS_alarm, AlarmData};

        let data = AlarmData { seconds: 60 };

        crate::tests::make_compact_test_data(SYS_alarm, 1001, 0, &data)
    },
    "1001 alarm(seconds: 60) = 0\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_pause,
    {
        use pinchy_common::{syscalls::SYS_pause, PauseData};

        let data = PauseData;

        crate::tests::make_compact_test_data(SYS_pause, 1001, -4, &data)
    },
    "1001 pause() = -4 (error)\n"
);

syscall_test!(
    parse_exit,
    {
        let data = pinchy_common::ExitData { status: 42 };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_exit, 1234, 0, &data)
    },
    "1234 exit(status: 42) = 0 (success)\n"
);

syscall_test!(
    parse_exit_with_zero,
    {
        let data = pinchy_common::ExitData { status: 0 };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_exit, 9999, 0, &data)
    },
    "9999 exit(status: 0) = 0 (success)\n"
);

syscall_test!(
    test_pidfd_getfd,
    {
        let data = pinchy_common::PidfdGetfdData {
            pidfd: 5,
            targetfd: 3,
            flags: 0,
        };

        crate::tests::make_compact_test_data(SYS_pidfd_getfd, 42, 7, &data)
    },
    "42 pidfd_getfd(pidfd: 5, targetfd: 3, flags: 0x0) = 7 (fd)\n"
);

syscall_test!(
    test_process_mrelease,
    {
        let data = pinchy_common::ProcessMreleaseData { pidfd: 5, flags: 0 };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_process_mrelease,
            4321,
            0,
            &data,
        )
    },
    "4321 process_mrelease(pidfd: 5, flags: 0x0) = 0 (success)\n"
);

syscall_test!(
    parse_setns_success,
    {
        let data = SetnsData {
            fd: 5,
            nstype: libc::CLONE_NEWNET | libc::CLONE_NEWPID,
        };

        crate::tests::make_compact_test_data(SYS_setns, 123, 0, &data)
    },
    "123 setns(fd: 5, nstype: 0x60000000 (CLONE_NEWPID|CLONE_NEWNET)) = 0 (success)\n"
);

syscall_test!(
    parse_setns_all_namespaces,
    {
        let data = SetnsData { fd: 6, nstype: 0 };

        crate::tests::make_compact_test_data(SYS_setns, 123, 0, &data)
    },
    "123 setns(fd: 6, nstype: 0) = 0 (success)\n"
);

syscall_test!(
    parse_unshare_success,
    {
        let data = UnshareData {
            flags: libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWNET,
        };

        crate::tests::make_compact_test_data(SYS_unshare, 123, 0, &data)
    },
    "123 unshare(flags: 0x60020000 (CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET)) = 0 (success)\n"
);

syscall_test!(
    parse_unshare_fs_and_files,
    {
        let data = UnshareData {
            flags: libc::CLONE_FS | libc::CLONE_FILES,
        };

        crate::tests::make_compact_test_data(SYS_unshare, 123, 0, &data)
    },
    "123 unshare(flags: 0x600 (CLONE_FS|CLONE_FILES)) = 0 (success)\n"
);

syscall_test!(
    test_kcmp_equal,
    {
        let data = KcmpData {
            pid1: 1000,
            pid2: 1001,
            type_: kcmp_constants::KCMP_FILE,
            idx1: 3,
            idx2: 3,
        };

        crate::tests::make_compact_test_data(SYS_kcmp, 1000, 0, &data)
    },
    "1000 kcmp(pid1: 1000, pid2: 1001, type: KCMP_FILE, idx1: 3, idx2: 3) = 0 (equal)\n"
);

syscall_test!(
    test_getgroups,
    {
        let data = GetgroupsData {
            size: 10,
            groups: [
                1000, 1001, 1002, 1003, 1004, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            groups_read_count: 5,
        };

        crate::tests::make_compact_test_data(SYS_getgroups, 2000, 5, &data)
    },
    "2000 getgroups(size: 10, list: [1000, 1001, 1002, 1003, 1004]) = 5 (groups)\n"
);

syscall_test!(
    test_setgroups,
    {
        let data = SetgroupsData {
            size: 3,
            groups: [1000, 1001, 1002, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            groups_read_count: 3,
        };

        crate::tests::make_compact_test_data(SYS_setgroups, 3000, 0, &data)
    },
    "3000 setgroups(size: 3, list: [1000, 1001, 1002]) = 0 (success)\n"
);

syscall_test!(
    test_getresuid,
    {
        let data = GetresuidData {
            ruid: 1000,
            euid: 1000,
            suid: 1000,
        };

        crate::tests::make_compact_test_data(SYS_getresuid, 4000, 0, &data)
    },
    "4000 getresuid(ruid: 1000, euid: 1000, suid: 1000) = 0 (success)\n"
);

syscall_test!(
    test_getresgid,
    {
        let data = GetresgidData {
            rgid: 1000,
            egid: 1000,
            sgid: 1000,
        };

        crate::tests::make_compact_test_data(SYS_getresgid, 5000, 0, &data)
    },
    "5000 getresgid(rgid: 1000, egid: 1000, sgid: 1000) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_fork_parent,
    {
        let data = ForkData;

        crate::tests::make_compact_test_data(SYS_fork, 1000, 1001, &data)
    },
    "1000 fork() = 1001 (child pid)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_fork_child,
    {
        let data = ForkData;

        crate::tests::make_compact_test_data(SYS_fork, 1001, 0, &data)
    },
    "1001 fork() = 0 (child)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_fork_error,
    {
        let data = ForkData;

        crate::tests::make_compact_test_data(SYS_fork, 1000, -1, &data)
    },
    "1000 fork() = -1 (error)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_vfork_parent,
    {
        let data = VforkData;

        crate::tests::make_compact_test_data(SYS_vfork, 2000, 2001, &data)
    },
    "2000 vfork() = 2001 (child pid)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_vfork_child,
    {
        let data = VforkData;

        crate::tests::make_compact_test_data(SYS_vfork, 2001, 0, &data)
    },
    "2001 vfork() = 0 (child)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_vfork_error,
    {
        let data = VforkData;

        crate::tests::make_compact_test_data(SYS_vfork, 2000, -1, &data)
    },
    "2000 vfork() = -1 (error)\n"
);
