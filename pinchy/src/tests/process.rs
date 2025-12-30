// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#[cfg(target_arch = "x86_64")]
use pinchy_common::syscalls::SYS_getpgrp;
#[cfg(target_arch = "x86_64")]
use pinchy_common::GetpgrpData;
use pinchy_common::{
    kernel_types::CloneArgs,
    syscalls::{
        SYS_clone3, SYS_execve, SYS_execveat, SYS_getegid, SYS_geteuid, SYS_getgid, SYS_getpgid,
        SYS_getpid, SYS_getppid, SYS_getsid, SYS_gettid, SYS_getuid, SYS_pidfd_getfd,
        SYS_pidfd_open, SYS_prctl, SYS_set_tid_address, SYS_setgid, SYS_setns, SYS_setpgid,
        SYS_setregid, SYS_setresgid, SYS_setresuid, SYS_setreuid, SYS_setsid, SYS_setuid,
        SYS_unshare,
    },
    Clone3Data, ExecveData, ExecveatData, GenericSyscallData, GetegidData, GeteuidData, GetgidData,
    GetpgidData, GetpidData, GetppidData, GetsidData, GettidData, GetuidData, PidfdOpenData,
    SetTidAddressData, SetgidData, SetnsData, SetpgidData, SetregidData, SetresgidData,
    SetresuidData, SetreuidData, SetsidData, SetuidData, SyscallEvent, UnshareData,
    SMALL_READ_SIZE,
};

use crate::syscall_test;

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_getpgrp,
    {
        SyscallEvent {
            syscall_nr: SYS_getpgrp,
            pid: 1001,
            tid: 1001,
            return_value: 1001,
            data: pinchy_common::SyscallEventData {
                getpgrp: GetpgrpData,
            },
        }
    },
    "1001 getpgrp() = 1001 (pid)\n"
);

syscall_test!(
    parse_execve,
    {
        let mut event = SyscallEvent {
            syscall_nr: SYS_execve,
            pid: 22,
            tid: 22,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                execve: ExecveData {
                    filename: [0u8; SMALL_READ_SIZE * 4],
                    filename_truncated: false,
                    argv: [[0u8; SMALL_READ_SIZE]; 4],
                    argv_len: [0u16; 4],
                    argc: 0,
                    envp: [[0u8; SMALL_READ_SIZE]; 2],
                    envp_len: [0u16; 2],
                    envc: 0,
                },
            },
        };

        let execve_data = unsafe { &mut event.data.execve };
        let filename = c"/bin/find".to_bytes_with_nul();
        execve_data.filename[..filename.len()].copy_from_slice(filename);

        let argv = [
            c"/etc".to_bytes_with_nul(),
            c"-name".to_bytes_with_nul(),
            c"org.pinc".to_bytes(),
        ];
        execve_data.argv[0][..argv[0].len()].copy_from_slice(argv[0]);
        execve_data.argv_len[0] = argv[0].len() as u16;

        execve_data.argv[1][..argv[1].len()].copy_from_slice(argv[1]);
        execve_data.argv_len[1] = argv[1].len() as u16;

        execve_data.argv[2][..argv[2].len()].copy_from_slice(argv[2]);
        execve_data.argv_len[2] = argv[2].len() as u16;

        execve_data.argc = 3;

        let envp = [c"HOME=/ro".to_bytes(), c"WAYLAND=".to_bytes()];
        execve_data.envp[0][..SMALL_READ_SIZE].copy_from_slice(&envp[0][..SMALL_READ_SIZE]);
        execve_data.envp_len[0] = envp[0].len() as u16;

        execve_data.envp[1][..SMALL_READ_SIZE].copy_from_slice(&envp[1][..SMALL_READ_SIZE]);
        execve_data.envp_len[1] = envp[1].len() as u16;

        execve_data.envc = 30;

        event
    },
    "22 execve(filename: \"/bin/find\", argv: [/etc\0, -name\0, org.pinc], envp: [HOME=/ro, WAYLAND=, ... (28 more)]) = 0 (success)\n"
);

syscall_test!(
    parse_execveat,
    {
        let mut event = SyscallEvent {
            syscall_nr: SYS_execveat,
            pid: 23,
            tid: 23,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                execveat: ExecveatData {
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
                },
            },
        };

        let execveat_data = unsafe { &mut event.data.execveat };
        let pathname = c"/bin/ls".to_bytes_with_nul();
        execveat_data.pathname[..pathname.len()].copy_from_slice(pathname);

        let argv = [
            c"/bin/ls".to_bytes_with_nul(),
            c"-la".to_bytes_with_nul(),
        ];
        execveat_data.argv[0][..argv[0].len()].copy_from_slice(argv[0]);
        execveat_data.argv_len[0] = argv[0].len() as u16;

        execveat_data.argv[1][..argv[1].len()].copy_from_slice(argv[1]);
        execveat_data.argv_len[1] = argv[1].len() as u16;

        execveat_data.argc = 2;

        let envp = [c"PATH=/u".to_bytes(), c"USER=te".to_bytes()];
        execveat_data.envp[0][..envp[0].len()].copy_from_slice(envp[0]);
        execveat_data.envp_len[0] = envp[0].len() as u16;

        execveat_data.envp[1][..envp[1].len()].copy_from_slice(envp[1]);
        execveat_data.envp_len[1] = envp[1].len() as u16;

        execveat_data.envc = 5;

        event
    },
    "23 execveat(dirfd: AT_FDCWD, pathname: \"/bin/ls\", argv: [/bin/ls\0, -la\0], envp: [PATH=/u, USER=te, ... (3 more)], flags: 0x1000 (AT_EMPTY_PATH)) = 0 (success)\n"
);

syscall_test!(
    parse_prctl,
    {
        SyscallEvent {
            syscall_nr: SYS_prctl,
            pid: 999,
            tid: 999,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                generic: GenericSyscallData {
                    args: [libc::PR_SET_NAME as usize, 0x7fffffff0000, 0, 0, 0, 0],
                },
            },
        }
    },
    "999 prctl(PR_SET_NAME, 0x7fffffff0000) = 0 (success)\n"
);

syscall_test!(
    parse_set_tid_address,
    {
        SyscallEvent {
            syscall_nr: SYS_set_tid_address,
            pid: 5678,
            tid: 5678,
            return_value: 5678,
            data: pinchy_common::SyscallEventData {
                set_tid_address: SetTidAddressData {
                    tidptr: 0x7f1234560000,
                },
            },
        }
    },
    "5678 set_tid_address(tidptr: 0x7f1234560000) = 5678\n"
);

syscall_test!(
    test_getpid,
    {
        SyscallEvent {
            syscall_nr: SYS_getpid,
            pid: 1234,
            tid: 1234,
            return_value: 1234,
            data: pinchy_common::SyscallEventData { getpid: GetpidData },
        }
    },
    "1234 getpid() = 1234 (pid)\n"
);

syscall_test!(
    test_gettid,
    {
        SyscallEvent {
            syscall_nr: SYS_gettid,
            pid: 1234,
            tid: 5678,
            return_value: 5678,
            data: pinchy_common::SyscallEventData { gettid: GettidData },
        }
    },
    "5678 gettid() = 5678 (pid)\n"
);

syscall_test!(
    test_getuid,
    {
        SyscallEvent {
            syscall_nr: SYS_getuid,
            pid: 1234,
            tid: 1234,
            return_value: 1000,
            data: pinchy_common::SyscallEventData { getuid: GetuidData },
        }
    },
    "1234 getuid() = 1000 (id)\n"
);

syscall_test!(
    test_geteuid,
    {
        SyscallEvent {
            syscall_nr: SYS_geteuid,
            pid: 1234,
            tid: 1234,
            return_value: 1000,
            data: pinchy_common::SyscallEventData {
                geteuid: GeteuidData,
            },
        }
    },
    "1234 geteuid() = 1000 (id)\n"
);

syscall_test!(
    test_getgid,
    {
        SyscallEvent {
            syscall_nr: SYS_getgid,
            pid: 1234,
            tid: 1234,
            return_value: 1000,
            data: pinchy_common::SyscallEventData { getgid: GetgidData },
        }
    },
    "1234 getgid() = 1000 (id)\n"
);

syscall_test!(
    test_getegid,
    {
        SyscallEvent {
            syscall_nr: SYS_getegid,
            pid: 1234,
            tid: 1234,
            return_value: 1000,
            data: pinchy_common::SyscallEventData {
                getegid: GetegidData,
            },
        }
    },
    "1234 getegid() = 1000 (id)\n"
);

syscall_test!(
    test_getppid,
    {
        SyscallEvent {
            syscall_nr: SYS_getppid,
            pid: 1234,
            tid: 1234,
            return_value: 987,
            data: pinchy_common::SyscallEventData {
                getppid: GetppidData,
            },
        }
    },
    "1234 getppid() = 987 (pid)\n"
);

syscall_test!(
    parse_prlimit64_new_and_old,
    {
        use pinchy_common::{
            kernel_types::Rlimit, syscalls::SYS_prlimit64, PrlimitData, SyscallEvent, SyscallEventData,
        };

        SyscallEvent {
            syscall_nr: SYS_prlimit64,
            pid: 9876,
            tid: 9876,
            return_value: 0, // Success
            data: SyscallEventData {
                prlimit: PrlimitData {
                    pid: 1234,
                    resource: 7, // RLIMIT_NOFILE
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
                },
            },
        }
    },
    "9876 prlimit64(pid: 1234, resource: RLIMIT_NOFILE, new_limit: { rlim_cur: 2048, rlim_max: 4096 }, old_limit: { rlim_cur: 1024, rlim_max: 4096 }) = 0 (success)\n"
);

syscall_test!(
    parse_prlimit64_old_only,
    {
        use pinchy_common::{
            kernel_types::Rlimit, syscalls::SYS_prlimit64, PrlimitData, SyscallEvent, SyscallEventData,
        };

        SyscallEvent {
            syscall_nr: SYS_prlimit64,
            pid: 9876,
            tid: 9876,
            return_value: 0, // Success
            data: SyscallEventData {
                prlimit: PrlimitData {
                    pid: 0,      // Current process
                    resource: 3, // RLIMIT_STACK
                    has_old: true,
                    has_new: false,
                    old_limit: Rlimit {
                        rlim_cur: 8 * 1024 * 1024, // 8MB
                        rlim_max: u64::MAX,        // RLIM_INFINITY
                    },
                    new_limit: Rlimit::default(),
                },
            },
        }
    },
    "9876 prlimit64(pid: 0, resource: RLIMIT_STACK, new_limit: NULL, old_limit: { rlim_cur: 8388608, rlim_max: RLIM_INFINITY }) = 0 (success)\n"
);

syscall_test!(
    parse_prlimit64_new_only_error,
    {
        use pinchy_common::{
            kernel_types::Rlimit, syscalls::SYS_prlimit64, PrlimitData, SyscallEvent, SyscallEventData,
        };

        SyscallEvent {
            syscall_nr: SYS_prlimit64,
            pid: 9876,
            tid: 9876,
            return_value: -1, // Error
            data: SyscallEventData {
                prlimit: PrlimitData {
                    pid: 5678,
                    resource: 9, // RLIMIT_AS
                    has_old: false,
                    has_new: true,
                    old_limit: Rlimit::default(),
                    new_limit: Rlimit {
                        rlim_cur: 4 * 1024 * 1024 * 1024, // 4GB
                        rlim_max: 8 * 1024 * 1024 * 1024, // 8GB
                    },
                },
            },
        }
    },
    "9876 prlimit64(pid: 5678, resource: RLIMIT_AS, new_limit: { rlim_cur: 4294967296, rlim_max: 8589934592 }, old_limit: NULL) = -1 (error)\n"
);

syscall_test!(
    parse_fchdir,
    {
        use pinchy_common::{syscalls::SYS_fchdir, FchdirData, SyscallEvent, SyscallEventData};

        SyscallEvent {
            syscall_nr: SYS_fchdir,
            pid: 42,
            tid: 42,
            return_value: 0,
            data: SyscallEventData {
                fchdir: FchdirData { fd: 5 },
            },
        }
    },
    "42 fchdir(fd: 5) = 0 (success)\n"
);

syscall_test!(
    test_wait4_successful,
    {
        use pinchy_common::{
            kernel_types::Rusage, syscalls::SYS_wait4, SyscallEvent, SyscallEventData, Wait4Data,
        };

        SyscallEvent {
            syscall_nr: SYS_wait4,
            pid: 1000,
            tid: 1001,
            return_value: 1234, // child PID that was waited on
            data: SyscallEventData {
                wait4: Wait4Data {
                    pid: -1,    // wait for any child
                    wstatus: 0, // child exited with status 0 (WIFEXITED)
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
                },
            },
        }
    },
    "1001 wait4(pid: -1, wstatus: {WIFEXITED(s) && WEXITSTATUS(s) == 0}, options: WNOHANG|WUNTRACED|WSTOPPED, rusage: { ru_utime: { tv_sec: 0, tv_usec: 123456 }, ru_stime: { tv_sec: 0, tv_usec: 78910 }, ru_maxrss: 1024, ru_ixrss: 0, ru_idrss: 0, ru_isrss: 0, ru_minflt: 100, ru_majflt: 5, ru_nswap: 0, ru_inblock: 0, ru_oublock: 0, ru_msgsnd: 0, ru_msgrcv: 0, ru_nsignals: 0, ru_nvcsw: 0, ru_nivcsw: 0 }) = 1234\n"
);

syscall_test!(
    test_wait4_no_rusage,
    {
        use pinchy_common::{
            syscalls::SYS_wait4, SyscallEvent, SyscallEventData, Wait4Data,
        };

        SyscallEvent {
            syscall_nr: SYS_wait4,
            pid: 2000,
            tid: 2001,
            return_value: 5678,
            data: SyscallEventData {
                wait4: Wait4Data {
                    pid: 1234,       // wait for specific child
                    wstatus: 9 << 8, // child exited with status 9
                    options: 0,
                    has_rusage: false,          // no rusage requested
                    rusage: Default::default(), // should be ignored
                },
            },
        }
    },
    "2001 wait4(pid: 1234, wstatus: {WIFEXITED(s) && WEXITSTATUS(s) == 9}, options: 0, rusage: NULL) = 5678\n"
);

syscall_test!(
    test_waitid_successful,
    {
        use pinchy_common::{
            kernel_types::Siginfo, syscalls::SYS_waitid, SyscallEvent, SyscallEventData, WaitidData,
        };

        SyscallEvent {
            syscall_nr: SYS_waitid,
            pid: 4000,
            tid: 4001,
            return_value: 0, // success
            data: SyscallEventData {
                waitid: WaitidData {
                    idtype: libc::P_PID,
                    id: 1234,  // wait for child with PID 1234
                    infop: Siginfo {
                        si_signo: libc::SIGCHLD,
                        si_errno: 0,
                        si_code: 1, // CLD_EXITED
                        si_pid: 1234,
                        si_uid: 1000,
                        si_status: 0, // exit status 0
                        ..Default::default()
                    },
                    options: libc::WEXITED,
                    has_infop: true,
                },
            },
        }
    },
    "4001 waitid(idtype: P_PID, id: 1234, infop: { signo: 17, errno: 0, code: 1, trapno: 0, pid: 1234, uid: 1000, status: 0, utime: 0, stime: 0, value: 0x0, int: 0, ptr: 0x0, overrun: 0, timerid: 0, addr: 0x0, band: 0, fd: 0, addr_lsb: 0, lower: 0x0, upper: 0x0, pkey: 0, call_addr: 0x0, syscall: 0, arch: 0 }, options: WEXITED) = 0 (success)\n"
);

syscall_test!(
    test_waitid_p_all,
    {
        use pinchy_common::{
            kernel_types::Siginfo, syscalls::SYS_waitid, SyscallEvent, SyscallEventData, WaitidData,
        };

        SyscallEvent {
            syscall_nr: SYS_waitid,
            pid: 5000,
            tid: 5001,
            return_value: 0, // success
            data: SyscallEventData {
                waitid: WaitidData {
                    idtype: libc::P_ALL,
                    id: 0,     // ignored for P_ALL
                    infop: Siginfo {
                        si_signo: libc::SIGCHLD,
                        si_errno: 0,
                        si_code: 2, // CLD_KILLED
                        si_pid: 5678,
                        si_uid: 0,
                        si_status: 9, // killed by signal 9 (SIGKILL)
                        ..Default::default()
                    },
                    options: libc::WNOHANG | libc::WEXITED,
                    has_infop: true,
                },
            },
        }
    },
    "5001 waitid(idtype: P_ALL, id: 0, infop: { signo: 17, errno: 0, code: 2, trapno: 0, pid: 5678, uid: 0, status: 9, utime: 0, stime: 0, value: 0x0, int: 0, ptr: 0x0, overrun: 0, timerid: 0, addr: 0x0, band: 0, fd: 0, addr_lsb: 0, lower: 0x0, upper: 0x0, pkey: 0, call_addr: 0x0, syscall: 0, arch: 0 }, options: WNOHANG|WEXITED) = 0 (success)\n"
);

syscall_test!(
    test_waitid_failed,
    {
        use pinchy_common::{syscalls::SYS_waitid, SyscallEvent, SyscallEventData, WaitidData};

        SyscallEvent {
            syscall_nr: SYS_waitid,
            pid: 6000,
            tid: 6001,
            return_value: -1, // error (e.g., ECHILD)
            data: SyscallEventData {
                waitid: WaitidData {
                    idtype: libc::P_PID,
                    id: 9999,                  // non-existent child
                    infop: Default::default(), // not filled on error
                    options: libc::WEXITED,
                    has_infop: false, // no siginfo on error
                },
            },
        }
    },
    "6001 waitid(idtype: P_PID, id: 9999, infop: NULL, options: WEXITED) = -1 (error)\n"
);

syscall_test!(
    test_getrusage_self,
    {
        use pinchy_common::{
            kernel_types::Rusage, syscalls::SYS_getrusage, SyscallEvent, SyscallEventData, GetrusageData,
        };

        SyscallEvent {
            syscall_nr: SYS_getrusage,
            pid: 3000,
            tid: 3001,
            return_value: 0, // success
            data: SyscallEventData {
                getrusage: GetrusageData {
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
                },
            },
        }
    },
    "3001 getrusage(who: RUSAGE_SELF, rusage: { ru_utime: { tv_sec: 1, tv_usec: 250000 }, ru_stime: { tv_sec: 0, tv_usec: 150000 }, ru_maxrss: 2048, ru_ixrss: 0, ru_idrss: 0, ru_isrss: 0, ru_minflt: 200, ru_majflt: 10, ru_nswap: 0, ru_inblock: 0, ru_oublock: 0, ru_msgsnd: 0, ru_msgrcv: 0, ru_nsignals: 0, ru_nvcsw: 50, ru_nivcsw: 5 }) = 0 (success)\n"
);

syscall_test!(
    test_getrusage_children,
    {
        use pinchy_common::{
            kernel_types::Rusage, syscalls::SYS_getrusage, SyscallEvent, SyscallEventData, GetrusageData,
        };

        SyscallEvent {
            syscall_nr: SYS_getrusage,
            pid: 4000,
            tid: 4001,
            return_value: 0, // success
            data: SyscallEventData {
                getrusage: GetrusageData {
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
                },
            },
        }
    },
    "4001 getrusage(who: RUSAGE_CHILDREN, rusage: { ru_utime: { tv_sec: 5, tv_usec: 750000 }, ru_stime: { tv_sec: 2, tv_usec: 500000 }, ru_maxrss: 4096, ru_ixrss: 0, ru_idrss: 0, ru_isrss: 0, ru_minflt: 0, ru_majflt: 0, ru_nswap: 0, ru_inblock: 100, ru_oublock: 50, ru_msgsnd: 0, ru_msgrcv: 0, ru_nsignals: 0, ru_nvcsw: 0, ru_nivcsw: 0 }) = 0 (success)\n"
);

syscall_test!(
    test_getrusage_error,
    {
        use pinchy_common::{
            syscalls::SYS_getrusage, GetrusageData, SyscallEvent, SyscallEventData,
        };

        SyscallEvent {
            syscall_nr: SYS_getrusage,
            pid: 5000,
            tid: 5001,
            return_value: -22, // -EINVAL
            data: SyscallEventData {
                getrusage: GetrusageData {
                    who: 999,                   // invalid who parameter
                    rusage: Default::default(), // should be ignored for failed calls
                },
            },
        }
    },
    "5001 getrusage(who: UNKNOWN, rusage: NULL) = -22 (error)\n"
);

syscall_test!(
    test_clone3,
    {
        SyscallEvent {
            syscall_nr: SYS_clone3,
            pid: 1000,
            tid: 1001,
            return_value: 1234, // child PID
            data: pinchy_common::SyscallEventData {
                clone3: Clone3Data {
                    cl_args: CloneArgs {
                        flags: 0x11200,
                        pidfd: 0,
                        child_tid: 0x7fff12345678,
                        parent_tid: 0x7fff87654321,
                        exit_signal: 17, // SIGCHLD
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
                },
            },
        }
    },
    "1001 clone3(cl_args: { flags: 0x11200 (CLONE_FS|CLONE_PIDFD|CLONE_THREAD), pidfd: 0x0, child_tid: 0x7fff12345678, parent_tid: 0x7fff87654321, exit_signal: 17, stack: 0x7fff00001000, stack_size: 8192, tls: 0x7fff00002000 }, size: 88) = 1234 (pid)\n"
);

syscall_test!(
    test_clone3_with_set_tid,
    {
        use pinchy_common::{
            kernel_types::CloneArgs, syscalls::SYS_clone3, SyscallEvent, SyscallEventData, Clone3Data,
        };

        SyscallEvent {
            syscall_nr: SYS_clone3,
            pid: 1000,
            tid: 1001,
            return_value: 1234, // child PID
            data: SyscallEventData {
                clone3: Clone3Data {
                    cl_args: CloneArgs {
                        flags: 0x11200,
                        pidfd: 0,
                        child_tid: 0x7fff12345678,
                        parent_tid: 0x7fff87654321,
                        exit_signal: 17, // SIGCHLD
                        stack: 0x7fff00001000,
                        stack_size: 8192,
                        tls: 0x7fff00002000,
                        set_tid: 0x7fff00003000, // Pointer to set_tid array
                        set_tid_size: 3,
                        cgroup: 0,
                    },
                    size: 88,
                    set_tid_count: 3,                             // We captured 3 PIDs
                    set_tid_array: [7, 42, 31496, 0, 0, 0, 0, 0], // Example from manpage
                },
            },
        }
    },
    "1001 clone3(cl_args: { flags: 0x11200 (CLONE_FS|CLONE_PIDFD|CLONE_THREAD), pidfd: 0x0, child_tid: 0x7fff12345678, parent_tid: 0x7fff87654321, exit_signal: 17, stack: 0x7fff00001000, stack_size: 8192, tls: 0x7fff00002000, set_tid: [ 7, 42, 31496 ], set_tid_size: 3 }, size: 88) = 1234 (pid)\n"
);

syscall_test!(
    test_clone,
    {
        use pinchy_common::{
            CloneData, syscalls::SYS_clone, SyscallEvent, SyscallEventData,
        };

        SyscallEvent {
            syscall_nr: SYS_clone,
            pid: 1000,
            tid: 1001,
            return_value: 4321, // child PID
            data: SyscallEventData {
                clone: CloneData {
                    flags: libc::CLONE_FS as u64 | libc::CLONE_THREAD as u64 | libc::CLONE_VM as u64,
                    stack: 0x7fff00001000,
                    parent_tid: 41,
                    child_tid: 42,
                    tls: 0x7fff00002000,
                },
            },
        }
    },
    "1001 clone(flags: 0x10300 (CLONE_VM|CLONE_FS|CLONE_THREAD), stack: 0x7fff00001000, parent_tid: 41, child_tid: 42, tls: 0x7fff00002000) = 4321 (pid)\n"
);

syscall_test!(
    test_setuid,
    {
        SyscallEvent {
            syscall_nr: SYS_setuid,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                setuid: SetuidData { uid: 1001 },
            },
        }
    },
    "1001 setuid(uid: 1001) = 0 (success)\n"
);

syscall_test!(
    test_setgid,
    {
        SyscallEvent {
            syscall_nr: SYS_setgid,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                setgid: SetgidData { gid: 1001 },
            },
        }
    },
    "1001 setgid(gid: 1001) = 0 (success)\n"
);

syscall_test!(
    test_setsid,
    {
        SyscallEvent {
            syscall_nr: SYS_setsid,
            pid: 1000,
            tid: 1001,
            return_value: 1001,
            data: pinchy_common::SyscallEventData { setsid: SetsidData },
        }
    },
    "1001 setsid() = 1001 (pid)\n"
);

syscall_test!(
    test_getpgid,
    {
        SyscallEvent {
            syscall_nr: SYS_getpgid,
            pid: 1000,
            tid: 1001,
            return_value: 1234,
            data: pinchy_common::SyscallEventData {
                getpgid: GetpgidData { pid: 0 },
            },
        }
    },
    "1001 getpgid(pid: 0) = 1234 (pid)\n"
);

syscall_test!(
    test_getsid,
    {
        SyscallEvent {
            syscall_nr: SYS_getsid,
            pid: 1000,
            tid: 1001,
            return_value: 5678,
            data: pinchy_common::SyscallEventData {
                getsid: GetsidData { pid: 1234 },
            },
        }
    },
    "1001 getsid(pid: 1234) = 5678 (pid)\n"
);

syscall_test!(
    test_setpgid,
    {
        SyscallEvent {
            syscall_nr: SYS_setpgid,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                setpgid: SetpgidData {
                    pid: 1234,
                    pgid: 5678,
                },
            },
        }
    },
    "1001 setpgid(pid: 1234, pgid: 5678) = 0 (success)\n"
);

syscall_test!(
    test_setreuid,
    {
        SyscallEvent {
            syscall_nr: SYS_setreuid,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                setreuid: SetreuidData {
                    ruid: 1001,
                    euid: 1002,
                },
            },
        }
    },
    "1001 setreuid(ruid: 1001, euid: 1002) = 0 (success)\n"
);

syscall_test!(
    test_setregid,
    {
        SyscallEvent {
            syscall_nr: SYS_setregid,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                setregid: SetregidData {
                    rgid: 1001,
                    egid: 1002,
                },
            },
        }
    },
    "1001 setregid(rgid: 1001, egid: 1002) = 0 (success)\n"
);

syscall_test!(
    test_setresuid,
    {
        SyscallEvent {
            syscall_nr: SYS_setresuid,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                setresuid: SetresuidData {
                    ruid: 1001,
                    euid: 1002,
                    suid: 1003,
                },
            },
        }
    },
    "1001 setresuid(ruid: 1001, euid: 1002, suid: 1003) = 0 (success)\n"
);

syscall_test!(
    test_setresgid,
    {
        SyscallEvent {
            syscall_nr: SYS_setresgid,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                setresgid: SetresgidData {
                    rgid: 1001,
                    egid: 1002,
                    sgid: 1003,
                },
            },
        }
    },
    "1001 setresgid(rgid: 1001, egid: 1002, sgid: 1003) = 0 (success)\n"
);

syscall_test!(
    parse_pidfd_open,
    {
        SyscallEvent {
            syscall_nr: SYS_pidfd_open,
            pid: 123,
            tid: 123,
            return_value: 5,
            data: pinchy_common::SyscallEventData {
                pidfd_open: PidfdOpenData {
                    pid: 12345,
                    flags: 0,
                },
            },
        }
    },
    "123 pidfd_open(pid: 12345, flags: 0x0) = 5 (fd)\n"
);

syscall_test!(
    test_pidfd_send_signal,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_pidfd_send_signal,
            pid: 42,
            tid: 42,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                pidfd_send_signal: pinchy_common::PidfdSendSignalData {
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
                },
            },
        }
    },
    "42 pidfd_send_signal(pidfd: 5, sig: SIGKILL, siginfo: { signo: 0, errno: 0, code: 0, trapno: 0, pid: 0, uid: 0, status: 0, utime: 0, stime: 0, value: 0x0, int: 0, ptr: 0x0, overrun: 0, timerid: 0, addr: 0x0, band: 0, fd: 0, addr_lsb: 0, lower: 0x0, upper: 0x0, pkey: 0, call_addr: 0x0, syscall: 0, arch: 0 }, flags: 0x0) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_alarm,
    {
        use pinchy_common::{syscalls::SYS_alarm, AlarmData, SyscallEvent, SyscallEventData};

        SyscallEvent {
            syscall_nr: SYS_alarm,
            pid: 1001,
            tid: 1001,
            return_value: 0,
            data: SyscallEventData {
                alarm: AlarmData { seconds: 60 },
            },
        }
    },
    "1001 alarm(seconds: 60) = 0\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_pause,
    {
        use pinchy_common::{syscalls::SYS_pause, PauseData, SyscallEvent, SyscallEventData};

        SyscallEvent {
            syscall_nr: SYS_pause,
            pid: 1001,
            tid: 1001,
            return_value: -4, // EINTR
            data: SyscallEventData { pause: PauseData },
        }
    },
    "1001 pause() = -4 (error)\n"
);

syscall_test!(
    parse_exit,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_exit,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                exit: pinchy_common::ExitData { status: 42 },
            },
        }
    },
    "1234 exit(status: 42) = 0 (success)\n"
);

syscall_test!(
    parse_exit_with_zero,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_exit,
            pid: 9999,
            tid: 9999,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                exit: pinchy_common::ExitData { status: 0 },
            },
        }
    },
    "9999 exit(status: 0) = 0 (success)\n"
);

syscall_test!(
    test_pidfd_getfd,
    {
        SyscallEvent {
            syscall_nr: SYS_pidfd_getfd,
            pid: 42,
            tid: 42,
            return_value: 7,
            data: pinchy_common::SyscallEventData {
                pidfd_getfd: pinchy_common::PidfdGetfdData {
                    pidfd: 5,
                    targetfd: 3,
                    flags: 0,
                },
            },
        }
    },
    "42 pidfd_getfd(pidfd: 5, targetfd: 3, flags: 0x0) = 7 (fd)\n"
);

syscall_test!(
    test_process_mrelease,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_process_mrelease,
            pid: 4321,
            tid: 4321,
            return_value: 0, // Success
            data: pinchy_common::SyscallEventData {
                process_mrelease: pinchy_common::ProcessMreleaseData { pidfd: 5, flags: 0 },
            },
        }
    },
    "4321 process_mrelease(pidfd: 5, flags: 0x0) = 0 (success)\n"
);

syscall_test!(
    parse_setns_success,
    {
        SyscallEvent {
            syscall_nr: SYS_setns,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                setns: SetnsData {
                    fd: 5,
                    nstype: libc::CLONE_NEWNET | libc::CLONE_NEWPID,
                },
            },
        }
    },
    "123 setns(fd: 5, nstype: 0x60000000 (CLONE_NEWPID|CLONE_NEWNET)) = 0 (success)\n"
);

syscall_test!(
    parse_setns_all_namespaces,
    {
        SyscallEvent {
            syscall_nr: SYS_setns,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                setns: SetnsData {
                    fd: 6,
                    nstype: 0, // Join all namespaces
                },
            },
        }
    },
    "123 setns(fd: 6, nstype: 0) = 0 (success)\n"
);

syscall_test!(
    parse_unshare_success,
    {
        SyscallEvent {
            syscall_nr: SYS_unshare,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                unshare: UnshareData {
                    flags: libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWNET,
                },
            },
        }
    },
    "123 unshare(flags: 0x60020000 (CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET)) = 0 (success)\n"
);

syscall_test!(
    parse_unshare_fs_and_files,
    {
        SyscallEvent {
            syscall_nr: SYS_unshare,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                unshare: UnshareData {
                    flags: libc::CLONE_FS | libc::CLONE_FILES,
                },
            },
        }
    },
    "123 unshare(flags: 0x600 (CLONE_FS|CLONE_FILES)) = 0 (success)\n"
);
