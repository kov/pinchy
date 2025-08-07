// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    syscalls::{
        SYS_rt_sigaction, SYS_rt_sigpending, SYS_rt_sigprocmask, SYS_rt_sigqueueinfo,
        SYS_rt_sigsuspend, SYS_rt_sigtimedwait, SYS_rt_tgsigqueueinfo,
    },
    RtSigactionData, RtSigpendingData, RtSigprocmaskData, RtSigqueueinfoData, RtSigsuspendData,
    RtSigtimedwaitData, RtTgsigqueueinfoData, SyscallEvent,
};

use crate::syscall_test;

syscall_test!(
    parse_rt_sigprocmask,
    {
        SyscallEvent {
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
                    set_data: pinchy_common::kernel_types::Sigset::default(),
                    oldset_data: pinchy_common::kernel_types::Sigset::default(),
                    has_set_data: false,
                    has_oldset_data: false,
                },
            },
        }
    },
    "1234 rt_sigprocmask(how: SIG_BLOCK, set: 0x7fff12345678, oldset: 0x7fff87654321, sigsetsize: 8) = 0\n"
);

syscall_test!(
    parse_rt_sigprocmask_with_sigset,
    {
        let mut set_data = pinchy_common::kernel_types::Sigset::default();
        let mut libc_set: libc::sigset_t = unsafe { std::mem::zeroed() };

        unsafe {
            libc::sigemptyset(&mut libc_set);
            libc::sigaddset(&mut libc_set, libc::SIGTERM);
            libc::sigaddset(&mut libc_set, libc::SIGUSR1);
        }

        let set_len = set_data.bytes.len();
        set_data.bytes.copy_from_slice(
            unsafe {
                std::slice::from_raw_parts(
                    &libc_set as *const _ as *const u8,
                    set_len,
                )
            }
        );

        let mut oldset_data = pinchy_common::kernel_types::Sigset::default();
        let mut libc_oldset: libc::sigset_t = unsafe { std::mem::zeroed() };

        unsafe {
            libc::sigemptyset(&mut libc_oldset);
            libc::sigaddset(&mut libc_oldset, libc::SIGINT);
        }

        let oldset_len = oldset_data.bytes.len();
        oldset_data.bytes.copy_from_slice(
            unsafe {
                std::slice::from_raw_parts(
                    &libc_oldset as *const _ as *const u8,
                    oldset_len,
                )
            }
        );

        SyscallEvent {
            syscall_nr: SYS_rt_sigprocmask,
            pid: 5678,
            tid: 5678,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rt_sigprocmask: RtSigprocmaskData {
                    how: libc::SIG_BLOCK,
                    set: 0x7fff12345678,
                    oldset: 0x7fff87654321,
                    sigsetsize: 8,
                    set_data,
                    oldset_data,
                    has_set_data: true,
                    has_oldset_data: true,
                },
            },
        }
    },
    "5678 rt_sigprocmask(how: SIG_BLOCK, set: [SIGUSR1|SIGTERM], oldset: [SIGINT], sigsetsize: 8) = 0\n"
);

syscall_test!(
    parse_rt_sigprocmask_null_set,
    {
        SyscallEvent {
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
                    set_data: pinchy_common::kernel_types::Sigset::default(),
                    oldset_data: pinchy_common::kernel_types::Sigset::default(),
                    has_set_data: false,
                    has_oldset_data: false,
                },
            },
        }
    },
    "5678 rt_sigprocmask(how: SIG_SETMASK, set: NULL, oldset: 0x7fff11223344, sigsetsize: 8) = 0\n"
);

syscall_test!(
    parse_rt_sigprocmask_unblock,
    {
        SyscallEvent {
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
                    set_data: pinchy_common::kernel_types::Sigset::default(),
                    oldset_data: pinchy_common::kernel_types::Sigset::default(),
                    has_set_data: false,
                    has_oldset_data: false,
                },
            },
        }
    },
    "9999 rt_sigprocmask(how: SIG_UNBLOCK, set: 0x7fffaabbccdd, oldset: NULL, sigsetsize: 8) = 0\n"
);

syscall_test!(
    parse_rt_sigaction,
    {
        SyscallEvent {
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
        }
    },
    "2468 rt_sigaction(signum: SIGTERM, act: 0x7fff12345678, oldact: 0x7fff87654321, sigsetsize: 8) = 0\n"
);

syscall_test!(
    parse_rt_sigaction_null_act,
    {
        SyscallEvent {
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
        }
    },
    "1357 rt_sigaction(signum: SIGUSR1, act: 0x0, oldact: 0x7fff11223344, sigsetsize: 8) = 0\n"
);

syscall_test!(
    parse_rt_sigaction_realtime_signal,
    {
        SyscallEvent {
            syscall_nr: SYS_rt_sigaction,
            pid: 8642,
            tid: 8642,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rt_sigaction: RtSigactionData {
                    signum: libc::SIGRTMIN() + 1,
                    act: 0x7fffaabbccdd,
                    oldact: 0,
                    sigsetsize: 8,
                },
            },
        }
    },
    "8642 rt_sigaction(signum: SIGRT1, act: 0x7fffaabbccdd, oldact: 0x0, sigsetsize: 8) = 0\n"
);

syscall_test!(
    parse_tkill,
    {
        SyscallEvent {
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
        }
    },
    "1234 tkill(pid: 5678, sig: SIGTERM) = 0 (success)\n"
);

syscall_test!(
    parse_tkill_with_sigusr1,
    {
        SyscallEvent {
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
        }
    },
    "9999 tkill(pid: 1111, sig: SIGUSR1) = 0 (success)\n"
);

syscall_test!(
    parse_tgkill,
    {
        SyscallEvent {
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
        }
    },
    "2468 tgkill(tgid: 1357, pid: 2468, sig: SIGKILL) = 0 (success)\n"
);

syscall_test!(
    parse_tgkill_error,
    {
        SyscallEvent {
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
        }
    },
    "1111 tgkill(tgid: 9999, pid: 8888, sig: SIGTERM) = -3 (error)\n"
);

syscall_test!(
    parse_kill,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_kill,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                kill: pinchy_common::KillData {
                    pid: 5678,
                    signal: libc::SIGTERM,
                },
            },
        }
    },
    "1234 kill(pid: 5678, sig: SIGTERM) = 0 (success)\n"
);

syscall_test!(
    parse_kill_with_sigkill,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_kill,
            pid: 9999,
            tid: 9999,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                kill: pinchy_common::KillData {
                    pid: 1111,
                    signal: libc::SIGKILL,
                },
            },
        }
    },
    "9999 kill(pid: 1111, sig: SIGKILL) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigpending,
    {
        SyscallEvent {
            syscall_nr: SYS_rt_sigpending,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rt_sigpending: RtSigpendingData {
                    set: 0x7fff12345678,
                    sigsetsize: 8,
                    set_data: pinchy_common::kernel_types::Sigset::default(),
                    has_set_data: false,
                },
            },
        }
    },
    "1234 rt_sigpending(set: 0x7fff12345678, sigsetsize: 8) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigpending_null_set,
    {
        SyscallEvent {
            syscall_nr: SYS_rt_sigpending,
            pid: 5678,
            tid: 5678,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rt_sigpending: RtSigpendingData {
                    set: 0,
                    sigsetsize: 8,
                    set_data: pinchy_common::kernel_types::Sigset::default(),
                    has_set_data: false,
                },
            },
        }
    },
    "5678 rt_sigpending(set: NULL, sigsetsize: 8) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigqueueinfo,
    {
        SyscallEvent {
            syscall_nr: SYS_rt_sigqueueinfo,
            pid: 2468,
            tid: 2468,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rt_sigqueueinfo: RtSigqueueinfoData {
                    tgid: 1234,
                    sig: libc::SIGUSR1,
                    uinfo: 0x7fff12345678,
                },
            },
        }
    },
    "2468 rt_sigqueueinfo(tgid: 1234, sig: SIGUSR1, uinfo: 0x7fff12345678) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigqueueinfo_null_uinfo,
    {
        SyscallEvent {
            syscall_nr: SYS_rt_sigqueueinfo,
            pid: 1357,
            tid: 1357,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rt_sigqueueinfo: RtSigqueueinfoData {
                    tgid: 5678,
                    sig: libc::SIGTERM,
                    uinfo: 0,
                },
            },
        }
    },
    "1357 rt_sigqueueinfo(tgid: 5678, sig: SIGTERM, uinfo: 0x0) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigsuspend,
    {
        SyscallEvent {
            syscall_nr: SYS_rt_sigsuspend,
            pid: 3691,
            tid: 3691,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                rt_sigsuspend: RtSigsuspendData {
                    mask: 0x7fff87654321,
                    sigsetsize: 8,
                    mask_data: pinchy_common::kernel_types::Sigset::default(),
                    has_mask_data: false,
                },
            },
        }
    },
    "3691 rt_sigsuspend(mask: 0x7fff87654321, sigsetsize: 8) = -1 (error)\n"
);

syscall_test!(
    parse_rt_sigsuspend_null_mask,
    {
        SyscallEvent {
            syscall_nr: SYS_rt_sigsuspend,
            pid: 4815,
            tid: 4815,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                rt_sigsuspend: RtSigsuspendData {
                    mask: 0,
                    sigsetsize: 8,
                    mask_data: pinchy_common::kernel_types::Sigset::default(),
                    has_mask_data: false,
                },
            },
        }
    },
    "4815 rt_sigsuspend(mask: NULL, sigsetsize: 8) = -1 (error)\n"
);

syscall_test!(
    parse_rt_sigtimedwait,
    {
        SyscallEvent {
            syscall_nr: SYS_rt_sigtimedwait,
            pid: 1928,
            tid: 1928,
            return_value: 10,
            data: pinchy_common::SyscallEventData {
                rt_sigtimedwait: RtSigtimedwaitData {
                    set: 0x7fff11111111,
                    info: 0x7fff22222222,
                    timeout: 0x7fff33333333,
                    sigsetsize: 8,
                    set_data: pinchy_common::kernel_types::Sigset::default(),
                    has_set_data: false,
                },
            },
        }
    },
    "1928 rt_sigtimedwait(set: 0x7fff11111111, info: 0x7fff22222222, timeout: 0x7fff33333333, sigsetsize: 8) = 10 (signal)\n"
);

syscall_test!(
    parse_rt_sigtimedwait_null_pointers,
    {
        SyscallEvent {
            syscall_nr: SYS_rt_sigtimedwait,
            pid: 3745,
            tid: 3745,
            return_value: 15,
            data: pinchy_common::SyscallEventData {
                rt_sigtimedwait: RtSigtimedwaitData {
                    set: 0x7fff44444444,
                    info: 0,
                    timeout: 0,
                    sigsetsize: 8,
                    set_data: pinchy_common::kernel_types::Sigset::default(),
                    has_set_data: false,
                },
            },
        }
    },
    "3745 rt_sigtimedwait(set: 0x7fff44444444, info: NULL, timeout: NULL, sigsetsize: 8) = 15 (signal)\n"
);

syscall_test!(
    parse_rt_tgsigqueueinfo,
    {
        SyscallEvent {
            syscall_nr: SYS_rt_tgsigqueueinfo,
            pid: 6174,
            tid: 6174,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rt_tgsigqueueinfo: RtTgsigqueueinfoData {
                    tgid: 1234,
                    tid: 5678,
                    sig: libc::SIGUSR2,
                    uinfo: 0x7fff55555555,
                },
            },
        }
    },
    "6174 rt_tgsigqueueinfo(tgid: 1234, tid: 5678, sig: SIGUSR2, uinfo: 0x7fff55555555) = 0 (success)\n"
);

syscall_test!(
    parse_rt_tgsigqueueinfo_null_uinfo,
    {
        SyscallEvent {
            syscall_nr: SYS_rt_tgsigqueueinfo,
            pid: 8529,
            tid: 8529,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rt_tgsigqueueinfo: RtTgsigqueueinfoData {
                    tgid: 9876,
                    tid: 5432,
                    sig: 35, // SIGRT1
                    uinfo: 0,
                },
            },
        }
    },
    "8529 rt_tgsigqueueinfo(tgid: 9876, tid: 5432, sig: SIGRT1, uinfo: 0x0) = 0 (success)\n"
);
