// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    kernel_types::{Sigset, StackT},
    syscalls::{
        self, SYS_rt_sigaction, SYS_rt_sigpending, SYS_rt_sigprocmask, SYS_rt_sigqueueinfo,
        SYS_rt_sigsuspend, SYS_rt_sigtimedwait, SYS_rt_tgsigqueueinfo,
    },
    RtSigactionData, RtSigpendingData, RtSigprocmaskData, RtSigqueueinfoData, RtSigsuspendData,
    RtSigtimedwaitData, RtTgsigqueueinfoData,
};

use crate::syscall_test;

syscall_test!(
    parse_rt_sigprocmask,
    {
        let data = RtSigprocmaskData {
                    how: libc::SIG_BLOCK,
                    set: 0x7fff12345678,
                    oldset: 0x7fff87654321,
                    sigsetsize: 8,
                    set_data: pinchy_common::kernel_types::Sigset::default(),
                    oldset_data: pinchy_common::kernel_types::Sigset::default(),
                    has_set_data: false,
                    has_oldset_data: false,
                };

        crate::tests::make_compact_test_data(SYS_rt_sigprocmask, 1234, 0, &data)
    },
    "1234 rt_sigprocmask(how: SIG_BLOCK, set: 0x7fff12345678, oldset: 0x7fff87654321, sigsetsize: 8) = 0 (success)\n"
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

        let data = RtSigprocmaskData {
                    how: libc::SIG_BLOCK,
                    set: 0x7fff12345678,
                    oldset: 0x7fff87654321,
                    sigsetsize: 8,
                    set_data,
                    oldset_data,
                    has_set_data: true,
                    has_oldset_data: true,
                };

        crate::tests::make_compact_test_data(SYS_rt_sigprocmask, 5678, 0, &data)
    },
    "5678 rt_sigprocmask(how: SIG_BLOCK, set: [SIGUSR1|SIGTERM], oldset: [SIGINT], sigsetsize: 8) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigprocmask_null_set,
    {
        let data = RtSigprocmaskData {
                    how: libc::SIG_SETMASK,
                    set: 0,
                    oldset: 0x7fff11223344,
                    sigsetsize: 8,
                    set_data: pinchy_common::kernel_types::Sigset::default(),
                    oldset_data: pinchy_common::kernel_types::Sigset::default(),
                    has_set_data: false,
                    has_oldset_data: false,
                };

        crate::tests::make_compact_test_data(SYS_rt_sigprocmask, 5678, 0, &data)
    },
    "5678 rt_sigprocmask(how: SIG_SETMASK, set: NULL, oldset: 0x7fff11223344, sigsetsize: 8) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigprocmask_unblock,
    {
        let data = RtSigprocmaskData {
                    how: libc::SIG_UNBLOCK,
                    set: 0x7fffaabbccdd,
                    oldset: 0,
                    sigsetsize: 8,
                    set_data: pinchy_common::kernel_types::Sigset::default(),
                    oldset_data: pinchy_common::kernel_types::Sigset::default(),
                    has_set_data: false,
                    has_oldset_data: false,
                };

        crate::tests::make_compact_test_data(SYS_rt_sigprocmask, 9999, 0, &data)
    },
    "9999 rt_sigprocmask(how: SIG_UNBLOCK, set: 0x7fffaabbccdd, oldset: NULL, sigsetsize: 8) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigaction,
    {
        let data = RtSigactionData {
                    signum: libc::SIGTERM,
                    act: 0x7fff12345678,
                    oldact: 0x7fff87654321,
                    sigsetsize: 8,
                };

        crate::tests::make_compact_test_data(SYS_rt_sigaction, 2468, 0, &data)
    },
    "2468 rt_sigaction(signum: SIGTERM, act: 0x7fff12345678, oldact: 0x7fff87654321, sigsetsize: 8) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigaction_null_act,
    {
        let data = RtSigactionData {
                    signum: libc::SIGUSR1,
                    act: 0,
                    oldact: 0x7fff11223344,
                    sigsetsize: 8,
                };

        crate::tests::make_compact_test_data(SYS_rt_sigaction, 1357, 0, &data)
    },
    "1357 rt_sigaction(signum: SIGUSR1, act: 0x0, oldact: 0x7fff11223344, sigsetsize: 8) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigaction_realtime_signal,
    {
        let data = RtSigactionData {
                    signum: libc::SIGRTMIN() + 1,
                    act: 0x7fffaabbccdd,
                    oldact: 0,
                    sigsetsize: 8,
                };

        crate::tests::make_compact_test_data(SYS_rt_sigaction, 8642, 0, &data)
    },
    "8642 rt_sigaction(signum: SIGRT1, act: 0x7fffaabbccdd, oldact: 0x0, sigsetsize: 8) = 0 (success)\n"
);

syscall_test!(
    parse_tkill,
    {
        let data = pinchy_common::TkillData {
            pid: 5678,
            signal: libc::SIGTERM,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_tkill, 1234, 0, &data)
    },
    "1234 tkill(pid: 5678, sig: SIGTERM) = 0 (success)\n"
);

syscall_test!(
    parse_tkill_with_sigusr1,
    {
        let data = pinchy_common::TkillData {
            pid: 1111,
            signal: libc::SIGUSR1,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_tkill, 9999, 0, &data)
    },
    "9999 tkill(pid: 1111, sig: SIGUSR1) = 0 (success)\n"
);

syscall_test!(
    parse_tgkill,
    {
        let data = pinchy_common::TgkillData {
            tgid: 1357,
            pid: 2468,
            signal: libc::SIGKILL,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_tgkill, 2468, 0, &data)
    },
    "2468 tgkill(tgid: 1357, pid: 2468, sig: SIGKILL) = 0 (success)\n"
);

syscall_test!(
    parse_tgkill_error,
    {
        let data = pinchy_common::TgkillData {
            tgid: 9999,
            pid: 8888,
            signal: libc::SIGTERM,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_tgkill, 1111, -3, &data)
    },
    "1111 tgkill(tgid: 9999, pid: 8888, sig: SIGTERM) = -3 (error)\n"
);

syscall_test!(
    parse_kill,
    {
        let data = pinchy_common::KillData {
            pid: 5678,
            signal: libc::SIGTERM,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_kill, 1234, 0, &data)
    },
    "1234 kill(pid: 5678, sig: SIGTERM) = 0 (success)\n"
);

syscall_test!(
    parse_kill_with_sigkill,
    {
        let data = pinchy_common::KillData {
            pid: 1111,
            signal: libc::SIGKILL,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_kill, 9999, 0, &data)
    },
    "9999 kill(pid: 1111, sig: SIGKILL) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigpending,
    {
        let data = RtSigpendingData {
            set: 0x7fff12345678,
            sigsetsize: 8,
            set_data: pinchy_common::kernel_types::Sigset::default(),
            has_set_data: false,
        };

        crate::tests::make_compact_test_data(SYS_rt_sigpending, 1234, 0, &data)
    },
    "1234 rt_sigpending(set: 0x7fff12345678, sigsetsize: 8) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigpending_null_set,
    {
        let data = RtSigpendingData {
            set: 0,
            sigsetsize: 8,
            set_data: pinchy_common::kernel_types::Sigset::default(),
            has_set_data: false,
        };

        crate::tests::make_compact_test_data(SYS_rt_sigpending, 5678, 0, &data)
    },
    "5678 rt_sigpending(set: NULL, sigsetsize: 8) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigqueueinfo,
    {
        let data = RtSigqueueinfoData {
            tgid: 1234,
            sig: libc::SIGUSR1,
            uinfo: 0x7fff12345678,
        };

        crate::tests::make_compact_test_data(SYS_rt_sigqueueinfo, 2468, 0, &data)
    },
    "2468 rt_sigqueueinfo(tgid: 1234, sig: SIGUSR1, uinfo: 0x7fff12345678) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigqueueinfo_null_uinfo,
    {
        let data = RtSigqueueinfoData {
            tgid: 5678,
            sig: libc::SIGTERM,
            uinfo: 0,
        };

        crate::tests::make_compact_test_data(SYS_rt_sigqueueinfo, 1357, 0, &data)
    },
    "1357 rt_sigqueueinfo(tgid: 5678, sig: SIGTERM, uinfo: 0x0) = 0 (success)\n"
);

syscall_test!(
    parse_rt_sigsuspend,
    {
        let data = RtSigsuspendData {
            mask: 0x7fff87654321,
            sigsetsize: 8,
            mask_data: pinchy_common::kernel_types::Sigset::default(),
            has_mask_data: false,
        };

        crate::tests::make_compact_test_data(SYS_rt_sigsuspend, 3691, -1, &data)
    },
    "3691 rt_sigsuspend(mask: 0x7fff87654321, sigsetsize: 8) = -1 (error)\n"
);

syscall_test!(
    parse_rt_sigsuspend_null_mask,
    {
        let data = RtSigsuspendData {
            mask: 0,
            sigsetsize: 8,
            mask_data: pinchy_common::kernel_types::Sigset::default(),
            has_mask_data: false,
        };

        crate::tests::make_compact_test_data(SYS_rt_sigsuspend, 4815, -1, &data)
    },
    "4815 rt_sigsuspend(mask: NULL, sigsetsize: 8) = -1 (error)\n"
);

syscall_test!(
    parse_rt_sigtimedwait,
    {
        let data = RtSigtimedwaitData {
                    set: 0x7fff11111111,
                    info: 0x7fff22222222,
                    timeout: 0x7fff33333333,
                    sigsetsize: 8,
                    set_data: pinchy_common::kernel_types::Sigset::default(),
                    has_set_data: false,
                };

        crate::tests::make_compact_test_data(SYS_rt_sigtimedwait, 1928, 10, &data)
    },
    "1928 rt_sigtimedwait(set: 0x7fff11111111, info: 0x7fff22222222, timeout: 0x7fff33333333, sigsetsize: 8) = 10 (signal)\n"
);

syscall_test!(
    parse_rt_sigtimedwait_null_pointers,
    {
        let data = RtSigtimedwaitData {
                    set: 0x7fff44444444,
                    info: 0,
                    timeout: 0,
                    sigsetsize: 8,
                    set_data: pinchy_common::kernel_types::Sigset::default(),
                    has_set_data: false,
                };

        crate::tests::make_compact_test_data(SYS_rt_sigtimedwait, 3745, 15, &data)
    },
    "3745 rt_sigtimedwait(set: 0x7fff44444444, info: NULL, timeout: NULL, sigsetsize: 8) = 15 (signal)\n"
);

syscall_test!(
    parse_rt_tgsigqueueinfo,
    {
        let data = RtTgsigqueueinfoData {
                    tgid: 1234,
                    tid: 5678,
                    sig: libc::SIGUSR2,
                    uinfo: 0x7fff55555555,
                };

        crate::tests::make_compact_test_data(SYS_rt_tgsigqueueinfo, 6174, 0, &data)
    },
    "6174 rt_tgsigqueueinfo(tgid: 1234, tid: 5678, sig: SIGUSR2, uinfo: 0x7fff55555555) = 0 (success)\n"
);

syscall_test!(
    parse_rt_tgsigqueueinfo_null_uinfo,
    {
        let data = RtTgsigqueueinfoData {
            tgid: 9876,
            tid: 5432,
            sig: 35,
            uinfo: 0,
        };

        crate::tests::make_compact_test_data(SYS_rt_tgsigqueueinfo, 8529, 0, &data)
    },
    "8529 rt_tgsigqueueinfo(tgid: 9876, tid: 5432, sig: SIGRT1, uinfo: 0x0) = 0 (success)\n"
);

syscall_test!(
    parse_sigaltstack_null,
    {
        let data = pinchy_common::SigaltstackData {
            ss_ptr: 0,
            old_ss_ptr: 0,
            has_ss: false,
            has_old_ss: false,
            ss: StackT::default(),
            old_ss: StackT::default(),
        };

        crate::tests::make_compact_test_data(syscalls::SYS_sigaltstack, 100, 0, &data)
    },
    "100 sigaltstack(ss_ptr: 0x0, ss: NULL, old_ss_ptr: 0x0, old_ss: NULL) = 0 (success)\n"
);

syscall_test!(
    parse_sigaltstack_full,
    {
        let data = pinchy_common::SigaltstackData {
                    ss_ptr: 0x1234,
                    old_ss_ptr: 0x5678,
                    has_ss: true,
                    has_old_ss: true,
                    ss: StackT {
                        ss_sp: 0xdeadbeef,
                        ss_flags: libc::SS_ONSTACK | libc::SS_DISABLE,
                        ss_size: 8192,
                    },
                    old_ss: StackT {
                        ss_sp: 0xcafebabe,
                        ss_flags: 0,
                        ss_size: 4096,
                    },
                };

        crate::tests::make_compact_test_data(syscalls::SYS_sigaltstack, 101, 0, &data)
    },
    "101 sigaltstack(ss_ptr: 0x1234, ss: { ss_sp: 0xdeadbeef, ss_flags: 0x3 (SS_ONSTACK|SS_DISABLE), ss_size: 8192 }, old_ss_ptr: 0x5678, old_ss: { ss_sp: 0xcafebabe, ss_flags: 0, ss_size: 4096 }) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_signalfd,
    {

        let mut mask = Sigset::default();
        let mut libc_mask: libc::sigset_t = unsafe { std::mem::zeroed() };

        unsafe {
            libc::sigemptyset(&mut libc_mask);
            libc::sigaddset(&mut libc_mask, libc::SIGUSR1);
            libc::sigaddset(&mut libc_mask, libc::SIGTERM);
        }

        let mask_len = mask.bytes.len();
        mask.bytes.copy_from_slice(unsafe {
            std::slice::from_raw_parts(&libc_mask as *const _ as *const u8, mask_len)
        });

        let data = pinchy_common::SignalfdData {
                    fd: 5,
                    flags: libc::SFD_CLOEXEC | libc::SFD_NONBLOCK,
                    has_mask: true,
                    mask,
                };

        crate::tests::make_compact_test_data(syscalls::SYS_signalfd, 102, 5, &data)
    },
    "102 signalfd(fd: 5, mask: [SIGUSR1|SIGTERM], flags: 0x80800 (SFD_CLOEXEC|SFD_NONBLOCK)) = 5 (fd)\n"
);

syscall_test!(
    parse_signalfd4,
    {

        let mut mask = Sigset::default();
        let mut libc_mask: libc::sigset_t = unsafe { std::mem::zeroed() };

        unsafe {
            libc::sigemptyset(&mut libc_mask);
            libc::sigaddset(&mut libc_mask, libc::SIGINT);
            libc::sigaddset(&mut libc_mask, libc::SIGUSR2);
        }

        let mask_len = mask.bytes.len();
        mask.bytes.copy_from_slice(
            unsafe {
                std::slice::from_raw_parts(
                    &libc_mask as *const _ as *const u8,
                    mask_len,
                )
            }
        );

        let data = pinchy_common::Signalfd4Data {
                    fd: 6,
                    flags: libc::SFD_CLOEXEC | libc::SFD_NONBLOCK,
                    has_mask: true,
                    mask,
                };

        crate::tests::make_compact_test_data(syscalls::SYS_signalfd4, 103, 6, &data)
    },
    "103 signalfd4(fd: 6, mask: [SIGINT|SIGUSR2], flags: 0x80800 (SFD_CLOEXEC|SFD_NONBLOCK)) = 6 (fd)\n"
);
