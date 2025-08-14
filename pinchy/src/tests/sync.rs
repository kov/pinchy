// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    kernel_types::{FutexWaitv, Timespec},
    syscalls::{
        SYS_futex, SYS_futex_waitv, SYS_get_robust_list, SYS_set_robust_list, SYS_set_tid_address,
    },
    FutexData, FutexWaitvData, GetRobustListData, SetRobustListData, SetTidAddressData,
    SyscallEvent,
};

use crate::syscall_test;

syscall_test!(
    parse_futex,
    {
        SyscallEvent {
            syscall_nr: SYS_futex,
            pid: 22,
            tid: 22,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                futex: FutexData {
                    uaddr: 0xbeef,
                    op: 10,
                    val: 11,
                    uaddr2: 0xbeef2,
                    val3: 12,
                    timeout: Timespec {
                        seconds: 13,
                        nanos: 14,
                    },
                },
            },
        }
    },
    "22 futex(uaddr: 0xbeef, op: 10, val: 11, uaddr2: 0xbeef2, val3: 12, timeout: { secs: 13, nanos: 14 }) = 0 (success)\n"
);

syscall_test!(
    parse_set_robust_list,
    {
        SyscallEvent {
            syscall_nr: SYS_set_robust_list,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                set_robust_list: SetRobustListData {
                    head: 0x7f1234560000,
                    len: 24,
                },
            },
        }
    },
    "1234 set_robust_list(head: 0x7f1234560000, len: 24) = 0 (success)\n"
);

syscall_test!(
    parse_set_robust_list_error,
    {
        SyscallEvent {
            syscall_nr: SYS_set_robust_list,
            pid: 1234,
            tid: 1234,
            return_value: -22,
            data: pinchy_common::SyscallEventData {
                set_robust_list: SetRobustListData {
                    head: 0x7f1234560000,
                    len: 0,
                },
            },
        }
    },
    "1234 set_robust_list(head: 0x7f1234560000, len: 0) = -22 (error)\n"
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
    parse_set_tid_address_null,
    {
        SyscallEvent {
            syscall_nr: SYS_set_tid_address,
            pid: 5678,
            tid: 5678,
            return_value: 5678,
            data: pinchy_common::SyscallEventData {
                set_tid_address: SetTidAddressData { tidptr: 0 },
            },
        }
    },
    "5678 set_tid_address(tidptr: 0x0) = 5678\n"
);

syscall_test!(
    parse_futex_waitv,
    {
        let mut event = SyscallEvent {
            syscall_nr: SYS_futex_waitv,
            pid: 42,
            tid: 42,
            return_value: 1,
            data: pinchy_common::SyscallEventData {
                futex_waitv: FutexWaitvData {
                    waiters: [FutexWaitv::default(); 4],
                    nr_waiters: 2,
                    flags: 0,
                    has_timeout: true,
                    timeout: Timespec {
                        seconds: 5,
                        nanos: 6,
                    },
                    clockid: libc::CLOCK_MONOTONIC,
                },
            },
        };

        {
            let data = unsafe { &mut event.data.futex_waitv };
            data.waiters[0].uaddr = 0xbeef;
            data.waiters[0].val = 1;
            data.waiters[1].uaddr = 0xbeef2;
            data.waiters[1].val = 2;
        }

        event
    },
    "42 futex_waitv(waiters: [ waiter { uaddr: 0xbeef, val: 1, flags: 0x0 }, waiter { uaddr: 0xbeef2, val: 2, flags: 0x0 } ], nr_waiters: 2, flags: 0x0, timeout: { secs: 5, nanos: 6 }, clockid: CLOCK_MONOTONIC) = 1 (woken)\n"
);

syscall_test!(
    parse_get_robust_list,
    {
        SyscallEvent {
            syscall_nr: SYS_get_robust_list,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                get_robust_list: GetRobustListData {
                    pid: 1234,
                    head: 0x7f1234560000,
                    len: 24,
                },
            },
        }
    },
    "123 get_robust_list(pid: 1234, head: 0x7f1234560000, len: 24) = 0 (success)\n"
);

syscall_test!(
    parse_get_robust_list_error,
    {
        SyscallEvent {
            syscall_nr: SYS_get_robust_list,
            pid: 123,
            tid: 123,
            return_value: -22,
            data: pinchy_common::SyscallEventData {
                get_robust_list: GetRobustListData { pid: 1234, head: 0, len: 0 },
            },
        }
    },
    "123 get_robust_list(pid: 1234, head: (content unavailable), len: (content unavailable)) = -22 (error)\n"
);
