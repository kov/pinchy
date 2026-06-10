// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    kernel_types::{FutexWaitv, Timespec},
    syscalls::{
        SYS_futex, SYS_futex_waitv, SYS_get_robust_list, SYS_set_robust_list, SYS_set_tid_address,
    },
    FutexData, FutexWaitvData, GetRobustListData, SetRobustListData, SetTidAddressData,
};

use crate::syscall_test;

syscall_test!(
    parse_futex,
    {
        let data = FutexData {
                    uaddr: 0xbeef,
                    op: 10,
                    val: 11,
                    uaddr2: 0xbeef2,
                    val3: 12,
                    timeout: Timespec {
                        seconds: 13,
                        nanos: 14,
                    },
                };

        crate::tests::make_compact_test_data(SYS_futex, 22, 0, &data)
    },
    "22 futex(uaddr: 0xbeef, op: 10, val: 11, uaddr2: 0xbeef2, val3: 12, timeout: { secs: 13, nanos: 14 }) = 0 (success)\n"
);

syscall_test!(
    parse_set_robust_list,
    {
        let data = SetRobustListData {
            head: 0x7f1234560000,
            len: 24,
        };

        crate::tests::make_compact_test_data(SYS_set_robust_list, 1234, 0, &data)
    },
    "1234 set_robust_list(head: 0x7f1234560000, len: 24) = 0 (success)\n"
);

syscall_test!(
    parse_set_robust_list_error,
    {
        let data = SetRobustListData {
            head: 0x7f1234560000,
            len: 0,
        };

        crate::tests::make_compact_test_data(SYS_set_robust_list, 1234, -22, &data)
    },
    "1234 set_robust_list(head: 0x7f1234560000, len: 0) = -22 (EINVAL: Invalid argument)\n"
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
    parse_set_tid_address_null,
    {
        let data = SetTidAddressData { tidptr: 0 };

        crate::tests::make_compact_test_data(SYS_set_tid_address, 5678, 5678, &data)
    },
    "5678 set_tid_address(tidptr: 0x0) = 5678\n"
);

syscall_test!(
    parse_futex_waitv,
    {
        let mut data = FutexWaitvData {
            waiters: [FutexWaitv::default(); 4],
            nr_waiters: 2,
            flags: 0,
            has_timeout: true,
            timeout: Timespec {
                seconds: 5,
                nanos: 6,
            },
            clockid: libc::CLOCK_MONOTONIC,
        };

        {
            data.waiters[0].uaddr = 0xbeef;
            data.waiters[0].val = 1;
            data.waiters[1].uaddr = 0xbeef2;
            data.waiters[1].val = 2;
        }

        crate::tests::make_compact_test_data(SYS_futex_waitv, 42, 1, &data)
    },
    "42 futex_waitv(waiters: [ waiter { uaddr: 0xbeef, val: 1, flags: 0 }, waiter { uaddr: 0xbeef2, val: 2, flags: 0 } ], nr_waiters: 2, flags: 0, timeout: { secs: 5, nanos: 6 }, clockid: CLOCK_MONOTONIC) = 1 (woken)\n"
);

syscall_test!(
    parse_get_robust_list,
    {
        let data = GetRobustListData {
            pid: 1234,
            head: 0x7f1234560000,
            len: 24,
        };

        crate::tests::make_compact_test_data(SYS_get_robust_list, 123, 0, &data)
    },
    "123 get_robust_list(pid: 1234, head: 0x7f1234560000, len: 24) = 0 (success)\n"
);

syscall_test!(
    parse_get_robust_list_error,
    {
        let data = GetRobustListData { pid: 1234, head: 0, len: 0 };

        crate::tests::make_compact_test_data(SYS_get_robust_list, 123, -22, &data)
    },
    "123 get_robust_list(pid: 1234, head: (content unavailable), len: (content unavailable)) = -22 (EINVAL: Invalid argument)\n"
);

syscall_test!(
    parse_futex_wake,
    {
        let data = pinchy_common::FutexWakeData {
            uaddr: 0xbeef,
            mask: u32::MAX as u64,
            nr: 1,
            flags: 0,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_futex_wake, 42, 1, &data)
    },
    "42 futex_wake(uaddr: 0xbeef, mask: 0xffffffff, nr: 1, flags: 0) = 1 (woken)\n"
);

syscall_test!(
    parse_futex_wait,
    {
        let data = pinchy_common::FutexWaitData {
            uaddr: 0xbeef,
            val: 0,
            mask: u32::MAX as u64,
            flags: 0,
            has_timeout: true,
            timeout: Timespec {
                seconds: 1,
                nanos: 500,
            },
            clockid: libc::CLOCK_MONOTONIC,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_futex_wait, 42, 0, &data)
    },
    "42 futex_wait(uaddr: 0xbeef, val: 0, mask: 0xffffffff, flags: 0, timeout: { secs: 1, nanos: 500 }, clockid: CLOCK_MONOTONIC) = 0 (success)\n"
);

syscall_test!(
    parse_futex_requeue,
    {
        let mut data = pinchy_common::FutexRequeueData {
            waiters: [FutexWaitv::default(); pinchy_common::FUTEX_REQUEUE_WAITERS],
            has_waiters: true,
            flags: 0,
            nr_wake: 1,
            nr_requeue: 1,
        };

        data.waiters[0].uaddr = 0xbeef;
        data.waiters[0].val = 1;
        data.waiters[1].uaddr = 0xbeef2;
        data.waiters[1].val = 2;

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_futex_requeue,
            42,
            1,
            &data,
        )
    },
    "42 futex_requeue(waiters: [ waiter { uaddr: 0xbeef, val: 1, flags: 0 }, waiter { uaddr: 0xbeef2, val: 2, flags: 0 } ], flags: 0, nr_wake: 1, nr_requeue: 1) = 1 (woken)\n"
);
