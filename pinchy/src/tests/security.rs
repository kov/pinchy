// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    syscalls::{SYS_ptrace, SYS_seccomp},
    PtraceData, SeccompData,
};

use crate::syscall_test;

syscall_test!(
    parse_ptrace_traceme_success,
    {
        let data = PtraceData {
            request: libc::PTRACE_TRACEME as i32,
            pid: 0,
            addr: 0,
            data: 0,
        };

        crate::tests::make_compact_test_data(SYS_ptrace, 5001, 0, &data)
    },
    "5001 ptrace(request: PTRACE_TRACEME, pid: 0, addr: 0x0, data: 0x0) = 0 (success)\n"
);

syscall_test!(
    parse_ptrace_peektext,
    {
        let data = PtraceData {
                    request: libc::PTRACE_PEEKTEXT as i32,
                    pid: 1234,
                    addr: 0x7fff12345678,
                    data: 0x7fff00001000,
                };

        crate::tests::make_compact_test_data(SYS_ptrace, 5002, 0, &data)
    },
    "5002 ptrace(request: PTRACE_PEEKTEXT, pid: 1234, addr: 0x7fff12345678, data: 0x7fff00001000) = 0 (success) (data ptr)\n"
);

syscall_test!(
    parse_ptrace_cont_error,
    {
        let data = PtraceData {
            request: libc::PTRACE_CONT as i32,
            pid: 9999,
            addr: 0,
            data: 0,
        };

        crate::tests::make_compact_test_data(SYS_ptrace, 5003, -1, &data)
    },
    "5003 ptrace(request: PTRACE_CONT, pid: 9999, addr: 0x0, sig: UNKNOWN(0)) = -1 (error)\n"
);

syscall_test!(
    parse_seccomp_set_mode_strict_success,
    {
        let data = SeccompData {
            operation: crate::format_helpers::seccomp_constants::SECCOMP_SET_MODE_STRICT,
            flags: 0,
            args: 0,
            action_avail: 0,
            action_read_ok: 0,
            filter_len: 0,
            notif_sizes: [0, 0, 0],
        };

        crate::tests::make_compact_test_data(SYS_seccomp, 6001, 0, &data)
    },
    "6001 seccomp(operation: SECCOMP_SET_MODE_STRICT, flags: 0, args: NULL) = 0 (success)\n"
);

syscall_test!(
    parse_seccomp_set_mode_filter_with_flags,
    {
        let data = SeccompData {
                    operation: crate::format_helpers::seccomp_constants::SECCOMP_SET_MODE_FILTER,
                    flags: (libc::SECCOMP_FILTER_FLAG_TSYNC
                        | libc::SECCOMP_FILTER_FLAG_LOG) as u32,
                    args: 0x7fff87654321,
                    action_avail: 0,
                    action_read_ok: 0,
                    filter_len: 16,
                    notif_sizes: [0, 0, 0],
                };

        crate::tests::make_compact_test_data(SYS_seccomp, 6002, 0, &data)
    },
    "6002 seccomp(operation: SECCOMP_SET_MODE_FILTER, flags: 0x3 (SECCOMP_FILTER_FLAG_TSYNC|SECCOMP_FILTER_FLAG_LOG), prog: {len: 16, filter: 0x7fff87654321}) = 0 (success)\n"
);

syscall_test!(
    parse_seccomp_get_action_avail_error,
    {
        let data = SeccompData {
            operation: crate::format_helpers::seccomp_constants::SECCOMP_GET_ACTION_AVAIL,
            flags: 0,
            args: 0,
            action_avail: 0,
            action_read_ok: 0,
            filter_len: 0,
            notif_sizes: [0, 0, 0],
        };

        crate::tests::make_compact_test_data(SYS_seccomp, 6003, -1, &data)
    },
    "6003 seccomp(operation: SECCOMP_GET_ACTION_AVAIL, flags: 0, action: NULL) = -1 (error)\n"
);

syscall_test!(
    parse_seccomp_get_action_avail_read_failed,
    {
        let data = SeccompData {
                    operation: crate::format_helpers::seccomp_constants::SECCOMP_GET_ACTION_AVAIL,
                    flags: 0,
                    args: 0xdeadbeef,
                    action_avail: 0,
                    action_read_ok: 0,
                    filter_len: 0,
                    notif_sizes: [0, 0, 0],
                };

        crate::tests::make_compact_test_data(SYS_seccomp, 6007, -14, &data)
    },
    "6007 seccomp(operation: SECCOMP_GET_ACTION_AVAIL, flags: 0, action: 0xdeadbeef) = -14 (error)\n"
);

syscall_test!(
    parse_seccomp_get_action_avail_allow,
    {
        let data = SeccompData {
                    operation: crate::format_helpers::seccomp_constants::SECCOMP_GET_ACTION_AVAIL,
                    flags: 0,
                    args: 0x7fff00001000,
                    action_avail: crate::format_helpers::seccomp_constants::SECCOMP_RET_ALLOW,
                    action_read_ok: 1,
                    filter_len: 0,
                    notif_sizes: [0, 0, 0],
                };

        crate::tests::make_compact_test_data(SYS_seccomp, 6004, 0, &data)
    },
    "6004 seccomp(operation: SECCOMP_GET_ACTION_AVAIL, flags: 0, action: SECCOMP_RET_ALLOW) = 0 (success)\n"
);

syscall_test!(
    parse_seccomp_get_action_avail_kill_process,
    {
        let data = SeccompData {
                    operation: crate::format_helpers::seccomp_constants::SECCOMP_GET_ACTION_AVAIL,
                    flags: 0,
                    args: 0x7fff00002000,
                    action_avail: crate::format_helpers::seccomp_constants::SECCOMP_RET_KILL_PROCESS,
                    action_read_ok: 1,
                    filter_len: 0,
                    notif_sizes: [0, 0, 0],
                };

        crate::tests::make_compact_test_data(SYS_seccomp, 6005, 0, &data)
    },
    "6005 seccomp(operation: SECCOMP_GET_ACTION_AVAIL, flags: 0, action: SECCOMP_RET_KILL_PROCESS) = 0 (success)\n"
);

syscall_test!(
    parse_seccomp_get_notif_sizes_success,
    {
        let data = SeccompData {
                    operation: crate::format_helpers::seccomp_constants::SECCOMP_GET_NOTIF_SIZES,
                    flags: 0,
                    args: 0x7fff00003000,
                    action_avail: 0,
                    action_read_ok: 0,
                    filter_len: 0,
                    notif_sizes: [128, 32, 64],
                };

        crate::tests::make_compact_test_data(SYS_seccomp, 6006, 0, &data)
    },
    "6006 seccomp(operation: SECCOMP_GET_NOTIF_SIZES, flags: 0, sizes: {notif: 128, resp: 32, data: 64}) = 0 (success)\n"
);
