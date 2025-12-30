// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    syscalls::{SYS_ptrace, SYS_seccomp},
    PtraceData, SeccompData, SyscallEvent, SyscallEventData,
};

use crate::syscall_test;

syscall_test!(
    parse_ptrace_traceme_success,
    {
        SyscallEvent {
            syscall_nr: SYS_ptrace,
            pid: 5001,
            tid: 5001,
            return_value: 0,
            data: SyscallEventData {
                ptrace: PtraceData {
                    request: libc::PTRACE_TRACEME as i32,
                    pid: 0,
                    addr: 0,
                    data: 0,
                },
            },
        }
    },
    "5001 ptrace(request: PTRACE_TRACEME, pid: 0, addr: 0x0, data: 0x0) = 0 (success)\n"
);

syscall_test!(
    parse_ptrace_peektext,
    {
        SyscallEvent {
            syscall_nr: SYS_ptrace,
            pid: 5002,
            tid: 5002,
            return_value: 0,
            data: SyscallEventData {
                ptrace: PtraceData {
                    request: libc::PTRACE_PEEKTEXT as i32,
                    pid: 1234,
                    addr: 0x7fff12345678,
                    data: 0x7fff00001000,
                },
            },
        }
    },
    "5002 ptrace(request: PTRACE_PEEKTEXT, pid: 1234, addr: 0x7fff12345678, data: 0x7fff00001000) = 0 (success) (data ptr)\n"
);

syscall_test!(
    parse_ptrace_cont_error,
    {
        SyscallEvent {
            syscall_nr: SYS_ptrace,
            pid: 5003,
            tid: 5003,
            return_value: -1,
            data: SyscallEventData {
                ptrace: PtraceData {
                    request: libc::PTRACE_CONT as i32,
                    pid: 9999,
                    addr: 0,
                    data: 0,
                },
            },
        }
    },
    "5003 ptrace(request: PTRACE_CONT, pid: 9999, addr: 0x0, sig: UNKNOWN(0)) = -1 (error)\n"
);

syscall_test!(
    parse_seccomp_set_mode_strict_success,
    {
        SyscallEvent {
            syscall_nr: SYS_seccomp,
            pid: 6001,
            tid: 6001,
            return_value: 0,
            data: SyscallEventData {
                seccomp: SeccompData {
                    operation: crate::format_helpers::seccomp_constants::SECCOMP_SET_MODE_STRICT,
                    flags: 0,
                    args: 0,
                    action_avail: 0,
                    filter_len: 0,
                    notif_sizes: [0, 0, 0],
                },
            },
        }
    },
    "6001 seccomp(operation: SECCOMP_SET_MODE_STRICT, flags: 0, args: NULL) = 0 (success)\n"
);

syscall_test!(
    parse_seccomp_set_mode_filter_with_flags,
    {
        SyscallEvent {
            syscall_nr: SYS_seccomp,
            pid: 6002,
            tid: 6002,
            return_value: 0,
            data: SyscallEventData {
                seccomp: SeccompData {
                    operation: crate::format_helpers::seccomp_constants::SECCOMP_SET_MODE_FILTER,
                    flags: (libc::SECCOMP_FILTER_FLAG_TSYNC
                        | libc::SECCOMP_FILTER_FLAG_LOG) as u32,
                    args: 0x7fff87654321,
                    action_avail: 0,
                    filter_len: 16,
                    notif_sizes: [0, 0, 0],
                },
            },
        }
    },
    "6002 seccomp(operation: SECCOMP_SET_MODE_FILTER, flags: 0x3 (SECCOMP_FILTER_FLAG_TSYNC|SECCOMP_FILTER_FLAG_LOG), prog: {len: 16, filter: 0x7fff87654321}) = 0 (success)\n"
);

syscall_test!(
    parse_seccomp_get_action_avail_error,
    {
        SyscallEvent {
            syscall_nr: SYS_seccomp,
            pid: 6003,
            tid: 6003,
            return_value: -1,
            data: SyscallEventData {
                seccomp: SeccompData {
                    operation: crate::format_helpers::seccomp_constants::SECCOMP_GET_ACTION_AVAIL,
                    flags: 0,
                    args: 0,
                    action_avail: 0,
                    filter_len: 0,
                    notif_sizes: [0, 0, 0],
                },
            },
        }
    },
    "6003 seccomp(operation: SECCOMP_GET_ACTION_AVAIL, flags: 0, action: NULL) = -1 (error)\n"
);

syscall_test!(
    parse_seccomp_get_action_avail_allow,
    {
        SyscallEvent {
            syscall_nr: SYS_seccomp,
            pid: 6004,
            tid: 6004,
            return_value: 0,
            data: SyscallEventData {
                seccomp: SeccompData {
                    operation: crate::format_helpers::seccomp_constants::SECCOMP_GET_ACTION_AVAIL,
                    flags: 0,
                    args: 0x7fff00001000,
                    action_avail: crate::format_helpers::seccomp_constants::SECCOMP_RET_ALLOW,
                    filter_len: 0,
                    notif_sizes: [0, 0, 0],
                },
            },
        }
    },
    "6004 seccomp(operation: SECCOMP_GET_ACTION_AVAIL, flags: 0, action: SECCOMP_RET_ALLOW) = 0 (success)\n"
);

syscall_test!(
    parse_seccomp_get_action_avail_kill_process,
    {
        SyscallEvent {
            syscall_nr: SYS_seccomp,
            pid: 6005,
            tid: 6005,
            return_value: 0,
            data: SyscallEventData {
                seccomp: SeccompData {
                    operation: crate::format_helpers::seccomp_constants::SECCOMP_GET_ACTION_AVAIL,
                    flags: 0,
                    args: 0x7fff00002000,
                    action_avail: crate::format_helpers::seccomp_constants::SECCOMP_RET_KILL_PROCESS,
                    filter_len: 0,
                    notif_sizes: [0, 0, 0],
                },
            },
        }
    },
    "6005 seccomp(operation: SECCOMP_GET_ACTION_AVAIL, flags: 0, action: SECCOMP_RET_KILL_PROCESS) = 0 (success)\n"
);

syscall_test!(
    parse_seccomp_get_notif_sizes_success,
    {
        SyscallEvent {
            syscall_nr: SYS_seccomp,
            pid: 6006,
            tid: 6006,
            return_value: 0,
            data: SyscallEventData {
                seccomp: SeccompData {
                    operation: crate::format_helpers::seccomp_constants::SECCOMP_GET_NOTIF_SIZES,
                    flags: 0,
                    args: 0x7fff00003000,
                    action_avail: 0,
                    filter_len: 0,
                    notif_sizes: [128, 32, 64],
                },
            },
        }
    },
    "6006 seccomp(operation: SECCOMP_GET_NOTIF_SIZES, flags: 0, sizes: {notif: 128, resp: 32, data: 64}) = 0 (success)\n"
);
