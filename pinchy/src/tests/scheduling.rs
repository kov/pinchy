// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    kernel_types::{Rseq, RseqCs},
    syscalls::{SYS_getpriority, SYS_rseq, SYS_sched_yield, SYS_setpriority},
    GetpriorityData, SchedYieldData, SetpriorityData, SyscallEvent,
};

use crate::syscall_test;

syscall_test!(
    parse_sched_yield,
    {
        SyscallEvent {
            syscall_nr: SYS_sched_yield,
            pid: 22,
            tid: 22,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                sched_yield: SchedYieldData {},
            },
        }
    },
    "22 sched_yield() = 0\n"
);

syscall_test!(
    parse_rseq_valid,
    {
        SyscallEvent {
            syscall_nr: SYS_rseq,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rseq: pinchy_common::RseqData {
                    rseq_ptr: 0x7f1234560000,
                    rseq_len: 32,
                    flags: 0,
                    signature: 0xabcdef12,
                    rseq: Rseq {
                        cpu_id_start: 0,
                        cpu_id: 0xffffffff,
                        rseq_cs: 0x7f1234570000,
                        flags: 0,
                        node_id: 0,
                        mm_cid: 0,
                    },
                    has_rseq: true,
                    rseq_cs: RseqCs {
                        version: 0,
                        flags: 1,
                        start_ip: 0x7f1234580000,
                        post_commit_offset: 0x100,
                        abort_ip: 0x7f1234590000,
                    },
                    has_rseq_cs: true,
                },
            },
        }
    },
    "1234 rseq(rseq: 0x7f1234560000, rseq_len: 32, flags: 0, signature: 0xabcdef12, rseq content: { cpu_id_start: 0, cpu_id: -1, rseq_cs: { version: 0, flags: RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT, start_ip: 0x7f1234580000, post_commit_offset: 0x100, abort_ip: 0x7f1234590000 }, flags: 0, node_id: 0, mm_cid: 0 }) = 0\n"
);

syscall_test!(
    parse_rseq_null,
    {
        SyscallEvent {
            syscall_nr: SYS_rseq,
            pid: 1234,
            tid: 1234,
            return_value: -22,
            data: pinchy_common::SyscallEventData {
                rseq: pinchy_common::RseqData {
                    rseq_ptr: 0,
                    rseq_len: 32,
                    flags: 0,
                    signature: 0xabcdef12,
                    rseq: Rseq::default(),
                    has_rseq: false,
                    rseq_cs: RseqCs::default(),
                    has_rseq_cs: true,
                },
            },
        }
    },
    "1234 rseq(rseq: NULL, rseq_len: 32, flags: 0, signature: 0xabcdef12) = -22 (error)\n"
);

syscall_test!(
    parse_rseq_unregister,
    {
        SyscallEvent {
            syscall_nr: SYS_rseq,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rseq: pinchy_common::RseqData {
                    rseq_ptr: 0x7f1234560000,
                    rseq_len: 32,
                    flags: 1,
                    signature: 0xabcdef12,
                    rseq: Rseq {
                        cpu_id_start: 0,
                        cpu_id: 2,
                        rseq_cs: 0,
                        flags: 0,
                        node_id: 0,
                        mm_cid: 0,
                    },
                    has_rseq: true,
                    rseq_cs: RseqCs {
                        version: 0,
                        flags: 1,
                        start_ip: 0x7f1234580000,
                        post_commit_offset: 0x100,
                        abort_ip: 0x7f1234590000,
                    },
                    has_rseq_cs: true,
                },
            },
        }
    },
    "1234 rseq(rseq: 0x7f1234560000, rseq_len: 32, flags: RSEQ_FLAG_UNREGISTER, signature: 0xabcdef12, rseq content: { cpu_id_start: 0, cpu_id: 2, rseq_cs: { version: 0, flags: RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT, start_ip: 0x7f1234580000, post_commit_offset: 0x100, abort_ip: 0x7f1234590000 }, flags: 0, node_id: 0, mm_cid: 0 }) = 0\n"
);

syscall_test!(
    test_getpriority,
    {
        SyscallEvent {
            syscall_nr: SYS_getpriority,
            pid: 1001,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                getpriority: GetpriorityData { which: 0, who: 0 },
            },
        }
    },
    "1001 getpriority(which: PRIO_PROCESS, who: 0) = 0\n"
);

syscall_test!(
    test_setpriority,
    {
        SyscallEvent {
            syscall_nr: SYS_setpriority,
            pid: 1001,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                setpriority: SetpriorityData {
                    which: 0,
                    who: 0,
                    prio: 10,
                },
            },
        }
    },
    "1001 setpriority(which: PRIO_PROCESS, who: 0, prio: 10) = 0 (success)\n"
);

syscall_test!(
    parse_sched_getscheduler,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_sched_getscheduler,
            pid: 2468,
            tid: 2468,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                sched_getscheduler: pinchy_common::SchedGetschedulerData { pid: 1234 },
            },
        }
    },
    "2468 sched_getscheduler(pid: 1234) = 0\n"
);

syscall_test!(
    parse_sched_getscheduler_self,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_sched_getscheduler,
            pid: 9999,
            tid: 9999,
            return_value: 1,
            data: pinchy_common::SyscallEventData {
                sched_getscheduler: pinchy_common::SchedGetschedulerData { pid: 0 },
            },
        }
    },
    "9999 sched_getscheduler(pid: 0) = 1\n"
);

syscall_test!(
    parse_sched_get_priority_max,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_sched_get_priority_max,
            pid: 1357,
            tid: 1357,
            return_value: 99,
            data: pinchy_common::SyscallEventData {
                sched_get_priority_max: pinchy_common::SchedGetPriorityMaxData {
                    policy: libc::SCHED_FIFO,
                },
            },
        }
    },
    "1357 sched_get_priority_max(policy: SCHED_FIFO) = 99\n"
);

syscall_test!(
    parse_sched_get_priority_min,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_sched_get_priority_min,
            pid: 2468,
            tid: 2468,
            return_value: 1,
            data: pinchy_common::SyscallEventData {
                sched_get_priority_min: pinchy_common::SchedGetPriorityMinData {
                    policy: libc::SCHED_FIFO,
                },
            },
        }
    },
    "2468 sched_get_priority_min(policy: SCHED_FIFO) = 1\n"
);

syscall_test!(
    parse_sched_get_priority_max_normal,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_sched_get_priority_max,
            pid: 8642,
            tid: 8642,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                sched_get_priority_max: pinchy_common::SchedGetPriorityMaxData {
                    policy: libc::SCHED_OTHER,
                },
            },
        }
    },
    "8642 sched_get_priority_max(policy: SCHED_OTHER) = 0\n"
);

syscall_test!(
    parse_sched_setscheduler,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_sched_setscheduler,
            pid: 1234,
            tid: 1234,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                sched_setscheduler: pinchy_common::SchedSetschedulerData {
                    pid: 1234,
                    policy: libc::SCHED_FIFO,
                    param: pinchy_common::kernel_types::SchedParam { sched_priority: 50 },
                    has_param: true,
                },
            },
        }
    },
    "1234 sched_setscheduler(pid: 1234, policy: SCHED_FIFO, param: { sched_priority: 50 }) = 0 (success)\n"
);

syscall_test!(
    parse_sched_setscheduler_with_reset_on_fork,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_sched_setscheduler,
            pid: 5678,
            tid: 5678,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                sched_setscheduler: pinchy_common::SchedSetschedulerData {
                    pid: 0,
                    policy: libc::SCHED_RR | libc::SCHED_RESET_ON_FORK,
                    param: pinchy_common::kernel_types::SchedParam { sched_priority: 10 },
                    has_param: true,
                },
            },
        }
    },
    "5678 sched_setscheduler(pid: 0, policy: SCHED_RR|SCHED_RESET_ON_FORK, param: { sched_priority: 10 }) = 0 (success)\n"
);

syscall_test!(
    parse_sched_setscheduler_null_param,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_sched_setscheduler,
            pid: 9999,
            tid: 9999,
            return_value: -22,
            data: pinchy_common::SyscallEventData {
                sched_setscheduler: pinchy_common::SchedSetschedulerData {
                    pid: 1234,
                    policy: libc::SCHED_OTHER,
                    param: pinchy_common::kernel_types::SchedParam::default(),
                    has_param: false,
                },
            },
        }
    },
    "9999 sched_setscheduler(pid: 1234, policy: SCHED_OTHER, param: NULL) = -22 (error)\n"
);
