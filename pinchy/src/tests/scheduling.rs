// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    kernel_types::{Rseq, RseqCs, SchedAttr, SchedParam, Timespec},
    syscalls::{
        SYS_getpriority, SYS_rseq, SYS_sched_getaffinity, SYS_sched_getattr, SYS_sched_getparam,
        SYS_sched_rr_get_interval, SYS_sched_setaffinity, SYS_sched_setattr, SYS_sched_setparam,
        SYS_sched_yield, SYS_setpriority,
    },
    GetpriorityData, SchedGetaffinityData, SchedGetattrData, SchedGetparamData,
    SchedRrGetIntervalData, SchedSetaffinityData, SchedSetattrData, SchedSetparamData,
    SchedYieldData, SetpriorityData,
};

use crate::syscall_test;

syscall_test!(
    parse_sched_yield,
    {
        let data = SchedYieldData {};

        crate::tests::make_compact_test_data(SYS_sched_yield, 22, 0, &data)
    },
    "22 sched_yield() = 0\n"
);

syscall_test!(
    parse_rseq_valid,
    {
        let data = pinchy_common::RseqData {
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
                };

        crate::tests::make_compact_test_data(SYS_rseq, 1234, 0, &data)
    },
    "1234 rseq(rseq: 0x7f1234560000, rseq_len: 32, flags: 0, signature: 0xabcdef12, rseq content: { cpu_id_start: 0, cpu_id: -1, rseq_cs: { version: 0, flags: RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT, start_ip: 0x7f1234580000, post_commit_offset: 0x100, abort_ip: 0x7f1234590000 }, flags: 0, node_id: 0, mm_cid: 0 }) = 0 (success)\n"
);

syscall_test!(
    parse_rseq_null,
    {
        let data = pinchy_common::RseqData {
            rseq_ptr: 0,
            rseq_len: 32,
            flags: 0,
            signature: 0xabcdef12,
            rseq: Rseq::default(),
            has_rseq: false,
            rseq_cs: RseqCs::default(),
            has_rseq_cs: true,
        };

        crate::tests::make_compact_test_data(SYS_rseq, 1234, -22, &data)
    },
    "1234 rseq(rseq: NULL, rseq_len: 32, flags: 0, signature: 0xabcdef12) = -22 (error)\n"
);

syscall_test!(
    parse_rseq_unregister,
    {
        let data = pinchy_common::RseqData {
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
                };

        crate::tests::make_compact_test_data(SYS_rseq, 1234, 0, &data)
    },
    "1234 rseq(rseq: 0x7f1234560000, rseq_len: 32, flags: RSEQ_FLAG_UNREGISTER, signature: 0xabcdef12, rseq content: { cpu_id_start: 0, cpu_id: 2, rseq_cs: { version: 0, flags: RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT, start_ip: 0x7f1234580000, post_commit_offset: 0x100, abort_ip: 0x7f1234590000 }, flags: 0, node_id: 0, mm_cid: 0 }) = 0 (success)\n"
);

syscall_test!(
    test_getpriority,
    {
        let data = GetpriorityData { which: 0, who: 0 };

        crate::tests::make_compact_test_data(SYS_getpriority, 1001, 0, &data)
    },
    "1001 getpriority(which: PRIO_PROCESS, who: 0) = 0\n"
);

syscall_test!(
    test_setpriority,
    {
        let data = SetpriorityData {
            which: 0,
            who: 0,
            prio: 10,
        };

        crate::tests::make_compact_test_data(SYS_setpriority, 1001, 0, &data)
    },
    "1001 setpriority(which: PRIO_PROCESS, who: 0, prio: 10) = 0 (success)\n"
);

syscall_test!(
    parse_sched_getscheduler,
    {
        let data = pinchy_common::SchedGetschedulerData { pid: 1234 };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_sched_getscheduler,
            2468,
            0,
            &data,
        )
    },
    "2468 sched_getscheduler(pid: 1234) = 0 (success)\n"
);

syscall_test!(
    parse_sched_getscheduler_self,
    {
        let data = pinchy_common::SchedGetschedulerData { pid: 0 };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_sched_getscheduler,
            9999,
            1,
            &data,
        )
    },
    "9999 sched_getscheduler(pid: 0) = 1\n"
);

syscall_test!(
    parse_sched_get_priority_max,
    {
        let data = pinchy_common::SchedGetPriorityMaxData {
            policy: libc::SCHED_FIFO,
        };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_sched_get_priority_max,
            1357,
            99,
            &data,
        )
    },
    "1357 sched_get_priority_max(policy: SCHED_FIFO) = 99\n"
);

syscall_test!(
    parse_sched_get_priority_min,
    {
        let data = pinchy_common::SchedGetPriorityMinData {
            policy: libc::SCHED_FIFO,
        };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_sched_get_priority_min,
            2468,
            1,
            &data,
        )
    },
    "2468 sched_get_priority_min(policy: SCHED_FIFO) = 1\n"
);

syscall_test!(
    parse_sched_get_priority_max_normal,
    {
        let data = pinchy_common::SchedGetPriorityMaxData {
            policy: libc::SCHED_OTHER,
        };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_sched_get_priority_max,
            8642,
            0,
            &data,
        )
    },
    "8642 sched_get_priority_max(policy: SCHED_OTHER) = 0 (success)\n"
);

syscall_test!(
    parse_sched_setscheduler,
    {
        let data = pinchy_common::SchedSetschedulerData {
                    pid: 1234,
                    policy: libc::SCHED_FIFO,
                    param: pinchy_common::kernel_types::SchedParam { sched_priority: 50 },
                    has_param: true,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_sched_setscheduler, 1234, 0, &data)
    },
    "1234 sched_setscheduler(pid: 1234, policy: SCHED_FIFO, param: { sched_priority: 50 }) = 0 (success)\n"
);

syscall_test!(
    parse_sched_setscheduler_with_reset_on_fork,
    {
        let data = pinchy_common::SchedSetschedulerData {
                    pid: 0,
                    policy: libc::SCHED_RR | libc::SCHED_RESET_ON_FORK,
                    param: pinchy_common::kernel_types::SchedParam { sched_priority: 10 },
                    has_param: true,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_sched_setscheduler, 5678, 0, &data)
    },
    "5678 sched_setscheduler(pid: 0, policy: SCHED_RR|SCHED_RESET_ON_FORK, param: { sched_priority: 10 }) = 0 (success)\n"
);

syscall_test!(
    parse_sched_setscheduler_null_param,
    {
        let data = pinchy_common::SchedSetschedulerData {
            pid: 1234,
            policy: libc::SCHED_OTHER,
            param: pinchy_common::kernel_types::SchedParam::default(),
            has_param: false,
        };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_sched_setscheduler,
            9999,
            -22,
            &data,
        )
    },
    "9999 sched_setscheduler(pid: 1234, policy: SCHED_OTHER, param: NULL) = -22 (error)\n"
);

syscall_test!(
    parse_sched_getaffinity,
    {
        let data = SchedGetaffinityData {
            pid: 42,
            cpusetsize: 8,
            mask: 0x7fffdeadbeef,
        };

        crate::tests::make_compact_test_data(SYS_sched_getaffinity, 42, 8, &data)
    },
    "42 sched_getaffinity(pid: 42, cpusetsize: 8, mask: 0x7fffdeadbeef) = 8 (bytes)\n"
);

syscall_test!(
    parse_sched_setaffinity,
    {
        let data = SchedSetaffinityData {
            pid: 43,
            cpusetsize: 8,
            mask: 0x7fffbeadbeef,
        };

        crate::tests::make_compact_test_data(SYS_sched_setaffinity, 43, 0, &data)
    },
    "43 sched_setaffinity(pid: 43, cpusetsize: 8, mask: 0x7fffbeadbeef) = 0 (success)\n"
);

syscall_test!(
    parse_sched_getparam,
    {
        let data = SchedGetparamData {
            pid: 44,
            param: SchedParam { sched_priority: 10 },
            has_param: true,
        };

        crate::tests::make_compact_test_data(SYS_sched_getparam, 44, 0, &data)
    },
    "44 sched_getparam(pid: 44, param: { sched_priority: 10 }) = 0 (success)\n"
);

syscall_test!(
    parse_sched_setparam,
    {
        let data = SchedSetparamData {
            pid: 45,
            param: SchedParam { sched_priority: 20 },
            has_param: true,
        };

        crate::tests::make_compact_test_data(SYS_sched_setparam, 45, 0, &data)
    },
    "45 sched_setparam(pid: 45, param: { sched_priority: 20 }) = 0 (success)\n"
);

syscall_test!(
    parse_sched_rr_get_interval,
    {
        let data = SchedRrGetIntervalData {
            pid: 46,
            interval: Timespec {
                seconds: 1,
                nanos: 5000000,
            },
        };

        crate::tests::make_compact_test_data(SYS_sched_rr_get_interval, 46, 0, &data)
    },
    "46 sched_rr_get_interval(pid: 46, interval: { secs: 1, nanos: 5000000 }) = 0 (success)\n"
);

syscall_test!(
    parse_sched_getattr,
    {
        let data = SchedGetattrData {
                    pid: 123,
                    size: 56,
                    flags: 0x41,
                    attr: SchedAttr {
                        size: 56,
                        sched_policy: 2,
                        sched_flags: 0x41,
                        sched_nice: 0,
                        sched_priority: 10,
                        sched_runtime: 1000000,
                        sched_deadline: 2000000,
                        sched_period: 3000000,
                        sched_util_min: 0,
                        sched_util_max: 0,
                    },
                };

        crate::tests::make_compact_test_data(SYS_sched_getattr, 123, 0, &data)
    },
    "123 sched_getattr(pid: 123, size: 56, flags: RESET_ON_FORK|UTIL_CLAMP_MAX, attr: { size: 56, sched_policy: SCHED_RR, sched_flags: RESET_ON_FORK|UTIL_CLAMP_MAX, sched_nice: 0, sched_priority: 10, sched_runtime: 1000000, sched_deadline: 2000000, sched_period: 3000000, sched_util_min: 0, sched_util_max: 0 }) = 0 (success)\n"
);

syscall_test!(
    parse_sched_setattr,
    {
        let data = SchedSetattrData {
                    pid: 456,
                    flags: 0x8,
                    attr: SchedAttr {
                        size: 56,
                        sched_policy: 0,
                        sched_flags: 0x8,
                        sched_nice: 5,
                        sched_priority: 0,
                        sched_runtime: 0,
                        sched_deadline: 0,
                        sched_period: 0,
                        sched_util_min: 0,
                        sched_util_max: 0,
                    },
                };

        crate::tests::make_compact_test_data(SYS_sched_setattr, 456, 0, &data)
    },
    "456 sched_setattr(pid: 456, flags: KEEP_POLICY, attr: { size: 56, sched_policy: SCHED_OTHER, sched_flags: KEEP_POLICY, sched_nice: 5, sched_priority: 0, sched_runtime: 0, sched_deadline: 0, sched_period: 0, sched_util_min: 0, sched_util_max: 0 }) = 0 (success)\n"
);
