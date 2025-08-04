// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::helpers::bpf_probe_read_user;
use pinchy_common::kernel_types::{Rseq, RseqCs, SchedParam};

use crate::{syscall_handler, util::read_timespec};

syscall_handler!(rseq, args, data, {
    let rseq_ptr = args[0] as *const Rseq;
    data.rseq_ptr = rseq_ptr as u64;
    data.rseq_len = args[1] as u32;
    data.flags = args[2] as i32;
    data.signature = args[3] as u32;

    data.has_rseq = !rseq_ptr.is_null();
    if data.has_rseq {
        if let Ok(val) = unsafe { bpf_probe_read_user::<Rseq>(rseq_ptr as *const _) } {
            data.rseq = val;
        }
    }

    data.has_rseq_cs = false;
    if data.has_rseq && data.rseq.rseq_cs != 0 {
        let rseq_cs_ptr = data.rseq.rseq_cs as *const RseqCs;
        if let Ok(val) = unsafe { bpf_probe_read_user::<RseqCs>(rseq_cs_ptr) } {
            data.rseq_cs = val;
            data.has_rseq_cs = true;
        }
    }
});

syscall_handler!(sched_setscheduler, args, data, {
    data.pid = args[0] as i32;
    data.policy = args[1] as i32;

    let param_ptr = args[2] as *const SchedParam;
    data.has_param = !param_ptr.is_null();
    if data.has_param {
        if let Ok(val) = unsafe { bpf_probe_read_user::<SchedParam>(param_ptr) } {
            data.param = val;
        }
    }
});

syscall_handler!(sched_getaffinity, args, data, {
    data.pid = args[0] as i32;
    data.cpusetsize = args[1];
    data.mask = args[2];
});

syscall_handler!(sched_setaffinity, args, data, {
    data.pid = args[0] as i32;
    data.cpusetsize = args[1];
    data.mask = args[2];
});

syscall_handler!(sched_getparam, args, data, {
    data.pid = args[0] as i32;

    let param_ptr = args[1] as *const SchedParam;
    data.has_param = !param_ptr.is_null();
    if data.has_param {
        if let Ok(val) = unsafe { bpf_probe_read_user::<SchedParam>(param_ptr) } {
            data.param = val;
        }
    }
});

syscall_handler!(sched_setparam, args, data, {
    data.pid = args[0] as i32;

    let param_ptr = args[1] as *const SchedParam;
    data.has_param = !param_ptr.is_null();
    if data.has_param {
        if let Ok(val) = unsafe { bpf_probe_read_user::<SchedParam>(param_ptr) } {
            data.param = val;
        }
    }
});

syscall_handler!(sched_rr_get_interval, args, data, {
    data.pid = args[0] as i32;
    data.interval = read_timespec(args[1] as *const _);
});
