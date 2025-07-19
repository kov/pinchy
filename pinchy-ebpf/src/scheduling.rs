// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{helpers::bpf_probe_read_user, macros::tracepoint, programs::TracePointContext};
use pinchy_common::{kernel_types::Rseq, syscalls::SYS_rseq};

use crate::util::{get_args, get_return_value, output_event};

#[tracepoint]
pub fn syscall_exit_rseq(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_rseq;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let rseq_ptr = args[0] as *const Rseq;
        let rseq_len = args[1] as u32;
        let flags = args[2] as i32;
        let signature = args[3] as u32;

        // Read the rseq structure if the pointer is valid
        let mut rseq = Rseq::default();
        let has_rseq = !rseq_ptr.is_null();

        // Only try to read the rseq struct if the pointer is valid
        if has_rseq {
            if let Ok(data) = unsafe { bpf_probe_read_user::<Rseq>(rseq_ptr as *const _) } {
                rseq = data;
            }
        }

        // Read the rseq_cs structure if the rseq pointer is valid and rseq_cs is valid
        let mut rseq_cs = pinchy_common::kernel_types::RseqCs::default();
        let mut has_rseq_cs = false;

        if has_rseq && rseq.rseq_cs != 0 {
            let rseq_cs_ptr = rseq.rseq_cs as *const pinchy_common::kernel_types::RseqCs;
            if let Ok(data) =
                unsafe { bpf_probe_read_user::<pinchy_common::kernel_types::RseqCs>(rseq_cs_ptr) }
            {
                rseq_cs = data;
                has_rseq_cs = true;
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                rseq: pinchy_common::RseqData {
                    rseq_ptr: rseq_ptr as u64,
                    rseq_len,
                    flags,
                    signature,
                    rseq,
                    has_rseq,
                    rseq_cs,
                    has_rseq_cs,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}
