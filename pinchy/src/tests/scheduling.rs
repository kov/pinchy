// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::pin::Pin;

use pinchy_common::{
    kernel_types::{Rseq, RseqCs},
    syscalls::{SYS_rseq, SYS_sched_yield},
    SchedYieldData, SyscallEvent,
};

use crate::{
    events::handle_event,
    formatting::{Formatter, FormattingStyle},
};

#[tokio::test]
async fn parse_sched_yield() {
    let event = SyscallEvent {
        syscall_nr: SYS_sched_yield,
        pid: 22,
        tid: 22,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            sched_yield: SchedYieldData {},
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("22 sched_yield() = 0\n")
    );
}

#[tokio::test]
async fn parse_rseq() {
    // Test with valid rseq argument and valid rseq_cs
    let event = SyscallEvent {
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
                    cpu_id: 0xffffffff, // -1 value
                    rseq_cs: 0x7f1234570000,
                    flags: 0,
                    node_id: 0,
                    mm_cid: 0,
                },
                has_rseq: true,
                rseq_cs: RseqCs {
                    version: 0,
                    flags: 1, // RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT
                    start_ip: 0x7f1234580000,
                    post_commit_offset: 0x100,
                    abort_ip: 0x7f1234590000,
                },
                has_rseq_cs: true,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "1234 rseq(rseq: 0x7f1234560000, rseq_len: 32, flags: 0, signature: 0xabcdef12, rseq content: {{ cpu_id_start: 0, cpu_id: -1, rseq_cs: {{ version: 0, flags: RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT, start_ip: 0x7f1234580000, post_commit_offset: 0x100, abort_ip: 0x7f1234590000 }}, flags: 0, node_id: 0, mm_cid: 0 }}) = 0\n"
        )
    );

    // Test with NULL rseq argument
    let event = SyscallEvent {
        syscall_nr: SYS_rseq,
        pid: 1234,
        tid: 1234,
        return_value: -22, // EINVAL
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1234 rseq(rseq: NULL, rseq_len: 32, flags: 0, signature: 0xabcdef12) = -22 (error)\n"
    );

    // Test with unregister flag
    let event = SyscallEvent {
        syscall_nr: SYS_rseq,
        pid: 1234,
        tid: 1234,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            rseq: pinchy_common::RseqData {
                rseq_ptr: 0x7f1234560000,
                rseq_len: 32,
                flags: 1, // RSEQ_FLAG_UNREGISTER
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
                    flags: 1, // RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT
                    start_ip: 0x7f1234580000,
                    post_commit_offset: 0x100,
                    abort_ip: 0x7f1234590000,
                },
                has_rseq_cs: true,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "1234 rseq(rseq: 0x7f1234560000, rseq_len: 32, flags: RSEQ_FLAG_UNREGISTER, signature: 0xabcdef12, rseq content: {{ cpu_id_start: 0, cpu_id: 2, rseq_cs: {{ version: 0, flags: RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT, start_ip: 0x7f1234580000, post_commit_offset: 0x100, abort_ip: 0x7f1234590000 }}, flags: 0, node_id: 0, mm_cid: 0 }}) = 0\n"
        )
    );
}
