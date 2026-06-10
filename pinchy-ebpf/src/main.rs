// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#![feature(macro_metavar_expr_concat)]
#![no_std]
#![no_main]
#![allow(non_snake_case, non_upper_case_globals, static_mut_refs)]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{Array, HashMap, PerCpuArray, ProgramArray, RingBuf},
    programs::TracePointContext,
    EbpfContext as _,
};
use aya_log_ebpf::{error, trace};
#[cfg(feature = "efficiency-metrics")]
use pinchy_common::EFF_STAT_COUNT;
use pinchy_common::{
    syscalls, Fadvise64Data, FchmodData, FchownData, FdatasyncData, FsyncData, FtruncateData,
    FutexWakeData, KexecFileLoadData, LsmSetSelfAttrData, MapShadowStackData,
};
#[cfg(x86_64)]
use pinchy_common::{
    ArchPrctlData, DeprecatedSyscallData, IopermData, IoplData, ModifyLdtData, ThreadAreaData,
    TimeData,
};

use crate::util::{get_args, get_syscall_nr, submit_compact_payload};

mod basic_io;
mod filesystem;
mod ipc;
mod memory;
mod network;
mod process;
mod scheduling;
mod security;
mod signal;
mod sync;
mod system;
mod time;
mod util;

#[map]
static mut PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// Treated as a bitmap for syscalls.
#[map]
static mut SYSCALL_FILTER: Array<u8> = Array::with_max_entries(64, 0);

#[cfg(feature = "efficiency-metrics")]
#[map]
static mut EFFICIENCY_STATS: Array<u64> = Array::with_max_entries(EFF_STAT_COUNT, 0);

#[map] // 80MiB output buffer
static mut EVENTS: RingBuf = RingBuf::with_byte_size(83886080, 0);

#[map]
static mut ENTER_MAP: HashMap<u32, SyscallEnterData> = HashMap::with_max_entries(10240, 0);

// Per-exit context shared between the dispatching exit program and the
// tail-called handler that builds the event. Filled once per exit so the
// many submit_compact_payload() monomorphizations stay small -- inlining
// the map lookups and helper calls at every submit site pushed the larger
// programs past the BPF branch offset range. Tracepoint programs are not
// preempted, so the per-CPU slot is stable across the tail call.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitContext {
    pub duration_ns: u64,
    pub comm: [u8; pinchy_common::COMM_LEN],
}

#[map]
static mut EXIT_CONTEXT: PerCpuArray<ExitContext> = PerCpuArray::with_max_entries(1, 0);

// Record the time spent in the syscall (when we saw its enter) and the
// process name for the handler this exit tail-calls into.
#[inline(always)]
pub fn fill_exit_context(ctx: &TracePointContext, syscall_nr: i64) {
    let tid = ctx.pid();

    let mut duration_ns = 0u64;

    if let Some(enter_data) = unsafe { ENTER_MAP.get(&tid) } {
        if enter_data.syscall_nr == syscall_nr {
            duration_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() }
                .saturating_sub(enter_data.enter_ns);
        }
    }

    if let Some(exit_ctx) = unsafe { EXIT_CONTEXT.get_ptr_mut(0) } {
        unsafe {
            (*exit_ctx).duration_ns = duration_ns;

            let comm_ptr = core::ptr::addr_of_mut!((*exit_ctx).comm);
            aya_ebpf::helpers::gen::bpf_get_current_comm(
                comm_ptr as *mut core::ffi::c_void,
                pinchy_common::COMM_LEN as u32,
            );
        }
    }
}

#[map(name = "SYSCALL_TAILCALLS")]
static mut SYSCALL_TAILCALLS: ProgramArray = ProgramArray::pinned(512, 0);

#[repr(C)]
pub struct SyscallEnterData {
    pub tgid: u32,
    pub syscall_nr: i64,
    pub args: [usize; SYSCALL_ARGS_COUNT],
    pub enter_ns: u64,
}

#[inline(always)]
fn is_syscall_enabled(nr: i64) -> bool {
    if !(0..512).contains(&nr) {
        return false;
    }
    let nr = nr as u64; // To calm the verifier down
    let idx = (nr / 8) as u32;
    let bit = (nr % 8) as u8;
    if let Some(&byte) = unsafe { SYSCALL_FILTER.get(idx) } {
        (byte & (1 << bit)) != 0
    } else {
        false
    }
}

// /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/format
//
// name: sys_enter
// ID: 25
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;
//
// 	field:long id;	offset:8;	size:8;	signed:1;
// 	field:unsigned long args[6];	offset:16;	size:48;	signed:0;
//
// print fmt: "NR %ld (%lx, %lx, %lx, %lx, %lx, %lx)", REC->id, REC->args[0], REC->args[1], REC->args[2], REC->args[3], REC->args[4], REC->args[5]
const SYSCALL_OFFSET: usize = 8;
const SYSCALL_ARGS_OFFSET: usize = 16;
const SYSCALL_ARGS_COUNT: usize = 6;
#[tracepoint]
pub fn pinchy(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<u32, u32> {
        let tgid = ctx.tgid();
        let tid = ctx.pid();

        if unsafe { PID_FILTER.get(&tgid).is_none() } {
            return Ok(0);
        }

        let syscall_nr = unsafe { ctx.read_at::<i64>(SYSCALL_OFFSET).map_err(|e| e as u32)? };

        if !is_syscall_enabled(syscall_nr) {
            return Ok(0);
        }

        // execve has its own enter entry point
        if syscall_nr == syscalls::SYS_execve || syscall_nr == syscalls::SYS_execveat {
            return Ok(0);
        }

        let args = unsafe {
            ctx.read_at::<[usize; SYSCALL_ARGS_COUNT]>(SYSCALL_ARGS_OFFSET)
                .map_err(|e| e as u32)?
        };

        let data = SyscallEnterData {
            tgid,
            syscall_nr,
            args,
            enter_ns: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
        };

        if let Err(err) = unsafe { ENTER_MAP.insert(&tid, &data, 0) } {
            error!(
                &ctx,
                "Failed to insert data for syscall {} (tid {}, tgid {}). Error code: {}",
                syscall_nr,
                tid,
                tgid,
                err
            );
            return Err(err as u32);
        }

        Ok(0)
    }
    match inner(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/format
//
// name: sys_exit
// ID: 24
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;
//
// 	field:long id;	offset:8;	size:8;	signed:1;
// 	field:long ret;	offset:16;	size:8;	signed:1;
//
// print fmt: "NR %ld = %ld", REC->id, REC->ret
const SYSCALL_RETURN_OFFSET: usize = 16;
#[tracepoint]
pub fn pinchy_exit(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<u32, u32> {
        let tgid = ctx.tgid();

        if unsafe { PID_FILTER.get(&tgid).is_none() } {
            return Ok(0);
        }

        let syscall_nr = unsafe { ctx.read_at::<i64>(SYSCALL_OFFSET).map_err(|e| e as u32)? };

        if !is_syscall_enabled(syscall_nr) {
            return Ok(0);
        }

        fill_exit_context(&ctx, syscall_nr);

        unsafe {
            let Err(_) = SYSCALL_TAILCALLS.tail_call(&ctx, syscall_nr as u32);
            error!(&ctx, "failed tailcall for syscall {}", syscall_nr);
            return Err(1);
        }

        #[allow(unreachable_code)]
        Ok(0)
    }
    match inner(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_trivial(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = get_syscall_nr(&ctx)?;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = util::get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_fchmod => {
                submit_compact_payload::<FchmodData, _>(
                    &ctx,
                    syscalls::SYS_fchmod,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.mode = args[1] as u32;
                    },
                )?;
            }
            syscalls::SYS_fsync => {
                submit_compact_payload::<FsyncData, _>(
                    &ctx,
                    syscalls::SYS_fsync,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_fdatasync => {
                submit_compact_payload::<FdatasyncData, _>(
                    &ctx,
                    syscalls::SYS_fdatasync,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_ftruncate => {
                submit_compact_payload::<FtruncateData, _>(
                    &ctx,
                    syscalls::SYS_ftruncate,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.length = args[1] as i64;
                    },
                )?;
            }
            syscalls::SYS_fchown => {
                submit_compact_payload::<FchownData, _>(
                    &ctx,
                    syscalls::SYS_fchown,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.uid = args[1] as u32;
                        payload.gid = args[2] as u32;
                    },
                )?;
            }
            syscalls::SYS_flock => {
                crate::util::submit_compact_payload::<pinchy_common::FlockData, _>(
                    &ctx,
                    syscalls::SYS_flock,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.operation = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_process_mrelease => {
                crate::util::submit_compact_payload::<pinchy_common::ProcessMreleaseData, _>(
                    &ctx,
                    syscalls::SYS_process_mrelease,
                    return_value,
                    |payload| {
                        payload.pidfd = args[0] as i32;
                        payload.flags = args[1] as u32;
                    },
                )?;
            }
            syscalls::SYS_brk => {
                crate::util::submit_compact_payload::<pinchy_common::BrkData, _>(
                    &ctx,
                    syscalls::SYS_brk,
                    return_value,
                    |payload| {
                        payload.addr = args[0];
                    },
                )?;
            }
            syscalls::SYS_mprotect => {
                crate::util::submit_compact_payload::<pinchy_common::MprotectData, _>(
                    &ctx,
                    syscalls::SYS_mprotect,
                    return_value,
                    |payload| {
                        payload.addr = args[0];
                        payload.length = args[1];
                        payload.prot = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_getrandom => {
                crate::util::submit_compact_payload::<pinchy_common::GetrandomData, _>(
                    &ctx,
                    syscalls::SYS_getrandom,
                    return_value,
                    |payload| {
                        payload.buf = args[0];
                        payload.buflen = args[1];
                        payload.flags = args[2] as u32;
                    },
                )?;
            }
            syscalls::SYS_set_robust_list => {
                crate::util::submit_compact_payload::<pinchy_common::SetRobustListData, _>(
                    &ctx,
                    syscalls::SYS_set_robust_list,
                    return_value,
                    |payload| {
                        payload.head = args[0];
                        payload.len = args[1];
                    },
                )?;
            }
            syscalls::SYS_set_tid_address => {
                crate::util::submit_compact_payload::<pinchy_common::SetTidAddressData, _>(
                    &ctx,
                    syscalls::SYS_set_tid_address,
                    return_value,
                    |payload| {
                        payload.tidptr = args[0];
                    },
                )?;
            }
            syscalls::SYS_rt_sigaction => {
                crate::util::submit_compact_payload::<pinchy_common::RtSigactionData, _>(
                    &ctx,
                    syscalls::SYS_rt_sigaction,
                    return_value,
                    |payload| {
                        payload.signum = args[0] as i32;
                        payload.act = args[1];
                        payload.oldact = args[2];
                        payload.sigsetsize = args[3];
                    },
                )?;
            }
            syscalls::SYS_rt_sigqueueinfo => {
                crate::util::submit_compact_payload::<pinchy_common::RtSigqueueinfoData, _>(
                    &ctx,
                    syscalls::SYS_rt_sigqueueinfo,
                    return_value,
                    |payload| {
                        payload.tgid = args[0] as i32;
                        payload.sig = args[1] as i32;
                        payload.uinfo = args[2];
                    },
                )?;
            }
            syscalls::SYS_rt_tgsigqueueinfo => {
                crate::util::submit_compact_payload::<pinchy_common::RtTgsigqueueinfoData, _>(
                    &ctx,
                    syscalls::SYS_rt_tgsigqueueinfo,
                    return_value,
                    |payload| {
                        payload.tgid = args[0] as i32;
                        payload.tid = args[1] as i32;
                        payload.sig = args[2] as i32;
                        payload.uinfo = args[3];
                    },
                )?;
            }
            syscalls::SYS_fchdir => {
                crate::util::submit_compact_payload::<pinchy_common::FchdirData, _>(
                    &ctx,
                    syscalls::SYS_fchdir,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_dup3 => {
                crate::util::submit_compact_payload::<pinchy_common::Dup3Data, _>(
                    &ctx,
                    syscalls::SYS_dup3,
                    return_value,
                    |payload| {
                        payload.oldfd = args[0] as i32;
                        payload.newfd = args[1] as i32;
                        payload.flags = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_exit_group => {
                crate::util::submit_compact_payload::<pinchy_common::ExitGroupData, _>(
                    &ctx,
                    syscalls::SYS_exit_group,
                    return_value,
                    |payload| {
                        payload.status = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_dup => {
                crate::util::submit_compact_payload::<pinchy_common::DupData, _>(
                    &ctx,
                    syscalls::SYS_dup,
                    return_value,
                    |payload| {
                        payload.oldfd = args[0] as i32;
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_dup2 => {
                crate::util::submit_compact_payload::<pinchy_common::Dup2Data, _>(
                    &ctx,
                    syscalls::SYS_dup2,
                    return_value,
                    |payload| {
                        payload.oldfd = args[0] as i32;
                        payload.newfd = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_setuid => {
                crate::util::submit_compact_payload::<pinchy_common::SetuidData, _>(
                    &ctx,
                    syscalls::SYS_setuid,
                    return_value,
                    |payload| {
                        payload.uid = args[0] as u32;
                    },
                )?;
            }
            syscalls::SYS_setgid => {
                crate::util::submit_compact_payload::<pinchy_common::SetgidData, _>(
                    &ctx,
                    syscalls::SYS_setgid,
                    return_value,
                    |payload| {
                        payload.gid = args[0] as u32;
                    },
                )?;
            }
            syscalls::SYS_close_range => {
                crate::util::submit_compact_payload::<pinchy_common::CloseRangeData, _>(
                    &ctx,
                    syscalls::SYS_close_range,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as u32;
                        payload.max_fd = args[1] as u32;
                        payload.flags = args[2] as u32;
                    },
                )?;
            }
            syscalls::SYS_getpgid => {
                crate::util::submit_compact_payload::<pinchy_common::GetpgidData, _>(
                    &ctx,
                    syscalls::SYS_getpgid,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_getsid => {
                crate::util::submit_compact_payload::<pinchy_common::GetsidData, _>(
                    &ctx,
                    syscalls::SYS_getsid,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_setpgid => {
                crate::util::submit_compact_payload::<pinchy_common::SetpgidData, _>(
                    &ctx,
                    syscalls::SYS_setpgid,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        payload.pgid = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_umask => {
                crate::util::submit_compact_payload::<pinchy_common::UmaskData, _>(
                    &ctx,
                    syscalls::SYS_umask,
                    return_value,
                    |payload| {
                        payload.mask = args[0] as u32;
                    },
                )?;
            }
            syscalls::SYS_ioprio_get => {
                crate::util::submit_compact_payload::<pinchy_common::IoprioGetData, _>(
                    &ctx,
                    syscalls::SYS_ioprio_get,
                    return_value,
                    |payload| {
                        payload.which = args[0] as i32;
                        payload.who = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_ioprio_set => {
                crate::util::submit_compact_payload::<pinchy_common::IoprioSetData, _>(
                    &ctx,
                    syscalls::SYS_ioprio_set,
                    return_value,
                    |payload| {
                        payload.which = args[0] as i32;
                        payload.who = args[1] as i32;
                        payload.ioprio = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_setregid => {
                crate::util::submit_compact_payload::<pinchy_common::SetregidData, _>(
                    &ctx,
                    syscalls::SYS_setregid,
                    return_value,
                    |payload| {
                        payload.rgid = args[0] as u32;
                        payload.egid = args[1] as u32;
                    },
                )?;
            }
            syscalls::SYS_setresgid => {
                crate::util::submit_compact_payload::<pinchy_common::SetresgidData, _>(
                    &ctx,
                    syscalls::SYS_setresgid,
                    return_value,
                    |payload| {
                        payload.rgid = args[0] as u32;
                        payload.egid = args[1] as u32;
                        payload.sgid = args[2] as u32;
                    },
                )?;
            }
            syscalls::SYS_setresuid => {
                crate::util::submit_compact_payload::<pinchy_common::SetresuidData, _>(
                    &ctx,
                    syscalls::SYS_setresuid,
                    return_value,
                    |payload| {
                        payload.ruid = args[0] as u32;
                        payload.euid = args[1] as u32;
                        payload.suid = args[2] as u32;
                    },
                )?;
            }
            syscalls::SYS_setreuid => {
                crate::util::submit_compact_payload::<pinchy_common::SetreuidData, _>(
                    &ctx,
                    syscalls::SYS_setreuid,
                    return_value,
                    |payload| {
                        payload.ruid = args[0] as u32;
                        payload.euid = args[1] as u32;
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_alarm => {
                crate::util::submit_compact_payload::<pinchy_common::AlarmData, _>(
                    &ctx,
                    syscalls::SYS_alarm,
                    return_value,
                    |payload| {
                        payload.seconds = args[0] as u32;
                    },
                )?;
            }
            syscalls::SYS_personality => {
                crate::util::submit_compact_payload::<pinchy_common::PersonalityData, _>(
                    &ctx,
                    syscalls::SYS_personality,
                    return_value,
                    |payload| {
                        payload.persona = args[0] as u64;
                    },
                )?;
            }
            syscalls::SYS_getpriority => {
                crate::util::submit_compact_payload::<pinchy_common::GetpriorityData, _>(
                    &ctx,
                    syscalls::SYS_getpriority,
                    return_value,
                    |payload| {
                        payload.which = args[0] as i32;
                        payload.who = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_setpriority => {
                crate::util::submit_compact_payload::<pinchy_common::SetpriorityData, _>(
                    &ctx,
                    syscalls::SYS_setpriority,
                    return_value,
                    |payload| {
                        payload.which = args[0] as i32;
                        payload.who = args[1] as i32;
                        payload.prio = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_tkill => {
                crate::util::submit_compact_payload::<pinchy_common::TkillData, _>(
                    &ctx,
                    syscalls::SYS_tkill,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        payload.signal = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_tgkill => {
                crate::util::submit_compact_payload::<pinchy_common::TgkillData, _>(
                    &ctx,
                    syscalls::SYS_tgkill,
                    return_value,
                    |payload| {
                        payload.tgid = args[0] as i32;
                        payload.pid = args[1] as i32;
                        payload.signal = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_kill => {
                crate::util::submit_compact_payload::<pinchy_common::KillData, _>(
                    &ctx,
                    syscalls::SYS_kill,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        payload.signal = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_exit => {
                crate::util::submit_compact_payload::<pinchy_common::ExitData, _>(
                    &ctx,
                    syscalls::SYS_exit,
                    return_value,
                    |payload| {
                        payload.status = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_sched_getscheduler => {
                crate::util::submit_compact_payload::<pinchy_common::SchedGetschedulerData, _>(
                    &ctx,
                    syscalls::SYS_sched_getscheduler,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_setfsuid => {
                crate::util::submit_compact_payload::<pinchy_common::SetfsuidData, _>(
                    &ctx,
                    syscalls::SYS_setfsuid,
                    return_value,
                    |payload| {
                        payload.uid = args[0] as u32;
                    },
                )?;
            }
            syscalls::SYS_setfsgid => {
                crate::util::submit_compact_payload::<pinchy_common::SetfsgidData, _>(
                    &ctx,
                    syscalls::SYS_setfsgid,
                    return_value,
                    |payload| {
                        payload.gid = args[0] as u32;
                    },
                )?;
            }
            syscalls::SYS_sched_get_priority_max => {
                crate::util::submit_compact_payload::<pinchy_common::SchedGetPriorityMaxData, _>(
                    &ctx,
                    syscalls::SYS_sched_get_priority_max,
                    return_value,
                    |payload| {
                        payload.policy = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_sched_get_priority_min => {
                crate::util::submit_compact_payload::<pinchy_common::SchedGetPriorityMinData, _>(
                    &ctx,
                    syscalls::SYS_sched_get_priority_min,
                    return_value,
                    |payload| {
                        payload.policy = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_inotify_rm_watch => {
                crate::util::submit_compact_payload::<pinchy_common::InotifyRmWatchData, _>(
                    &ctx,
                    syscalls::SYS_inotify_rm_watch,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.wd = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_inotify_init1 => {
                crate::util::submit_compact_payload::<pinchy_common::InotifyInit1Data, _>(
                    &ctx,
                    syscalls::SYS_inotify_init1,
                    return_value,
                    |payload| {
                        payload.flags = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_socket => {
                crate::util::submit_compact_payload::<pinchy_common::SocketData, _>(
                    &ctx,
                    syscalls::SYS_socket,
                    return_value,
                    |payload| {
                        payload.domain = args[0] as i32;
                        payload.type_ = args[1] as i32;
                        payload.protocol = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_listen => {
                crate::util::submit_compact_payload::<pinchy_common::ListenData, _>(
                    &ctx,
                    syscalls::SYS_listen,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.backlog = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_shutdown => {
                crate::util::submit_compact_payload::<pinchy_common::ShutdownData, _>(
                    &ctx,
                    syscalls::SYS_shutdown,
                    return_value,
                    |payload| {
                        payload.sockfd = args[0] as i32;
                        payload.how = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_fcntl => {
                crate::util::submit_compact_payload::<pinchy_common::FcntlData, _>(
                    &ctx,
                    syscalls::SYS_fcntl,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.cmd = args[1] as i32;
                        payload.arg = args[2];
                    },
                )?;
            }
            syscalls::SYS_fsmount => {
                crate::util::submit_compact_payload::<pinchy_common::FsmountData, _>(
                    &ctx,
                    syscalls::SYS_fsmount,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.flags = args[1] as u32;
                        payload.attr_flags = args[2] as u32;
                    },
                )?;
            }
            syscalls::SYS_pidfd_open => {
                crate::util::submit_compact_payload::<pinchy_common::PidfdOpenData, _>(
                    &ctx,
                    syscalls::SYS_pidfd_open,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        payload.flags = args[1] as u32;
                    },
                )?;
            }
            _ => {
                trace!(&ctx, "unknown syscall {}", syscall_nr);
            }
        }

        Ok(())
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

// Split from syscall_exit_trivial: with every submit site inlined, a single
// program holding all trivial syscalls exceeds the BPF branch offset range
// on x86_64 ("Branch target out of insn range" at link time). Each syscall
// is registered against exactly one of the two programs in the tailcall
// array.
#[tracepoint]
pub fn syscall_exit_trivial2(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = get_syscall_nr(&ctx)?;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = util::get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_pidfd_getfd => {
                crate::util::submit_compact_payload::<pinchy_common::PidfdGetfdData, _>(
                    &ctx,
                    syscalls::SYS_pidfd_getfd,
                    return_value,
                    |payload| {
                        payload.pidfd = args[0] as i32;
                        payload.targetfd = args[1] as i32;
                        payload.flags = args[2] as u32;
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_epoll_create => {
                crate::util::submit_compact_payload::<pinchy_common::EpollCreateData, _>(
                    &ctx,
                    syscalls::SYS_epoll_create,
                    return_value,
                    |payload| {
                        payload.size = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_epoll_create1 => {
                crate::util::submit_compact_payload::<pinchy_common::EpollCreate1Data, _>(
                    &ctx,
                    syscalls::SYS_epoll_create1,
                    return_value,
                    |payload| {
                        payload.flags = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_memfd_secret => {
                crate::util::submit_compact_payload::<pinchy_common::MemfdSecretData, _>(
                    &ctx,
                    syscalls::SYS_memfd_secret,
                    return_value,
                    |payload| {
                        payload.flags = args[0] as u32;
                    },
                )?;
            }
            syscalls::SYS_userfaultfd => {
                crate::util::submit_compact_payload::<pinchy_common::UserfaultfdData, _>(
                    &ctx,
                    syscalls::SYS_userfaultfd,
                    return_value,
                    |payload| {
                        payload.flags = args[0] as u32;
                    },
                )?;
            }
            syscalls::SYS_pkey_alloc => {
                crate::util::submit_compact_payload::<pinchy_common::PkeyAllocData, _>(
                    &ctx,
                    syscalls::SYS_pkey_alloc,
                    return_value,
                    |payload| {
                        payload.flags = args[0] as u32;
                        payload.access_rights = args[1] as u32;
                    },
                )?;
            }
            syscalls::SYS_pkey_free => {
                crate::util::submit_compact_payload::<pinchy_common::PkeyFreeData, _>(
                    &ctx,
                    syscalls::SYS_pkey_free,
                    return_value,
                    |payload| {
                        payload.pkey = args[0] as i32;
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_eventfd => {
                crate::util::submit_compact_payload::<pinchy_common::EventfdData, _>(
                    &ctx,
                    syscalls::SYS_eventfd,
                    return_value,
                    |payload| {
                        payload.initval = args[0] as u32;
                        payload.flags = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_eventfd2 => {
                crate::util::submit_compact_payload::<pinchy_common::Eventfd2Data, _>(
                    &ctx,
                    syscalls::SYS_eventfd2,
                    return_value,
                    |payload| {
                        payload.initval = args[0] as u32;
                        payload.flags = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_mlock => {
                crate::util::submit_compact_payload::<pinchy_common::MlockData, _>(
                    &ctx,
                    syscalls::SYS_mlock,
                    return_value,
                    |payload| {
                        payload.addr = args[0];
                        payload.len = args[1];
                    },
                )?;
            }
            syscalls::SYS_mlock2 => {
                crate::util::submit_compact_payload::<pinchy_common::Mlock2Data, _>(
                    &ctx,
                    syscalls::SYS_mlock2,
                    return_value,
                    |payload| {
                        payload.addr = args[0];
                        payload.len = args[1];
                        payload.flags = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_mlockall => {
                crate::util::submit_compact_payload::<pinchy_common::MlockallData, _>(
                    &ctx,
                    syscalls::SYS_mlockall,
                    return_value,
                    |payload| {
                        payload.flags = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_membarrier => {
                crate::util::submit_compact_payload::<pinchy_common::MembarrierData, _>(
                    &ctx,
                    syscalls::SYS_membarrier,
                    return_value,
                    |payload| {
                        payload.cmd = args[0] as i32;
                        payload.flags = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_mremap => {
                crate::util::submit_compact_payload::<pinchy_common::MremapData, _>(
                    &ctx,
                    syscalls::SYS_mremap,
                    return_value,
                    |payload| {
                        payload.old_address = args[0];
                        payload.old_size = args[1];
                        payload.new_size = args[2];
                        payload.flags = args[3] as i32;
                    },
                )?;
            }
            syscalls::SYS_msync => {
                crate::util::submit_compact_payload::<pinchy_common::MsyncData, _>(
                    &ctx,
                    syscalls::SYS_msync,
                    return_value,
                    |payload| {
                        payload.addr = args[0];
                        payload.length = args[1];
                        payload.flags = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_munlock => {
                crate::util::submit_compact_payload::<pinchy_common::MunlockData, _>(
                    &ctx,
                    syscalls::SYS_munlock,
                    return_value,
                    |payload| {
                        payload.addr = args[0];
                        payload.len = args[1];
                    },
                )?;
            }
            syscalls::SYS_readahead => {
                crate::util::submit_compact_payload::<pinchy_common::ReadaheadData, _>(
                    &ctx,
                    syscalls::SYS_readahead,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.offset = args[1];
                        payload.count = args[2];
                    },
                )?;
            }
            syscalls::SYS_setns => {
                crate::util::submit_compact_payload::<pinchy_common::SetnsData, _>(
                    &ctx,
                    syscalls::SYS_setns,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.nstype = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_unshare => {
                crate::util::submit_compact_payload::<pinchy_common::UnshareData, _>(
                    &ctx,
                    syscalls::SYS_unshare,
                    return_value,
                    |payload| {
                        payload.flags = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_timer_delete => {
                crate::util::submit_compact_payload::<pinchy_common::TimerDeleteData, _>(
                    &ctx,
                    syscalls::SYS_timer_delete,
                    return_value,
                    |payload| {
                        payload.timerid = args[0];
                    },
                )?;
            }
            syscalls::SYS_timer_getoverrun => {
                crate::util::submit_compact_payload::<pinchy_common::TimerGetoverrunData, _>(
                    &ctx,
                    syscalls::SYS_timer_getoverrun,
                    return_value,
                    |payload| {
                        payload.timerid = args[0];
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_pause => {
                crate::util::submit_compact_payload::<pinchy_common::PauseData, _>(
                    &ctx,
                    syscalls::SYS_pause,
                    return_value,
                    |_payload| {},
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_getpgrp => {
                crate::util::submit_compact_payload::<pinchy_common::GetpgrpData, _>(
                    &ctx,
                    syscalls::SYS_getpgrp,
                    return_value,
                    |_payload| {},
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_inotify_init => {
                crate::util::submit_compact_payload::<pinchy_common::InotifyInitData, _>(
                    &ctx,
                    syscalls::SYS_inotify_init,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_sched_yield => {
                crate::util::submit_compact_payload::<pinchy_common::SchedYieldData, _>(
                    &ctx,
                    syscalls::SYS_sched_yield,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_getpid => {
                crate::util::submit_compact_payload::<pinchy_common::GetpidData, _>(
                    &ctx,
                    syscalls::SYS_getpid,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_gettid => {
                crate::util::submit_compact_payload::<pinchy_common::GettidData, _>(
                    &ctx,
                    syscalls::SYS_gettid,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_getuid => {
                crate::util::submit_compact_payload::<pinchy_common::GetuidData, _>(
                    &ctx,
                    syscalls::SYS_getuid,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_geteuid => {
                crate::util::submit_compact_payload::<pinchy_common::GeteuidData, _>(
                    &ctx,
                    syscalls::SYS_geteuid,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_getgid => {
                crate::util::submit_compact_payload::<pinchy_common::GetgidData, _>(
                    &ctx,
                    syscalls::SYS_getgid,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_getegid => {
                crate::util::submit_compact_payload::<pinchy_common::GetegidData, _>(
                    &ctx,
                    syscalls::SYS_getegid,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_getppid => {
                crate::util::submit_compact_payload::<pinchy_common::GetppidData, _>(
                    &ctx,
                    syscalls::SYS_getppid,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_rt_sigreturn => {
                crate::util::submit_compact_payload::<pinchy_common::RtSigreturnData, _>(
                    &ctx,
                    syscalls::SYS_rt_sigreturn,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_sync => {
                crate::util::submit_compact_payload::<pinchy_common::SyncData, _>(
                    &ctx,
                    syscalls::SYS_sync,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_setsid => {
                crate::util::submit_compact_payload::<pinchy_common::SetsidData, _>(
                    &ctx,
                    syscalls::SYS_setsid,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_munlockall => {
                crate::util::submit_compact_payload::<pinchy_common::MunlockallData, _>(
                    &ctx,
                    syscalls::SYS_munlockall,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_vhangup => {
                crate::util::submit_compact_payload::<pinchy_common::VhangupData, _>(
                    &ctx,
                    syscalls::SYS_vhangup,
                    return_value,
                    |_payload| {},
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_fork => {
                crate::util::submit_compact_payload::<pinchy_common::ForkData, _>(
                    &ctx,
                    syscalls::SYS_fork,
                    return_value,
                    |_payload| {},
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_vfork => {
                crate::util::submit_compact_payload::<pinchy_common::VforkData, _>(
                    &ctx,
                    syscalls::SYS_vfork,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_set_mempolicy_home_node => {
                crate::util::submit_compact_payload::<pinchy_common::SetMempolicyHomeNodeData, _>(
                    &ctx,
                    syscalls::SYS_set_mempolicy_home_node,
                    return_value,
                    |payload| {
                        payload.start = args[0] as u64;
                        payload.len = args[1] as u64;
                        payload.home_node = args[2] as u64;
                        payload.flags = args[3] as u64;
                    },
                )?;
            }
            syscalls::SYS_fadvise64 => {
                crate::util::submit_compact_payload::<Fadvise64Data, _>(
                    &ctx,
                    syscalls::SYS_fadvise64,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.advice = args[3] as i32;
                        payload.offset = args[1] as i64;
                        payload.len = args[2] as i64;
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_arch_prctl => {
                crate::util::submit_compact_payload::<ArchPrctlData, _>(
                    &ctx,
                    syscalls::SYS_arch_prctl,
                    return_value,
                    |payload| {
                        payload.code = args[0] as i32;
                        payload.addr = args[1] as u64;
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_ioperm => {
                crate::util::submit_compact_payload::<IopermData, _>(
                    &ctx,
                    syscalls::SYS_ioperm,
                    return_value,
                    |payload| {
                        payload.from = args[0] as u64;
                        payload.num = args[1] as u64;
                        payload.turn_on = args[2] as i32;
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_iopl => {
                crate::util::submit_compact_payload::<IoplData, _>(
                    &ctx,
                    syscalls::SYS_iopl,
                    return_value,
                    |payload| {
                        payload.level = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_map_shadow_stack => {
                crate::util::submit_compact_payload::<MapShadowStackData, _>(
                    &ctx,
                    syscalls::SYS_map_shadow_stack,
                    return_value,
                    |payload| {
                        payload.addr = args[0] as u64;
                        payload.size = args[1] as u64;
                        payload.flags = args[2] as u32;
                    },
                )?;
            }
            syscalls::SYS_lsm_set_self_attr => {
                crate::util::submit_compact_payload::<LsmSetSelfAttrData, _>(
                    &ctx,
                    syscalls::SYS_lsm_set_self_attr,
                    return_value,
                    |payload| {
                        payload.attr = args[0] as u32;
                        payload.ctx = args[1] as u64;
                        payload.size = args[2] as u64;
                        payload.flags = args[3] as u32;
                    },
                )?;
            }
            syscalls::SYS_rseq_slice_yield => {
                crate::util::submit_compact_payload::<pinchy_common::RseqSliceYieldData, _>(
                    &ctx,
                    syscalls::SYS_rseq_slice_yield,
                    return_value,
                    |_payload| {},
                )?;
            }
            syscalls::SYS_futex_wake => {
                crate::util::submit_compact_payload::<FutexWakeData, _>(
                    &ctx,
                    syscalls::SYS_futex_wake,
                    return_value,
                    |payload| {
                        payload.uaddr = args[0] as u64;
                        payload.mask = args[1] as u64;
                        payload.nr = args[2] as i32;
                        payload.flags = args[3] as u32;
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_time => {
                crate::util::submit_compact_payload::<TimeData, _>(
                    &ctx,
                    syscalls::SYS_time,
                    return_value,
                    |payload| {
                        payload.tloc = args[0] as u64;
                    },
                )?;
            }
            syscalls::SYS_kexec_file_load => {
                crate::util::submit_compact_payload::<KexecFileLoadData, _>(
                    &ctx,
                    syscalls::SYS_kexec_file_load,
                    return_value,
                    |payload| {
                        payload.kernel_fd = args[0] as i32;
                        payload.initrd_fd = args[1] as i32;
                        payload.cmdline_len = args[2] as u64;
                        payload.cmdline = args[3] as u64;
                        payload.flags = args[4] as u64;
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_get_thread_area | syscalls::SYS_set_thread_area => {
                crate::util::submit_compact_payload::<ThreadAreaData, _>(
                    &ctx,
                    syscall_nr,
                    return_value,
                    |payload| {
                        payload.u_info = args[0] as u64;
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_modify_ldt => {
                crate::util::submit_compact_payload::<ModifyLdtData, _>(
                    &ctx,
                    syscalls::SYS_modify_ldt,
                    return_value,
                    |payload| {
                        payload.func = args[0] as i32;
                        payload.ptr = args[1] as u64;
                        payload.bytecount = args[2] as u64;
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_uselib
            | syscalls::SYS_ustat
            | syscalls::SYS_sysfs
            | syscalls::SYS__sysctl
            | syscalls::SYS_create_module
            | syscalls::SYS_get_kernel_syms
            | syscalls::SYS_query_module
            | syscalls::SYS_getpmsg
            | syscalls::SYS_putpmsg
            | syscalls::SYS_afs_syscall
            | syscalls::SYS_tuxcall
            | syscalls::SYS_security
            | syscalls::SYS_epoll_ctl_old
            | syscalls::SYS_epoll_wait_old
            | syscalls::SYS_vserver => {
                crate::util::submit_compact_payload::<DeprecatedSyscallData, _>(
                    &ctx,
                    syscall_nr,
                    return_value,
                    |payload| {
                        payload.args = [
                            args[0] as u64,
                            args[1] as u64,
                            args[2] as u64,
                            args[3] as u64,
                            args[4] as u64,
                            args[5] as u64,
                        ];
                    },
                )?;
            }
            _ => {
                trace!(&ctx, "unknown syscall {}", syscall_nr);
            }
        }

        Ok(())
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_generic(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = get_syscall_nr(&ctx)?;
        let return_value = crate::util::get_return_value(&ctx)?;
        let args = get_args(&ctx, syscall_nr)?;
        crate::util::submit_compact_payload::<pinchy_common::GenericSyscallData, _>(
            &ctx,
            syscall_nr,
            return_value,
            |payload| {
                payload.args = args;
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
