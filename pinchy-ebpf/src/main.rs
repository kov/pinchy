// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#![no_std]
#![no_main]
#![allow(non_snake_case, non_upper_case_globals, static_mut_refs)]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{Array, HashMap, ProgramArray, RingBuf},
    programs::TracePointContext,
    EbpfContext as _,
};
use aya_log_ebpf::{error, trace};
use pinchy_common::syscalls;

use crate::util::{get_args, get_return_value, get_syscall_nr, output_event};

mod basic_io;
mod filesystem;
mod memory;
mod network;
mod process;
mod scheduling;
mod sync;
mod system;
mod util;

#[map]
static mut PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// Treated as a bitmap for syscalls.
#[map]
static mut SYSCALL_FILTER: Array<u8> = Array::with_max_entries(64, 0);

#[map] // 80MiB output buffer
static mut EVENTS: RingBuf = RingBuf::with_byte_size(83886080, 0);

#[map]
static mut ENTER_MAP: HashMap<u32, SyscallEnterData> = HashMap::with_max_entries(10240, 0);

#[map(name = "SYSCALL_TAILCALLS")]
static mut SYSCALL_TAILCALLS: ProgramArray = ProgramArray::pinned(512, 0);

#[repr(C)]
pub struct SyscallEnterData {
    pub tgid: u32,
    pub syscall_nr: i64,
    pub args: [usize; SYSCALL_ARGS_COUNT],
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
        if syscall_nr == syscalls::SYS_execve {
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
        let return_value = get_return_value(&ctx)?;

        let data = match syscall_nr {
            syscalls::SYS_close => {
                let fd = args[0] as i32;
                pinchy_common::SyscallEventData {
                    close: pinchy_common::CloseData { fd },
                }
            }
            syscalls::SYS_lseek => {
                let fd = args[0] as i32;
                let offset = args[1] as i64;
                let whence = args[2] as i32;
                pinchy_common::SyscallEventData {
                    lseek: pinchy_common::LseekData { fd, offset, whence },
                }
            }
            syscalls::SYS_sched_yield => pinchy_common::SyscallEventData {
                sched_yield: pinchy_common::SchedYieldData,
            },
            syscalls::SYS_getpid => pinchy_common::SyscallEventData {
                getpid: pinchy_common::GetpidData,
            },
            syscalls::SYS_gettid => pinchy_common::SyscallEventData {
                gettid: pinchy_common::GettidData,
            },
            syscalls::SYS_getuid => pinchy_common::SyscallEventData {
                getuid: pinchy_common::GetuidData,
            },
            syscalls::SYS_geteuid => pinchy_common::SyscallEventData {
                geteuid: pinchy_common::GeteuidData,
            },
            syscalls::SYS_getgid => pinchy_common::SyscallEventData {
                getgid: pinchy_common::GetgidData,
            },
            syscalls::SYS_getegid => pinchy_common::SyscallEventData {
                getegid: pinchy_common::GetegidData,
            },
            syscalls::SYS_getppid => pinchy_common::SyscallEventData {
                getppid: pinchy_common::GetppidData,
            },
            syscalls::SYS_brk => pinchy_common::SyscallEventData {
                brk: pinchy_common::BrkData { addr: args[0] },
            },
            syscalls::SYS_mprotect => {
                let addr = args[0];
                let length = args[1];
                let prot = args[2] as i32;
                pinchy_common::SyscallEventData {
                    mprotect: pinchy_common::MprotectData { addr, length, prot },
                }
            }
            syscalls::SYS_getrandom => {
                let buf = args[0];
                let buflen = args[1];
                let flags = args[2] as u32;
                pinchy_common::SyscallEventData {
                    getrandom: pinchy_common::GetrandomData { buf, buflen, flags },
                }
            }
            syscalls::SYS_set_robust_list => {
                let head = args[0];
                let len = args[1];
                pinchy_common::SyscallEventData {
                    set_robust_list: pinchy_common::SetRobustListData { head, len },
                }
            }
            syscalls::SYS_set_tid_address => {
                let tidptr = args[0];
                pinchy_common::SyscallEventData {
                    set_tid_address: pinchy_common::SetTidAddressData { tidptr },
                }
            }
            syscalls::SYS_rt_sigprocmask => {
                let how = args[0] as i32;
                let set = args[1];
                let oldset = args[2];
                let sigsetsize = args[3];
                pinchy_common::SyscallEventData {
                    rt_sigprocmask: pinchy_common::RtSigprocmaskData {
                        how,
                        set,
                        oldset,
                        sigsetsize,
                    },
                }
            }
            syscalls::SYS_rt_sigaction => {
                let signum = args[0] as i32;
                let act = args[1];
                let oldact = args[2];
                let sigsetsize = args[3];
                pinchy_common::SyscallEventData {
                    rt_sigaction: pinchy_common::RtSigactionData {
                        signum,
                        act,
                        oldact,
                        sigsetsize,
                    },
                }
            }
            syscalls::SYS_fchdir => {
                let fd = args[0] as i32;
                pinchy_common::SyscallEventData {
                    fchdir: pinchy_common::FchdirData { fd },
                }
            }
            syscalls::SYS_dup3 => {
                let oldfd = args[0] as i32;
                let newfd = args[1] as i32;
                let flags = args[2] as i32;
                pinchy_common::SyscallEventData {
                    dup3: pinchy_common::Dup3Data {
                        oldfd,
                        newfd,
                        flags,
                    },
                }
            }
            syscalls::SYS_exit_group => {
                let status = args[0] as i32;
                pinchy_common::SyscallEventData {
                    exit_group: pinchy_common::ExitGroupData { status },
                }
            }
            syscalls::SYS_rt_sigreturn => pinchy_common::SyscallEventData {
                rt_sigreturn: pinchy_common::RtSigreturnData {},
            },
            syscalls::SYS_dup => {
                let oldfd = args[0] as i32;
                pinchy_common::SyscallEventData {
                    dup: pinchy_common::DupData { oldfd },
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_dup2 => {
                let oldfd = args[0] as i32;
                let newfd = args[1] as i32;
                pinchy_common::SyscallEventData {
                    dup2: pinchy_common::Dup2Data { oldfd, newfd },
                }
            }
            syscalls::SYS_sync => pinchy_common::SyscallEventData {
                sync: pinchy_common::SyncData,
            },
            syscalls::SYS_setsid => pinchy_common::SyscallEventData {
                setsid: pinchy_common::SetsidData,
            },
            syscalls::SYS_setuid => {
                let uid = args[0] as u32;
                pinchy_common::SyscallEventData {
                    setuid: pinchy_common::SetuidData { uid },
                }
            }
            syscalls::SYS_setgid => {
                let gid = args[0] as u32;
                pinchy_common::SyscallEventData {
                    setgid: pinchy_common::SetgidData { gid },
                }
            }
            syscalls::SYS_close_range => {
                let fd = args[0] as u32;
                let max_fd = args[1] as u32;
                let flags = args[2] as u32;
                pinchy_common::SyscallEventData {
                    close_range: pinchy_common::CloseRangeData { fd, max_fd, flags },
                }
            }
            syscalls::SYS_getpgid => {
                let pid = args[0] as i32;
                pinchy_common::SyscallEventData {
                    getpgid: pinchy_common::GetpgidData { pid },
                }
            }
            syscalls::SYS_getsid => {
                let pid = args[0] as i32;
                pinchy_common::SyscallEventData {
                    getsid: pinchy_common::GetsidData { pid },
                }
            }
            syscalls::SYS_setpgid => {
                let pid = args[0] as i32;
                let pgid = args[1] as i32;
                pinchy_common::SyscallEventData {
                    setpgid: pinchy_common::SetpgidData { pid, pgid },
                }
            }
            syscalls::SYS_umask => {
                let mask = args[0] as u32;
                pinchy_common::SyscallEventData {
                    umask: pinchy_common::UmaskData { mask },
                }
            }
            syscalls::SYS_vhangup => pinchy_common::SyscallEventData {
                vhangup: pinchy_common::VhangupData,
            },
            syscalls::SYS_ioprio_get => {
                let which = args[0] as i32;
                let who = args[1] as i32;
                pinchy_common::SyscallEventData {
                    ioprio_get: pinchy_common::IoprioGetData { which, who },
                }
            }
            syscalls::SYS_ioprio_set => {
                let which = args[0] as i32;
                let who = args[1] as i32;
                let ioprio = args[2] as i32;
                pinchy_common::SyscallEventData {
                    ioprio_set: pinchy_common::IoprioSetData { which, who, ioprio },
                }
            }
            syscalls::SYS_setregid => {
                let rgid = args[0] as u32;
                let egid = args[1] as u32;
                pinchy_common::SyscallEventData {
                    setregid: pinchy_common::SetregidData { rgid, egid },
                }
            }
            syscalls::SYS_setresgid => {
                let rgid = args[0] as u32;
                let egid = args[1] as u32;
                let sgid = args[2] as u32;
                pinchy_common::SyscallEventData {
                    setresgid: pinchy_common::SetresgidData { rgid, egid, sgid },
                }
            }
            syscalls::SYS_setresuid => {
                let ruid = args[0] as u32;
                let euid = args[1] as u32;
                let suid = args[2] as u32;
                pinchy_common::SyscallEventData {
                    setresuid: pinchy_common::SetresuidData { ruid, euid, suid },
                }
            }
            syscalls::SYS_setreuid => {
                let ruid = args[0] as u32;
                let euid = args[1] as u32;
                pinchy_common::SyscallEventData {
                    setreuid: pinchy_common::SetreuidData { ruid, euid },
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_alarm => {
                let seconds = args[0] as u32;
                pinchy_common::SyscallEventData {
                    alarm: pinchy_common::AlarmData { seconds },
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_pause => pinchy_common::SyscallEventData {
                pause: pinchy_common::PauseData,
            },
            #[cfg(x86_64)]
            syscalls::SYS_getpgrp => pinchy_common::SyscallEventData {
                getpgrp: pinchy_common::GetpgrpData,
            },
            syscalls::SYS_personality => {
                let persona = args[0] as u64;
                pinchy_common::SyscallEventData {
                    personality: pinchy_common::PersonalityData { persona },
                }
            }
            syscalls::SYS_getpriority => {
                let which = args[0] as i32;
                let who = args[1] as i32;
                pinchy_common::SyscallEventData {
                    getpriority: pinchy_common::GetpriorityData { which, who },
                }
            }
            syscalls::SYS_setpriority => {
                let which = args[0] as i32;
                let who = args[1] as i32;
                let prio = args[2] as i32;
                pinchy_common::SyscallEventData {
                    setpriority: pinchy_common::SetpriorityData { which, who, prio },
                }
            }
            syscalls::SYS_tkill => {
                let pid = args[0] as i32;
                let signal = args[1] as i32;
                pinchy_common::SyscallEventData {
                    tkill: pinchy_common::TkillData { pid, signal },
                }
            }
            syscalls::SYS_tgkill => {
                let tgid = args[0] as i32;
                let pid = args[1] as i32;
                let signal = args[2] as i32;
                pinchy_common::SyscallEventData {
                    tgkill: pinchy_common::TgkillData { tgid, pid, signal },
                }
            }
            syscalls::SYS_kill => {
                let pid = args[0] as i32;
                let signal = args[1] as i32;
                pinchy_common::SyscallEventData {
                    kill: pinchy_common::KillData { pid, signal },
                }
            }
            syscalls::SYS_exit => {
                let status = args[0] as i32;
                pinchy_common::SyscallEventData {
                    exit: pinchy_common::ExitData { status },
                }
            }
            syscalls::SYS_sched_getscheduler => {
                let pid = args[0] as i32;
                pinchy_common::SyscallEventData {
                    sched_getscheduler: pinchy_common::SchedGetschedulerData { pid },
                }
            }
            syscalls::SYS_setfsuid => {
                let uid = args[0] as u32;
                pinchy_common::SyscallEventData {
                    setfsuid: pinchy_common::SetfsuidData { uid },
                }
            }
            syscalls::SYS_setfsgid => {
                let gid = args[0] as u32;
                pinchy_common::SyscallEventData {
                    setfsgid: pinchy_common::SetfsgidData { gid },
                }
            }
            syscalls::SYS_sched_get_priority_max => {
                let policy = args[0] as i32;
                pinchy_common::SyscallEventData {
                    sched_get_priority_max: pinchy_common::SchedGetPriorityMaxData { policy },
                }
            }
            syscalls::SYS_sched_get_priority_min => {
                let policy = args[0] as i32;
                pinchy_common::SyscallEventData {
                    sched_get_priority_min: pinchy_common::SchedGetPriorityMinData { policy },
                }
            }
            syscalls::SYS_socket => {
                let domain = args[0] as i32;
                let type_ = args[1] as i32;
                let protocol = args[2] as i32;
                pinchy_common::SyscallEventData {
                    socket: pinchy_common::SocketData {
                        domain,
                        type_,
                        protocol,
                    },
                }
            }
            syscalls::SYS_listen => {
                let sockfd = args[0] as i32;
                let backlog = args[1] as i32;
                pinchy_common::SyscallEventData {
                    listen: pinchy_common::ListenData { sockfd, backlog },
                }
            }
            syscalls::SYS_shutdown => {
                let sockfd = args[0] as i32;
                let how = args[1] as i32;
                pinchy_common::SyscallEventData {
                    shutdown: pinchy_common::ShutdownData { sockfd, how },
                }
            }
            syscalls::SYS_fsync => {
                let fd = args[0] as i32;
                pinchy_common::SyscallEventData {
                    fsync: pinchy_common::FsyncData { fd },
                }
            }
            syscalls::SYS_fdatasync => {
                let fd = args[0] as i32;
                pinchy_common::SyscallEventData {
                    fdatasync: pinchy_common::FdatasyncData { fd },
                }
            }
            syscalls::SYS_ftruncate => {
                let fd = args[0] as i32;
                let length = args[1] as i64;
                pinchy_common::SyscallEventData {
                    ftruncate: pinchy_common::FtruncateData { fd, length },
                }
            }
            syscalls::SYS_fchown => {
                let fd = args[0] as i32;
                let uid = args[1] as u32;
                let gid = args[2] as u32;
                pinchy_common::SyscallEventData {
                    fchown: pinchy_common::FchownData { fd, uid, gid },
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_epoll_create => {
                let size = args[0] as i32;
                pinchy_common::SyscallEventData {
                    epoll_create: pinchy_common::EpollCreateData { size },
                }
            }
            syscalls::SYS_epoll_create1 => {
                let flags = args[0] as i32;
                pinchy_common::SyscallEventData {
                    epoll_create1: pinchy_common::EpollCreate1Data { flags },
                }
            }
            _ => {
                trace!(&ctx, "unknown syscall {}", syscall_nr);
                return Ok(());
            }
        };

        output_event(&ctx, syscall_nr, return_value, data)
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
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                generic: pinchy_common::GenericSyscallData { args },
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
