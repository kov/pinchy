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
use pinchy_common::syscalls::{
    SYS_brk, SYS_close, SYS_dup3, SYS_execve, SYS_fchdir, SYS_getegid, SYS_geteuid, SYS_getgid,
    SYS_getpid, SYS_getppid, SYS_getrandom, SYS_gettid, SYS_getuid, SYS_lseek, SYS_mprotect,
    SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_sched_yield, SYS_set_robust_list,
    SYS_set_tid_address,
};

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
        if syscall_nr == SYS_execve {
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
            SYS_close => {
                let fd = args[0] as i32;
                pinchy_common::SyscallEventData {
                    close: pinchy_common::CloseData { fd },
                }
            }
            SYS_lseek => {
                let fd = args[0] as i32;
                let offset = args[1] as i64;
                let whence = args[2] as i32;
                pinchy_common::SyscallEventData {
                    lseek: pinchy_common::LseekData { fd, offset, whence },
                }
            }
            SYS_sched_yield => pinchy_common::SyscallEventData {
                sched_yield: pinchy_common::SchedYieldData,
            },
            SYS_getpid => pinchy_common::SyscallEventData {
                getpid: pinchy_common::GetpidData,
            },
            SYS_gettid => pinchy_common::SyscallEventData {
                gettid: pinchy_common::GettidData,
            },
            SYS_getuid => pinchy_common::SyscallEventData {
                getuid: pinchy_common::GetuidData,
            },
            SYS_geteuid => pinchy_common::SyscallEventData {
                geteuid: pinchy_common::GeteuidData,
            },
            SYS_getgid => pinchy_common::SyscallEventData {
                getgid: pinchy_common::GetgidData,
            },
            SYS_getegid => pinchy_common::SyscallEventData {
                getegid: pinchy_common::GetegidData,
            },
            SYS_getppid => pinchy_common::SyscallEventData {
                getppid: pinchy_common::GetppidData,
            },
            SYS_brk => pinchy_common::SyscallEventData {
                brk: pinchy_common::BrkData { addr: args[0] },
            },
            SYS_mprotect => {
                let addr = args[0];
                let length = args[1];
                let prot = args[2] as i32;
                pinchy_common::SyscallEventData {
                    mprotect: pinchy_common::MprotectData { addr, length, prot },
                }
            }
            SYS_getrandom => {
                let buf = args[0];
                let buflen = args[1];
                let flags = args[2] as u32;
                pinchy_common::SyscallEventData {
                    getrandom: pinchy_common::GetrandomData { buf, buflen, flags },
                }
            }
            SYS_set_robust_list => {
                let head = args[0];
                let len = args[1];
                pinchy_common::SyscallEventData {
                    set_robust_list: pinchy_common::SetRobustListData { head, len },
                }
            }
            SYS_set_tid_address => {
                let tidptr = args[0];
                pinchy_common::SyscallEventData {
                    set_tid_address: pinchy_common::SetTidAddressData { tidptr },
                }
            }
            SYS_rt_sigprocmask => {
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
            SYS_rt_sigaction => {
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
            SYS_fchdir => {
                let fd = args[0] as i32;
                pinchy_common::SyscallEventData {
                    fchdir: pinchy_common::FchdirData { fd },
                }
            }
            SYS_dup3 => {
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
