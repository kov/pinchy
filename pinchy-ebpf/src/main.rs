// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#![feature(macro_metavar_expr_concat)]
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

use crate::util::{get_args, get_syscall_nr, read_sigset};

mod basic_io;
mod filesystem;
mod ipc;
mod memory;
mod network;
mod process;
mod scheduling;
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

        let mut entry = util::Entry::new(&ctx, syscall_nr)?;

        match syscall_nr {
            syscalls::SYS_flock => {
                let data = unsafe { &mut entry.data.flock };
                data.fd = args[0] as i32;
                data.operation = args[1] as i32;
            }
            syscalls::SYS_process_mrelease => {
                let data = unsafe { &mut entry.data.process_mrelease };
                data.pidfd = args[0] as i32;
                data.flags = args[1] as u32;
            }
            syscalls::SYS_close => {
                let data = unsafe { &mut entry.data.close };
                data.fd = args[0] as i32;
            }
            syscalls::SYS_lseek => {
                let data = unsafe { &mut entry.data.lseek };
                data.fd = args[0] as i32;
                data.offset = args[1] as i64;
                data.whence = args[2] as i32;
            }
            syscalls::SYS_brk => {
                let data = unsafe { &mut entry.data.brk };
                data.addr = args[0];
            }
            syscalls::SYS_mprotect => {
                let data = unsafe { &mut entry.data.mprotect };
                data.addr = args[0];
                data.length = args[1];
                data.prot = args[2] as i32;
            }
            syscalls::SYS_getrandom => {
                let data = unsafe { &mut entry.data.getrandom };
                data.buf = args[0];
                data.buflen = args[1];
                data.flags = args[2] as u32;
            }
            syscalls::SYS_set_robust_list => {
                let data = unsafe { &mut entry.data.set_robust_list };
                data.head = args[0];
                data.len = args[1];
            }
            syscalls::SYS_set_tid_address => {
                let data = unsafe { &mut entry.data.set_tid_address };
                data.tidptr = args[0];
            }
            syscalls::SYS_rt_sigprocmask => {
                let data = unsafe { &mut entry.data.rt_sigprocmask };
                data.how = args[0] as i32;
                data.set = args[1];
                data.oldset = args[2];
                data.sigsetsize = args[3];

                // Try to read the signal sets from user memory
                if let Some(set_data) = read_sigset(args[1] as *const _) {
                    data.set_data = set_data;
                    data.has_set_data = true;
                }

                if let Some(oldset_data) = read_sigset(args[2] as *const _) {
                    data.oldset_data = oldset_data;
                    data.has_oldset_data = true;
                }
            }
            syscalls::SYS_rt_sigaction => {
                let data = unsafe { &mut entry.data.rt_sigaction };
                data.signum = args[0] as i32;
                data.act = args[1];
                data.oldact = args[2];
                data.sigsetsize = args[3];
            }
            syscalls::SYS_rt_sigpending => {
                let data = unsafe { &mut entry.data.rt_sigpending };
                data.set = args[0];
                data.sigsetsize = args[1];

                // Try to read the signal set from user memory
                if let Some(set_data) = read_sigset(args[0] as *const _) {
                    data.set_data = set_data;
                    data.has_set_data = true;
                }
            }
            syscalls::SYS_rt_sigqueueinfo => {
                let data = unsafe { &mut entry.data.rt_sigqueueinfo };
                data.tgid = args[0] as i32;
                data.sig = args[1] as i32;
                data.uinfo = args[2];
            }
            syscalls::SYS_rt_sigsuspend => {
                let data = unsafe { &mut entry.data.rt_sigsuspend };
                data.mask = args[0];
                data.sigsetsize = args[1];

                // Try to read the signal set from user memory
                if let Some(mask_data) = read_sigset(args[0] as *const _) {
                    data.mask_data = mask_data;
                    data.has_mask_data = true;
                }
            }
            syscalls::SYS_rt_sigtimedwait => {
                let data = unsafe { &mut entry.data.rt_sigtimedwait };
                data.set = args[0];
                data.info = args[1];
                data.timeout = args[2];
                data.sigsetsize = args[3];

                // Try to read the signal set from user memory
                if let Some(set_data) = read_sigset(args[0] as *const _) {
                    data.set_data = set_data;
                    data.has_set_data = true;
                }
            }
            syscalls::SYS_rt_tgsigqueueinfo => {
                let data = unsafe { &mut entry.data.rt_tgsigqueueinfo };
                data.tgid = args[0] as i32;
                data.tid = args[1] as i32;
                data.sig = args[2] as i32;
                data.uinfo = args[3];
            }
            syscalls::SYS_fchdir => {
                let data = unsafe { &mut entry.data.fchdir };
                data.fd = args[0] as i32;
            }
            syscalls::SYS_dup3 => {
                let data = unsafe { &mut entry.data.dup3 };
                data.oldfd = args[0] as i32;
                data.newfd = args[1] as i32;
                data.flags = args[2] as i32;
            }
            syscalls::SYS_exit_group => {
                let data = unsafe { &mut entry.data.exit_group };
                data.status = args[0] as i32;
            }
            syscalls::SYS_dup => {
                let data = unsafe { &mut entry.data.dup };
                data.oldfd = args[0] as i32;
            }
            #[cfg(x86_64)]
            syscalls::SYS_dup2 => {
                let data = unsafe { &mut entry.data.dup2 };
                data.oldfd = args[0] as i32;
                data.newfd = args[1] as i32;
            }
            syscalls::SYS_setuid => {
                let data = unsafe { &mut entry.data.setuid };
                data.uid = args[0] as u32;
            }
            syscalls::SYS_setgid => {
                let data = unsafe { &mut entry.data.setgid };
                data.gid = args[0] as u32;
            }
            syscalls::SYS_close_range => {
                let data = unsafe { &mut entry.data.close_range };
                data.fd = args[0] as u32;
                data.max_fd = args[1] as u32;
                data.flags = args[2] as u32;
            }
            syscalls::SYS_getpgid => {
                let data = unsafe { &mut entry.data.getpgid };
                data.pid = args[0] as i32;
            }
            syscalls::SYS_getsid => {
                let data = unsafe { &mut entry.data.getsid };
                data.pid = args[0] as i32;
            }
            syscalls::SYS_setpgid => {
                let data = unsafe { &mut entry.data.setpgid };
                data.pid = args[0] as i32;
                data.pgid = args[1] as i32;
            }
            syscalls::SYS_umask => {
                let data = unsafe { &mut entry.data.umask };
                data.mask = args[0] as u32;
            }
            syscalls::SYS_ioprio_get => {
                let data = unsafe { &mut entry.data.ioprio_get };
                data.which = args[0] as i32;
                data.who = args[1] as i32;
            }
            syscalls::SYS_ioprio_set => {
                let data = unsafe { &mut entry.data.ioprio_set };
                data.which = args[0] as i32;
                data.who = args[1] as i32;
                data.ioprio = args[2] as i32;
            }
            syscalls::SYS_setregid => {
                let data = unsafe { &mut entry.data.setregid };
                data.rgid = args[0] as u32;
                data.egid = args[1] as u32;
            }
            syscalls::SYS_setresgid => {
                let data = unsafe { &mut entry.data.setresgid };
                data.rgid = args[0] as u32;
                data.egid = args[1] as u32;
                data.sgid = args[2] as u32;
            }
            syscalls::SYS_setresuid => {
                let data = unsafe { &mut entry.data.setresuid };
                data.ruid = args[0] as u32;
                data.euid = args[1] as u32;
                data.suid = args[2] as u32;
            }
            syscalls::SYS_setreuid => {
                let data = unsafe { &mut entry.data.setreuid };
                data.ruid = args[0] as u32;
                data.euid = args[1] as u32;
            }
            #[cfg(x86_64)]
            syscalls::SYS_alarm => {
                let data = unsafe { &mut entry.data.alarm };
                data.seconds = args[0] as u32;
            }
            syscalls::SYS_personality => {
                let data = unsafe { &mut entry.data.personality };
                data.persona = args[0] as u64;
            }
            syscalls::SYS_getpriority => {
                let data = unsafe { &mut entry.data.getpriority };
                data.which = args[0] as i32;
                data.who = args[1] as i32;
            }
            syscalls::SYS_setpriority => {
                let data = unsafe { &mut entry.data.setpriority };
                data.which = args[0] as i32;
                data.who = args[1] as i32;
                data.prio = args[2] as i32;
            }
            syscalls::SYS_tkill => {
                let data = unsafe { &mut entry.data.tkill };
                data.pid = args[0] as i32;
                data.signal = args[1] as i32;
            }
            syscalls::SYS_tgkill => {
                let data = unsafe { &mut entry.data.tgkill };
                data.tgid = args[0] as i32;
                data.pid = args[1] as i32;
                data.signal = args[2] as i32;
            }
            syscalls::SYS_kill => {
                let data = unsafe { &mut entry.data.kill };
                data.pid = args[0] as i32;
                data.signal = args[1] as i32;
            }
            syscalls::SYS_exit => {
                let data = unsafe { &mut entry.data.exit };
                data.status = args[0] as i32;
            }
            syscalls::SYS_sched_getscheduler => {
                let data = unsafe { &mut entry.data.sched_getscheduler };
                data.pid = args[0] as i32;
            }
            syscalls::SYS_setfsuid => {
                let data = unsafe { &mut entry.data.setfsuid };
                data.uid = args[0] as u32;
            }
            syscalls::SYS_setfsgid => {
                let data = unsafe { &mut entry.data.setfsgid };
                data.gid = args[0] as u32;
            }
            syscalls::SYS_sched_get_priority_max => {
                let data = unsafe { &mut entry.data.sched_get_priority_max };
                data.policy = args[0] as i32;
            }
            syscalls::SYS_sched_get_priority_min => {
                let data = unsafe { &mut entry.data.sched_get_priority_min };
                data.policy = args[0] as i32;
            }
            syscalls::SYS_inotify_rm_watch => {
                let data = unsafe { &mut entry.data.inotify_rm_watch };
                data.fd = args[0] as i32;
                data.wd = args[1] as i32;
            }
            syscalls::SYS_inotify_init1 => {
                let data = unsafe { &mut entry.data.inotify_init1 };
                data.flags = args[0] as i32;
            }
            syscalls::SYS_socket => {
                let data = unsafe { &mut entry.data.socket };
                data.domain = args[0] as i32;
                data.type_ = args[1] as i32;
                data.protocol = args[2] as i32;
            }
            syscalls::SYS_listen => {
                let data = unsafe { &mut entry.data.listen };
                data.sockfd = args[0] as i32;
                data.backlog = args[1] as i32;
            }
            syscalls::SYS_shutdown => {
                let data = unsafe { &mut entry.data.shutdown };
                data.sockfd = args[0] as i32;
                data.how = args[1] as i32;
            }
            syscalls::SYS_fcntl => {
                let data = unsafe { &mut entry.data.fcntl };
                data.fd = args[0] as i32;
                data.cmd = args[1] as i32;
                data.arg = args[2];
            }
            syscalls::SYS_fchmod => {
                let data = unsafe { &mut entry.data.fchmod };
                data.fd = args[0] as i32;
                data.mode = args[1] as u32;
            }
            syscalls::SYS_fsync => {
                let data = unsafe { &mut entry.data.fsync };
                data.fd = args[0] as i32;
            }
            syscalls::SYS_pidfd_open => {
                let data = unsafe { &mut entry.data.pidfd_open };
                data.pid = args[0] as i32;
                data.flags = args[1] as u32;
            }
            syscalls::SYS_pidfd_getfd => {
                let data = unsafe { &mut entry.data.pidfd_getfd };
                data.pidfd = args[0] as i32;
                data.targetfd = args[1] as i32;
                data.flags = args[2] as u32;
            }
            syscalls::SYS_fdatasync => {
                let data = unsafe { &mut entry.data.fdatasync };
                data.fd = args[0] as i32;
            }
            syscalls::SYS_ftruncate => {
                let data = unsafe { &mut entry.data.ftruncate };
                data.fd = args[0] as i32;
                data.length = args[1] as i64;
            }
            syscalls::SYS_fchown => {
                let data = unsafe { &mut entry.data.fchown };
                data.fd = args[0] as i32;
                data.uid = args[1] as u32;
                data.gid = args[2] as u32;
            }
            #[cfg(x86_64)]
            syscalls::SYS_epoll_create => {
                let data = unsafe { &mut entry.data.epoll_create };
                data.size = args[0] as i32;
            }
            syscalls::SYS_epoll_create1 => {
                let data = unsafe { &mut entry.data.epoll_create1 };
                data.flags = args[0] as i32;
            }
            syscalls::SYS_memfd_secret => {
                let data = unsafe { &mut entry.data.memfd_secret };
                data.flags = args[0] as u32;
            }
            syscalls::SYS_userfaultfd => {
                let data = unsafe { &mut entry.data.userfaultfd };
                data.flags = args[0] as u32;
            }
            syscalls::SYS_pkey_alloc => {
                let data = unsafe { &mut entry.data.pkey_alloc };
                data.flags = args[0] as u32;
                data.access_rights = args[1] as u32;
            }
            syscalls::SYS_pkey_free => {
                let data = unsafe { &mut entry.data.pkey_free };
                data.pkey = args[0] as i32;
            }
            #[cfg(x86_64)]
            syscalls::SYS_eventfd => {
                let data = unsafe { &mut entry.data.eventfd };
                data.initval = args[0] as u32;
                data.flags = args[1] as i32;
            }
            syscalls::SYS_eventfd2 => {
                let data = unsafe { &mut entry.data.eventfd2 };
                data.initval = args[0] as u32;
                data.flags = args[1] as i32;
            }
            syscalls::SYS_mlock => {
                let data = unsafe { &mut entry.data.mlock };
                data.addr = args[0];
                data.len = args[1];
            }
            syscalls::SYS_mlock2 => {
                let data = unsafe { &mut entry.data.mlock2 };
                data.addr = args[0];
                data.len = args[1];
                data.flags = args[2] as i32;
            }
            syscalls::SYS_mlockall => {
                let data = unsafe { &mut entry.data.mlockall };
                data.flags = args[0] as i32;
            }
            syscalls::SYS_membarrier => {
                let data = unsafe { &mut entry.data.membarrier };
                data.cmd = args[0] as i32;
                data.flags = args[1] as i32;
            }
            syscalls::SYS_mremap => {
                let data = unsafe { &mut entry.data.mremap };
                data.old_address = args[0];
                data.old_size = args[1];
                data.new_size = args[2];
                data.flags = args[3] as i32;
            }
            syscalls::SYS_msync => {
                let data = unsafe { &mut entry.data.msync };
                data.addr = args[0];
                data.length = args[1];
                data.flags = args[2] as i32;
            }
            syscalls::SYS_munlock => {
                let data = unsafe { &mut entry.data.munlock };
                data.addr = args[0];
                data.len = args[1];
            }
            syscalls::SYS_readahead => {
                let data = unsafe { &mut entry.data.readahead };
                data.fd = args[0] as i32;
                data.offset = args[1];
                data.count = args[2];
            }
            syscalls::SYS_setns => {
                let data = unsafe { &mut entry.data.setns };
                data.fd = args[0] as i32;
                data.nstype = args[1] as i32;
            }
            syscalls::SYS_unshare => {
                let data = unsafe { &mut entry.data.unshare };
                data.flags = args[0] as i32;
            }
            #[cfg(x86_64)]
            syscalls::SYS_pause | syscalls::SYS_getpgrp | syscalls::SYS_inotify_init => {}
            syscalls::SYS_sched_yield
            | syscalls::SYS_getpid
            | syscalls::SYS_gettid
            | syscalls::SYS_getuid
            | syscalls::SYS_geteuid
            | syscalls::SYS_getgid
            | syscalls::SYS_getegid
            | syscalls::SYS_getppid
            | syscalls::SYS_rt_sigreturn
            | syscalls::SYS_sync
            | syscalls::SYS_setsid
            | syscalls::SYS_munlockall
            | syscalls::SYS_vhangup => {}
            _ => {
                trace!(&ctx, "unknown syscall {}", syscall_nr);
                entry.discard();
                return Ok(());
            }
        }

        entry.submit();

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
        let args = get_args(&ctx, syscall_nr)?;

        let mut entry = util::Entry::new(&ctx, syscall_nr)?;

        let data = unsafe { &mut entry.data.generic };

        data.args = args;

        entry.submit();

        Ok(())
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
