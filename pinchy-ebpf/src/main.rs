// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#![no_std]
#![no_main]
#![allow(non_snake_case, non_upper_case_globals, static_mut_refs)]
use core::ops::DerefMut;

use aya_ebpf::{
    bindings::BPF_RB_FORCE_WAKEUP,
    helpers::{bpf_probe_read_buf, bpf_probe_read_user},
    macros::{map, tracepoint},
    maps::{Array, HashMap, ProgramArray, RingBuf},
    programs::TracePointContext,
    EbpfContext as _,
};
use aya_log_ebpf::{error, trace};
use pinchy_common::{
    kernel_types::{EpollEvent, LinuxDirent64, Pollfd, Rlimit, Rseq, Stat, Timespec, Utsname},
    syscalls::{
        SYS_brk, SYS_close, SYS_epoll_pwait, SYS_execve, SYS_faccessat, SYS_fcntl, SYS_fstat,
        SYS_getdents64, SYS_getrandom, SYS_ioctl, SYS_lseek, SYS_mmap, SYS_mprotect, SYS_munmap,
        SYS_newfstatat, SYS_openat, SYS_ppoll, SYS_prlimit64, SYS_read, SYS_rseq, SYS_rt_sigaction,
        SYS_rt_sigprocmask, SYS_sched_yield, SYS_set_robust_list, SYS_set_tid_address, SYS_statfs,
        SYS_uname, SYS_write,
    },
    SyscallEvent, DATA_READ_SIZE, SMALL_READ_SIZE,
};

#[map]
static mut PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// Treated as a bitmap for syscalls.
#[map]
static mut SYSCALL_FILTER: Array<u8> = Array::with_max_entries(64, 0);

#[map] // 80MiB output buffer
static mut EVENTS: RingBuf = RingBuf::with_byte_size(83886080, 0);

#[map]
static mut ENTER_MAP: HashMap<u32, SyscallEnterData> = HashMap::with_max_entries(10240, 0);

#[map]
static mut EXECVE_ENTER_MAP: HashMap<u32, ExecveEnterData> =
    HashMap::<u32, ExecveEnterData>::with_max_entries(10240, 0);

#[map(name = "SYSCALL_TAILCALLS")]
static mut SYSCALL_TAILCALLS: ProgramArray = ProgramArray::pinned(512, 0);

#[repr(C)]
pub struct SyscallEnterData {
    pub tgid: u32,
    pub syscall_nr: i64,
    pub args: [usize; SYSCALL_ARGS_COUNT],
}

#[repr(C)]
pub struct ExecveEnterData {
    pub filename: [u8; SMALL_READ_SIZE * 4],
    pub filename_truncated: bool,
    pub argv: [[u8; SMALL_READ_SIZE]; 4],
    pub argv_len: [u16; 4],
    pub argc: u8,
    pub envp: [[u8; SMALL_READ_SIZE]; 2],
    pub envp_len: [u16; 2],
    pub envc: u8,
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
pub fn syscall_exit_futex(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = get_syscall_nr(&ctx)?;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let uaddr = args[0];
        let op = args[1] as i32;
        let val = args[2] as u32;
        let timeout_ptr = args[3] as *const Timespec;
        let uaddr2 = args[4];
        let val3 = args[5] as u32;
        let timeout = if timeout_ptr.is_null() {
            unsafe { core::mem::zeroed() }
        } else {
            read_timespec(timeout_ptr)
        };

        let data = pinchy_common::SyscallEventData {
            futex: pinchy_common::FutexData {
                uaddr,
                op: op as u32,
                val,
                uaddr2,
                val3,
                timeout,
            },
        };

        output_event(&ctx, syscall_nr, return_value, data)
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(err) => err,
    }
}

#[tracepoint]
pub fn syscall_exit_openat(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_openat;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let dfd = args[0] as i32;
        let pathname_ptr = args[1] as *const u8;
        let flags = args[2] as i32;
        let mode = args[3] as u32;

        let mut pathname = [0u8; DATA_READ_SIZE];
        unsafe {
            let _ = bpf_probe_read_buf(pathname_ptr as *const _, &mut pathname);
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                openat: pinchy_common::OpenAtData {
                    dfd,
                    pathname,
                    flags,
                    mode,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_epoll_pwait(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_epoll_pwait;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let epfd = args[0] as i32;
        let events_ptr = args[1] as *const EpollEvent;
        let max_events = args[2] as i32;
        let timeout = args[3] as i32;

        let mut events = [EpollEvent::default(); 8];
        for (i, item) in events.iter_mut().enumerate() {
            if i < return_value as usize {
                unsafe {
                    let events_ptr = events_ptr.add(i);
                    if let Ok(evt) = bpf_probe_read_user::<EpollEvent>(events_ptr as *const _) {
                        *item = evt;
                    }
                }
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                epoll_pwait: pinchy_common::EpollPWaitData {
                    epfd,
                    events,
                    max_events,
                    timeout,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_ppoll(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_ppoll;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let nfds = args[1];
        let fds_ptr = args[0] as *const Pollfd;
        let mut fds = [0i32; 16];
        let mut events = [0i16; 16];
        let mut revents = [0i16; 16];
        for i in 0..fds.len() {
            if i < nfds {
                unsafe {
                    let entry_ptr = fds_ptr.add(i);
                    if let Ok(pollfd) = bpf_probe_read_user::<Pollfd>(entry_ptr as *const _) {
                        fds[i] = pollfd.fd;
                        events[i] = pollfd.events;
                        revents[i] = pollfd.revents;
                    }
                }
            }
        }
        let timeout = read_timespec(args[2] as *const _);

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                ppoll: pinchy_common::PpollData {
                    fds,
                    events,
                    revents,
                    nfds: nfds as u32,
                    timeout,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_read(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_read;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let buf_addr = args[1];
        let count = args[2];

        let mut buf = [0u8; DATA_READ_SIZE];
        let to_read = core::cmp::min(return_value as usize, buf.len());
        unsafe {
            let _ = bpf_probe_read_buf(buf_addr as *const _, &mut buf[..to_read]);
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                read: pinchy_common::ReadData { fd, buf, count },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_ioctl(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_ioctl;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let request = args[1] as u32;
        let arg = args[2];

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                ioctl: pinchy_common::IoctlData { fd, request, arg },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_fcntl(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_fcntl;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let cmd = args[1] as i32;
        let arg = args[2];

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                fcntl: pinchy_common::FcntlData { fd, cmd, arg },
            },
        )
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

#[tracepoint]
pub fn syscall_exit_write(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_write;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let buf_addr = args[1];
        let count = args[2];

        let mut buf = [0u8; DATA_READ_SIZE];
        let to_copy = core::cmp::min(count as usize, buf.len());
        unsafe {
            let _ = bpf_probe_read_buf(buf_addr as *const _, &mut buf[..to_copy]);
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                write: pinchy_common::WriteData { fd, buf, count },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_fstat(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_fstat;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let stat_ptr = args[1] as *const u8;
        let mut stat = Stat::default();
        unsafe {
            let _ = bpf_probe_read_buf(
                stat_ptr,
                core::slice::from_raw_parts_mut(
                    &mut stat as *mut _ as *mut u8,
                    core::mem::size_of::<Stat>(),
                ),
            );
        }
        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                fstat: pinchy_common::FstatData { fd, stat },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_newfstatat(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_newfstatat;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let dirfd = args[0] as i32;
        let pathname_ptr = args[1] as *const u8;
        let stat_ptr = args[2] as *const u8;
        let flags = args[3] as i32;

        let mut pathname = [0u8; pinchy_common::DATA_READ_SIZE];
        let mut stat = Stat::default();

        unsafe {
            let _ = bpf_probe_read_buf(pathname_ptr as *const _, &mut pathname);

            // Only read the stat buffer if the syscall was successful (return_value == 0)
            if return_value == 0 {
                let _ = bpf_probe_read_buf(
                    stat_ptr,
                    core::slice::from_raw_parts_mut(
                        &mut stat as *mut _ as *mut u8,
                        core::mem::size_of::<Stat>(),
                    ),
                );
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                newfstatat: pinchy_common::NewfstatatData {
                    dirfd,
                    pathname,
                    stat,
                    flags,
                },
            },
        )
    }

    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_getdents64(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_getdents64;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let dirp = args[1] as *const u8;
        let count = args[2] as usize;

        let mut dirents: [LinuxDirent64; 4] = [LinuxDirent64::default(); 4];
        let mut num_dirents = 0u8;
        let mut offset = 0usize;
        let bytes = core::cmp::min(return_value as usize, count);
        while offset < bytes && (num_dirents as usize) < dirents.len() {
            let mut d: LinuxDirent64 = LinuxDirent64::default();
            let base = unsafe { dirp.add(offset) };

            if let Ok(val) = unsafe { bpf_probe_read_user::<LinuxDirent64>(base as *const _) } {
                d = val;
            }

            let reclen = d.d_reclen as usize;
            if reclen == 0 {
                break;
            }

            dirents[num_dirents as usize] = d;
            num_dirents += 1;
            offset += reclen;
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                getdents64: pinchy_common::Getdents64Data {
                    fd,
                    count,
                    dirents,
                    num_dirents,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_execve(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let tid = ctx.pid();
        let return_value = get_return_value(&ctx)?;
        let enter_data = unsafe { EXECVE_ENTER_MAP.get(&tid) };
        if let Some(enter_data) = enter_data {
            let _ = unsafe { EXECVE_ENTER_MAP.remove(&tid) };
            output_event(
                &ctx,
                SYS_execve,
                return_value,
                pinchy_common::SyscallEventData {
                    execve: pinchy_common::ExecveData {
                        filename: enter_data.filename,
                        filename_truncated: enter_data.filename_truncated,
                        argv: enter_data.argv,
                        argv_len: enter_data.argv_len,
                        argc: enter_data.argc,
                        envp: enter_data.envp,
                        envp_len: enter_data.envp_len,
                        envc: enter_data.envc,
                    },
                },
            )
        } else {
            // fallback: emit empty event
            output_event(
                &ctx,
                SYS_execve,
                return_value,
                pinchy_common::SyscallEventData {
                    execve: unsafe { core::mem::zeroed() },
                },
            )
        }
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_enter_execve(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        if unsafe { PID_FILTER.get(&ctx.tgid()).is_none() } {
            return Ok(());
        }

        let tid = ctx.pid();

        let args = unsafe {
            ctx.read_at::<[usize; 6]>(SYSCALL_ARGS_OFFSET)
                .map_err(|e| e as u32)?
        };
        let filename_ptr = args[0] as *const u8;
        let argv_ptr = args[1] as *const *const u8;
        let envp_ptr = args[2] as *const *const u8;

        let mut filename = [0u8; SMALL_READ_SIZE * 4];
        unsafe {
            let _ = bpf_probe_read_buf(filename_ptr as *const _, &mut filename);
        }
        let mut filename_truncated = true;
        for byte in filename {
            if byte == 0 {
                filename_truncated = false;
                break;
            }
        }

        let mut argv = [[0u8; SMALL_READ_SIZE]; 4];
        let mut argv_len = [0u16; 4];
        let mut argc = 0u8;
        for i in 0..128 {
            let ptr = unsafe { bpf_probe_read_user(argv_ptr.add(i)) };
            if let Ok(arg_ptr) = ptr {
                if arg_ptr.is_null() {
                    break;
                }
                if i < 4 {
                    unsafe {
                        let _ = bpf_probe_read_buf(arg_ptr as *const _, &mut argv[i]);
                    }
                    for j in 0..argv[i].len() {
                        if argv[i][j] == 0 {
                            argv_len[i] = j as u16;
                            break;
                        }
                    }
                    if argv_len[i] == 0 && argv[i][0] != 0 {
                        argv_len[i] = argv[i].len() as u16;
                    }
                }
                argc += 1;
            } else {
                break;
            }
        }

        let mut envp = [[0u8; SMALL_READ_SIZE]; 2];
        let mut envp_len = [0u16; 2];
        let mut envc = 0u8;
        for i in 0..128 {
            let ptr = unsafe { bpf_probe_read_user(envp_ptr.add(i)) };
            if let Ok(env_ptr) = ptr {
                if env_ptr.is_null() {
                    break;
                }
                if i < 2 {
                    unsafe {
                        let _ = bpf_probe_read_buf(env_ptr as *const _, &mut envp[i]);
                    }
                    for j in 0..envp[i].len() {
                        if envp[i][j] == 0 {
                            envp_len[i] = j as u16;
                            break;
                        }
                    }
                    if envp_len[i] == 0 && envp[i][0] != 0 {
                        envp_len[i] = envp[i].len() as u16;
                    }
                }
                envc += 1;
            } else {
                break;
            }
        }

        let data = ExecveEnterData {
            filename,
            filename_truncated,
            argv,
            argv_len,
            argc,
            envp,
            envp_len,
            envc,
        };
        unsafe {
            EXECVE_ENTER_MAP
                .insert(&tid, &data, 0)
                .map_err(|e| e as u32)?;
        }
        Ok(())
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_mmap(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_mmap;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let addr = args[0];
        let length = args[1];
        let prot = args[2] as i32;
        let flags = args[3] as i32;
        let fd = args[4] as i32;
        let offset = args[5];

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                mmap: pinchy_common::MmapData {
                    addr,
                    length,
                    prot,
                    flags,
                    fd,
                    offset,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_munmap(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_munmap;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let addr = args[0];
        let length = args[1];

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                munmap: pinchy_common::MunmapData { addr, length },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_statfs(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_statfs;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let pathname_ptr = args[0] as *const u8;
        let buf_ptr = args[1] as *const pinchy_common::kernel_types::Statfs;

        // Only parse the buffer if the syscall succeeded
        let mut pathname = [0u8; DATA_READ_SIZE];
        let mut statfs = pinchy_common::kernel_types::Statfs::default();

        unsafe {
            let _ = bpf_probe_read_buf(pathname_ptr as *const _, &mut pathname);

            // Only read the statfs buffer if the syscall was successful (return_value == 0)
            if return_value == 0 {
                if let Ok(data) = bpf_probe_read_user(buf_ptr as *const _) {
                    statfs = data;
                }
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                statfs: pinchy_common::StatfsData { pathname, statfs },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_prlimit64(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_prlimit64;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let pid = args[0] as i32;
        let resource = args[1] as i32;
        let new_limit_ptr = args[2] as *const Rlimit;
        let old_limit_ptr = args[3] as *const Rlimit;

        // Default values for limits
        let mut new_limit = Rlimit::default();
        let mut old_limit = Rlimit::default();

        // Track whether new and old limits are present
        let has_new = !new_limit_ptr.is_null();
        let has_old = !old_limit_ptr.is_null();

        // Only try to read the new limit if provided
        if has_new {
            if let Ok(limit) = unsafe { bpf_probe_read_user::<Rlimit>(new_limit_ptr as *const _) } {
                new_limit = limit;
            }
        }

        // Only try to read the old limit if provided and call was successful
        if has_old && return_value == 0 {
            if let Ok(limit) = unsafe { bpf_probe_read_user::<Rlimit>(old_limit_ptr as *const _) } {
                old_limit = limit;
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                prlimit: pinchy_common::PrlimitData {
                    pid,
                    resource,
                    has_old,
                    has_new,
                    old_limit,
                    new_limit,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_faccessat(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_faccessat;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let dirfd = args[0] as i32;
        let pathname_ptr = args[1] as *const u8;
        let mode = args[2] as i32;
        let flags = args[3] as i32;

        let mut pathname = [0u8; DATA_READ_SIZE];
        unsafe {
            let _ = bpf_probe_read_buf(pathname_ptr as *const _, &mut pathname);
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                faccessat: pinchy_common::FaccessatData {
                    dirfd,
                    pathname,
                    mode,
                    flags,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

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

#[tracepoint]
pub fn syscall_exit_uname(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_uname;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let buf_ptr = args[0] as *const u8;
        let mut utsname = Utsname::default();

        // Each field in the Linux kernel utsname struct is 65 bytes
        // We read fewer bytes of most fields to fit within eBPF stack limits
        const FIELD_SIZE: usize = 65; // Linux kernel field size

        // Read sysname (offset 0)
        unsafe {
            let _ = bpf_probe_read_buf(
                buf_ptr,
                core::slice::from_raw_parts_mut(
                    utsname.sysname.as_mut_ptr(),
                    pinchy_common::kernel_types::SYSNAME_READ_SIZE,
                ),
            );
        }

        // Read nodename (offset FIELD_SIZE)
        unsafe {
            let _ = bpf_probe_read_buf(
                buf_ptr.add(FIELD_SIZE),
                core::slice::from_raw_parts_mut(
                    utsname.nodename.as_mut_ptr(),
                    pinchy_common::kernel_types::NODENAME_READ_SIZE,
                ),
            );
        }

        // Read release (offset 2 * FIELD_SIZE)
        unsafe {
            let _ = bpf_probe_read_buf(
                buf_ptr.add(2 * FIELD_SIZE),
                core::slice::from_raw_parts_mut(
                    utsname.release.as_mut_ptr(),
                    pinchy_common::kernel_types::RELEASE_READ_SIZE,
                ),
            );
        }

        // Read version (offset 3 * FIELD_SIZE)
        unsafe {
            let _ = bpf_probe_read_buf(
                buf_ptr.add(3 * FIELD_SIZE),
                core::slice::from_raw_parts_mut(
                    utsname.version.as_mut_ptr(),
                    pinchy_common::kernel_types::VERSION_READ_SIZE,
                ),
            );
        }

        // Read machine (offset 4 * FIELD_SIZE)
        unsafe {
            let _ = bpf_probe_read_buf(
                buf_ptr.add(4 * FIELD_SIZE),
                core::slice::from_raw_parts_mut(
                    utsname.machine.as_mut_ptr(),
                    pinchy_common::kernel_types::MACHINE_READ_SIZE,
                ),
            );
        }

        // Read domainname (offset 5 * FIELD_SIZE)
        unsafe {
            let _ = bpf_probe_read_buf(
                buf_ptr.add(5 * FIELD_SIZE),
                core::slice::from_raw_parts_mut(
                    utsname.domainname.as_mut_ptr(),
                    pinchy_common::kernel_types::DOMAIN_READ_SIZE,
                ),
            );
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                uname: pinchy_common::UnameData { utsname },
            },
        )
    }

    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn read_timespec(ptr: *const Timespec) -> Timespec {
    unsafe { bpf_probe_read_user::<Timespec>(ptr) }.unwrap_or_default()
}

#[inline(always)]
fn get_syscall_nr(ctx: &TracePointContext) -> Result<i64, u32> {
    unsafe { ENTER_MAP.get(&ctx.pid()) }
        .map(|data| data.syscall_nr)
        .ok_or(1)
}

#[inline(always)]
fn get_args(ctx: &TracePointContext, expected_syscall_nr: i64) -> Result<[usize; 6], u32> {
    let tgid = ctx.tgid();
    let tid = ctx.pid();
    let syscall_nr = SYS_read;

    let Some(enter_data) = (unsafe { ENTER_MAP.get(&tid) }) else {
        error!(
            ctx,
            "Could not find matching enter data for syscall {} exit (tid {}, tgid {})",
            syscall_nr,
            tid,
            tgid
        );
        return Err(1);
    };

    if enter_data.syscall_nr != expected_syscall_nr {
        error!(
            ctx,
            "Expected syscall {} found syscall {} on enter data (tid {}, tgid {})",
            expected_syscall_nr,
            enter_data.syscall_nr,
            tid,
            tgid
        );
        return Err(1);
    }

    // Copy the part of the enter data we care about...
    let args = enter_data.args;

    // Then remove the item from the map.
    let _ = unsafe { ENTER_MAP.remove(&tid) };

    Ok(args)
}

#[inline(always)]
fn get_return_value(ctx: &TracePointContext) -> Result<i64, u32> {
    Ok(unsafe {
        ctx.read_at::<i64>(SYSCALL_RETURN_OFFSET)
            .map_err(|_| 1u32)?
    })
}

#[inline(always)]
fn output_event(
    ctx: &TracePointContext,
    syscall_nr: i64,
    return_value: i64,
    data: pinchy_common::SyscallEventData,
) -> Result<(), u32> {
    let tgid = ctx.tgid();
    let tid = ctx.pid();

    unsafe {
        let mut buf: Option<aya_ebpf::maps::ring_buf::RingBufEntry<SyscallEvent>> = None;

        // Retry a few times if the buffer is full, give time for userspace to catch up
        for _ in 0..1_024 {
            buf = EVENTS.reserve(0);
            if buf.is_some() {
                break;
            }
        }

        match buf {
            Some(mut entry) => {
                let event = entry.deref_mut();
                event.write(SyscallEvent {
                    syscall_nr,
                    pid: tgid,
                    tid,
                    return_value,
                    data,
                });
                entry.submit(BPF_RB_FORCE_WAKEUP.into());
            }
            None => {
                error!(
                    ctx,
                    "Failed to reserve space for event - ring buffer was full."
                );
            }
        }
    }

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
