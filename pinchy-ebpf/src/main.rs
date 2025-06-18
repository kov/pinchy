// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#![no_std]
#![no_main]
#![allow(non_snake_case, non_upper_case_globals, static_mut_refs)]
use core::ops::DerefMut;

use aya_ebpf::{
    helpers::{bpf_probe_read_buf, bpf_probe_read_user},
    macros::{map, tracepoint},
    maps::{Array, HashMap, ProgramArray, RingBuf},
    programs::TracePointContext,
    EbpfContext as _,
};
use aya_log_ebpf::{error, trace};
use pinchy_common::{
    kernel_types::{EpollEvent, LinuxDirent64, Pollfd, Stat, Timespec},
    syscalls::{
        SYS_brk, SYS_close, SYS_epoll_pwait, SYS_execve, SYS_fstat, SYS_getdents64, SYS_getrandom,
        SYS_ioctl, SYS_lseek, SYS_mmap, SYS_mprotect, SYS_munmap, SYS_openat, SYS_ppoll, SYS_read,
        SYS_sched_yield, SYS_write,
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
    if nr < 0 || nr >= 512 {
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
        for i in 0..events.len() {
            if i < return_value as usize {
                unsafe {
                    let events_ptr = events_ptr.add(i as usize);
                    if let Ok(evt) = bpf_probe_read_user::<EpollEvent>(events_ptr as *const _) {
                        events[i] = evt;
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
                    let entry_ptr = fds_ptr.add(i as usize);
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
            return output_event(
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
            );
        } else {
            // fallback: emit empty event
            return output_event(
                &ctx,
                SYS_execve,
                return_value,
                pinchy_common::SyscallEventData {
                    execve: unsafe { core::mem::zeroed() },
                },
            );
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
        for i in 0..filename.len() {
            if filename[i] == 0 {
                filename_truncated = false;
                break;
            }
        }

        let mut argv = [[0u8; SMALL_READ_SIZE]; 4];
        let mut argv_len = [0u16; 4];
        let mut argc = 0u8;
        for i in 0..128 {
            let ptr = unsafe { bpf_probe_read_user(argv_ptr.add(i) as *const *const u8) };
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
            let ptr = unsafe { bpf_probe_read_user(envp_ptr.add(i) as *const *const u8) };
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
                entry.submit(0);
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
