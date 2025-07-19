// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_buf, bpf_probe_read_user},
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
    EbpfContext as _,
};
use pinchy_common::{
    kernel_types::Rlimit,
    syscalls::{SYS_execve, SYS_getrusage, SYS_prlimit64, SYS_wait4},
    SMALL_READ_SIZE,
};

use crate::{
    util::{get_args, get_return_value, output_event},
    PID_FILTER, SYSCALL_ARGS_OFFSET,
};

#[map]
static mut EXECVE_ENTER_MAP: HashMap<u32, ExecveEnterData> =
    HashMap::<u32, ExecveEnterData>::with_max_entries(10240, 0);

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
pub fn syscall_exit_wait4(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_wait4;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let pid = args[0] as i32;
        let wstatus_ptr = args[1] as *const i32;
        let options = args[2] as i32;
        let rusage_ptr = args[3] as *const pinchy_common::kernel_types::Rusage;

        let mut wstatus = 0i32;
        let mut rusage = pinchy_common::kernel_types::Rusage::default();
        let mut has_rusage = false;

        // Only read wstatus if the call was successful and pointer is not null
        if return_value >= 0 && wstatus_ptr != core::ptr::null() {
            unsafe {
                if let Ok(status) = bpf_probe_read_user::<i32>(wstatus_ptr) {
                    wstatus = status;
                }
            }
        }

        // Only read rusage if the call was successful and pointer is not null
        if return_value >= 0 && rusage_ptr != core::ptr::null() {
            unsafe {
                if let Ok(usage) =
                    bpf_probe_read_user::<pinchy_common::kernel_types::Rusage>(rusage_ptr)
                {
                    rusage = usage;
                    has_rusage = true;
                }
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                wait4: pinchy_common::Wait4Data {
                    pid,
                    wstatus,
                    options,
                    has_rusage,
                    rusage,
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
pub fn syscall_exit_getrusage(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_getrusage;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let who = args[0] as i32;
        let usage_ptr = args[1] as *const pinchy_common::kernel_types::Rusage;

        let mut rusage = pinchy_common::kernel_types::Rusage::default();

        // Only read rusage if the call was successful and pointer is not null
        if return_value >= 0 && usage_ptr != core::ptr::null() {
            unsafe {
                if let Ok(usage) =
                    bpf_probe_read_user::<pinchy_common::kernel_types::Rusage>(usage_ptr)
                {
                    rusage = usage;
                }
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                getrusage: pinchy_common::GetrusageData { who, rusage },
            },
        )
    }

    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}
