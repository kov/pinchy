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
    kernel_types::{CloneArgs, Rlimit, Rusage},
    syscalls, SMALL_READ_SIZE,
};

use crate::{PID_FILTER, SYSCALL_ARGS_OFFSET};

#[map]
static mut EXECVE_ENTER_MAP: HashMap<u32, ExecveEnterData> =
    HashMap::<u32, ExecveEnterData>::with_max_entries(10240, 0);

#[map]
static mut EXECVEAT_ENTER_MAP: HashMap<u32, ExecveatEnterData> =
    HashMap::<u32, ExecveatEnterData>::with_max_entries(10240, 0);

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

#[repr(C)]
pub struct ExecveatEnterData {
    pub dirfd: i32,
    pub pathname: [u8; SMALL_READ_SIZE * 4],
    pub pathname_truncated: bool,
    pub argv: [[u8; SMALL_READ_SIZE]; 4],
    pub argv_len: [u16; 4],
    pub argc: u8,
    pub envp: [[u8; SMALL_READ_SIZE]; 2],
    pub envp_len: [u16; 2],
    pub envc: u8,
    pub flags: i32,
}

#[tracepoint]
pub fn syscall_exit_execve(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let tid = ctx.pid();
        let return_value = crate::util::get_return_value(&ctx)?;

        // On x86_64, execveat becomes execve after the process has been replaced, so we need to
        // use the same handler for both and check which map has the entry to decide which one was
        // traced.
        let enter_data = unsafe { EXECVE_ENTER_MAP.get(&tid) };
        if let Some(enter_data) = enter_data {
            let data = pinchy_common::SyscallEventData {
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
            };
            let _ = unsafe { EXECVE_ENTER_MAP.remove(&tid) };
            return crate::util::output_event(
                &ctx,
                pinchy_common::syscalls::SYS_execve,
                return_value,
                data,
            );
        }

        let enter_data = unsafe { EXECVEAT_ENTER_MAP.get(&tid) };
        if let Some(enter_data) = enter_data {
            let data = pinchy_common::SyscallEventData {
                execveat: pinchy_common::ExecveatData {
                    dirfd: enter_data.dirfd,
                    pathname: enter_data.pathname,
                    pathname_truncated: enter_data.pathname_truncated,
                    argv: enter_data.argv,
                    argv_len: enter_data.argv_len,
                    argc: enter_data.argc,
                    envp: enter_data.envp,
                    envp_len: enter_data.envp_len,
                    envc: enter_data.envc,
                    flags: enter_data.flags,
                },
            };
            let _ = unsafe { EXECVEAT_ENTER_MAP.remove(&tid) };
            return crate::util::output_event(
                &ctx,
                pinchy_common::syscalls::SYS_execveat,
                return_value,
                data,
            );
        }

        aya_log_ebpf::error!(
            &ctx,
            "did not find matching enter data for execve for PID",
            tid
        );

        return Err(1);
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

        let mut data = ExecveEnterData {
            filename: [0u8; SMALL_READ_SIZE * 4],
            filename_truncated: true,
            argv: [[0u8; SMALL_READ_SIZE]; 4],
            argv_len: [0u16; 4],
            argc: 0,
            envp: [[0u8; SMALL_READ_SIZE]; 2],
            envp_len: [0u16; 2],
            envc: 0,
        };
        let filename_ptr = args[0] as *const u8;
        let argv_ptr = args[1] as *const *const u8;
        let envp_ptr = args[2] as *const *const u8;

        read_execve_enter_data(
            filename_ptr,
            argv_ptr,
            envp_ptr,
            &mut data.filename,
            &mut data.filename_truncated,
            &mut data.argv,
            &mut data.argv_len,
            &mut data.argc,
            &mut data.envp,
            &mut data.envp_len,
            &mut data.envc,
        );

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
pub fn syscall_enter_execveat(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        if unsafe { PID_FILTER.get(&ctx.tgid()).is_none() } {
            return Ok(());
        }

        let tid = ctx.pid();

        let args = unsafe {
            ctx.read_at::<[usize; 6]>(SYSCALL_ARGS_OFFSET)
                .map_err(|e| e as u32)?
        };

        let mut data = ExecveatEnterData {
            dirfd: args[0] as i32,
            pathname: [0u8; SMALL_READ_SIZE * 4],
            pathname_truncated: true,
            argv: [[0u8; SMALL_READ_SIZE]; 4],
            argv_len: [0u16; 4],
            argc: 0,
            envp: [[0u8; SMALL_READ_SIZE]; 2],
            envp_len: [0u16; 2],
            envc: 0,
            flags: 0,
        };

        let pathname_ptr = args[1] as *const u8;
        let argv_ptr = args[2] as *const *const u8;
        let envp_ptr = args[3] as *const *const u8;

        read_execve_enter_data(
            pathname_ptr,
            argv_ptr,
            envp_ptr,
            &mut data.pathname,
            &mut data.pathname_truncated,
            &mut data.argv,
            &mut data.argv_len,
            &mut data.argc,
            &mut data.envp,
            &mut data.envp_len,
            &mut data.envc,
        );

        unsafe {
            EXECVEAT_ENTER_MAP
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

#[inline(always)]
fn read_execve_enter_data(
    pathname_ptr: *const u8,
    argv_ptr: *const *const u8,
    envp_ptr: *const *const u8,
    pathname: &mut [u8; SMALL_READ_SIZE * 4],
    pathname_truncated: &mut bool,
    argv: &mut [[u8; SMALL_READ_SIZE]; 4],
    argv_len: &mut [u16; 4],
    argc: &mut u8,
    envp: &mut [[u8; SMALL_READ_SIZE]; 2],
    envp_len: &mut [u16; 2],
    envc: &mut u8,
) {
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr as *const _, pathname);
    }

    for byte in pathname {
        if *byte == 0 {
            *pathname_truncated = false;
            break;
        }
    }

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
            *argc += 1;
        } else {
            break;
        }
    }

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
            *envc += 1;
        } else {
            break;
        }
    }
}

#[tracepoint]
pub fn syscall_exit_process(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = crate::util::get_syscall_nr(&ctx)?;
        let args = crate::util::get_args(&ctx, syscall_nr)?;
        let return_value = crate::util::get_return_value(&ctx)?;

        let mut entry = crate::util::Entry::new(&ctx, syscall_nr)?;

        match syscall_nr {
            pinchy_common::syscalls::SYS_wait4 => {
                let data = crate::data_mut!(entry, wait4);
                data.pid = args[0] as i32;
                let wstatus_ptr = args[1] as *const i32;
                data.options = args[2] as i32;
                let rusage_ptr = args[3] as *const Rusage;

                data.wstatus = 0i32;
                data.rusage = Rusage::default();
                data.has_rusage = false;

                if return_value >= 0 && !wstatus_ptr.is_null() {
                    unsafe {
                        if let Ok(status) = bpf_probe_read_user::<i32>(wstatus_ptr) {
                            data.wstatus = status;
                        }
                    }
                }
                if return_value >= 0 && !rusage_ptr.is_null() {
                    unsafe {
                        if let Ok(usage) = bpf_probe_read_user::<Rusage>(rusage_ptr) {
                            data.rusage = usage;
                            data.has_rusage = true;
                        }
                    }
                }
            }
            syscalls::SYS_waitid => {
                let data = crate::data_mut!(entry, waitid);
                data.idtype = args[0] as u32;
                data.id = args[1] as u32;
                let infop_ptr = args[2] as *const pinchy_common::kernel_types::Siginfo;
                data.options = args[3] as i32;

                data.infop = pinchy_common::kernel_types::Siginfo::default();
                data.has_infop = false;

                if return_value >= 0 && !infop_ptr.is_null() {
                    unsafe {
                        if let Ok(siginfo) =
                            bpf_probe_read_user::<pinchy_common::kernel_types::Siginfo>(infop_ptr)
                        {
                            data.infop = siginfo;
                            data.has_infop = true;
                        }
                    }
                }
            }
            syscalls::SYS_getrusage => {
                let data = crate::data_mut!(entry, getrusage);
                data.who = args[0] as i32;
                let usage_ptr = args[1] as *const Rusage;
                data.rusage = Rusage::default();
                if return_value >= 0 && !usage_ptr.is_null() {
                    unsafe {
                        if let Ok(usage) = bpf_probe_read_user::<Rusage>(usage_ptr) {
                            data.rusage = usage;
                        }
                    }
                }
            }
            syscalls::SYS_clone3 => {
                let data = crate::data_mut!(entry, clone3);
                let cl_args_ptr = args[0] as *const CloneArgs;
                data.size = args[1] as u64;
                data.cl_args = CloneArgs::default();

                unsafe {
                    let read_size =
                        core::cmp::min(data.size as usize, core::mem::size_of::<CloneArgs>());
                    if read_size > 0 {
                        let _ = bpf_probe_read_buf(
                            cl_args_ptr as *const u8,
                            &mut core::slice::from_raw_parts_mut(
                                &mut data.cl_args as *mut CloneArgs as *mut u8,
                                read_size,
                            ),
                        );
                    }
                    if data.cl_args.set_tid != 0 && data.cl_args.set_tid_size > 0 {
                        let set_tid_ptr = data.cl_args.set_tid as *const i32;
                        let max_count = core::cmp::min(
                            data.cl_args.set_tid_size as usize,
                            pinchy_common::CLONE_SET_TID_MAX,
                        );
                        for i in 0..max_count {
                            if let Ok(pid) = bpf_probe_read_user::<i32>(set_tid_ptr.add(i)) {
                                data.set_tid_array[i] = pid;
                                data.set_tid_count += 1;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
            syscalls::SYS_clone => {
                let data = crate::data_mut!(entry, clone);
                data.flags = args[0] as u64;
                data.stack = args[1];
                data.tls = args[4] as u64;

                let parent_tid_ptr = args[2] as *const i32;
                data.parent_tid = if !parent_tid_ptr.is_null() {
                    unsafe { bpf_probe_read_user(parent_tid_ptr).unwrap_or(0) }
                } else {
                    0
                };

                let child_tid_ptr = args[3] as *const i32;
                data.child_tid = if !child_tid_ptr.is_null() {
                    unsafe { bpf_probe_read_user(child_tid_ptr).unwrap_or(0) }
                } else {
                    0
                };
            }
            syscalls::SYS_pidfd_send_signal => {
                let data = crate::data_mut!(entry, pidfd_send_signal);
                data.pidfd = args[0] as i32;
                data.sig = args[1] as i32;
                data.info_ptr = args[2];
                data.flags = args[3] as u32;
                let info_ptr = args[2] as *const pinchy_common::kernel_types::Siginfo;
                if !info_ptr.is_null() {
                    unsafe {
                        if let Ok(info) =
                            bpf_probe_read_user::<pinchy_common::kernel_types::Siginfo>(info_ptr)
                        {
                            data.info = info;
                        }
                    }
                }
            }
            syscalls::SYS_prlimit64 => {
                let data = crate::data_mut!(entry, prlimit);
                data.pid = args[0] as i32;
                data.resource = args[1] as i32;
                let new_limit_ptr = args[2] as *const Rlimit;
                let old_limit_ptr = args[3] as *const Rlimit;

                data.has_new = !new_limit_ptr.is_null();
                data.has_old = !old_limit_ptr.is_null();
                data.new_limit = Rlimit::default();
                data.old_limit = Rlimit::default();

                if data.has_new {
                    if let Ok(limit) =
                        unsafe { bpf_probe_read_user::<Rlimit>(new_limit_ptr as *const _) }
                    {
                        data.new_limit = limit;
                    }
                }
                if data.has_old && return_value == 0 {
                    if let Ok(limit) =
                        unsafe { bpf_probe_read_user::<Rlimit>(old_limit_ptr as *const _) }
                    {
                        data.old_limit = limit;
                    }
                }
            }

            _ => {
                entry.discard();
                return Ok(());
            }
        }

        entry.submit();
        Ok(())
    }

    match inner(ctx) {
        Ok(()) => 0,
        Err(code) => code,
    }
}
