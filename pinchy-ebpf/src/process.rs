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
    SMALL_READ_SIZE,
};

use crate::{syscall_handler, PID_FILTER, SYSCALL_ARGS_OFFSET};

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
        let return_value = crate::util::get_return_value(&ctx)?;

        let enter_data = unsafe { EXECVE_ENTER_MAP.get(&tid) };
        if let Some(enter_data) = enter_data {
            let _ = unsafe { EXECVE_ENTER_MAP.remove(&tid) };
            crate::util::output_event(
                &ctx,
                pinchy_common::syscalls::SYS_execve,
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
            aya_log_ebpf::error!(
                &ctx,
                "did not find matching enter data for execve for PID",
                tid
            );
            return Err(1);
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

        unsafe {
            EXECVE_ENTER_MAP
                .insert(
                    &tid,
                    &ExecveEnterData {
                        filename,
                        filename_truncated,
                        argv,
                        argv_len,
                        argc,
                        envp,
                        envp_len,
                        envc,
                    },
                    0,
                )
                .map_err(|e| e as u32)?;
        }
        Ok(())
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

syscall_handler!(prlimit64, prlimit, args, data, return_value, {
    data.pid = args[0] as i32;
    data.resource = args[1] as i32;
    let new_limit_ptr = args[2] as *const Rlimit;
    let old_limit_ptr = args[3] as *const Rlimit;

    data.has_new = !new_limit_ptr.is_null();
    data.has_old = !old_limit_ptr.is_null();
    data.new_limit = Rlimit::default();
    data.old_limit = Rlimit::default();

    if data.has_new {
        if let Ok(limit) = unsafe { bpf_probe_read_user::<Rlimit>(new_limit_ptr as *const _) } {
            data.new_limit = limit;
        }
    }
    if data.has_old && return_value == 0 {
        if let Ok(limit) = unsafe { bpf_probe_read_user::<Rlimit>(old_limit_ptr as *const _) } {
            data.old_limit = limit;
        }
    }
});

syscall_handler!(wait4, wait4, args, data, return_value, {
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
});

syscall_handler!(waitid, waitid, args, data, return_value, {
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
});

syscall_handler!(getrusage, getrusage, args, data, return_value, {
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
});

syscall_handler!(clone3, args, data, {
    let cl_args_ptr = args[0] as *const CloneArgs;
    data.size = args[1] as u64;
    data.cl_args = CloneArgs::default();

    unsafe {
        let read_size = core::cmp::min(data.size as usize, core::mem::size_of::<CloneArgs>());
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
});

syscall_handler!(clone, args, data, {
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
});

syscall_handler!(pidfd_send_signal, args, data, {
    data.pidfd = args[0] as i32;
    data.sig = args[1] as i32;
    data.info_ptr = args[2];
    data.flags = args[3] as u32;
    let info_ptr = args[2] as *const pinchy_common::kernel_types::Siginfo;
    if !info_ptr.is_null() {
        unsafe {
            if let Ok(info) = bpf_probe_read_user::<pinchy_common::kernel_types::Siginfo>(info_ptr)
            {
                data.info = info;
            }
        }
    }
});
