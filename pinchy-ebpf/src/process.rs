// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_user, bpf_probe_read_user_buf},
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
            crate::util::submit_compact_payload::<pinchy_common::ExecveData, _>(
                &ctx,
                pinchy_common::syscalls::SYS_execve,
                return_value,
                |payload| {
                    payload.filename = enter_data.filename;
                    payload.filename_truncated = enter_data.filename_truncated;
                    payload.argv = enter_data.argv;
                    payload.argv_len = enter_data.argv_len;
                    payload.argc = enter_data.argc;
                    payload.envp = enter_data.envp;
                    payload.envp_len = enter_data.envp_len;
                    payload.envc = enter_data.envc;
                },
            )?;

            let _ = unsafe { EXECVE_ENTER_MAP.remove(&tid) };

            return Ok(());
        }

        let enter_data = unsafe { EXECVEAT_ENTER_MAP.get(&tid) };
        if let Some(enter_data) = enter_data {
            crate::util::submit_compact_payload::<pinchy_common::ExecveatData, _>(
                &ctx,
                pinchy_common::syscalls::SYS_execveat,
                return_value,
                |payload| {
                    payload.dirfd = enter_data.dirfd;
                    payload.pathname = enter_data.pathname;
                    payload.pathname_truncated = enter_data.pathname_truncated;
                    payload.argv = enter_data.argv;
                    payload.argv_len = enter_data.argv_len;
                    payload.argc = enter_data.argc;
                    payload.envp = enter_data.envp;
                    payload.envp_len = enter_data.envp_len;
                    payload.envc = enter_data.envc;
                    payload.flags = enter_data.flags;
                },
            )?;

            let _ = unsafe { EXECVEAT_ENTER_MAP.remove(&tid) };

            return Ok(());
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
        let _ = bpf_probe_read_user_buf(pathname_ptr as *const _, pathname);
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
                    let _ = bpf_probe_read_user_buf(arg_ptr as *const _, &mut argv[i]);
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
                    let _ = bpf_probe_read_user_buf(env_ptr as *const _, &mut envp[i]);
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

        match syscall_nr {
            pinchy_common::syscalls::SYS_wait4 => {
                crate::util::submit_compact_payload::<pinchy_common::Wait4Data, _>(
                    &ctx,
                    pinchy_common::syscalls::SYS_wait4,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        let wstatus_ptr = args[1] as *const i32;
                        payload.options = args[2] as i32;
                        let rusage_ptr = args[3] as *const Rusage;

                        payload.wstatus = 0i32;
                        payload.rusage = Rusage::default();
                        payload.has_rusage = false;

                        if return_value >= 0 && !wstatus_ptr.is_null() {
                            unsafe {
                                if let Ok(status) = bpf_probe_read_user::<i32>(wstatus_ptr) {
                                    payload.wstatus = status;
                                }
                            }
                        }

                        if return_value >= 0 && !rusage_ptr.is_null() {
                            unsafe {
                                if let Ok(usage) = bpf_probe_read_user::<Rusage>(rusage_ptr) {
                                    payload.rusage = usage;
                                    payload.has_rusage = true;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_waitid => {
                crate::util::submit_compact_payload::<pinchy_common::WaitidData, _>(
                    &ctx,
                    syscalls::SYS_waitid,
                    return_value,
                    |payload| {
                        payload.idtype = args[0] as u32;
                        payload.id = args[1] as u32;
                        let infop_ptr = args[2] as *const pinchy_common::kernel_types::Siginfo;
                        payload.options = args[3] as i32;

                        payload.infop = pinchy_common::kernel_types::Siginfo::default();
                        payload.has_infop = false;

                        if return_value >= 0 && !infop_ptr.is_null() {
                            unsafe {
                                if let Ok(siginfo) = bpf_probe_read_user::<
                                    pinchy_common::kernel_types::Siginfo,
                                >(infop_ptr)
                                {
                                    payload.infop = siginfo;
                                    payload.has_infop = true;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_getrusage => {
                crate::util::submit_compact_payload::<pinchy_common::GetrusageData, _>(
                    &ctx,
                    syscalls::SYS_getrusage,
                    return_value,
                    |payload| {
                        payload.who = args[0] as i32;
                        let usage_ptr = args[1] as *const Rusage;
                        payload.rusage = Rusage::default();
                        if return_value >= 0 && !usage_ptr.is_null() {
                            unsafe {
                                if let Ok(usage) = bpf_probe_read_user::<Rusage>(usage_ptr) {
                                    payload.rusage = usage;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_clone3 => {
                crate::util::submit_compact_payload::<pinchy_common::Clone3Data, _>(
                    &ctx,
                    syscalls::SYS_clone3,
                    return_value,
                    |payload| {
                        let cl_args_ptr = args[0] as *const CloneArgs;
                        payload.size = args[1] as u64;
                        payload.cl_args = CloneArgs::default();

                        unsafe {
                            let read_size = core::cmp::min(
                                payload.size as usize,
                                core::mem::size_of::<CloneArgs>(),
                            );
                            if read_size > 0 {
                                let _ = bpf_probe_read_user_buf(
                                    cl_args_ptr as *const u8,
                                    &mut core::slice::from_raw_parts_mut(
                                        &mut payload.cl_args as *mut CloneArgs as *mut u8,
                                        read_size,
                                    ),
                                );
                            }
                            if payload.cl_args.set_tid != 0 && payload.cl_args.set_tid_size > 0 {
                                let set_tid_ptr = payload.cl_args.set_tid as *const i32;
                                let max_count = core::cmp::min(
                                    payload.cl_args.set_tid_size as usize,
                                    pinchy_common::CLONE_SET_TID_MAX,
                                );
                                for i in 0..max_count {
                                    if let Ok(pid) = bpf_probe_read_user::<i32>(set_tid_ptr.add(i))
                                    {
                                        payload.set_tid_array[i] = pid;
                                        payload.set_tid_count += 1;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_clone => {
                crate::util::submit_compact_payload::<pinchy_common::CloneData, _>(
                    &ctx,
                    syscalls::SYS_clone,
                    return_value,
                    |payload| {
                        payload.flags = args[0] as u64;
                        payload.stack = args[1];
                        payload.tls = args[4] as u64;

                        let parent_tid_ptr = args[2] as *const i32;
                        payload.parent_tid = if !parent_tid_ptr.is_null() {
                            unsafe { bpf_probe_read_user(parent_tid_ptr).unwrap_or(0) }
                        } else {
                            0
                        };

                        let child_tid_ptr = args[3] as *const i32;
                        payload.child_tid = if !child_tid_ptr.is_null() {
                            unsafe { bpf_probe_read_user(child_tid_ptr).unwrap_or(0) }
                        } else {
                            0
                        };
                    },
                )?;
            }
            syscalls::SYS_pidfd_send_signal => {
                crate::util::submit_compact_payload::<pinchy_common::PidfdSendSignalData, _>(
                    &ctx,
                    syscalls::SYS_pidfd_send_signal,
                    return_value,
                    |payload| {
                        payload.pidfd = args[0] as i32;
                        payload.sig = args[1] as i32;
                        payload.info_ptr = args[2];
                        payload.flags = args[3] as u32;
                        let info_ptr = args[2] as *const pinchy_common::kernel_types::Siginfo;
                        if !info_ptr.is_null() {
                            unsafe {
                                if let Ok(info) = bpf_probe_read_user::<
                                    pinchy_common::kernel_types::Siginfo,
                                >(info_ptr)
                                {
                                    payload.info = info;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_prlimit64 => {
                crate::util::submit_compact_payload::<pinchy_common::PrlimitData, _>(
                    &ctx,
                    syscalls::SYS_prlimit64,
                    return_value,
                    |payload| {
                        payload.pid = args[0] as i32;
                        payload.resource = args[1] as i32;
                        let new_limit_ptr = args[2] as *const Rlimit;
                        let old_limit_ptr = args[3] as *const Rlimit;

                        payload.has_new = !new_limit_ptr.is_null();
                        payload.has_old = !old_limit_ptr.is_null();
                        payload.new_limit = Rlimit::default();
                        payload.old_limit = Rlimit::default();

                        if payload.has_new {
                            if let Ok(limit) =
                                unsafe { bpf_probe_read_user::<Rlimit>(new_limit_ptr as *const _) }
                            {
                                payload.new_limit = limit;
                            }
                        }
                        if payload.has_old && return_value == 0 {
                            if let Ok(limit) =
                                unsafe { bpf_probe_read_user::<Rlimit>(old_limit_ptr as *const _) }
                            {
                                payload.old_limit = limit;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_kcmp => {
                crate::util::submit_compact_payload::<pinchy_common::KcmpData, _>(
                    &ctx,
                    syscalls::SYS_kcmp,
                    return_value,
                    |payload| {
                        payload.pid1 = args[0] as i32;
                        payload.pid2 = args[1] as i32;
                        payload.type_ = args[2] as i32;
                        payload.idx1 = args[3] as u64;
                        payload.idx2 = args[4] as u64;
                    },
                )?;
            }
            syscalls::SYS_getgroups => {
                crate::util::submit_compact_payload::<pinchy_common::GetgroupsData, _>(
                    &ctx,
                    syscalls::SYS_getgroups,
                    return_value,
                    |payload| {
                        payload.size = args[0] as i32;

                        let list_ptr = args[1] as *const u32;

                        if return_value >= 0 && !list_ptr.is_null() && payload.size > 0 {
                            let max_to_read = core::cmp::min(
                                pinchy_common::GROUP_ARRAY_CAP,
                                core::cmp::min(payload.size as usize, return_value as usize),
                            );

                            for i in 0..max_to_read {
                                unsafe {
                                    let ptr = list_ptr.add(i);

                                    if let Ok(gid) = bpf_probe_read_user(ptr) {
                                        payload.groups[i] = gid;
                                        payload.groups_read_count += 1;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_setgroups => {
                crate::util::submit_compact_payload::<pinchy_common::SetgroupsData, _>(
                    &ctx,
                    syscalls::SYS_setgroups,
                    return_value,
                    |payload| {
                        payload.size = args[0] as usize;

                        let list_ptr = args[1] as *const u32;

                        if !list_ptr.is_null() && payload.size > 0 {
                            let max_to_read =
                                core::cmp::min(pinchy_common::GROUP_ARRAY_CAP, payload.size);

                            for i in 0..max_to_read {
                                unsafe {
                                    let ptr = list_ptr.add(i);

                                    if let Ok(gid) = bpf_probe_read_user(ptr) {
                                        payload.groups[i] = gid;
                                        payload.groups_read_count += 1;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_getresuid => {
                crate::util::submit_compact_payload::<pinchy_common::GetresuidData, _>(
                    &ctx,
                    syscalls::SYS_getresuid,
                    return_value,
                    |payload| {
                        let ruid_ptr = args[0] as *const u32;
                        let euid_ptr = args[1] as *const u32;
                        let suid_ptr = args[2] as *const u32;

                        payload.ruid = if return_value >= 0 && !ruid_ptr.is_null() {
                            unsafe { bpf_probe_read_user(ruid_ptr).unwrap_or(0) }
                        } else {
                            0
                        };

                        payload.euid = if return_value >= 0 && !euid_ptr.is_null() {
                            unsafe { bpf_probe_read_user(euid_ptr).unwrap_or(0) }
                        } else {
                            0
                        };

                        payload.suid = if return_value >= 0 && !suid_ptr.is_null() {
                            unsafe { bpf_probe_read_user(suid_ptr).unwrap_or(0) }
                        } else {
                            0
                        };
                    },
                )?;
            }
            syscalls::SYS_getresgid => {
                crate::util::submit_compact_payload::<pinchy_common::GetresgidData, _>(
                    &ctx,
                    syscalls::SYS_getresgid,
                    return_value,
                    |payload| {
                        let rgid_ptr = args[0] as *const u32;
                        let egid_ptr = args[1] as *const u32;
                        let sgid_ptr = args[2] as *const u32;

                        payload.rgid = if return_value >= 0 && !rgid_ptr.is_null() {
                            unsafe { bpf_probe_read_user(rgid_ptr).unwrap_or(0) }
                        } else {
                            0
                        };

                        payload.egid = if return_value >= 0 && !egid_ptr.is_null() {
                            unsafe { bpf_probe_read_user(egid_ptr).unwrap_or(0) }
                        } else {
                            0
                        };

                        payload.sgid = if return_value >= 0 && !sgid_ptr.is_null() {
                            unsafe { bpf_probe_read_user(sgid_ptr).unwrap_or(0) }
                        } else {
                            0
                        };
                    },
                )?;
            }
            _ => {}
        }

        Ok(())
    }

    match inner(ctx) {
        Ok(()) => 0,
        Err(code) => code,
    }
}
