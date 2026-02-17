// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_user, bpf_probe_read_user_buf},
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::error;
#[cfg(x86_64)]
use pinchy_common::kernel_types::LinuxDirent;
use pinchy_common::{
    kernel_types::{LinuxDirent64, Stat},
    syscalls, ChdirData, FaccessatData, FchmodatData, FchownatData, FgetxattrData, FlistxattrData,
    FremovexattrData, FsetxattrData, FstatData, FstatfsData, GetcwdData, GetxattrData,
    LgetxattrData, LinkatData, ListxattrData, LlistxattrData, LremovexattrData, LsetxattrData,
    MkdiratData, NewfstatatData, ReadlinkatData, RemovexattrData, Renameat2Data, RenameatData,
    SetxattrData, StatfsData, SymlinkatData, UnlinkatData, DATA_READ_SIZE,
};

use crate::{util, util::submit_compact_payload};

#[tracepoint]
pub fn syscall_exit_filesystem(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;
        let return_value = util::get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_fstat => {
                submit_compact_payload::<FstatData, _>(
                    &ctx,
                    syscalls::SYS_fstat,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;

                        let stat_ptr = args[1] as *const u8;

                        if !stat_ptr.is_null() {
                            unsafe {
                                payload.stat = bpf_probe_read_user(stat_ptr as *const _)
                                    .unwrap_or_else(|_| Stat::default());
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_newfstatat => {
                submit_compact_payload::<NewfstatatData, _>(
                    &ctx,
                    syscalls::SYS_newfstatat,
                    return_value,
                    |payload| {
                        payload.dirfd = args[0] as i32;
                        payload.flags = args[3] as i32;

                        let pathname_ptr = args[1] as *const u8;
                        let stat_ptr = args[2] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);

                            if return_value == 0 {
                                let _ = bpf_probe_read_user_buf(
                                    stat_ptr,
                                    core::slice::from_raw_parts_mut(
                                        &mut payload.stat as *mut _ as *mut u8,
                                        core::mem::size_of::<Stat>(),
                                    ),
                                );
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_readlinkat => {
                submit_compact_payload::<ReadlinkatData, _>(
                    &ctx,
                    syscalls::SYS_readlinkat,
                    return_value,
                    |payload| {
                        payload.dirfd = args[0] as i32;
                        payload.bufsiz = args[3] as usize;

                        let pathname_ptr = args[1] as *const u8;
                        let buf_ptr = args[2] as *const u8;
                        let to_copy = if return_value > 0 {
                            let returned = return_value as usize;
                            let max_requested = core::cmp::min(payload.bufsiz, returned);

                            core::cmp::min(max_requested, payload.buf.len())
                        } else {
                            0
                        };

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);

                            if to_copy > 0 {
                                let _ =
                                    bpf_probe_read_user_buf(buf_ptr, &mut payload.buf[..to_copy]);

                                if to_copy < payload.buf.len() {
                                    payload.buf[to_copy] = 0;
                                } else {
                                    let last = payload.buf.len() - 1;
                                    payload.buf[last] = 0;
                                }
                            } else if !payload.buf.is_empty() {
                                payload.buf[0] = 0;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_statfs => {
                submit_compact_payload::<StatfsData, _>(
                    &ctx,
                    syscalls::SYS_statfs,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        let buf_ptr = args[1] as *const pinchy_common::kernel_types::Statfs;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);

                            if return_value == 0 {
                                if let Ok(val) = bpf_probe_read_user(buf_ptr as *const _) {
                                    payload.statfs = val;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_faccessat | syscalls::SYS_faccessat2 => {
                submit_compact_payload::<FaccessatData, _>(
                    &ctx,
                    syscall_nr,
                    return_value,
                    |payload| {
                        payload.dirfd = args[0] as i32;
                        payload.mode = args[2] as i32;
                        payload.flags = args[3] as i32;

                        let pathname_ptr = args[1] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            syscalls::SYS_fstatfs => {
                submit_compact_payload::<FstatfsData, _>(
                    &ctx,
                    syscalls::SYS_fstatfs,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;

                        let buf_ptr = args[1] as *const pinchy_common::kernel_types::Statfs;

                        unsafe {
                            if return_value == 0 {
                                if let Ok(val) = bpf_probe_read_user(buf_ptr as *const _) {
                                    payload.statfs = val;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_flistxattr => {
                submit_compact_payload::<FlistxattrData, _>(
                    &ctx,
                    syscalls::SYS_flistxattr,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.list = args[1] as u64;
                        payload.size = args[2] as usize;
                        payload.xattr_list = pinchy_common::kernel_types::XattrList::default();

                        let list_ptr = args[1] as *const u8;

                        if !list_ptr.is_null() && payload.size > 0 {
                            let read_size = core::cmp::min(payload.size, DATA_READ_SIZE);

                            unsafe {
                                let _ = bpf_probe_read_user_buf(
                                    list_ptr,
                                    &mut payload.xattr_list.data[..read_size],
                                );
                            }

                            payload.xattr_list.size = read_size;
                        }
                    },
                )?;
            }
            syscalls::SYS_listxattr => {
                submit_compact_payload::<ListxattrData, _>(
                    &ctx,
                    syscalls::SYS_listxattr,
                    return_value,
                    |payload| {
                        payload.list = args[1] as u64;
                        payload.size = args[2] as usize;
                        payload.xattr_list = pinchy_common::kernel_types::XattrList::default();

                        let pathname_ptr = args[0] as *const u8;
                        let list_ptr = args[1] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }

                        if !list_ptr.is_null() && payload.size > 0 {
                            let read_size = core::cmp::min(payload.size, DATA_READ_SIZE);

                            unsafe {
                                let _ = bpf_probe_read_user_buf(
                                    list_ptr,
                                    &mut payload.xattr_list.data[..read_size],
                                );
                            }

                            payload.xattr_list.size = read_size;
                        }
                    },
                )?;
            }
            syscalls::SYS_llistxattr => {
                submit_compact_payload::<LlistxattrData, _>(
                    &ctx,
                    syscalls::SYS_llistxattr,
                    return_value,
                    |payload| {
                        payload.list = args[1] as u64;
                        payload.size = args[2] as usize;
                        payload.xattr_list = pinchy_common::kernel_types::XattrList::default();

                        let pathname_ptr = args[0] as *const u8;
                        let list_ptr = args[1] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }

                        if !list_ptr.is_null() && payload.size > 0 {
                            let read_size = core::cmp::min(payload.size, DATA_READ_SIZE);

                            unsafe {
                                let _ = bpf_probe_read_user_buf(
                                    list_ptr,
                                    &mut payload.xattr_list.data[..read_size],
                                );
                            }

                            payload.xattr_list.size = read_size;
                        }
                    },
                )?;
            }
            syscalls::SYS_setxattr => {
                submit_compact_payload::<SetxattrData, _>(
                    &ctx,
                    syscalls::SYS_setxattr,
                    return_value,
                    |payload| {
                        payload.size = args[3] as usize;
                        payload.flags = args[4] as i32;

                        let pathname_ptr = args[0] as *const u8;
                        let name_ptr = args[1] as *const u8;
                        let value_ptr = args[2] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            let _ = bpf_probe_read_user_buf(name_ptr, &mut payload.name);

                            if !value_ptr.is_null() && payload.size > 0 {
                                let read_size = core::cmp::min(payload.size, DATA_READ_SIZE);
                                let _ = bpf_probe_read_user_buf(
                                    value_ptr,
                                    &mut payload.value[..read_size],
                                );
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_lsetxattr => {
                submit_compact_payload::<LsetxattrData, _>(
                    &ctx,
                    syscalls::SYS_lsetxattr,
                    return_value,
                    |payload| {
                        payload.size = args[3] as usize;
                        payload.flags = args[4] as i32;

                        let pathname_ptr = args[0] as *const u8;
                        let name_ptr = args[1] as *const u8;
                        let value_ptr = args[2] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            let _ = bpf_probe_read_user_buf(name_ptr, &mut payload.name);

                            if !value_ptr.is_null() && payload.size > 0 {
                                let read_size = core::cmp::min(payload.size, DATA_READ_SIZE);
                                let _ = bpf_probe_read_user_buf(
                                    value_ptr,
                                    &mut payload.value[..read_size],
                                );
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_fsetxattr => {
                submit_compact_payload::<FsetxattrData, _>(
                    &ctx,
                    syscalls::SYS_fsetxattr,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.size = args[3] as usize;
                        payload.flags = args[4] as i32;

                        let name_ptr = args[1] as *const u8;
                        let value_ptr = args[2] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(name_ptr, &mut payload.name);

                            if !value_ptr.is_null() && payload.size > 0 {
                                let read_size = core::cmp::min(payload.size, DATA_READ_SIZE);
                                let _ = bpf_probe_read_user_buf(
                                    value_ptr,
                                    &mut payload.value[..read_size],
                                );
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_getxattr => {
                submit_compact_payload::<GetxattrData, _>(
                    &ctx,
                    syscalls::SYS_getxattr,
                    return_value,
                    |payload| {
                        payload.size = args[3] as usize;

                        let pathname_ptr = args[0] as *const u8;
                        let name_ptr = args[1] as *const u8;
                        let value_ptr = args[2] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            let _ = bpf_probe_read_user_buf(name_ptr, &mut payload.name);

                            if !value_ptr.is_null() && return_value > 0 && payload.size > 0 {
                                let read_size = core::cmp::min(
                                    return_value as usize,
                                    core::cmp::min(payload.size, DATA_READ_SIZE),
                                );
                                let _ = bpf_probe_read_user_buf(
                                    value_ptr,
                                    &mut payload.value[..read_size],
                                );
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_lgetxattr => {
                submit_compact_payload::<LgetxattrData, _>(
                    &ctx,
                    syscalls::SYS_lgetxattr,
                    return_value,
                    |payload| {
                        payload.size = args[3] as usize;

                        let pathname_ptr = args[0] as *const u8;
                        let name_ptr = args[1] as *const u8;
                        let value_ptr = args[2] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            let _ = bpf_probe_read_user_buf(name_ptr, &mut payload.name);

                            if !value_ptr.is_null() && return_value > 0 && payload.size > 0 {
                                let read_size = core::cmp::min(
                                    return_value as usize,
                                    core::cmp::min(payload.size, DATA_READ_SIZE),
                                );
                                let _ = bpf_probe_read_user_buf(
                                    value_ptr,
                                    &mut payload.value[..read_size],
                                );
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_fgetxattr => {
                submit_compact_payload::<FgetxattrData, _>(
                    &ctx,
                    syscalls::SYS_fgetxattr,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.size = args[3] as usize;

                        let name_ptr = args[1] as *const u8;
                        let value_ptr = args[2] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(name_ptr, &mut payload.name);

                            if !value_ptr.is_null() && return_value > 0 && payload.size > 0 {
                                let read_size = core::cmp::min(
                                    return_value as usize,
                                    core::cmp::min(payload.size, DATA_READ_SIZE),
                                );
                                let _ = bpf_probe_read_user_buf(
                                    value_ptr,
                                    &mut payload.value[..read_size],
                                );
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_removexattr => {
                submit_compact_payload::<RemovexattrData, _>(
                    &ctx,
                    syscalls::SYS_removexattr,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        let name_ptr = args[1] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            let _ = bpf_probe_read_user_buf(name_ptr, &mut payload.name);
                        }
                    },
                )?;
            }
            syscalls::SYS_lremovexattr => {
                submit_compact_payload::<LremovexattrData, _>(
                    &ctx,
                    syscalls::SYS_lremovexattr,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        let name_ptr = args[1] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            let _ = bpf_probe_read_user_buf(name_ptr, &mut payload.name);
                        }
                    },
                )?;
            }
            syscalls::SYS_fremovexattr => {
                submit_compact_payload::<FremovexattrData, _>(
                    &ctx,
                    syscalls::SYS_fremovexattr,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;

                        let name_ptr = args[1] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(name_ptr, &mut payload.name);
                        }
                    },
                )?;
            }
            syscalls::SYS_getcwd => {
                submit_compact_payload::<GetcwdData, _>(
                    &ctx,
                    syscalls::SYS_getcwd,
                    return_value,
                    |payload| {
                        payload.buf = args[0] as u64;
                        payload.size = args[1] as usize;

                        let buf_ptr = args[0] as *const u8;

                        if return_value > 0 {
                            let max_len = core::cmp::min(payload.size, payload.path.len());
                            let copy_len = core::cmp::min(max_len, return_value as usize);

                            unsafe {
                                if copy_len > 0 {
                                    let _ = bpf_probe_read_user_buf(
                                        buf_ptr,
                                        &mut payload.path[..copy_len],
                                    );

                                    if copy_len < payload.path.len() {
                                        payload.path[copy_len] = 0;
                                    } else {
                                        let last = payload.path.len() - 1;
                                        payload.path[last] = 0;
                                    }
                                } else if !payload.path.is_empty() {
                                    payload.path[0] = 0;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_chdir => {
                submit_compact_payload::<ChdirData, _>(
                    &ctx,
                    syscalls::SYS_chdir,
                    return_value,
                    |payload| {
                        let path_ptr = args[0] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(path_ptr, &mut payload.path);
                        }
                    },
                )?;
            }
            syscalls::SYS_mkdirat => {
                submit_compact_payload::<MkdiratData, _>(
                    &ctx,
                    syscalls::SYS_mkdirat,
                    return_value,
                    |payload| {
                        payload.dirfd = args[0] as i32;
                        payload.mode = args[2] as u32;

                        let pathname_ptr = args[1] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            syscalls::SYS_fchmodat => {
                submit_compact_payload::<FchmodatData, _>(
                    &ctx,
                    syscalls::SYS_fchmodat,
                    return_value,
                    |payload| {
                        payload.dirfd = args[0] as i32;
                        payload.mode = args[2] as u32;
                        payload.flags = args[3] as i32;

                        let pathname_ptr = args[1] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            syscalls::SYS_fchownat => {
                submit_compact_payload::<FchownatData, _>(
                    &ctx,
                    syscalls::SYS_fchownat,
                    return_value,
                    |payload| {
                        payload.dirfd = args[0] as i32;
                        payload.uid = args[2] as u32;
                        payload.gid = args[3] as u32;
                        payload.flags = args[4] as i32;

                        let pathname_ptr = args[1] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            syscalls::SYS_renameat => {
                submit_compact_payload::<RenameatData, _>(
                    &ctx,
                    syscalls::SYS_renameat,
                    return_value,
                    |payload| {
                        payload.olddirfd = args[0] as i32;
                        payload.newdirfd = args[2] as i32;

                        let oldpath_ptr = args[1] as *const u8;
                        let newpath_ptr = args[3] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(oldpath_ptr, &mut payload.oldpath);
                            let _ = bpf_probe_read_user_buf(newpath_ptr, &mut payload.newpath);
                        }
                    },
                )?;
            }
            syscalls::SYS_renameat2 => {
                submit_compact_payload::<Renameat2Data, _>(
                    &ctx,
                    syscalls::SYS_renameat2,
                    return_value,
                    |payload| {
                        payload.olddirfd = args[0] as i32;
                        payload.newdirfd = args[2] as i32;
                        payload.flags = args[4] as u32;

                        let oldpath_ptr = args[1] as *const u8;
                        let newpath_ptr = args[3] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(oldpath_ptr, &mut payload.oldpath);
                            let _ = bpf_probe_read_user_buf(newpath_ptr, &mut payload.newpath);
                        }
                    },
                )?;
            }
            syscalls::SYS_unlinkat => {
                submit_compact_payload::<UnlinkatData, _>(
                    &ctx,
                    syscalls::SYS_unlinkat,
                    return_value,
                    |payload| {
                        payload.dirfd = args[0] as i32;
                        payload.flags = args[2] as i32;

                        let pathname_ptr = args[1] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            syscalls::SYS_symlinkat => {
                submit_compact_payload::<SymlinkatData, _>(
                    &ctx,
                    syscalls::SYS_symlinkat,
                    return_value,
                    |payload| {
                        payload.newdirfd = args[1] as i32;

                        let target_ptr = args[0] as *const u8;
                        let linkpath_ptr = args[2] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(target_ptr, &mut payload.target);
                            let _ = bpf_probe_read_user_buf(linkpath_ptr, &mut payload.linkpath);
                        }
                    },
                )?;
            }
            syscalls::SYS_linkat => {
                submit_compact_payload::<LinkatData, _>(
                    &ctx,
                    syscalls::SYS_linkat,
                    return_value,
                    |payload| {
                        payload.olddirfd = args[0] as i32;
                        payload.newdirfd = args[2] as i32;
                        payload.flags = args[4] as i32;

                        let oldpath_ptr = args[1] as *const u8;
                        let newpath_ptr = args[3] as *const u8;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(oldpath_ptr, &mut payload.oldpath);
                            let _ = bpf_probe_read_user_buf(newpath_ptr, &mut payload.newpath);
                        }
                    },
                )?;
            }
            syscalls::SYS_getdents64 => {
                crate::util::submit_compact_payload::<pinchy_common::Getdents64Data, _>(
                    &ctx,
                    syscalls::SYS_getdents64,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.count = args[2] as usize;
                        payload.num_dirents = 0;

                        let dirp = args[1] as *const u8;
                        let mut offset = 0usize;
                        for dirent in payload.dirents.iter_mut() {
                            if offset < payload.count {
                                let base = unsafe { dirp.add(offset) };
                                if base.is_null() {
                                    break;
                                }

                                if let Ok(val) = unsafe {
                                    bpf_probe_read_user::<LinuxDirent64>(base as *const _)
                                } {
                                    *dirent = val;
                                }

                                // The entries have different sizes, since the d_name field is an actual array of bytes.
                                // We need to keep track of the offset so we can read the next entry properly.
                                let reclen = dirent.d_reclen as usize;
                                if reclen == 0 {
                                    error!(
                                        &ctx,
                                        "Read a dent with reclen=0 in getdents64 handler."
                                    );
                                    break; // This should not really happen.
                                }

                                payload.num_dirents += 1;
                                offset += reclen;
                            }
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_getdents => {
                crate::util::submit_compact_payload::<pinchy_common::GetdentsData, _>(
                    &ctx,
                    syscalls::SYS_getdents,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.count = args[2] as usize;
                        payload.num_dirents = 0;

                        let dirp = args[1] as *const u8;
                        let mut offset = 0usize;

                        for dirent in payload.dirents.iter_mut() {
                            if offset < payload.count {
                                let base = unsafe { dirp.add(offset) };

                                if base.is_null() {
                                    break;
                                }

                                if let Ok(val) =
                                    unsafe { bpf_probe_read_user::<LinuxDirent>(base as *const _) }
                                {
                                    *dirent = val;
                                }

                                let reclen = dirent.d_reclen as usize;

                                if reclen == 0 {
                                    error!(&ctx, "Read a dent with reclen=0 in getdents handler.");
                                    break;
                                }

                                payload.num_dirents += 1;
                                offset += reclen;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_inotify_add_watch => {
                crate::util::submit_compact_payload::<pinchy_common::InotifyAddWatchData, _>(
                    &ctx,
                    syscalls::SYS_inotify_add_watch,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.mask = args[2] as u32;
                        let pathname_ptr = args[1] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_chown => {
                crate::util::submit_compact_payload::<pinchy_common::ChownData, _>(
                    &ctx,
                    syscalls::SYS_chown,
                    return_value,
                    |payload| {
                        payload.uid = args[1] as u32;
                        payload.gid = args[2] as u32;
                        let pathname_ptr = args[0] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_lchown => {
                crate::util::submit_compact_payload::<pinchy_common::ChownData, _>(
                    &ctx,
                    syscalls::SYS_lchown,
                    return_value,
                    |payload| {
                        payload.uid = args[1] as u32;
                        payload.gid = args[2] as u32;
                        let pathname_ptr = args[0] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            syscalls::SYS_truncate => {
                crate::util::submit_compact_payload::<pinchy_common::TruncateData, _>(
                    &ctx,
                    syscalls::SYS_truncate,
                    return_value,
                    |payload| {
                        payload.length = args[1] as i64;
                        let pathname_ptr = args[0] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_rename => {
                crate::util::submit_compact_payload::<pinchy_common::RenameData, _>(
                    &ctx,
                    syscalls::SYS_rename,
                    return_value,
                    |payload| {
                        let oldpath_ptr = args[0] as *const u8;
                        let newpath_ptr = args[1] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(oldpath_ptr, &mut payload.oldpath);
                            let _ = bpf_probe_read_user_buf(newpath_ptr, &mut payload.newpath);
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_rmdir => {
                crate::util::submit_compact_payload::<pinchy_common::RmdirData, _>(
                    &ctx,
                    syscalls::SYS_rmdir,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_unlink => {
                crate::util::submit_compact_payload::<pinchy_common::UnlinkData, _>(
                    &ctx,
                    syscalls::SYS_unlink,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            syscalls::SYS_acct => {
                crate::util::submit_compact_payload::<pinchy_common::AcctData, _>(
                    &ctx,
                    syscalls::SYS_acct,
                    return_value,
                    |payload| {
                        let filename_ptr = args[0] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(filename_ptr, &mut payload.filename);
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_symlink => {
                crate::util::submit_compact_payload::<pinchy_common::SymlinkData, _>(
                    &ctx,
                    syscalls::SYS_symlink,
                    return_value,
                    |payload| {
                        let target_ptr = args[0] as *const u8;
                        let linkpath_ptr = args[1] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(target_ptr, &mut payload.target);
                            let _ = bpf_probe_read_user_buf(linkpath_ptr, &mut payload.linkpath);
                        }
                    },
                )?;
            }
            syscalls::SYS_statx => {
                crate::util::submit_compact_payload::<pinchy_common::StatxData, _>(
                    &ctx,
                    syscalls::SYS_statx,
                    return_value,
                    |payload| {
                        payload.dirfd = args[0] as i32;
                        let pathname_ptr = args[1] as *const u8;
                        payload.flags = args[2] as i32;
                        payload.mask = args[3] as u32;
                        let statxbuf_ptr = args[4] as *const pinchy_common::kernel_types::Statx;
                        payload.statxbuf = statxbuf_ptr as u64;

                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            if return_value == 0 {
                                let _ = bpf_probe_read_user_buf(
                                    statxbuf_ptr as *const u8,
                                    core::slice::from_raw_parts_mut(
                                        &mut payload.statx as *mut _ as *mut u8,
                                        core::mem::size_of::<pinchy_common::kernel_types::Statx>(),
                                    ),
                                );
                            }
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_mknod => {
                crate::util::submit_compact_payload::<pinchy_common::MknodData, _>(
                    &ctx,
                    syscalls::SYS_mknod,
                    return_value,
                    |payload| {
                        payload.mode = args[1] as u32;
                        payload.dev = args[2] as u64;
                        let pathname_ptr = args[0] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            syscalls::SYS_mknodat => {
                crate::util::submit_compact_payload::<pinchy_common::MknodatData, _>(
                    &ctx,
                    syscalls::SYS_mknodat,
                    return_value,
                    |payload| {
                        payload.dirfd = args[0] as i32;
                        payload.mode = args[2] as u32;
                        payload.dev = args[3] as u64;
                        let pathname_ptr = args[1] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            syscalls::SYS_pivot_root => {
                crate::util::submit_compact_payload::<pinchy_common::PivotRootData, _>(
                    &ctx,
                    syscalls::SYS_pivot_root,
                    return_value,
                    |payload| {
                        let new_root_ptr = args[0] as *const u8;
                        let put_old_ptr = args[1] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(new_root_ptr, &mut payload.new_root);
                            let _ = bpf_probe_read_user_buf(put_old_ptr, &mut payload.put_old);
                        }
                    },
                )?;
            }
            syscalls::SYS_chroot => {
                crate::util::submit_compact_payload::<pinchy_common::ChrootData, _>(
                    &ctx,
                    syscalls::SYS_chroot,
                    return_value,
                    |payload| {
                        let path_ptr = args[0] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(path_ptr, &mut payload.path);
                        }
                    },
                )?;
            }
            syscalls::SYS_open_tree => {
                crate::util::submit_compact_payload::<pinchy_common::OpenTreeData, _>(
                    &ctx,
                    syscalls::SYS_open_tree,
                    return_value,
                    |payload| {
                        payload.dfd = args[0] as i32;
                        let pathname_ptr = args[1] as *const u8;
                        payload.flags = args[2] as u32;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            syscalls::SYS_mount => {
                crate::util::submit_compact_payload::<pinchy_common::MountData, _>(
                    &ctx,
                    syscalls::SYS_mount,
                    return_value,
                    |payload| {
                        let source_ptr = args[0] as *const u8;
                        let target_ptr = args[1] as *const u8;
                        let filesystemtype_ptr = args[2] as *const u8;
                        payload.mountflags = args[3] as u64;
                        payload.data = args[4] as u64;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(source_ptr, &mut payload.source);
                            let _ = bpf_probe_read_user_buf(target_ptr, &mut payload.target);
                            let _ = bpf_probe_read_user_buf(
                                filesystemtype_ptr,
                                &mut payload.filesystemtype,
                            );
                        }
                    },
                )?;
            }
            syscalls::SYS_umount2 => {
                crate::util::submit_compact_payload::<pinchy_common::Umount2Data, _>(
                    &ctx,
                    syscalls::SYS_umount2,
                    return_value,
                    |payload| {
                        let target_ptr = args[0] as *const u8;
                        payload.flags = args[1] as i32;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(target_ptr, &mut payload.target);
                        }
                    },
                )?;
            }
            syscalls::SYS_mount_setattr => {
                crate::util::submit_compact_payload::<pinchy_common::MountSetattrData, _>(
                    &ctx,
                    syscalls::SYS_mount_setattr,
                    return_value,
                    |payload| {
                        payload.dfd = args[0] as i32;
                        let path_ptr = args[1] as *const u8;
                        payload.flags = args[2] as u32;
                        payload.size = args[4] as usize;

                        let attr_ptr = args[3] as *const u8;
                        if !attr_ptr.is_null() {
                            payload.has_attr = true;
                            unsafe {
                                let _ = bpf_probe_read_user_buf(path_ptr, &mut payload.path);
                                let read_size = core::cmp::min(
                                    payload.size,
                                    core::mem::size_of::<pinchy_common::kernel_types::MountAttr>(),
                                );
                                let _ = bpf_probe_read_user_buf(
                                    attr_ptr,
                                    core::slice::from_raw_parts_mut(
                                        &mut payload.attr as *mut _ as *mut u8,
                                        read_size,
                                    ),
                                );
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_move_mount => {
                crate::util::submit_compact_payload::<pinchy_common::MoveMountData, _>(
                    &ctx,
                    syscalls::SYS_move_mount,
                    return_value,
                    |payload| {
                        payload.from_dfd = args[0] as i32;
                        let from_pathname_ptr = args[1] as *const u8;
                        payload.to_dfd = args[2] as i32;
                        let to_pathname_ptr = args[3] as *const u8;
                        payload.flags = args[4] as u32;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(
                                from_pathname_ptr,
                                &mut payload.from_pathname,
                            );
                            let _ =
                                bpf_probe_read_user_buf(to_pathname_ptr, &mut payload.to_pathname);
                        }
                    },
                )?;
            }
            syscalls::SYS_swapon => {
                crate::util::submit_compact_payload::<pinchy_common::SwaponData, _>(
                    &ctx,
                    syscalls::SYS_swapon,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        payload.flags = args[1] as i32;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            syscalls::SYS_swapoff => {
                crate::util::submit_compact_payload::<pinchy_common::SwapoffData, _>(
                    &ctx,
                    syscalls::SYS_swapoff,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                        }
                    },
                )?;
            }
            syscalls::SYS_fsopen => {
                crate::util::submit_compact_payload::<pinchy_common::FsopenData, _>(
                    &ctx,
                    syscalls::SYS_fsopen,
                    return_value,
                    |payload| {
                        let fsname_ptr = args[0] as *const u8;
                        payload.flags = args[1] as u32;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(fsname_ptr, &mut payload.fsname);
                        }
                    },
                )?;
            }
            syscalls::SYS_fsconfig => {
                crate::util::submit_compact_payload::<pinchy_common::FsconfigData, _>(
                    &ctx,
                    syscalls::SYS_fsconfig,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.cmd = args[1] as u32;
                        let key_ptr = args[2] as *const u8;
                        let value_ptr = args[3] as *const u8;
                        payload.aux = args[4] as i32;
                        unsafe {
                            if !key_ptr.is_null() {
                                let _ = bpf_probe_read_user_buf(key_ptr, &mut payload.key);
                            }
                            if !value_ptr.is_null() {
                                let _ = bpf_probe_read_user_buf(value_ptr, &mut payload.value);
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_fspick => {
                crate::util::submit_compact_payload::<pinchy_common::FspickData, _>(
                    &ctx,
                    syscalls::SYS_fspick,
                    return_value,
                    |payload| {
                        payload.dfd = args[0] as i32;
                        let path_ptr = args[1] as *const u8;
                        payload.flags = args[2] as u32;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(path_ptr, &mut payload.path);
                        }
                    },
                )?;
            }
            syscalls::SYS_fallocate => {
                crate::util::submit_compact_payload::<pinchy_common::FallocateData, _>(
                    &ctx,
                    syscalls::SYS_fallocate,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.mode = args[1] as i32;
                        payload.offset = args[2] as i64;
                        payload.size = args[3] as i64;
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_link => {
                crate::util::submit_compact_payload::<pinchy_common::LinkData, _>(
                    &ctx,
                    syscalls::SYS_link,
                    return_value,
                    |payload| {
                        let oldpath_ptr = args[0] as *const u8;
                        let newpath_ptr = args[1] as *const u8;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(oldpath_ptr, &mut payload.oldpath);
                            let _ = bpf_probe_read_user_buf(newpath_ptr, &mut payload.newpath);
                        }
                    },
                )?;
            }
            syscalls::SYS_fanotify_init => {
                crate::util::submit_compact_payload::<pinchy_common::FanotifyInitData, _>(
                    &ctx,
                    syscalls::SYS_fanotify_init,
                    return_value,
                    |payload| {
                        payload.flags = args[0] as u32;
                        payload.event_f_flags = args[1] as u32;
                    },
                )?;
            }
            syscalls::SYS_fanotify_mark => {
                crate::util::submit_compact_payload::<pinchy_common::FanotifyMarkData, _>(
                    &ctx,
                    syscalls::SYS_fanotify_mark,
                    return_value,
                    |payload| {
                        payload.fanotify_fd = args[0] as i32;
                        payload.flags = args[1] as u32;
                        payload.mask = args[2] as u64;
                        payload.dirfd = args[3] as i32;
                        let pathname_ptr = args[4] as *const u8;
                        if !pathname_ptr.is_null() {
                            unsafe {
                                let _ =
                                    bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_name_to_handle_at => {
                crate::util::submit_compact_payload::<pinchy_common::NameToHandleAtData, _>(
                    &ctx,
                    syscalls::SYS_name_to_handle_at,
                    return_value,
                    |payload| {
                        payload.dirfd = args[0] as i32;
                        let pathname_ptr = args[1] as *const u8;
                        payload.handle = args[2] as u64;
                        payload.mount_id = args[3] as u64;
                        payload.flags = args[4] as i32;

                        if !pathname_ptr.is_null() {
                            unsafe {
                                let _ =
                                    bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_open_by_handle_at => {
                crate::util::submit_compact_payload::<pinchy_common::OpenByHandleAtData, _>(
                    &ctx,
                    syscalls::SYS_open_by_handle_at,
                    return_value,
                    |payload| {
                        payload.mount_fd = args[0] as i32;
                        payload.handle = args[1] as u64;
                        payload.flags = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_copy_file_range => {
                crate::util::submit_compact_payload::<pinchy_common::CopyFileRangeData, _>(
                    &ctx,
                    syscalls::SYS_copy_file_range,
                    return_value,
                    |payload| {
                        payload.fd_in = args[0] as i32;

                        let off_in_ptr = args[1] as *const i64;

                        if off_in_ptr.is_null() {
                            payload.off_in_is_null = 1;
                        } else {
                            payload.off_in_is_null = 0;

                            unsafe {
                                if let Ok(off) = bpf_probe_read_user(off_in_ptr) {
                                    payload.off_in = off as u64;
                                }
                            }
                        }

                        payload.fd_out = args[2] as i32;

                        let off_out_ptr = args[3] as *const i64;

                        if off_out_ptr.is_null() {
                            payload.off_out_is_null = 1;
                        } else {
                            payload.off_out_is_null = 0;

                            unsafe {
                                if let Ok(off) = bpf_probe_read_user(off_out_ptr) {
                                    payload.off_out = off as u64;
                                }
                            }
                        }

                        payload.len = args[4] as usize;
                        payload.flags = args[5] as u32;
                    },
                )?;
            }
            syscalls::SYS_sync_file_range => {
                crate::util::submit_compact_payload::<pinchy_common::SyncFileRangeData, _>(
                    &ctx,
                    syscalls::SYS_sync_file_range,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.offset = args[1] as i64;
                        payload.nbytes = args[2] as i64;
                        payload.flags = args[3] as u32;
                    },
                )?;
            }
            syscalls::SYS_syncfs => {
                crate::util::submit_compact_payload::<pinchy_common::SyncfsData, _>(
                    &ctx,
                    syscalls::SYS_syncfs,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                    },
                )?;
            }
            syscalls::SYS_utimensat => {
                crate::util::submit_compact_payload::<pinchy_common::UtimensatData, _>(
                    &ctx,
                    syscalls::SYS_utimensat,
                    return_value,
                    |payload| {
                        payload.dirfd = args[0] as i32;

                        let pathname_ptr = args[1] as *const u8;

                        if !pathname_ptr.is_null() {
                            unsafe {
                                let _ =
                                    bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            }
                        }

                        let times_ptr =
                            args[2] as *const [pinchy_common::kernel_types::Timespec; 2];

                        if times_ptr.is_null() {
                            payload.times_is_null = 1;
                        } else {
                            payload.times_is_null = 0;

                            unsafe {
                                if let Ok(times) = bpf_probe_read_user(times_ptr) {
                                    payload.times = times;
                                }
                            }
                        }

                        payload.flags = args[3] as i32;
                    },
                )?;
            }
            syscalls::SYS_quotactl => {
                crate::util::submit_compact_payload::<pinchy_common::QuotactlData, _>(
                    &ctx,
                    syscalls::SYS_quotactl,
                    return_value,
                    |payload| {
                        payload.op = args[0] as i32;
                        let special_ptr = args[1] as *const u8;
                        payload.id = args[2] as i32;
                        payload.addr = args[3] as u64;

                        if !special_ptr.is_null() {
                            unsafe {
                                let _ = bpf_probe_read_user_buf(
                                    special_ptr as *const _,
                                    &mut payload.special,
                                );
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_quotactl_fd => {
                crate::util::submit_compact_payload::<pinchy_common::QuotactlFdData, _>(
                    &ctx,
                    syscalls::SYS_quotactl_fd,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.cmd = args[1] as u32;
                        payload.id = args[2] as i32;
                        payload.addr = args[3] as u64;
                    },
                )?;
            }
            syscalls::SYS_lookup_dcookie => {
                crate::util::submit_compact_payload::<pinchy_common::LookupDcookieData, _>(
                    &ctx,
                    syscalls::SYS_lookup_dcookie,
                    return_value,
                    |payload| {
                        payload.cookie = args[0] as u64;
                        payload.size = args[2] as u64;

                        let buffer_ptr = args[1] as *const u8;

                        if !buffer_ptr.is_null() && return_value > 0 {
                            unsafe {
                                let _ = bpf_probe_read_user_buf(buffer_ptr, &mut payload.buffer);
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_nfsservctl => {
                crate::util::submit_compact_payload::<pinchy_common::NfsservctlData, _>(
                    &ctx,
                    syscalls::SYS_nfsservctl,
                    return_value,
                    |payload| {
                        payload.cmd = args[0] as i32;
                        payload.argp = args[1] as u64;
                        payload.resp = args[2] as u64;
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_utime => {
                crate::util::submit_compact_payload::<pinchy_common::UtimeData, _>(
                    &ctx,
                    syscalls::SYS_utime,
                    return_value,
                    |payload| {
                        let filename_ptr = args[0] as *const u8;
                        let times_ptr = args[1] as *const pinchy_common::kernel_types::Utimbuf;

                        if !filename_ptr.is_null() {
                            unsafe {
                                let _ =
                                    bpf_probe_read_user_buf(filename_ptr, &mut payload.filename);
                            }
                        }

                        if times_ptr.is_null() {
                            payload.times_is_null = 1;
                        } else {
                            payload.times_is_null = 0;

                            unsafe {
                                if let Ok(times) = bpf_probe_read_user(times_ptr) {
                                    payload.times = times;
                                }
                            }
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_access => {
                crate::util::submit_compact_payload::<pinchy_common::AccessData, _>(
                    &ctx,
                    syscalls::SYS_access,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        payload.mode = args[1] as i32;

                        if !pathname_ptr.is_null() {
                            unsafe {
                                let _ =
                                    bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            }
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_chmod => {
                crate::util::submit_compact_payload::<pinchy_common::ChmodData, _>(
                    &ctx,
                    syscalls::SYS_chmod,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        payload.mode = args[1] as u32;

                        if !pathname_ptr.is_null() {
                            unsafe {
                                let _ =
                                    bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            }
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_creat => {
                crate::util::submit_compact_payload::<pinchy_common::CreatData, _>(
                    &ctx,
                    syscalls::SYS_creat,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        payload.mode = args[1] as u32;

                        if !pathname_ptr.is_null() {
                            unsafe {
                                let _ =
                                    bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            }
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_mkdir => {
                crate::util::submit_compact_payload::<pinchy_common::MkdirData, _>(
                    &ctx,
                    syscalls::SYS_mkdir,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        payload.mode = args[1] as u32;

                        if !pathname_ptr.is_null() {
                            unsafe {
                                let _ =
                                    bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            }
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_readlink => {
                crate::util::submit_compact_payload::<pinchy_common::ReadlinkData, _>(
                    &ctx,
                    syscalls::SYS_readlink,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        let buf_ptr = args[1] as *const u8;
                        payload.bufsiz = args[2] as u64;

                        if !pathname_ptr.is_null() {
                            unsafe {
                                let _ =
                                    bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            }
                        }

                        if !buf_ptr.is_null() && return_value > 0 {
                            unsafe {
                                let _ = bpf_probe_read_user_buf(buf_ptr, &mut payload.buf);
                            }
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_stat => {
                crate::util::submit_compact_payload::<pinchy_common::StatData, _>(
                    &ctx,
                    syscalls::SYS_stat,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        let statbuf_ptr = args[1] as *const u8;

                        if !pathname_ptr.is_null() {
                            unsafe {
                                let _ =
                                    bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            }
                        }

                        if !statbuf_ptr.is_null() && return_value == 0 {
                            unsafe {
                                let _ = bpf_probe_read_user_buf(
                                    statbuf_ptr,
                                    core::slice::from_raw_parts_mut(
                                        &mut payload.statbuf as *mut _ as *mut u8,
                                        core::mem::size_of::<pinchy_common::kernel_types::Stat>(),
                                    ),
                                );
                            }
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_lstat => {
                crate::util::submit_compact_payload::<pinchy_common::LstatData, _>(
                    &ctx,
                    syscalls::SYS_lstat,
                    return_value,
                    |payload| {
                        let pathname_ptr = args[0] as *const u8;
                        let statbuf_ptr = args[1] as *const u8;

                        if !pathname_ptr.is_null() {
                            unsafe {
                                let _ =
                                    bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            }
                        }

                        if !statbuf_ptr.is_null() && return_value == 0 {
                            unsafe {
                                let _ = bpf_probe_read_user_buf(
                                    statbuf_ptr,
                                    core::slice::from_raw_parts_mut(
                                        &mut payload.statbuf as *mut _ as *mut u8,
                                        core::mem::size_of::<pinchy_common::kernel_types::Stat>(),
                                    ),
                                );
                            }
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_utimes => {
                crate::util::submit_compact_payload::<pinchy_common::UtimesData, _>(
                    &ctx,
                    syscalls::SYS_utimes,
                    return_value,
                    |payload| {
                        let filename_ptr = args[0] as *const u8;
                        let times_ptr = args[1] as *const [pinchy_common::kernel_types::Timeval; 2];

                        if !filename_ptr.is_null() {
                            unsafe {
                                let _ =
                                    bpf_probe_read_user_buf(filename_ptr, &mut payload.filename);
                            }
                        }

                        if times_ptr.is_null() {
                            payload.times_is_null = 1;
                        } else {
                            payload.times_is_null = 0;

                            unsafe {
                                if let Ok(times) = bpf_probe_read_user(times_ptr) {
                                    payload.times = times;
                                }
                            }
                        }
                    },
                )?;
            }
            #[cfg(x86_64)]
            syscalls::SYS_futimesat => {
                crate::util::submit_compact_payload::<pinchy_common::FutimesatData, _>(
                    &ctx,
                    syscalls::SYS_futimesat,
                    return_value,
                    |payload| {
                        payload.dirfd = args[0] as i32;
                        let pathname_ptr = args[1] as *const u8;
                        let times_ptr = args[2] as *const [pinchy_common::kernel_types::Timeval; 2];

                        if !pathname_ptr.is_null() {
                            unsafe {
                                let _ =
                                    bpf_probe_read_user_buf(pathname_ptr, &mut payload.pathname);
                            }
                        }

                        if times_ptr.is_null() {
                            payload.times_is_null = 1;
                        } else {
                            payload.times_is_null = 0;

                            unsafe {
                                if let Ok(times) = bpf_probe_read_user(times_ptr) {
                                    payload.times = times;
                                }
                            }
                        }
                    },
                )?;
            }
            _ => {}
        }

        Ok(())
    }

    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}
