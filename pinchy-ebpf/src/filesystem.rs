// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_buf, bpf_probe_read_user},
    macros::tracepoint,
    programs::TracePointContext,
};
use pinchy_common::{
    kernel_types::{LinuxDirent64, Stat},
    syscalls, DATA_READ_SIZE,
};

use crate::util::{get_args, get_return_value, output_event};

#[tracepoint]
pub fn syscall_exit_fstat(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = syscalls::SYS_fstat;
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
        let syscall_nr = syscalls::SYS_newfstatat;
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
        let syscall_nr = syscalls::SYS_getdents64;
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
pub fn syscall_exit_readlinkat(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = syscalls::SYS_readlinkat;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let mut readlinkat = pinchy_common::ReadlinkatData {
            dirfd: args[0] as i32,
            pathname: [0u8; pinchy_common::MEDIUM_READ_SIZE],
            buf: [0u8; pinchy_common::MEDIUM_READ_SIZE],
            bufsiz: args[3] as usize,
        };

        let pathname_ptr = args[1] as *const u8;
        let buf_ptr = args[2] as *const u8;

        unsafe {
            let _ = bpf_probe_read_buf(pathname_ptr, &mut readlinkat.pathname);
            let _ = bpf_probe_read_buf(buf_ptr, &mut readlinkat.buf);
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData { readlinkat },
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
        let syscall_nr = syscalls::SYS_statfs;
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
pub fn syscall_exit_faccessat(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = syscalls::SYS_faccessat;
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

fn parse_xattr_list(list_ptr: *const u8, size: usize) -> pinchy_common::kernel_types::XattrList {
    let mut xattr_list = pinchy_common::kernel_types::XattrList::default();
    if !list_ptr.is_null() && size > 0 {
        let read_size = core::cmp::min(size, DATA_READ_SIZE);
        unsafe {
            let _ = bpf_probe_read_buf(list_ptr, &mut xattr_list.data[..read_size]);
        }
        xattr_list.size = read_size;
    }
    xattr_list
}

#[tracepoint]
pub fn syscall_exit_flistxattr(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = syscalls::SYS_flistxattr;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let list_ptr = args[1] as *const u8;
        let size = args[2] as usize;

        let xattr_list = parse_xattr_list(list_ptr, size);

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                flistxattr: pinchy_common::FlistxattrData {
                    fd,
                    list: list_ptr as u64,
                    size,
                    xattr_list,
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
pub fn syscall_exit_listxattr(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = syscalls::SYS_listxattr;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let pathname_ptr = args[0] as *const u8;
        let list_ptr = args[1] as *const u8;
        let size = args[2] as usize;

        let mut pathname = [0u8; DATA_READ_SIZE];

        unsafe {
            let _ = bpf_probe_read_buf(pathname_ptr, &mut pathname);
        }

        let xattr_list = parse_xattr_list(list_ptr, size);

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                listxattr: pinchy_common::ListxattrData {
                    pathname,
                    list: list_ptr as u64,
                    size,
                    xattr_list,
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
pub fn syscall_exit_llistxattr(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = syscalls::SYS_llistxattr;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let pathname_ptr = args[0] as *const u8;
        let list_ptr = args[1] as *const u8;
        let size = args[2] as usize;

        let mut pathname = [0u8; DATA_READ_SIZE];

        unsafe {
            let _ = bpf_probe_read_buf(pathname_ptr, &mut pathname);
        }

        let xattr_list = parse_xattr_list(list_ptr, size);

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                llistxattr: pinchy_common::LlistxattrData {
                    pathname,
                    list: list_ptr as u64,
                    size,
                    xattr_list,
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
pub fn syscall_exit_getcwd(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = syscalls::SYS_getcwd;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let buf_ptr = args[0] as *const u8;
        let size = args[1] as usize;
        let mut path = [0u8; DATA_READ_SIZE];

        // Only read the buffer if the syscall succeeded
        // The return value is a pointer to the buffer (or negative on error)
        if return_value > 0 {
            unsafe {
                let _ = bpf_probe_read_buf(buf_ptr, &mut path);
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                getcwd: pinchy_common::GetcwdData {
                    buf: buf_ptr as u64,
                    size,
                    path,
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
pub fn syscall_exit_chdir(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = syscalls::SYS_chdir;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let path_ptr = args[0] as *const u8;
        let mut path = [0u8; DATA_READ_SIZE];

        unsafe {
            let _ = bpf_probe_read_buf(path_ptr, &mut path);
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                chdir: pinchy_common::ChdirData { path },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}
