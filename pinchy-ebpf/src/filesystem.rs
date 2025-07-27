// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::helpers::{bpf_probe_read_buf, bpf_probe_read_user};
use aya_log_ebpf::error;
use pinchy_common::{
    kernel_types::{LinuxDirent64, Stat},
    DATA_READ_SIZE,
};

use crate::syscall_handler;

syscall_handler!(fstat, args, data, {
    data.fd = args[0] as i32;
    let stat_ptr = args[1] as *const u8;
    if !stat_ptr.is_null() {
        unsafe {
            data.stat =
                bpf_probe_read_user(stat_ptr as *const _).unwrap_or_else(|_| Stat::default());
        }
    }
});

syscall_handler!(newfstatat, newfstatat, args, data, return_value, {
    data.dirfd = args[0] as i32;
    let pathname_ptr = args[1] as *const u8;
    let stat_ptr = args[2] as *const u8;
    data.flags = args[3] as i32;
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr as *const _, &mut data.pathname);
        if return_value == 0 {
            let _ = bpf_probe_read_buf(
                stat_ptr,
                core::slice::from_raw_parts_mut(
                    &mut data.stat as *mut _ as *mut u8,
                    core::mem::size_of::<Stat>(),
                ),
            );
        }
    }
});

syscall_handler!(getdents64, getdents64, args, data, _return_value, ctx, {
    data.fd = args[0] as i32;
    data.count = args[2] as usize;
    data.num_dirents = 0;

    let dirp = args[1] as *const u8;
    let mut offset = 0usize;
    for dirent in data.dirents.iter_mut() {
        if offset < data.count {
            let base = unsafe { dirp.add(offset) };
            if base.is_null() {
                break;
            }

            if let Ok(val) = unsafe { bpf_probe_read_user::<LinuxDirent64>(base as *const _) } {
                *dirent = val;
            }

            // The entries have different sizes, since the d_name field is an actual array of bytes.
            // We need to keep track of the offset so we can read the next entry properly.
            let reclen = dirent.d_reclen as usize;
            if reclen == 0 {
                error!(ctx, "Read a dent with reclen=0 in getdents64 handler.");
                break; // This should not really happen.
            }

            data.num_dirents += 1;
            offset += reclen;
        }
    }
});

syscall_handler!(readlinkat, args, data, {
    data.dirfd = args[0] as i32;
    let pathname_ptr = args[1] as *const u8;
    let buf_ptr = args[2] as *const u8;
    data.bufsiz = args[3] as usize;
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr, &mut data.pathname);
        let _ = bpf_probe_read_buf(buf_ptr, &mut data.buf);
    }
});

syscall_handler!(statfs, statfs, args, data, return_value, {
    let pathname_ptr = args[0] as *const u8;
    let buf_ptr = args[1] as *const pinchy_common::kernel_types::Statfs;
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr as *const _, &mut data.pathname);
        if return_value == 0 {
            if let Ok(val) = bpf_probe_read_user(buf_ptr as *const _) {
                data.statfs = val;
            }
        }
    }
});

syscall_handler!(faccessat, args, data, {
    data.dirfd = args[0] as i32;
    let pathname_ptr = args[1] as *const u8;
    data.mode = args[2] as i32;
    data.flags = args[3] as i32;
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr as *const _, &mut data.pathname);
    }
});

syscall_handler!(flistxattr, args, data, {
    data.fd = args[0] as i32;
    let list_ptr = args[1] as *const u8;
    data.list = list_ptr as u64;
    data.size = args[2] as usize;
    data.xattr_list = pinchy_common::kernel_types::XattrList::default();
    if !list_ptr.is_null() && data.size > 0 {
        let read_size = core::cmp::min(data.size, DATA_READ_SIZE);
        unsafe {
            let _ = bpf_probe_read_buf(list_ptr, &mut data.xattr_list.data[..read_size]);
        }
        data.xattr_list.size = read_size;
    }
});

syscall_handler!(listxattr, args, data, {
    let pathname_ptr = args[0] as *const u8;
    let list_ptr = args[1] as *const u8;
    data.size = args[2] as usize;
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr, &mut data.pathname);
    }
    data.list = list_ptr as u64;
    data.xattr_list = pinchy_common::kernel_types::XattrList::default();
    if !list_ptr.is_null() && data.size > 0 {
        let read_size = core::cmp::min(data.size, DATA_READ_SIZE);
        unsafe {
            let _ = bpf_probe_read_buf(list_ptr, &mut data.xattr_list.data[..read_size]);
        }
        data.xattr_list.size = read_size;
    }
});

syscall_handler!(llistxattr, args, data, {
    let pathname_ptr = args[0] as *const u8;
    let list_ptr = args[1] as *const u8;
    data.size = args[2] as usize;
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr, &mut data.pathname);
    }
    data.list = list_ptr as u64;
    data.xattr_list = pinchy_common::kernel_types::XattrList::default();
    if !list_ptr.is_null() && data.size > 0 {
        let read_size = core::cmp::min(data.size, DATA_READ_SIZE);
        unsafe {
            let _ = bpf_probe_read_buf(list_ptr, &mut data.xattr_list.data[..read_size]);
        }
        data.xattr_list.size = read_size;
    }
});

syscall_handler!(getcwd, getcwd, args, data, return_value, {
    let buf_ptr = args[0] as *const u8;
    data.buf = buf_ptr as u64;
    data.size = args[1] as usize;
    if return_value > 0 {
        unsafe {
            let _ = bpf_probe_read_buf(buf_ptr, &mut data.path);
        }
    }
});

syscall_handler!(chdir, args, data, {
    let path_ptr = args[0] as *const u8;
    unsafe {
        let _ = bpf_probe_read_buf(path_ptr, &mut data.path);
    }
});

syscall_handler!(mkdirat, args, data, {
    data.dirfd = args[0] as i32;
    data.mode = args[2] as u32;

    let pathname_ptr = args[1] as *const u8;
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr, &mut data.pathname);
    }
});

#[cfg(x86_64)]
syscall_handler!(chown, chown, args, data, {
    data.uid = args[1] as u32;
    data.gid = args[2] as u32;

    let pathname_ptr = args[0] as *const u8;
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr, &mut data.pathname);
    }
});

#[cfg(x86_64)]
syscall_handler!(lchown, chown, args, data, {
    data.uid = args[1] as u32;
    data.gid = args[2] as u32;

    let pathname_ptr = args[0] as *const u8;
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr, &mut data.pathname);
    }
});

syscall_handler!(truncate, truncate, args, data, {
    data.length = args[1] as i64;

    let pathname_ptr = args[0] as *const u8;
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr, &mut data.pathname);
    }
});

#[cfg(x86_64)]
syscall_handler!(rename, rename, args, data, {
    let oldpath_ptr = args[0] as *const u8;
    let newpath_ptr = args[1] as *const u8;
    unsafe {
        let _ = bpf_probe_read_buf(oldpath_ptr, &mut data.oldpath);
        let _ = bpf_probe_read_buf(newpath_ptr, &mut data.newpath);
    }
});

syscall_handler!(renameat, renameat, args, data, {
    data.olddirfd = args[0] as i32;
    let oldpath_ptr = args[1] as *const u8;

    data.newdirfd = args[2] as i32;
    let newpath_ptr = args[3] as *const u8;
    unsafe {
        let _ = bpf_probe_read_buf(oldpath_ptr, &mut data.oldpath);
        let _ = bpf_probe_read_buf(newpath_ptr, &mut data.newpath);
    }
});

syscall_handler!(renameat2, renameat2, args, data, {
    data.olddirfd = args[0] as i32;
    let oldpath_ptr = args[1] as *const u8;
    data.newdirfd = args[2] as i32;
    let newpath_ptr = args[3] as *const u8;
    data.flags = args[4] as u32;
    unsafe {
        let _ = bpf_probe_read_buf(oldpath_ptr, &mut data.oldpath);
        let _ = bpf_probe_read_buf(newpath_ptr, &mut data.newpath);
    }
});

syscall_handler!(fchmodat, fchmodat, args, data, {
    data.dirfd = args[0] as i32;
    data.mode = args[2] as u32;
    data.flags = args[3] as i32;

    let pathname_ptr = args[1] as *const u8;
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr, &mut data.pathname);
    }
});

syscall_handler!(fchownat, fchownat, args, data, {
    data.dirfd = args[0] as i32;
    data.uid = args[2] as u32;
    data.gid = args[3] as u32;
    data.flags = args[4] as i32;

    let pathname_ptr = args[1] as *const u8;
    unsafe {
        let _ = bpf_probe_read_buf(pathname_ptr, &mut data.pathname);
    }
});
