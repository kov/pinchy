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
    syscalls, DATA_READ_SIZE,
};

use crate::{data_mut, util};

#[tracepoint]
pub fn syscall_exit_filesystem(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;
        let return_value = util::get_return_value(&ctx)?;

        let mut entry = util::Entry::new(&ctx, syscall_nr)?;

        match syscall_nr {
            syscalls::SYS_fstat => {
                let data = data_mut!(entry, fstat);
                data.fd = args[0] as i32;
                let stat_ptr = args[1] as *const u8;
                if !stat_ptr.is_null() {
                    unsafe {
                        data.stat = bpf_probe_read_user(stat_ptr as *const _)
                            .unwrap_or_else(|_| Stat::default());
                    }
                }
            }
            syscalls::SYS_newfstatat => {
                let data = data_mut!(entry, newfstatat);
                data.dirfd = args[0] as i32;
                let pathname_ptr = args[1] as *const u8;
                let stat_ptr = args[2] as *const u8;
                data.flags = args[3] as i32;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr as *const _, &mut data.pathname);
                    if return_value == 0 {
                        let _ = bpf_probe_read_user_buf(
                            stat_ptr,
                            core::slice::from_raw_parts_mut(
                                &mut data.stat as *mut _ as *mut u8,
                                core::mem::size_of::<Stat>(),
                            ),
                        );
                    }
                }
            }
            syscalls::SYS_getdents64 => {
                let data = data_mut!(entry, getdents64);
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

                        if let Ok(val) =
                            unsafe { bpf_probe_read_user::<LinuxDirent64>(base as *const _) }
                        {
                            *dirent = val;
                        }

                        // The entries have different sizes, since the d_name field is an actual array of bytes.
                        // We need to keep track of the offset so we can read the next entry properly.
                        let reclen = dirent.d_reclen as usize;
                        if reclen == 0 {
                            error!(&ctx, "Read a dent with reclen=0 in getdents64 handler.");
                            break; // This should not really happen.
                        }

                        data.num_dirents += 1;
                        offset += reclen;
                    }
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_getdents => {
                let data = data_mut!(entry, getdents);

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

                        data.num_dirents += 1;
                        offset += reclen;
                    }
                }
            }
            syscalls::SYS_readlinkat => {
                let data = data_mut!(entry, readlinkat);
                data.dirfd = args[0] as i32;
                let pathname_ptr = args[1] as *const u8;
                let buf_ptr = args[2] as *const u8;
                data.bufsiz = args[3] as usize;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    let _ = bpf_probe_read_user_buf(buf_ptr, &mut data.buf);
                }
            }
            syscalls::SYS_statfs => {
                let data = data_mut!(entry, statfs);
                let pathname_ptr = args[0] as *const u8;
                let buf_ptr = args[1] as *const pinchy_common::kernel_types::Statfs;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr as *const _, &mut data.pathname);
                    if return_value == 0 {
                        if let Ok(val) = bpf_probe_read_user(buf_ptr as *const _) {
                            data.statfs = val;
                        }
                    }
                }
            }
            syscalls::SYS_faccessat | syscalls::SYS_faccessat2 => {
                let data = data_mut!(entry, faccessat);
                data.dirfd = args[0] as i32;
                let pathname_ptr = args[1] as *const u8;
                data.mode = args[2] as i32;
                data.flags = args[3] as i32;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr as *const _, &mut data.pathname);
                }
            }
            syscalls::SYS_inotify_add_watch => {
                let data = data_mut!(entry, inotify_add_watch);
                data.fd = args[0] as i32;
                data.mask = args[2] as u32;
                let pathname_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            syscalls::SYS_flistxattr => {
                let data = data_mut!(entry, flistxattr);
                data.fd = args[0] as i32;
                let list_ptr = args[1] as *const u8;
                data.list = list_ptr as u64;
                data.size = args[2] as usize;
                data.xattr_list = pinchy_common::kernel_types::XattrList::default();
                if !list_ptr.is_null() && data.size > 0 {
                    let read_size = core::cmp::min(data.size, DATA_READ_SIZE);
                    unsafe {
                        let _ = bpf_probe_read_user_buf(
                            list_ptr,
                            &mut data.xattr_list.data[..read_size],
                        );
                    }
                    data.xattr_list.size = read_size;
                }
            }
            syscalls::SYS_listxattr => {
                let data = data_mut!(entry, listxattr);
                let pathname_ptr = args[0] as *const u8;
                let list_ptr = args[1] as *const u8;
                data.size = args[2] as usize;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
                data.list = list_ptr as u64;
                data.xattr_list = pinchy_common::kernel_types::XattrList::default();
                if !list_ptr.is_null() && data.size > 0 {
                    let read_size = core::cmp::min(data.size, DATA_READ_SIZE);
                    unsafe {
                        let _ = bpf_probe_read_user_buf(
                            list_ptr,
                            &mut data.xattr_list.data[..read_size],
                        );
                    }
                    data.xattr_list.size = read_size;
                }
            }
            syscalls::SYS_llistxattr => {
                let data = data_mut!(entry, llistxattr);
                let pathname_ptr = args[0] as *const u8;
                let list_ptr = args[1] as *const u8;
                data.size = args[2] as usize;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
                data.list = list_ptr as u64;
                data.xattr_list = pinchy_common::kernel_types::XattrList::default();
                if !list_ptr.is_null() && data.size > 0 {
                    let read_size = core::cmp::min(data.size, DATA_READ_SIZE);
                    unsafe {
                        let _ = bpf_probe_read_user_buf(
                            list_ptr,
                            &mut data.xattr_list.data[..read_size],
                        );
                    }
                    data.xattr_list.size = read_size;
                }
            }
            syscalls::SYS_setxattr => {
                let data = data_mut!(entry, setxattr);
                let pathname_ptr = args[0] as *const u8;
                let name_ptr = args[1] as *const u8;
                let value_ptr = args[2] as *const u8;
                data.size = args[3] as usize;
                data.flags = args[4] as i32;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    let _ = bpf_probe_read_user_buf(name_ptr, &mut data.name);
                    if !value_ptr.is_null() && data.size > 0 {
                        let read_size = core::cmp::min(data.size, DATA_READ_SIZE);
                        let _ = bpf_probe_read_user_buf(value_ptr, &mut data.value[..read_size]);
                    }
                }
            }
            syscalls::SYS_lsetxattr => {
                let data = data_mut!(entry, lsetxattr);
                let pathname_ptr = args[0] as *const u8;
                let name_ptr = args[1] as *const u8;
                let value_ptr = args[2] as *const u8;
                data.size = args[3] as usize;
                data.flags = args[4] as i32;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    let _ = bpf_probe_read_user_buf(name_ptr, &mut data.name);
                    if !value_ptr.is_null() && data.size > 0 {
                        let read_size = core::cmp::min(data.size, DATA_READ_SIZE);
                        let _ = bpf_probe_read_user_buf(value_ptr, &mut data.value[..read_size]);
                    }
                }
            }
            syscalls::SYS_fsetxattr => {
                let data = data_mut!(entry, fsetxattr);
                data.fd = args[0] as i32;
                let name_ptr = args[1] as *const u8;
                let value_ptr = args[2] as *const u8;
                data.size = args[3] as usize;
                data.flags = args[4] as i32;
                unsafe {
                    let _ = bpf_probe_read_user_buf(name_ptr, &mut data.name);
                    if !value_ptr.is_null() && data.size > 0 {
                        let read_size = core::cmp::min(data.size, DATA_READ_SIZE);
                        let _ = bpf_probe_read_user_buf(value_ptr, &mut data.value[..read_size]);
                    }
                }
            }
            syscalls::SYS_getxattr => {
                let data = data_mut!(entry, getxattr);
                let pathname_ptr = args[0] as *const u8;
                let name_ptr = args[1] as *const u8;
                let value_ptr = args[2] as *const u8;
                data.size = args[3] as usize;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    let _ = bpf_probe_read_user_buf(name_ptr, &mut data.name);
                    if !value_ptr.is_null() && return_value > 0 && data.size > 0 {
                        let read_size = core::cmp::min(
                            return_value as usize,
                            core::cmp::min(data.size, DATA_READ_SIZE),
                        );
                        let _ = bpf_probe_read_user_buf(value_ptr, &mut data.value[..read_size]);
                    }
                }
            }
            syscalls::SYS_lgetxattr => {
                let data = data_mut!(entry, lgetxattr);
                let pathname_ptr = args[0] as *const u8;
                let name_ptr = args[1] as *const u8;
                let value_ptr = args[2] as *const u8;
                data.size = args[3] as usize;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    let _ = bpf_probe_read_user_buf(name_ptr, &mut data.name);
                    if !value_ptr.is_null() && return_value > 0 && data.size > 0 {
                        let read_size = core::cmp::min(
                            return_value as usize,
                            core::cmp::min(data.size, DATA_READ_SIZE),
                        );
                        let _ = bpf_probe_read_user_buf(value_ptr, &mut data.value[..read_size]);
                    }
                }
            }
            syscalls::SYS_fgetxattr => {
                let data = data_mut!(entry, fgetxattr);
                data.fd = args[0] as i32;
                let name_ptr = args[1] as *const u8;
                let value_ptr = args[2] as *const u8;
                data.size = args[3] as usize;
                unsafe {
                    let _ = bpf_probe_read_user_buf(name_ptr, &mut data.name);
                    if !value_ptr.is_null() && return_value > 0 && data.size > 0 {
                        let read_size = core::cmp::min(
                            return_value as usize,
                            core::cmp::min(data.size, DATA_READ_SIZE),
                        );
                        let _ = bpf_probe_read_user_buf(value_ptr, &mut data.value[..read_size]);
                    }
                }
            }
            syscalls::SYS_removexattr => {
                let data = data_mut!(entry, removexattr);
                let pathname_ptr = args[0] as *const u8;
                let name_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    let _ = bpf_probe_read_user_buf(name_ptr, &mut data.name);
                }
            }
            syscalls::SYS_lremovexattr => {
                let data = data_mut!(entry, lremovexattr);
                let pathname_ptr = args[0] as *const u8;
                let name_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    let _ = bpf_probe_read_user_buf(name_ptr, &mut data.name);
                }
            }
            syscalls::SYS_fremovexattr => {
                let data = data_mut!(entry, fremovexattr);
                data.fd = args[0] as i32;
                let name_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(name_ptr, &mut data.name);
                }
            }
            syscalls::SYS_getcwd => {
                let data = data_mut!(entry, getcwd);
                let buf_ptr = args[0] as *const u8;
                data.buf = buf_ptr as u64;
                data.size = args[1] as usize;
                if return_value > 0 {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(buf_ptr, &mut data.path);
                    }
                }
            }
            syscalls::SYS_chdir => {
                let data = data_mut!(entry, chdir);
                let path_ptr = args[0] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(path_ptr, &mut data.path);
                }
            }
            syscalls::SYS_mkdirat => {
                let data = data_mut!(entry, mkdirat);
                data.dirfd = args[0] as i32;
                data.mode = args[2] as u32;
                let pathname_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_chown => {
                let data = data_mut!(entry, chown);
                data.uid = args[1] as u32;
                data.gid = args[2] as u32;
                let pathname_ptr = args[0] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_lchown => {
                let data = data_mut!(entry, chown);
                data.uid = args[1] as u32;
                data.gid = args[2] as u32;
                let pathname_ptr = args[0] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            syscalls::SYS_truncate => {
                let data = data_mut!(entry, truncate);
                data.length = args[1] as i64;
                let pathname_ptr = args[0] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_rename => {
                let data = data_mut!(entry, rename);
                let oldpath_ptr = args[0] as *const u8;
                let newpath_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(oldpath_ptr, &mut data.oldpath);
                    let _ = bpf_probe_read_user_buf(newpath_ptr, &mut data.newpath);
                }
            }
            syscalls::SYS_renameat => {
                let data = data_mut!(entry, renameat);
                data.olddirfd = args[0] as i32;
                let oldpath_ptr = args[1] as *const u8;
                data.newdirfd = args[2] as i32;
                let newpath_ptr = args[3] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(oldpath_ptr, &mut data.oldpath);
                    let _ = bpf_probe_read_user_buf(newpath_ptr, &mut data.newpath);
                }
            }
            syscalls::SYS_renameat2 => {
                let data = data_mut!(entry, renameat2);
                data.olddirfd = args[0] as i32;
                let oldpath_ptr = args[1] as *const u8;
                data.newdirfd = args[2] as i32;
                let newpath_ptr = args[3] as *const u8;
                data.flags = args[4] as u32;
                unsafe {
                    let _ = bpf_probe_read_user_buf(oldpath_ptr, &mut data.oldpath);
                    let _ = bpf_probe_read_user_buf(newpath_ptr, &mut data.newpath);
                }
            }
            syscalls::SYS_fchmodat => {
                let data = data_mut!(entry, fchmodat);
                data.dirfd = args[0] as i32;
                data.mode = args[2] as u32;
                data.flags = args[3] as i32;
                let pathname_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            syscalls::SYS_fchownat => {
                let data = data_mut!(entry, fchownat);
                data.dirfd = args[0] as i32;
                data.uid = args[2] as u32;
                data.gid = args[3] as u32;
                data.flags = args[4] as i32;
                let pathname_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_rmdir => {
                let data = data_mut!(entry, rmdir);
                let pathname_ptr = args[0] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_unlink => {
                let data = data_mut!(entry, unlink);
                let pathname_ptr = args[0] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            syscalls::SYS_unlinkat => {
                let data = data_mut!(entry, unlinkat);
                data.dirfd = args[0] as i32;
                data.flags = args[2] as i32;
                let pathname_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            syscalls::SYS_acct => {
                let data = data_mut!(entry, acct);
                let filename_ptr = args[0] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(filename_ptr, &mut data.filename);
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_symlink => {
                let data = data_mut!(entry, symlink);
                let target_ptr = args[0] as *const u8;
                let linkpath_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(target_ptr, &mut data.target);
                    let _ = bpf_probe_read_user_buf(linkpath_ptr, &mut data.linkpath);
                }
            }
            syscalls::SYS_symlinkat => {
                let data = data_mut!(entry, symlinkat);
                data.newdirfd = args[1] as i32;
                let target_ptr = args[0] as *const u8;
                let linkpath_ptr = args[2] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(target_ptr, &mut data.target);
                    let _ = bpf_probe_read_user_buf(linkpath_ptr, &mut data.linkpath);
                }
            }
            syscalls::SYS_statx => {
                let data = data_mut!(entry, statx);
                data.dirfd = args[0] as i32;
                let pathname_ptr = args[1] as *const u8;
                data.flags = args[2] as i32;
                data.mask = args[3] as u32;
                let statxbuf_ptr = args[4] as *const pinchy_common::kernel_types::Statx;
                data.statxbuf = statxbuf_ptr as u64;

                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    if return_value == 0 {
                        let _ = bpf_probe_read_user_buf(
                            statxbuf_ptr as *const u8,
                            core::slice::from_raw_parts_mut(
                                &mut data.statx as *mut _ as *mut u8,
                                core::mem::size_of::<pinchy_common::kernel_types::Statx>(),
                            ),
                        );
                    }
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_mknod => {
                let data = data_mut!(entry, mknod);
                data.mode = args[1] as u32;
                data.dev = args[2] as u64;
                let pathname_ptr = args[0] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            syscalls::SYS_mknodat => {
                let data = data_mut!(entry, mknodat);
                data.dirfd = args[0] as i32;
                data.mode = args[2] as u32;
                data.dev = args[3] as u64;
                let pathname_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            syscalls::SYS_pivot_root => {
                let data = data_mut!(entry, pivot_root);
                let new_root_ptr = args[0] as *const u8;
                let put_old_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(new_root_ptr, &mut data.new_root);
                    let _ = bpf_probe_read_user_buf(put_old_ptr, &mut data.put_old);
                }
            }
            syscalls::SYS_chroot => {
                let data = data_mut!(entry, chroot);
                let path_ptr = args[0] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(path_ptr, &mut data.path);
                }
            }
            syscalls::SYS_open_tree => {
                let data = data_mut!(entry, open_tree);
                data.dfd = args[0] as i32;
                let pathname_ptr = args[1] as *const u8;
                data.flags = args[2] as u32;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            syscalls::SYS_mount => {
                let data = data_mut!(entry, mount);
                let source_ptr = args[0] as *const u8;
                let target_ptr = args[1] as *const u8;
                let filesystemtype_ptr = args[2] as *const u8;
                data.mountflags = args[3] as u64;
                data.data = args[4] as u64;
                unsafe {
                    let _ = bpf_probe_read_user_buf(source_ptr, &mut data.source);
                    let _ = bpf_probe_read_user_buf(target_ptr, &mut data.target);
                    let _ = bpf_probe_read_user_buf(filesystemtype_ptr, &mut data.filesystemtype);
                }
            }
            syscalls::SYS_umount2 => {
                let data = data_mut!(entry, umount2);
                let target_ptr = args[0] as *const u8;
                data.flags = args[1] as i32;
                unsafe {
                    let _ = bpf_probe_read_user_buf(target_ptr, &mut data.target);
                }
            }
            syscalls::SYS_mount_setattr => {
                let data = data_mut!(entry, mount_setattr);
                data.dfd = args[0] as i32;
                let path_ptr = args[1] as *const u8;
                data.flags = args[2] as u32;
                data.size = args[4] as usize;

                let attr_ptr = args[3] as *const u8;
                if !attr_ptr.is_null() {
                    data.has_attr = true;
                    unsafe {
                        let _ = bpf_probe_read_user_buf(path_ptr, &mut data.path);
                        let read_size = core::cmp::min(
                            data.size,
                            core::mem::size_of::<pinchy_common::kernel_types::MountAttr>(),
                        );
                        let _ = bpf_probe_read_user_buf(
                            attr_ptr,
                            core::slice::from_raw_parts_mut(
                                &mut data.attr as *mut _ as *mut u8,
                                read_size,
                            ),
                        );
                    }
                }
            }
            syscalls::SYS_move_mount => {
                let data = data_mut!(entry, move_mount);
                data.from_dfd = args[0] as i32;
                let from_pathname_ptr = args[1] as *const u8;
                data.to_dfd = args[2] as i32;
                let to_pathname_ptr = args[3] as *const u8;
                data.flags = args[4] as u32;
                unsafe {
                    let _ = bpf_probe_read_user_buf(from_pathname_ptr, &mut data.from_pathname);
                    let _ = bpf_probe_read_user_buf(to_pathname_ptr, &mut data.to_pathname);
                }
            }
            syscalls::SYS_swapon => {
                let data = data_mut!(entry, swapon);
                let pathname_ptr = args[0] as *const u8;
                data.flags = args[1] as i32;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            syscalls::SYS_swapoff => {
                let data = data_mut!(entry, swapoff);
                let pathname_ptr = args[0] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                }
            }
            syscalls::SYS_fstatfs => {
                let data = data_mut!(entry, fstatfs);
                data.fd = args[0] as i32;
                let buf_ptr = args[1] as *const pinchy_common::kernel_types::Statfs;
                unsafe {
                    if return_value == 0 {
                        if let Ok(val) = bpf_probe_read_user(buf_ptr as *const _) {
                            data.statfs = val;
                        }
                    }
                }
            }
            syscalls::SYS_fsopen => {
                let data = data_mut!(entry, fsopen);
                let fsname_ptr = args[0] as *const u8;
                data.flags = args[1] as u32;
                unsafe {
                    let _ = bpf_probe_read_user_buf(fsname_ptr, &mut data.fsname);
                }
            }
            syscalls::SYS_fsconfig => {
                let data = data_mut!(entry, fsconfig);
                data.fd = args[0] as i32;
                data.cmd = args[1] as u32;
                let key_ptr = args[2] as *const u8;
                let value_ptr = args[3] as *const u8;
                data.aux = args[4] as i32;
                unsafe {
                    if !key_ptr.is_null() {
                        let _ = bpf_probe_read_user_buf(key_ptr, &mut data.key);
                    }
                    if !value_ptr.is_null() {
                        let _ = bpf_probe_read_user_buf(value_ptr, &mut data.value);
                    }
                }
            }
            syscalls::SYS_fspick => {
                let data = data_mut!(entry, fspick);
                data.dfd = args[0] as i32;
                let path_ptr = args[1] as *const u8;
                data.flags = args[2] as u32;
                unsafe {
                    let _ = bpf_probe_read_user_buf(path_ptr, &mut data.path);
                }
            }
            syscalls::SYS_fallocate => {
                let data = data_mut!(entry, fallocate);
                data.fd = args[0] as i32;
                data.mode = args[1] as i32;
                data.offset = args[2] as i64;
                data.size = args[3] as i64;
            }
            #[cfg(x86_64)]
            syscalls::SYS_link => {
                let data = data_mut!(entry, link);
                let oldpath_ptr = args[0] as *const u8;
                let newpath_ptr = args[1] as *const u8;
                unsafe {
                    let _ = bpf_probe_read_user_buf(oldpath_ptr, &mut data.oldpath);
                    let _ = bpf_probe_read_user_buf(newpath_ptr, &mut data.newpath);
                }
            }
            syscalls::SYS_linkat => {
                let data = data_mut!(entry, linkat);
                data.olddirfd = args[0] as i32;
                let oldpath_ptr = args[1] as *const u8;
                data.newdirfd = args[2] as i32;
                let newpath_ptr = args[3] as *const u8;
                data.flags = args[4] as i32;
                unsafe {
                    let _ = bpf_probe_read_user_buf(oldpath_ptr, &mut data.oldpath);
                    let _ = bpf_probe_read_user_buf(newpath_ptr, &mut data.newpath);
                }
            }
            syscalls::SYS_fanotify_init => {
                let data = data_mut!(entry, fanotify_init);
                data.flags = args[0] as u32;
                data.event_f_flags = args[1] as u32;
            }
            syscalls::SYS_fanotify_mark => {
                let data = data_mut!(entry, fanotify_mark);
                data.fanotify_fd = args[0] as i32;
                data.flags = args[1] as u32;
                data.mask = args[2] as u64;
                data.dirfd = args[3] as i32;
                let pathname_ptr = args[4] as *const u8;
                if !pathname_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    }
                }
            }
            syscalls::SYS_name_to_handle_at => {
                let data = data_mut!(entry, name_to_handle_at);
                data.dirfd = args[0] as i32;
                let pathname_ptr = args[1] as *const u8;
                data.handle = args[2] as u64;
                data.mount_id = args[3] as u64;
                data.flags = args[4] as i32;

                if !pathname_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    }
                }
            }
            syscalls::SYS_open_by_handle_at => {
                let data = data_mut!(entry, open_by_handle_at);
                data.mount_fd = args[0] as i32;
                data.handle = args[1] as u64;
                data.flags = args[2] as i32;
            }
            syscalls::SYS_copy_file_range => {
                let data = data_mut!(entry, copy_file_range);
                data.fd_in = args[0] as i32;

                let off_in_ptr = args[1] as *const i64;

                if off_in_ptr.is_null() {
                    data.off_in_is_null = 1;
                } else {
                    data.off_in_is_null = 0;

                    unsafe {
                        if let Ok(off) = bpf_probe_read_user(off_in_ptr) {
                            data.off_in = off as u64;
                        }
                    }
                }

                data.fd_out = args[2] as i32;

                let off_out_ptr = args[3] as *const i64;

                if off_out_ptr.is_null() {
                    data.off_out_is_null = 1;
                } else {
                    data.off_out_is_null = 0;

                    unsafe {
                        if let Ok(off) = bpf_probe_read_user(off_out_ptr) {
                            data.off_out = off as u64;
                        }
                    }
                }

                data.len = args[4] as usize;
                data.flags = args[5] as u32;
            }
            syscalls::SYS_sync_file_range => {
                let data = data_mut!(entry, sync_file_range);
                data.fd = args[0] as i32;
                data.offset = args[1] as i64;
                data.nbytes = args[2] as i64;
                data.flags = args[3] as u32;
            }
            syscalls::SYS_syncfs => {
                let data = data_mut!(entry, syncfs);
                data.fd = args[0] as i32;
            }
            syscalls::SYS_utimensat => {
                let data = data_mut!(entry, utimensat);
                data.dirfd = args[0] as i32;

                let pathname_ptr = args[1] as *const u8;

                if !pathname_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    }
                }

                let times_ptr = args[2] as *const [pinchy_common::kernel_types::Timespec; 2];

                if times_ptr.is_null() {
                    data.times_is_null = 1;
                } else {
                    data.times_is_null = 0;

                    unsafe {
                        if let Ok(times) = bpf_probe_read_user(times_ptr) {
                            data.times = times;
                        }
                    }
                }

                data.flags = args[3] as i32;
            }
            syscalls::SYS_quotactl => {
                let data = data_mut!(entry, quotactl);
                data.op = args[0] as i32;
                let special_ptr = args[1] as *const u8;
                data.id = args[2] as i32;
                data.addr = args[3] as u64;

                if !special_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(special_ptr as *const _, &mut data.special);
                    }
                }
            }
            syscalls::SYS_quotactl_fd => {
                let data = data_mut!(entry, quotactl_fd);
                data.fd = args[0] as i32;
                data.cmd = args[1] as u32;
                data.id = args[2] as i32;
                data.addr = args[3] as u64;
            }
            syscalls::SYS_lookup_dcookie => {
                let data = data_mut!(entry, lookup_dcookie);
                data.cookie = args[0] as u64;
                data.size = args[2] as u64;

                let buffer_ptr = args[1] as *const u8;

                if !buffer_ptr.is_null() && return_value > 0 {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(buffer_ptr, &mut data.buffer);
                    }
                }
            }
            syscalls::SYS_nfsservctl => {
                let data = data_mut!(entry, nfsservctl);
                data.cmd = args[0] as i32;
                data.argp = args[1] as u64;
                data.resp = args[2] as u64;
            }
            #[cfg(x86_64)]
            syscalls::SYS_utime => {
                let data = data_mut!(entry, utime);

                let filename_ptr = args[0] as *const u8;
                let times_ptr = args[1] as *const pinchy_common::kernel_types::Utimbuf;

                if !filename_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(filename_ptr, &mut data.filename);
                    }
                }

                if times_ptr.is_null() {
                    data.times_is_null = 1;
                } else {
                    data.times_is_null = 0;

                    unsafe {
                        if let Ok(times) = bpf_probe_read_user(times_ptr) {
                            data.times = times;
                        }
                    }
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_access => {
                let data = data_mut!(entry, access);

                let pathname_ptr = args[0] as *const u8;
                data.mode = args[1] as i32;

                if !pathname_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    }
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_chmod => {
                let data = data_mut!(entry, chmod);

                let pathname_ptr = args[0] as *const u8;
                data.mode = args[1] as u32;

                if !pathname_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    }
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_creat => {
                let data = data_mut!(entry, creat);

                let pathname_ptr = args[0] as *const u8;
                data.mode = args[1] as u32;

                if !pathname_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    }
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_mkdir => {
                let data = data_mut!(entry, mkdir);

                let pathname_ptr = args[0] as *const u8;
                data.mode = args[1] as u32;

                if !pathname_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    }
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_readlink => {
                let data = data_mut!(entry, readlink);

                let pathname_ptr = args[0] as *const u8;
                let buf_ptr = args[1] as *const u8;
                data.bufsiz = args[2] as u64;

                if !pathname_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    }
                }

                if !buf_ptr.is_null() && return_value > 0 {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(buf_ptr, &mut data.buf);
                    }
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_stat => {
                let data = data_mut!(entry, stat);

                let pathname_ptr = args[0] as *const u8;
                let statbuf_ptr = args[1] as *const u8;

                if !pathname_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    }
                }

                if !statbuf_ptr.is_null() && return_value == 0 {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(
                            statbuf_ptr,
                            core::slice::from_raw_parts_mut(
                                &mut data.statbuf as *mut _ as *mut u8,
                                core::mem::size_of::<pinchy_common::kernel_types::Stat>(),
                            ),
                        );
                    }
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_lstat => {
                let data = data_mut!(entry, lstat);

                let pathname_ptr = args[0] as *const u8;
                let statbuf_ptr = args[1] as *const u8;

                if !pathname_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    }
                }

                if !statbuf_ptr.is_null() && return_value == 0 {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(
                            statbuf_ptr,
                            core::slice::from_raw_parts_mut(
                                &mut data.statbuf as *mut _ as *mut u8,
                                core::mem::size_of::<pinchy_common::kernel_types::Stat>(),
                            ),
                        );
                    }
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_utimes => {
                let data = data_mut!(entry, utimes);

                let filename_ptr = args[0] as *const u8;
                let times_ptr = args[1] as *const [pinchy_common::kernel_types::Timeval; 2];

                if !filename_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(filename_ptr, &mut data.filename);
                    }
                }

                if times_ptr.is_null() {
                    data.times_is_null = 1;
                } else {
                    data.times_is_null = 0;

                    unsafe {
                        if let Ok(times) = bpf_probe_read_user(times_ptr) {
                            data.times = times;
                        }
                    }
                }
            }
            #[cfg(x86_64)]
            syscalls::SYS_futimesat => {
                let data = data_mut!(entry, futimesat);

                data.dirfd = args[0] as i32;
                let pathname_ptr = args[1] as *const u8;
                let times_ptr = args[2] as *const [pinchy_common::kernel_types::Timeval; 2];

                if !pathname_ptr.is_null() {
                    unsafe {
                        let _ = bpf_probe_read_user_buf(pathname_ptr, &mut data.pathname);
                    }
                }

                if times_ptr.is_null() {
                    data.times_is_null = 1;
                } else {
                    data.times_is_null = 0;

                    unsafe {
                        if let Ok(times) = bpf_probe_read_user(times_ptr) {
                            data.times = times;
                        }
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
        Ok(_) => 0,
        Err(ret) => ret,
    }
}
