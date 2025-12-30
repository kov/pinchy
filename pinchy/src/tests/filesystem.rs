// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#[cfg(target_arch = "x86_64")]
use pinchy_common::syscalls::SYS_link;
#[cfg(target_arch = "x86_64")]
use pinchy_common::LinkData;
use pinchy_common::{
    kernel_types::Timespec,
    syscalls::{
        self, SYS_acct, SYS_chdir, SYS_copy_file_range, SYS_faccessat, SYS_fallocate,
        SYS_fanotify_init, SYS_fanotify_mark, SYS_fchmod, SYS_fchmodat, SYS_fchown, SYS_fchownat,
        SYS_fdatasync, SYS_fstat, SYS_fsync, SYS_ftruncate, SYS_getcwd, SYS_getdents64,
        SYS_inotify_add_watch, SYS_inotify_init1, SYS_inotify_rm_watch, SYS_linkat, SYS_mkdirat,
        SYS_name_to_handle_at, SYS_newfstatat, SYS_open_by_handle_at, SYS_quotactl,
        SYS_quotactl_fd, SYS_readlinkat, SYS_renameat, SYS_renameat2, SYS_statfs,
        SYS_sync_file_range, SYS_syncfs, SYS_truncate, SYS_utimensat,
    },
    AcctData, CopyFileRangeData, FaccessatData, FallocateData, FanotifyInitData, FanotifyMarkData,
    FchmodData, FchmodatData, FchownData, FchownatData, FdatasyncData, FsyncData, FtruncateData,
    InotifyAddWatchData, InotifyInit1Data, InotifyRmWatchData, LinkatData, MkdiratData,
    MknodatData, NameToHandleAtData, OpenByHandleAtData, QuotactlFdData, Renameat2Data,
    RenameatData, SyncFileRangeData, SyncfsData, SyscallEvent, SyscallEventData, UtimensatData,
    DATA_READ_SIZE, MEDIUM_READ_SIZE, SMALLISH_READ_SIZE,
};
#[cfg(target_arch = "x86_64")]
use pinchy_common::{
    kernel_types::{LinuxDirent, Stat, Timeval},
    syscalls::{
        SYS_access, SYS_chmod, SYS_creat, SYS_futimesat, SYS_getdents, SYS_lstat, SYS_mkdir,
        SYS_readlink, SYS_stat, SYS_utime, SYS_utimes,
    },
    AccessData, ChmodData, CreatData, FutimesatData, GetdentsData, LstatData, MkdirData,
    ReadlinkData, StatData, UtimeData, UtimesData,
};

use crate::syscall_test;

syscall_test!(
    parse_fstat_success,
    {
        use pinchy_common::{kernel_types::Stat, FstatData};
        let mut event = SyscallEvent {
            syscall_nr: SYS_fstat,
            pid: 33,
            tid: 33,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                fstat: FstatData {
                    fd: 5,
                    stat: Stat::default(),
                },
            },
        };
        let stat_data = unsafe { &mut event.data.fstat.stat };
        stat_data.st_mode = libc::S_IFREG | 0o644;
        stat_data.st_size = 12345;
        stat_data.st_uid = 1000;
        stat_data.st_gid = 1000;
        stat_data.st_blocks = 24;
        stat_data.st_blksize = 4096;
        stat_data.st_ino = 9876543;
        event
    },
    &"33 fstat(fd: 5, struct stat: { mode: 0o644 (rw-r--r--), ino: 9876543, dev: 0, nlink: 0, uid: 1000, gid: 1000, size: 12345, blksize: 4096, blocks: 24, atime: 0, mtime: 0, ctime: 0 }) = 0 (success)\n".to_string()
);

syscall_test!(
    parse_inotify_add_watch,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let p = b"/tmp/watch";
        pathname[..p.len()].copy_from_slice(p);

        SyscallEvent {
            syscall_nr: SYS_inotify_add_watch,
            pid: 10,
            tid: 10,
            return_value: 3,
            data: SyscallEventData {
                inotify_add_watch: InotifyAddWatchData {
                    fd: 5,
                    pathname,
                    mask: (libc::IN_CREATE | libc::IN_DELETE | libc::IN_MODIFY),
                },
            },
        }
    },
    "10 inotify_add_watch(fd: 5, pathname: \"/tmp/watch\", mask: 0x302 (IN_MODIFY|IN_CREATE|IN_DELETE)) = 3 (wd)\n"
);

syscall_test!(
    parse_inotify_rm_watch,
    {
        SyscallEvent {
            syscall_nr: SYS_inotify_rm_watch,
            pid: 11,
            tid: 11,
            return_value: 0,
            data: SyscallEventData {
                inotify_rm_watch: InotifyRmWatchData { fd: 5, wd: 7 },
            },
        }
    },
    "11 inotify_rm_watch(fd: 5, wd: 7) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_inotify_init,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_inotify_init,
            pid: 12,
            tid: 12,
            return_value: 9,
            data: SyscallEventData {
                inotify_init: pinchy_common::InotifyInitData {},
            },
        }
    },
    "12 inotify_init() = 9 (fd)\n"
);

syscall_test!(
    parse_inotify_init1,
    {
        SyscallEvent {
            syscall_nr: SYS_inotify_init1,
            pid: 13,
            tid: 13,
            return_value: 10,
            data: SyscallEventData {
                inotify_init1: InotifyInit1Data {
                    flags: libc::IN_NONBLOCK | libc::IN_CLOEXEC,
                },
            },
        }
    },
    "13 inotify_init1(flags: 0x80800 (IN_NONBLOCK|IN_CLOEXEC)) = 10 (fd)\n"
);

syscall_test!(
    parse_fstat_error,
    {
        use pinchy_common::{kernel_types::Stat, FstatData};
        let mut event = SyscallEvent {
            syscall_nr: SYS_fstat,
            pid: 33,
            tid: 33,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                fstat: FstatData {
                    fd: 5,
                    stat: Stat::default(),
                },
            },
        };
        let stat_data = unsafe { &mut event.data.fstat.stat };
        stat_data.st_mode = libc::S_IFREG | 0o644;
        stat_data.st_size = 12345;
        stat_data.st_uid = 1000;
        stat_data.st_gid = 1000;
        stat_data.st_blocks = 24;
        stat_data.st_blksize = 4096;
        stat_data.st_ino = 9876543;
        event
    },
    &"33 fstat(fd: 5, struct stat: { mode: 0o644 (rw-r--r--), ino: 9876543, dev: 0, nlink: 0, uid: 1000, gid: 1000, size: 12345, blksize: 4096, blocks: 24, atime: 0, mtime: 0, ctime: 0 }) = -1 (error)\n".to_string()
);

syscall_test!(
    parse_statfs_success,
    {
        use pinchy_common::{kernel_types::Statfs, StatfsData};
        let mut event = SyscallEvent {
            syscall_nr: SYS_statfs,
            pid: 44,
            tid: 44,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                statfs: StatfsData {
                    pathname: [0u8; DATA_READ_SIZE],
                    statfs: Statfs::default(),
                },
            },
        };
        let statfs_data = unsafe { &mut event.data.statfs };
        let path = c"/mnt/data".to_bytes_with_nul();
        statfs_data.pathname[..path.len()].copy_from_slice(path);
        statfs_data.statfs.f_type = 0x01021994;
        statfs_data.statfs.f_bsize = 4096;
        statfs_data.statfs.f_blocks = 1024000;
        statfs_data.statfs.f_bfree = 512000;
        statfs_data.statfs.f_bavail = 512000;
        statfs_data.statfs.f_files = 65536;
        statfs_data.statfs.f_ffree = 65000;
        statfs_data.statfs.f_namelen = 255;
        statfs_data.statfs.f_flags = (libc::ST_NOEXEC | libc::ST_RDONLY) as i64;
        event
    },
    &"44 statfs(pathname: \"/mnt/data\", buf: { type: TMPFS_MAGIC (0x1021994), block_size: 4096, blocks: 1024000, blocks_free: 512000, blocks_available: 512000, files: 65536, files_free: 65000, fsid: [0, 0], name_max: 255, fragment_size: 0, mount_flags: 0x9 (ST_RDONLY|ST_NOEXEC) }) = 0 (success)\n".to_string()
);

syscall_test!(
    parse_statfs_error,
    {
        use pinchy_common::{kernel_types::Statfs, StatfsData};
        let mut event = SyscallEvent {
            syscall_nr: SYS_statfs,
            pid: 44,
            tid: 44,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                statfs: StatfsData {
                    pathname: [0u8; DATA_READ_SIZE],
                    statfs: Statfs::default(),
                },
            },
        };
        let statfs_data = unsafe { &mut event.data.statfs };
        let path = c"/mnt/data".to_bytes_with_nul();
        statfs_data.pathname[..path.len()].copy_from_slice(path);
        statfs_data.statfs.f_type = 0x01021994;
        statfs_data.statfs.f_bsize = 4096;
        statfs_data.statfs.f_blocks = 1024000;
        statfs_data.statfs.f_bfree = 512000;
        statfs_data.statfs.f_bavail = 512000;
        statfs_data.statfs.f_files = 65536;
        statfs_data.statfs.f_ffree = 65000;
        statfs_data.statfs.f_namelen = 255;
        statfs_data.statfs.f_flags = (libc::ST_NOEXEC | libc::ST_RDONLY) as i64;
        event
    },
    "44 statfs(pathname: \"/mnt/data\", buf: <unavailable>) = -1 (error)\n"
);

syscall_test!(
    parse_getdents64_populated,
    {
        use pinchy_common::{kernel_types::LinuxDirent64, Getdents64Data};
        let mut event = SyscallEvent {
            syscall_nr: SYS_getdents64,
            pid: 55,
            tid: 55,
            return_value: 3,
            data: pinchy_common::SyscallEventData {
                getdents64: Getdents64Data {
                    fd: 7,
                    count: 1024,
                    dirents: [LinuxDirent64::default(); 4],
                    num_dirents: 3,
                },
            },
        };
        {
            let getdents_data = unsafe { &mut event.data.getdents64 };
            getdents_data.dirents[0].d_ino = 123456;
            getdents_data.dirents[0].d_off = 1;
            getdents_data.dirents[0].d_reclen = 24;
            getdents_data.dirents[0].d_type = 4;
            let dot = c".".to_bytes_with_nul();
            getdents_data.dirents[0].d_name[..dot.len()].copy_from_slice(dot);
            getdents_data.dirents[1].d_ino = 123457;
            getdents_data.dirents[1].d_off = 2;
            getdents_data.dirents[1].d_reclen = 25;
            getdents_data.dirents[1].d_type = 4;
            let dot_dot = c"..".to_bytes_with_nul();
            getdents_data.dirents[1].d_name[..dot_dot.len()].copy_from_slice(dot_dot);
            getdents_data.dirents[2].d_ino = 123458;
            getdents_data.dirents[2].d_off = 3;
            getdents_data.dirents[2].d_reclen = 32;
            getdents_data.dirents[2].d_type = 8;
            let filename = c"file.txt".to_bytes();
            getdents_data.dirents[2].d_name[..filename.len()].copy_from_slice(filename);
        }
        event
    },
    &"55 getdents64(fd: 7, count: 1024, entries: [ dirent { ino: 123456, off: 1, reclen: 24, type: 4, name: \".\" }, dirent { ino: 123457, off: 2, reclen: 25, type: 4, name: \"..\" }, dirent { ino: 123458, off: 3, reclen: 32, type: 8, name: \"file.txt\" ... (truncated) } ]) = 3 (bytes)\n".to_string()
);

syscall_test!(
    parse_getdents64_empty,
    {
        use pinchy_common::{kernel_types::LinuxDirent64, Getdents64Data};

        SyscallEvent {
            syscall_nr: SYS_getdents64,
            pid: 55,
            tid: 55,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                getdents64: Getdents64Data {
                    fd: 7,
                    count: 1024,
                    dirents: [LinuxDirent64::default(); 4],
                    num_dirents: 0,
                },
            },
        }
    },
    &"55 getdents64(fd: 7, count: 1024, entries: [  ]) = 0 (bytes)\n".to_string()
);

syscall_test!(
    parse_faccessat_success,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/etc/hosts.conf";
        pathname[0..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: SYS_faccessat,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                faccessat: FaccessatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    mode: libc::R_OK | libc::W_OK,
                    flags: 0,
                },
            },
        }
    },
    &"1001 faccessat(dirfd: AT_FDCWD, pathname: \"/etc/hosts.conf\", mode: R_OK|W_OK) = 0 (success)\n".to_string()
);

syscall_test!(
    parse_faccessat_with_flags_error,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/etc/hosts";
        pathname[0..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: SYS_faccessat,
            pid: 1000,
            tid: 1001,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                faccessat: FaccessatData {
                    dirfd: 3,
                    pathname,
                    mode: libc::F_OK,
                    flags: libc::AT_SYMLINK_NOFOLLOW,
                },
            },
        }
    },
    "1001 faccessat(dirfd: 3, pathname: \"/etc/hosts\", mode: F_OK) = -1 (error)\n"
);

syscall_test!(
    parse_faccessat2_success,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/etc/hosts.conf";
        pathname[0..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: syscalls::SYS_faccessat2,
            pid: 1000,
            tid: 1002,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                faccessat: FaccessatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    mode: libc::R_OK | libc::W_OK,
                    flags: 0,
                },
            },
        }
    },
    &"1002 faccessat2(dirfd: AT_FDCWD, pathname: \"/etc/hosts.conf\", mode: R_OK|W_OK, flags: 0) = 0 (success)\n".to_string()
);

syscall_test!(
    parse_faccessat2_with_flags_error,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/etc/hosts";
        pathname[0..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_faccessat2,
            pid: 1000,
            tid: 1003,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                faccessat: FaccessatData {
                    dirfd: 3,
                    pathname,
                    mode: libc::F_OK,
                    flags: libc::AT_SYMLINK_NOFOLLOW,
                },
            },
        }
    },
    "1003 faccessat2(dirfd: 3, pathname: \"/etc/hosts\", mode: F_OK, flags: AT_SYMLINK_NOFOLLOW (0x100)) = -1 (error)\n"
);

syscall_test!(
    parse_newfstatat_success,
    {
        use pinchy_common::{kernel_types::Stat, NewfstatatData};
        let mut event = SyscallEvent {
            syscall_nr: SYS_newfstatat,
            pid: 42,
            tid: 42,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                newfstatat: NewfstatatData {
                    dirfd: libc::AT_FDCWD,
                    pathname: [0u8; DATA_READ_SIZE],
                    stat: Stat::default(),
                    flags: libc::AT_SYMLINK_NOFOLLOW,
                },
            },
        };
        let pathname = b"test_file.txt\0";
        let data = unsafe { &mut event.data.newfstatat };
        data.pathname[..pathname.len()].copy_from_slice(pathname);
        let stat_data = unsafe { &mut event.data.newfstatat.stat };
        stat_data.st_mode = libc::S_IFREG | 0o755;
        stat_data.st_size = 54321;
        stat_data.st_uid = 500;
        stat_data.st_gid = 500;
        stat_data.st_blocks = 108;
        stat_data.st_blksize = 4096;
        stat_data.st_ino = 1234567;
        event
    },
    &"42 newfstatat(dirfd: AT_FDCWD, pathname: \"test_file.txt\", struct stat: { mode: 0o755 (rwxr-xr-x), ino: 1234567, dev: 0, nlink: 0, uid: 500, gid: 500, size: 54321, blksize: 4096, blocks: 108, atime: 0, mtime: 0, ctime: 0 }, flags: AT_SYMLINK_NOFOLLOW (0x100)) = 0 (success)\n".to_string()
);

syscall_test!(
    parse_newfstatat_error,
    {
        use pinchy_common::{kernel_types::Stat, NewfstatatData};
        let mut event = SyscallEvent {
            syscall_nr: SYS_newfstatat,
            pid: 42,
            tid: 42,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                newfstatat: NewfstatatData {
                    dirfd: libc::AT_FDCWD,
                    pathname: [0u8; DATA_READ_SIZE],
                    stat: Stat::default(),
                    flags: libc::AT_SYMLINK_NOFOLLOW,
                },
            },
        };
        let pathname = b"test_file.txt\0";
        let data = unsafe { &mut event.data.newfstatat };
        data.pathname[..pathname.len()].copy_from_slice(pathname);
        let stat_data = unsafe { &mut event.data.newfstatat.stat };
        stat_data.st_mode = libc::S_IFREG | 0o755;
        stat_data.st_size = 54321;
        stat_data.st_uid = 500;
        stat_data.st_gid = 500;
        stat_data.st_blocks = 108;
        stat_data.st_blksize = 4096;
        stat_data.st_ino = 1234567;
        event
    },
    &"42 newfstatat(dirfd: AT_FDCWD, pathname: \"test_file.txt\", struct stat: <unavailable>, flags: AT_SYMLINK_NOFOLLOW (0x100)) = -1 (error)\n".to_string()
);

syscall_test!(
    parse_newfstatat_noflags,
    {
        use pinchy_common::{kernel_types::Stat, NewfstatatData};
        let mut event = SyscallEvent {
            syscall_nr: SYS_newfstatat,
            pid: 42,
            tid: 42,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                newfstatat: NewfstatatData {
                    dirfd: libc::AT_FDCWD,
                    pathname: [0u8; DATA_READ_SIZE],
                    stat: Stat::default(),
                    flags: 0,
                },
            },
        };
        let pathname = b"test_file.txt\0";
        let data = unsafe { &mut event.data.newfstatat };
        data.pathname[..pathname.len()].copy_from_slice(pathname);
        let stat_data = unsafe { &mut event.data.newfstatat.stat };
        stat_data.st_mode = libc::S_IFREG | 0o755;
        stat_data.st_size = 54321;
        stat_data.st_uid = 500;
        stat_data.st_gid = 500;
        stat_data.st_blocks = 108;
        stat_data.st_blksize = 4096;
        stat_data.st_ino = 1234567;
        event
    },
    &"42 newfstatat(dirfd: AT_FDCWD, pathname: \"test_file.txt\", struct stat: { mode: 0o755 (rwxr-xr-x), ino: 1234567, dev: 0, nlink: 0, uid: 500, gid: 500, size: 54321, blksize: 4096, blocks: 108, atime: 0, mtime: 0, ctime: 0 }, flags: 0) = 0 (success)\n".to_string()
);

syscall_test!(
    parse_newfstatat_dirfd,
    {
        use pinchy_common::{kernel_types::Stat, NewfstatatData};
        let mut event = SyscallEvent {
            syscall_nr: SYS_newfstatat,
            pid: 42,
            tid: 42,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                newfstatat: NewfstatatData {
                    dirfd: 5,
                    pathname: [0u8; DATA_READ_SIZE],
                    stat: Stat::default(),
                    flags: 0,
                },
            },
        };
        let pathname = b"test_file.txt\0";
        let data = unsafe { &mut event.data.newfstatat };
        data.pathname[..pathname.len()].copy_from_slice(pathname);
        let stat_data = unsafe { &mut event.data.newfstatat.stat };
        stat_data.st_mode = libc::S_IFREG | 0o755;
        stat_data.st_size = 54321;
        stat_data.st_uid = 500;
        stat_data.st_gid = 500;
        stat_data.st_blocks = 108;
        stat_data.st_blksize = 4096;
        stat_data.st_ino = 1234567;
        event
    },
    &"42 newfstatat(dirfd: 5, pathname: \"test_file.txt\", struct stat: { mode: 0o755 (rwxr-xr-x), ino: 1234567, dev: 0, nlink: 0, uid: 500, gid: 500, size: 54321, blksize: 4096, blocks: 108, atime: 0, mtime: 0, ctime: 0 }, flags: 0) = 0 (success)\n".to_string()
);

syscall_test!(
    parse_readlinkat_event,
    {
        let exe_link = b"/proc/self/exe\0";
        let bin_path = b"/usr/bin/pinchy\0";
        let mut readlinkat = pinchy_common::ReadlinkatData {
            dirfd: 3,
            pathname: [0u8; MEDIUM_READ_SIZE],
            buf: [0u8; MEDIUM_READ_SIZE],
            bufsiz: 16,
        };
        readlinkat.pathname[..exe_link.len()].copy_from_slice(exe_link);
        readlinkat.buf[..bin_path.len()].copy_from_slice(bin_path);
        SyscallEvent {
            syscall_nr: SYS_readlinkat,
            pid: 1234,
            tid: 5678,
            return_value: 0,
            data: pinchy_common::SyscallEventData { readlinkat },
        }
    },
    &"5678 readlinkat(dirfd: 3, pathname: \"/proc/self/exe\", buf: \"/usr/bin/pinchy\", bufsiz: 16) = 0 (success)\n".to_string()
);

syscall_test!(
    parse_flistxattr,
    {
        use pinchy_common::{kernel_types::XattrList, syscalls::SYS_flistxattr, FlistxattrData};
        let mut xattr_list = XattrList::default();
        let names = b"user.attr1\0user.attr2\0";
        xattr_list.data[..names.len()].copy_from_slice(names);
        xattr_list.size = names.len();
        SyscallEvent {
            syscall_nr: SYS_flistxattr,
            pid: 42,
            tid: 42,
            return_value: names.len() as i64,
            data: pinchy_common::SyscallEventData {
                flistxattr: FlistxattrData {
                    fd: 7,
                    list: 0xdeadbeef,
                    size: 256,
                    xattr_list,
                },
            },
        }
    },
    "42 flistxattr(fd: 7, list: [ user.attr1, user.attr2 ], size: 256) = 22\n"
);

syscall_test!(
    parse_listxattr,
    {
        use pinchy_common::{kernel_types::XattrList, syscalls::SYS_listxattr, ListxattrData};
        let mut xattr_list = XattrList::default();
        let names = b"user.attr1\0user.attr2\0";
        xattr_list.data[..names.len()].copy_from_slice(names);
        xattr_list.size = names.len();
        SyscallEvent {
            syscall_nr: SYS_listxattr,
            pid: 43,
            tid: 43,
            return_value: names.len() as i64,
            data: pinchy_common::SyscallEventData {
                listxattr: ListxattrData {
                    pathname: {
                        let mut arr = [0u8; pinchy_common::DATA_READ_SIZE];
                        let path = b"/tmp/testfile\0";
                        arr[..path.len()].copy_from_slice(path);
                        arr
                    },
                    list: 0xabadcafe,
                    size: 128,
                    xattr_list,
                },
            },
        }
    },
    "43 listxattr(pathname: \"/tmp/testfile\", list: [ user.attr1, user.attr2 ], size: 128) = 22\n"
);

syscall_test!(
    parse_llistxattr,
    {
        use pinchy_common::{kernel_types::XattrList, syscalls::SYS_llistxattr, LlistxattrData};
        let mut xattr_list = XattrList::default();
        let names = b"user.attr1\0user.attr2\0";
        xattr_list.data[..names.len()].copy_from_slice(names);
        xattr_list.size = names.len();
        SyscallEvent {
            syscall_nr: SYS_llistxattr,
            pid: 44,
            tid: 44,
            return_value: names.len() as i64,
            data: pinchy_common::SyscallEventData {
                llistxattr: LlistxattrData {
                    pathname: {
                        let mut arr = [0u8; pinchy_common::DATA_READ_SIZE];
                        let path = b"/tmp/testlink\0";
                        arr[..path.len()].copy_from_slice(path);
                        arr
                    },
                    list: 0xfeedface,
                    size: 64,
                    xattr_list,
                },
            },
        }
    },
    "44 llistxattr(pathname: \"/tmp/testlink\", list: [ user.attr1, user.attr2 ], size: 64) = 22\n"
);

syscall_test!(
    parse_setxattr,
    {
        use pinchy_common::{syscalls::SYS_setxattr, SetxattrData, DATA_READ_SIZE, MEDIUM_READ_SIZE};
        let mut pathname = [0u8; DATA_READ_SIZE];
        pathname[..12].copy_from_slice(b"/tmp/myfile\0");
        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..10].copy_from_slice(b"user.attr\0");
        let mut value = [0u8; DATA_READ_SIZE];
        value[..6].copy_from_slice(b"value\0");
        SyscallEvent {
            syscall_nr: SYS_setxattr,
            pid: 45,
            tid: 45,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                setxattr: SetxattrData {
                    pathname,
                    name,
                    value,
                    size: 6,
                    flags: 0,
                },
            },
        }
    },
    "45 setxattr(pathname: \"/tmp/myfile\", name: \"user.attr\", value: \"value\\0\", size: 6, flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_lsetxattr,
    {
        use pinchy_common::{syscalls::SYS_lsetxattr, LsetxattrData, DATA_READ_SIZE, MEDIUM_READ_SIZE};
        let mut pathname = [0u8; DATA_READ_SIZE];
        pathname[..12].copy_from_slice(b"/tmp/mylink\0");
        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..10].copy_from_slice(b"user.test\0");
        let mut value = [0u8; DATA_READ_SIZE];
        value[..4].copy_from_slice(b"test");
        SyscallEvent {
            syscall_nr: SYS_lsetxattr,
            pid: 46,
            tid: 46,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                lsetxattr: LsetxattrData {
                    pathname,
                    name,
                    value,
                    size: 4,
                    flags: libc::XATTR_CREATE,
                },
            },
        }
    },
    "46 lsetxattr(pathname: \"/tmp/mylink\", name: \"user.test\", value: \"test\", size: 4, flags: 0x1 (XATTR_CREATE)) = 0 (success)\n"
);

syscall_test!(
    parse_fsetxattr,
    {
        use pinchy_common::{syscalls::SYS_fsetxattr, FsetxattrData, DATA_READ_SIZE, MEDIUM_READ_SIZE};
        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..9].copy_from_slice(b"user.foo\0");
        let mut value = [0u8; DATA_READ_SIZE];
        value[..3].copy_from_slice(b"bar");
        SyscallEvent {
            syscall_nr: SYS_fsetxattr,
            pid: 47,
            tid: 47,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                fsetxattr: FsetxattrData {
                    fd: 8,
                    name,
                    value,
                    size: 3,
                    flags: libc::XATTR_REPLACE,
                },
            },
        }
    },
    "47 fsetxattr(fd: 8, name: \"user.foo\", value: \"bar\", size: 3, flags: 0x2 (XATTR_REPLACE)) = 0 (success)\n"
);

syscall_test!(
    parse_getxattr,
    {
        use pinchy_common::{syscalls::SYS_getxattr, GetxattrData, DATA_READ_SIZE, MEDIUM_READ_SIZE};
        let mut pathname = [0u8; DATA_READ_SIZE];
        pathname[..12].copy_from_slice(b"/tmp/myfile\0");
        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..10].copy_from_slice(b"user.attr\0");
        let mut value = [0u8; DATA_READ_SIZE];
        value[..6].copy_from_slice(b"value\0");
        SyscallEvent {
            syscall_nr: SYS_getxattr,
            pid: 48,
            tid: 48,
            return_value: 6,
            data: pinchy_common::SyscallEventData {
                getxattr: GetxattrData {
                    pathname,
                    name,
                    value,
                    size: 100,
                },
            },
        }
    },
    "48 getxattr(pathname: \"/tmp/myfile\", name: \"user.attr\", value: \"value\\0\", size: 100) = 6\n"
);

syscall_test!(
    parse_lgetxattr,
    {
        use pinchy_common::{
            syscalls::SYS_lgetxattr, LgetxattrData, DATA_READ_SIZE, MEDIUM_READ_SIZE,
        };
        let mut pathname = [0u8; DATA_READ_SIZE];
        pathname[..12].copy_from_slice(b"/tmp/mylink\0");
        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..10].copy_from_slice(b"user.test\0");
        let mut value = [0u8; DATA_READ_SIZE];
        value[..4].copy_from_slice(b"test");
        SyscallEvent {
            syscall_nr: SYS_lgetxattr,
            pid: 49,
            tid: 49,
            return_value: 4,
            data: pinchy_common::SyscallEventData {
                lgetxattr: LgetxattrData {
                    pathname,
                    name,
                    value,
                    size: 50,
                },
            },
        }
    },
    "49 lgetxattr(pathname: \"/tmp/mylink\", name: \"user.test\", value: \"test\", size: 50) = 4\n"
);

syscall_test!(
    parse_fgetxattr,
    {
        use pinchy_common::{
            syscalls::SYS_fgetxattr, FgetxattrData, DATA_READ_SIZE, MEDIUM_READ_SIZE,
        };
        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..9].copy_from_slice(b"user.foo\0");
        let mut value = [0u8; DATA_READ_SIZE];
        value[..3].copy_from_slice(b"bar");
        SyscallEvent {
            syscall_nr: SYS_fgetxattr,
            pid: 50,
            tid: 50,
            return_value: 3,
            data: pinchy_common::SyscallEventData {
                fgetxattr: FgetxattrData {
                    fd: 9,
                    name,
                    value,
                    size: 10,
                },
            },
        }
    },
    "50 fgetxattr(fd: 9, name: \"user.foo\", value: \"bar\", size: 10) = 3\n"
);

syscall_test!(
    parse_removexattr,
    {
        use pinchy_common::{
            syscalls::SYS_removexattr, RemovexattrData, DATA_READ_SIZE, MEDIUM_READ_SIZE,
        };
        let mut pathname = [0u8; DATA_READ_SIZE];
        pathname[..12].copy_from_slice(b"/tmp/myfile\0");
        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..10].copy_from_slice(b"user.attr\0");
        SyscallEvent {
            syscall_nr: SYS_removexattr,
            pid: 51,
            tid: 51,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                removexattr: RemovexattrData { pathname, name },
            },
        }
    },
    "51 removexattr(pathname: \"/tmp/myfile\", name: \"user.attr\") = 0 (success)\n"
);

syscall_test!(
    parse_lremovexattr,
    {
        use pinchy_common::{
            syscalls::SYS_lremovexattr, LremovexattrData, DATA_READ_SIZE, MEDIUM_READ_SIZE,
        };
        let mut pathname = [0u8; DATA_READ_SIZE];
        pathname[..12].copy_from_slice(b"/tmp/mylink\0");
        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..10].copy_from_slice(b"user.test\0");
        SyscallEvent {
            syscall_nr: SYS_lremovexattr,
            pid: 52,
            tid: 52,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                lremovexattr: LremovexattrData { pathname, name },
            },
        }
    },
    "52 lremovexattr(pathname: \"/tmp/mylink\", name: \"user.test\") = 0 (success)\n"
);

syscall_test!(
    parse_fremovexattr,
    {
        use pinchy_common::{syscalls::SYS_fremovexattr, FremovexattrData, MEDIUM_READ_SIZE};
        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..9].copy_from_slice(b"user.foo\0");
        SyscallEvent {
            syscall_nr: SYS_fremovexattr,
            pid: 53,
            tid: 53,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                fremovexattr: FremovexattrData { fd: 10, name },
            },
        }
    },
    "53 fremovexattr(fd: 10, name: \"user.foo\") = 0 (success)\n"
);

syscall_test!(
    parse_getcwd,
    {
        use pinchy_common::GetcwdData;

        SyscallEvent {
            syscall_nr: SYS_getcwd,
            pid: 55,
            tid: 55,
            return_value: 16, // Return value is a pointer (success)
            data: pinchy_common::SyscallEventData {
                getcwd: GetcwdData {
                    buf: 0x7ffe12345000,
                    size: 4096,
                    path: {
                        let mut arr = [0u8; DATA_READ_SIZE];
                        let path = b"/home/user/work\0";
                        arr[..path.len()].copy_from_slice(path);
                        arr
                    },
                },
            },
        }
    },
    "55 getcwd(buf: 0x7ffe12345000, size: 4096, path: \"/home/user/work\") = 16\n"
);
syscall_test!(
    parse_getcwd_error,
    {
        use pinchy_common::GetcwdData;

        SyscallEvent {
            syscall_nr: SYS_getcwd,
            pid: 55,
            tid: 55,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                getcwd: GetcwdData {
                    buf: 0x7ffe12345000,
                    size: 4096,
                    path: {
                        let mut arr = [0u8; DATA_READ_SIZE];
                        let path = b"/home/user/work\0";
                        arr[..path.len()].copy_from_slice(path);
                        arr
                    },
                },
            },
        }
    },
    "55 getcwd(buf: 0x7ffe12345000, size: 4096) = -1 (error)\n"
);

syscall_test!(
    parse_chdir,
    {
        use pinchy_common::ChdirData;

        SyscallEvent {
            syscall_nr: SYS_chdir,
            pid: 66,
            tid: 66,
            return_value: 0, // Success
            data: pinchy_common::SyscallEventData {
                chdir: ChdirData {
                    path: {
                        let mut arr = [0u8; DATA_READ_SIZE];
                        let path = b"/home/user/newdir\0";
                        arr[..path.len()].copy_from_slice(path);
                        arr
                    },
                },
            },
        }
    },
    "66 chdir(path: \"/home/user/newdir\") = 0 (success)\n"
);
syscall_test!(
    parse_chdir_error,
    {
        use pinchy_common::ChdirData;

        SyscallEvent {
            syscall_nr: SYS_chdir,
            pid: 66,
            tid: 66,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                chdir: ChdirData {
                    path: {
                        let mut arr = [0u8; DATA_READ_SIZE];
                        let path = b"/home/user/newdir\0";
                        arr[..path.len()].copy_from_slice(path);
                        arr
                    },
                },
            },
        }
    },
    "66 chdir(path: \"/home/user/newdir\") = -1 (error)\n"
);

syscall_test!(
    parse_mkdirat,
    {
        SyscallEvent {
            syscall_nr: SYS_mkdirat,
            pid: 77,
            tid: 77,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                mkdirat: MkdiratData {
                    dirfd: libc::AT_FDCWD,
                    pathname: {
                        let mut arr = [0u8; DATA_READ_SIZE];
                        let path = b"/home/user/newdir\0";
                        arr[..path.len()].copy_from_slice(path);
                        arr
                    },
                    mode: 0o755,
                },
            },
        }
    },
    "77 mkdirat(dirfd: AT_FDCWD, pathname: \"/home/user/newdir\", mode: 0o755 (rwxr-xr-x)) = 0 (success)\n"
);
syscall_test!(
    parse_mkdirat_dirfd,
    {
        SyscallEvent {
            syscall_nr: SYS_mkdirat,
            pid: 77,
            tid: 77,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                mkdirat: MkdiratData {
                    dirfd: 5,
                    pathname: {
                        let mut arr = [0u8; DATA_READ_SIZE];
                        let path = b"/home/user/newdir\0";
                        arr[..path.len()].copy_from_slice(path);
                        arr
                    },
                    mode: 0o700,
                },
            },
        }
    },
    "77 mkdirat(dirfd: 5, pathname: \"/home/user/newdir\", mode: 0o700 (rwx------)) = 0 (success)\n"
);
syscall_test!(
    parse_mkdirat_error,
    {
        SyscallEvent {
            syscall_nr: SYS_mkdirat,
            pid: 77,
            tid: 77,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                mkdirat: MkdiratData {
                    dirfd: 5,
                    pathname: {
                        let mut arr = [0u8; DATA_READ_SIZE];
                        let path = b"/home/user/newdir\0";
                        arr[..path.len()].copy_from_slice(path);
                        arr
                    },
                    mode: 0o700,
                },
            },
        }
    },
    "77 mkdirat(dirfd: 5, pathname: \"/home/user/newdir\", mode: 0o700 (rwx------)) = -1 (error)\n"
);

syscall_test!(
    parse_fsync,
    {
        SyscallEvent {
            syscall_nr: SYS_fsync,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                fsync: FsyncData { fd: 5 },
            },
        }
    },
    "123 fsync(fd: 5) = 0 (success)\n"
);

syscall_test!(
    parse_fdatasync,
    {
        SyscallEvent {
            syscall_nr: SYS_fdatasync,
            pid: 124,
            tid: 124,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                fdatasync: FdatasyncData { fd: 8 },
            },
        }
    },
    "124 fdatasync(fd: 8) = 0 (success)\n"
);

syscall_test!(
    parse_ftruncate,
    {
        SyscallEvent {
            syscall_nr: SYS_ftruncate,
            pid: 125,
            tid: 125,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                ftruncate: FtruncateData {
                    fd: 3,
                    length: 4096,
                },
            },
        }
    },
    "125 ftruncate(fd: 3, length: 4096) = 0 (success)\n"
);
syscall_test!(
    parse_ftruncate_error,
    {
        SyscallEvent {
            syscall_nr: SYS_ftruncate,
            pid: 125,
            tid: 125,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                ftruncate: FtruncateData {
                    fd: 3,
                    length: 4096,
                },
            },
        }
    },
    "125 ftruncate(fd: 3, length: 4096) = -1 (error)\n"
);

syscall_test!(
    parse_fchmod,
    {
        SyscallEvent {
            syscall_nr: SYS_fchmod,
            pid: 126,
            tid: 126,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                fchmod: FchmodData { fd: 3, mode: 0o644 },
            },
        }
    },
    "126 fchmod(fd: 3, mode: 0o644 (rw-r--r--)) = 0 (success)\n"
);
syscall_test!(
    parse_fchmod_error,
    {
        SyscallEvent {
            syscall_nr: SYS_fchmod,
            pid: 126,
            tid: 126,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                fchmod: FchmodData { fd: 3, mode: 0o644 },
            },
        }
    },
    "126 fchmod(fd: 3, mode: 0o644 (rw-r--r--)) = -1 (error)\n"
);
syscall_test!(
    parse_fchmod_mode_755,
    {
        SyscallEvent {
            syscall_nr: SYS_fchmod,
            pid: 126,
            tid: 126,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                fchmod: FchmodData { fd: 3, mode: 0o755 },
            },
        }
    },
    "126 fchmod(fd: 3, mode: 0o755 (rwxr-xr-x)) = 0 (success)\n"
);

syscall_test!(
    parse_fchmodat,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/testfile";
        pathname[0..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: SYS_fchmodat,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                fchmodat: FchmodatData {
                    dirfd: 3,
                    pathname,
                    mode: 0o755,
                    flags: 0,
                },
            },
        }
    },
    "1001 fchmodat(dirfd: 3, pathname: \"/tmp/testfile\", mode: 0o755 (rwxr-xr-x), flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_fchown,
    {
        SyscallEvent {
            syscall_nr: SYS_fchown,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                fchown: FchownData {
                    fd: 3,
                    uid: 1000,
                    gid: 1000,
                },
            },
        }
    },
    "1001 fchown(fd: 3, uid: 1000, gid: 1000) = 0 (success)\n"
);

syscall_test!(
    parse_fchownat,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/etc/passwd";
        pathname[0..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: SYS_fchownat,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                fchownat: FchownatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    uid: 1000,
                    gid: 1000,
                    flags: 0,
                },
            },
        }
    },
    "1001 fchownat(dirfd: AT_FDCWD, pathname: \"/etc/passwd\", uid: 1000, gid: 1000, flags: 0) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_chown,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/home/user";
        pathname[0..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_chown,
            pid: 2000,
            tid: 2001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                chown: pinchy_common::ChownData {
                    pathname,
                    uid: 1000,
                    gid: 1000,
                },
            },
        }
    },
    "2001 chown(pathname: \"/home/user\", uid: 1000, gid: 1000) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_lchown,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/var/log";
        pathname[0..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_lchown,
            pid: 3000,
            tid: 3001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                chown: pinchy_common::ChownData {
                    pathname,
                    uid: 2000,
                    gid: 2000,
                },
            },
        }
    },
    "3001 lchown(pathname: \"/var/log\", uid: 2000, gid: 2000) = 0 (success)\n"
);

syscall_test!(
    parse_truncate,
    {
        let path = b"/tmp/testfile\0";
        let mut pathname = [0u8; DATA_READ_SIZE];
        pathname[0..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: SYS_truncate,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                truncate: pinchy_common::TruncateData {
                    pathname,
                    length: 1024,
                },
            },
        }
    },
    "123 truncate(pathname: \"/tmp/testfile\", length: 1024) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_rename,
    {
        let mut oldpath = [0u8; SMALLISH_READ_SIZE];
        let mut newpath = [0u8; SMALLISH_READ_SIZE];
        oldpath[..10].copy_from_slice(b"/old/path\0");
        newpath[..10].copy_from_slice(b"/new/path\0");
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_rename,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rename: pinchy_common::RenameData { oldpath, newpath },
            },
        }
    },
    "1001 rename(oldpath: \"/old/path\", newpath: \"/new/path\") = 0 (success)\n"
);

syscall_test!(
    parse_renameat,
    {
        let mut oldpath = [0u8; SMALLISH_READ_SIZE];
        let mut newpath = [0u8; SMALLISH_READ_SIZE];
        oldpath[..10].copy_from_slice(b"/old/path\0");
        newpath[..10].copy_from_slice(b"/new/path\0");
        SyscallEvent {
            syscall_nr: SYS_renameat,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                renameat: RenameatData {
                    olddirfd: libc::AT_FDCWD,
                    oldpath,
                    newdirfd: libc::AT_FDCWD,
                    newpath,
                },
            },
        }
    },
    "1001 renameat(olddirfd: AT_FDCWD, oldpath: \"/old/path\", newdirfd: AT_FDCWD, newpath: \"/new/path\") = 0 (success)\n"
);

syscall_test!(
    parse_renameat2,
    {
        let mut oldpath = [0u8; SMALLISH_READ_SIZE];
        let mut newpath = [0u8; SMALLISH_READ_SIZE];
        oldpath[..10].copy_from_slice(b"/old/path\0");
        newpath[..10].copy_from_slice(b"/new/path\0");
        SyscallEvent {
            syscall_nr: SYS_renameat2,
            pid: 1000,
            tid: 1001,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                renameat2: Renameat2Data {
                    olddirfd: libc::AT_FDCWD,
                    oldpath,
                    newdirfd: libc::AT_FDCWD,
                    newpath,
                    flags: libc::RENAME_NOREPLACE,
                },
            },
        }
    },
    "1001 renameat2(olddirfd: AT_FDCWD, oldpath: \"/old/path\", newdirfd: AT_FDCWD, newpath: \"/new/path\", flags: 0x1 (RENAME_NOREPLACE)) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_rmdir,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/testdir\0";
        pathname[..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_rmdir,
            pid: 1,
            tid: 1,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                rmdir: pinchy_common::RmdirData { pathname },
            },
        }
    },
    "1 rmdir(pathname: \"/tmp/testdir\") = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_unlink,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/testfile\0";
        pathname[..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_unlink,
            pid: 200,
            tid: 201,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                unlink: pinchy_common::UnlinkData { pathname },
            },
        }
    },
    "201 unlink(pathname: \"/tmp/testfile\") = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_unlink_error,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/nonexistent\0";
        pathname[..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_unlink,
            pid: 300,
            tid: 301,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                unlink: pinchy_common::UnlinkData { pathname },
            },
        }
    },
    "301 unlink(pathname: \"/tmp/nonexistent\") = -1 (error)\n"
);

syscall_test!(
    parse_unlinkat,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/testdir\0";
        pathname[..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_unlinkat,
            pid: 400,
            tid: 401,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                unlinkat: pinchy_common::UnlinkatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    flags: libc::AT_REMOVEDIR,
                },
            },
        }
    },
    "401 unlinkat(dirfd: AT_FDCWD, pathname: \"/tmp/testdir\", flags: AT_EACCESS|AT_REMOVEDIR (0x200)) = 0 (success)\n"
);

syscall_test!(
    parse_unlinkat_error,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/nonexistent\0";
        pathname[..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_unlinkat,
            pid: 500,
            tid: 501,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                unlinkat: pinchy_common::UnlinkatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    flags: 0,
                },
            },
        }
    },
    "501 unlinkat(dirfd: AT_FDCWD, pathname: \"/tmp/nonexistent\", flags: 0) = -1 (error)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_symlink,
    {
        let mut target = [0u8; DATA_READ_SIZE];
        let mut linkpath = [0u8; DATA_READ_SIZE];
        let target_bytes = b"/target\0";
        let linkpath_bytes = b"/link\0";
        target[..target_bytes.len()].copy_from_slice(target_bytes);
        linkpath[..linkpath_bytes.len()].copy_from_slice(linkpath_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_symlink,
            pid: 600,
            tid: 601,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                symlink: pinchy_common::SymlinkData { target, linkpath },
            },
        }
    },
    "601 symlink(target: \"/target\", linkpath: \"/link\") = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_symlink_error,
    {
        let mut target = [0u8; DATA_READ_SIZE];
        let mut linkpath = [0u8; DATA_READ_SIZE];
        let target_bytes = b"/target\0";
        let linkpath_bytes = b"/link\0";
        target[..target_bytes.len()].copy_from_slice(target_bytes);
        linkpath[..linkpath_bytes.len()].copy_from_slice(linkpath_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_symlink,
            pid: 600,
            tid: 601,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                symlink: pinchy_common::SymlinkData { target, linkpath },
            },
        }
    },
    "601 symlink(target: \"/target\", linkpath: \"/link\") = -1 (error)\n"
);

syscall_test!(
    parse_symlinkat,
    {
        let mut target = [0u8; DATA_READ_SIZE];
        let mut linkpath = [0u8; DATA_READ_SIZE];
        let target_bytes = b"/target\0";
        let linkpath_bytes = b"/link\0";
        target[..target_bytes.len()].copy_from_slice(target_bytes);
        linkpath[..linkpath_bytes.len()].copy_from_slice(linkpath_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_symlinkat,
            pid: 700,
            tid: 701,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                symlinkat: pinchy_common::SymlinkatData {
                    target,
                    newdirfd: libc::AT_FDCWD,
                    linkpath,
                },
            },
        }
    },
    "701 symlinkat(target: \"/target\", newdirfd: AT_FDCWD, linkpath: \"/link\") = 0 (success)\n"
);

syscall_test!(
    parse_symlinkat_error,
    {
        let mut target = [0u8; DATA_READ_SIZE];
        let mut linkpath = [0u8; DATA_READ_SIZE];
        let target_bytes = b"/target\0";
        let linkpath_bytes = b"/link\0";
        target[..target_bytes.len()].copy_from_slice(target_bytes);
        linkpath[..linkpath_bytes.len()].copy_from_slice(linkpath_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_symlinkat,
            pid: 700,
            tid: 701,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                symlinkat: pinchy_common::SymlinkatData {
                    target,
                    newdirfd: libc::AT_FDCWD,
                    linkpath,
                },
            },
        }
    },
    "701 symlinkat(target: \"/target\", newdirfd: AT_FDCWD, linkpath: \"/link\") = -1 (error)\n"
);

syscall_test!(
    parse_acct,
    {
        let mut filename = [0u8; DATA_READ_SIZE];
        let path = b"/var/log/account\0";
        filename[..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: SYS_acct,
            pid: 800,
            tid: 801,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                acct: AcctData { filename },
            },
        }
    },
    "801 acct(filename: \"/var/log/account\") = 0 (success)\n"
);

syscall_test!(
    parse_acct_error,
    {
        let mut filename = [0u8; DATA_READ_SIZE];
        let path = b"/var/log/account\0";
        filename[..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: SYS_acct,
            pid: 900,
            tid: 901,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                acct: AcctData { filename },
            },
        }
    },
    "901 acct(filename: \"/var/log/account\") = -1 (error)\n"
);

syscall_test!(
    parse_statx_success,
    {
        use pinchy_common::{kernel_types::Statx, StatxData};
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_statx,
            pid: 42,
            tid: 42,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                statx: StatxData {
                    dirfd: 3,
                    pathname: {
                        let mut arr = [0u8; DATA_READ_SIZE];
                        let s = b"/tmp/testfile\0";
                        arr[..s.len()].copy_from_slice(s);
                        arr
                    },
                    flags: 0,
                    mask: 0xFFF,
                    statxbuf: 0x12345678,
                    statx: Statx {
                        stx_mask: 0xFFF,
                        stx_mode: libc::S_IFREG as u16 | 0o644,
                        stx_size: 98765,
                        stx_uid: 1000,
                        stx_gid: 1000,
                        stx_blocks: 20,
                        stx_blksize: 4096,
                        ..Default::default()
                    }
                },
            },
        }
    },
    "42 statx(dirfd: 3, pathname: \"/tmp/testfile\", flags: 0x0, mask: 0xfff, statxbuf: 0x12345678, struct statx: { mask: 0xfff, blksize: 4096, attributes: 0x0, nlink: 0, uid: 1000, gid: 1000, mode: 0100644, ino: 0, size: 98765, blocks: 20, attributes_mask: 0x0, atime: 0.0, btime: 0.0, ctime: 0.0, mtime: 0.0, rdev: 0:0, dev: 0:0 }) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_mknod_regular_file,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/testfile\0";
        pathname[..path.len()].copy_from_slice(path);
        SyscallEvent {
            syscall_nr: syscalls::SYS_mknod,
            pid: 100,
            tid: 100,
            return_value: 0,
            data: SyscallEventData {
                mknod: pinchy_common::MknodData {
                    pathname,
                    mode: libc::S_IFREG | 0o644,
                    dev: 0,
                },
            },
        }
    },
    "100 mknod(pathname: \"/tmp/testfile\", mode: 0o644 (rw-r--r--) (S_IFREG), dev: 0) = 0 (success)\n"
);

syscall_test!(
    parse_mknodat_regular_file,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/testfile\0";
        pathname[..path.len()].copy_from_slice(path);

        SyscallEvent {
            syscall_nr: syscalls::SYS_mknodat,
            pid: 200,
            tid: 200,
            return_value: 0,
            data: SyscallEventData {
                mknodat: MknodatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    mode: libc::S_IFREG | 0o644,
                    dev: 0,
                },
            },
        }
    },
    "200 mknodat(dirfd: AT_FDCWD, pathname: \"/tmp/testfile\", mode: 0o644 (rw-r--r--) (S_IFREG), dev: 0) = 0 (success)\n"
);

syscall_test!(
    parse_mknodat_device_file,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/dev/mydevice\0";
        pathname[..path.len()].copy_from_slice(path);

        SyscallEvent {
            syscall_nr: syscalls::SYS_mknodat,
            pid: 201,
            tid: 201,
            return_value: 0,
            data: SyscallEventData {
                mknodat: MknodatData {
                    dirfd: 5,
                    pathname,
                    mode: libc::S_IFCHR | 0o666,
                    dev: (1 << 8) | 5, // major=1, minor=5
                },
            },
        }
    },
    "201 mknodat(dirfd: 5, pathname: \"/dev/mydevice\", mode: 0o666 (rw-rw-rw-) (S_IFCHR), dev: 1:5) = 0 (success)\n"
);

syscall_test!(
    parse_mknodat_fifo,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/myfifo\0";
        pathname[..path.len()].copy_from_slice(path);

        SyscallEvent {
            syscall_nr: syscalls::SYS_mknodat,
            pid: 202,
            tid: 202,
            return_value: 0,
            data: SyscallEventData {
                mknodat: MknodatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    mode: libc::S_IFIFO | 0o600,
                    dev: 0,
                },
            },
        }
    },
    "202 mknodat(dirfd: AT_FDCWD, pathname: \"/tmp/myfifo\", mode: 0o600 (rw-------) (S_IFIFO), dev: 0) = 0 (success)\n"
);

syscall_test!(
    parse_mknodat_error,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/testfile\0";
        pathname[..path.len()].copy_from_slice(path);

        SyscallEvent {
            syscall_nr: syscalls::SYS_mknodat,
            pid: 203,
            tid: 203,
            return_value: -1,
            data: SyscallEventData {
                mknodat: MknodatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    mode: libc::S_IFREG | 0o644,
                    dev: 0,
                },
            },
        }
    },
    "203 mknodat(dirfd: AT_FDCWD, pathname: \"/tmp/testfile\", mode: 0o644 (rw-r--r--) (S_IFREG), dev: 0) = -1 (error)\n"
);

// Mount management syscalls tests

syscall_test!(
    parse_pivot_root,
    {
        use pinchy_common::PivotRootData;
        let mut new_root = [0u8; DATA_READ_SIZE];
        let mut put_old = [0u8; DATA_READ_SIZE];
        let new_root_bytes = b"/mnt/root\0";
        let put_old_bytes = b"/mnt/old\0";
        new_root[..new_root_bytes.len()].copy_from_slice(new_root_bytes);
        put_old[..put_old_bytes.len()].copy_from_slice(put_old_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_pivot_root,
            pid: 1000,
            tid: 1000,
            return_value: 0,
            data: SyscallEventData {
                pivot_root: PivotRootData { new_root, put_old },
            },
        }
    },
    "1000 pivot_root(new_root: \"/mnt/root\", put_old: \"/mnt/old\") = 0 (success)\n"
);

syscall_test!(
    parse_pivot_root_error,
    {
        use pinchy_common::PivotRootData;
        let mut new_root = [0u8; DATA_READ_SIZE];
        let mut put_old = [0u8; DATA_READ_SIZE];
        let new_root_bytes = b"/mnt/root\0";
        let put_old_bytes = b"/mnt/old\0";
        new_root[..new_root_bytes.len()].copy_from_slice(new_root_bytes);
        put_old[..put_old_bytes.len()].copy_from_slice(put_old_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_pivot_root,
            pid: 1001,
            tid: 1001,
            return_value: -1,
            data: SyscallEventData {
                pivot_root: PivotRootData { new_root, put_old },
            },
        }
    },
    "1001 pivot_root(new_root: \"/mnt/root\", put_old: \"/mnt/old\") = -1 (error)\n"
);

syscall_test!(
    parse_chroot,
    {
        use pinchy_common::ChrootData;
        let mut path = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/new/root\0";
        path[..path_bytes.len()].copy_from_slice(path_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_chroot,
            pid: 1002,
            tid: 1002,
            return_value: 0,
            data: SyscallEventData {
                chroot: ChrootData { path },
            },
        }
    },
    "1002 chroot(path: \"/new/root\") = 0 (success)\n"
);

syscall_test!(
    parse_chroot_error,
    {
        use pinchy_common::ChrootData;
        let mut path = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/bad/path\0";
        path[..path_bytes.len()].copy_from_slice(path_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_chroot,
            pid: 1003,
            tid: 1003,
            return_value: -1,
            data: SyscallEventData {
                chroot: ChrootData { path },
            },
        }
    },
    "1003 chroot(path: \"/bad/path\") = -1 (error)\n"
);

syscall_test!(
    parse_open_tree,
    {
        use pinchy_common::OpenTreeData;
        let mut pathname = [0u8; DATA_READ_SIZE];
        let pathname_bytes = b"/mnt/source\0";
        pathname[..pathname_bytes.len()].copy_from_slice(pathname_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_open_tree,
            pid: 1004,
            tid: 1004,
            return_value: 5,
            data: SyscallEventData {
                open_tree: OpenTreeData {
                    dfd: libc::AT_FDCWD,
                    pathname,
                    flags: 1, // OPEN_TREE_CLONE
                },
            },
        }
    },
    "1004 open_tree(dfd: AT_FDCWD, pathname: \"/mnt/source\", flags: 0x1 (OPEN_TREE_CLONE)) = 5 (fd)\n"
);

syscall_test!(
    parse_mount,
    {
        use pinchy_common::MountData;
        let mut source = [0u8; DATA_READ_SIZE];
        let mut target = [0u8; DATA_READ_SIZE];
        let mut filesystemtype = [0u8; pinchy_common::SMALL_READ_SIZE];
        let source_bytes = b"/dev/sda1\0";
        let target_bytes = b"/mnt/disk\0";
        let fs_bytes = b"ext4\0";
        source[..source_bytes.len()].copy_from_slice(source_bytes);
        target[..target_bytes.len()].copy_from_slice(target_bytes);
        filesystemtype[..fs_bytes.len()].copy_from_slice(fs_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_mount,
            pid: 1005,
            tid: 1005,
            return_value: 0,
            data: SyscallEventData {
                mount: MountData {
                    source,
                    target,
                    filesystemtype,
                    mountflags: libc::MS_RDONLY,
                    data: 0,
                },
            },
        }
    },
    "1005 mount(source: \"/dev/sda1\", target: \"/mnt/disk\", filesystemtype: \"ext4\", mountflags: 0x1 (ST_RDONLY), data: NULL) = 0 (success)\n"
);

syscall_test!(
    parse_mount_with_data,
    {
        use pinchy_common::MountData;
        let mut source = [0u8; DATA_READ_SIZE];
        let mut target = [0u8; DATA_READ_SIZE];
        let mut filesystemtype = [0u8; pinchy_common::SMALL_READ_SIZE];
        let source_bytes = b"/dev/sdb2\0";
        let target_bytes = b"/mnt/test\0";
        let fs_bytes = b"ext4\0";
        source[..source_bytes.len()].copy_from_slice(source_bytes);
        target[..target_bytes.len()].copy_from_slice(target_bytes);
        filesystemtype[..fs_bytes.len()].copy_from_slice(fs_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_mount,
            pid: 1006,
            tid: 1006,
            return_value: 0,
            data: SyscallEventData {
                mount: MountData {
                    source,
                    target,
                    filesystemtype,
                    mountflags: libc::MS_NOSUID | libc::MS_NODEV,
                    data: 0x12345678,
                },
            },
        }
    },
    "1006 mount(source: \"/dev/sdb2\", target: \"/mnt/test\", filesystemtype: \"ext4\", mountflags: 0x6 (ST_NOSUID|ST_NODEV), data: 0x12345678) = 0 (success)\n"
);

syscall_test!(
    parse_mount_null_source,
    {
        use pinchy_common::MountData;
        let source = [0u8; DATA_READ_SIZE];
        let mut target = [0u8; DATA_READ_SIZE];
        let mut filesystemtype = [0u8; pinchy_common::SMALL_READ_SIZE];
        // source is NULL (first byte is 0)
        let target_bytes = b"/proc\0";
        let fs_bytes = b"proc\0";
        target[..target_bytes.len()].copy_from_slice(target_bytes);
        filesystemtype[..fs_bytes.len()].copy_from_slice(fs_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_mount,
            pid: 1007,
            tid: 1007,
            return_value: 0,
            data: SyscallEventData {
                mount: MountData {
                    source,
                    target,
                    filesystemtype,
                    mountflags: 0,
                    data: 0,
                },
            },
        }
    },
    "1007 mount(source: NULL, target: \"/proc\", filesystemtype: \"proc\", mountflags: 0x0, data: NULL) = 0 (success)\n"
);

syscall_test!(
    parse_umount2,
    {
        use pinchy_common::Umount2Data;
        let mut target = [0u8; DATA_READ_SIZE];
        let target_bytes = b"/mnt/disk\0";
        target[..target_bytes.len()].copy_from_slice(target_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_umount2,
            pid: 1008,
            tid: 1008,
            return_value: 0,
            data: SyscallEventData {
                umount2: Umount2Data {
                    target,
                    flags: libc::MNT_FORCE,
                },
            },
        }
    },
    "1008 umount2(target: \"/mnt/disk\", flags: 0x1 (MNT_FORCE)) = 0 (success)\n"
);

syscall_test!(
    parse_umount2_detach,
    {
        use pinchy_common::Umount2Data;
        let mut target = [0u8; DATA_READ_SIZE];
        let target_bytes = b"/mnt/test\0";
        target[..target_bytes.len()].copy_from_slice(target_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_umount2,
            pid: 1009,
            tid: 1009,
            return_value: 0,
            data: SyscallEventData {
                umount2: Umount2Data {
                    target,
                    flags: libc::MNT_DETACH,
                },
            },
        }
    },
    "1009 umount2(target: \"/mnt/test\", flags: 0x2 (MNT_DETACH)) = 0 (success)\n"
);

syscall_test!(
    parse_mount_setattr,
    {
        use pinchy_common::{MountSetattrData, kernel_types::MountAttr};
        let mut path = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/mnt/test\0";
        path[..path_bytes.len()].copy_from_slice(path_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_mount_setattr,
            pid: 1010,
            tid: 1010,
            return_value: 0,
            data: SyscallEventData {
                mount_setattr: MountSetattrData {
                    dfd: libc::AT_FDCWD,
                    path,
                    flags: 0x8000, // AT_RECURSIVE
                    size: std::mem::size_of::<MountAttr>(),
                    has_attr: true,
                    attr: MountAttr {
                        attr_set: 0x1 | 0x2, // RDONLY|NOSUID
                        attr_clr: 0x4,       // NODEV
                        propagation: libc::MS_SHARED,
                        userns_fd: 42,
                    },
                },
            },
        }
    },
    "1010 mount_setattr(dfd: AT_FDCWD, path: \"/mnt/test\", flags: 0x8000 (AT_RECURSIVE), mount_attr: { attr_set: 0x3 (RDONLY|NOSUID), attr_clr: 0x4 (NODEV), propagation: MS_SHARED, userns_fd: 42 }, size: 32) = 0 (success)\n"
);

syscall_test!(
    parse_move_mount,
    {
        use pinchy_common::MoveMountData;
        let mut from_pathname = [0u8; DATA_READ_SIZE];
        let mut to_pathname = [0u8; DATA_READ_SIZE];
        let from_bytes = b"/mnt/source\0";
        let to_bytes = b"/mnt/target\0";
        from_pathname[..from_bytes.len()].copy_from_slice(from_bytes);
        to_pathname[..to_bytes.len()].copy_from_slice(to_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_move_mount,
            pid: 1011,
            tid: 1011,
            return_value: 0,
            data: SyscallEventData {
                move_mount: MoveMountData {
                    from_dfd: libc::AT_FDCWD,
                    from_pathname,
                    to_dfd: libc::AT_FDCWD,
                    to_pathname,
                    flags: 0x00000001, // MOVE_MOUNT_F_SYMLINKS
                },
            },
        }
    },
    "1011 move_mount(from_dfd: AT_FDCWD, from_pathname: \"/mnt/source\", to_dfd: AT_FDCWD, to_pathname: \"/mnt/target\", flags: 0x1 (MOVE_MOUNT_F_SYMLINKS)) = 0 (success)\n"
);

syscall_test!(
    parse_move_mount_error,
    {
        use pinchy_common::MoveMountData;
        let mut from_pathname = [0u8; DATA_READ_SIZE];
        let mut to_pathname = [0u8; DATA_READ_SIZE];
        let from_bytes = b"/mnt/source\0";
        let to_bytes = b"/mnt/target\0";
        from_pathname[..from_bytes.len()].copy_from_slice(from_bytes);
        to_pathname[..to_bytes.len()].copy_from_slice(to_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_move_mount,
            pid: 1012,
            tid: 1012,
            return_value: -1,
            data: SyscallEventData {
                move_mount: MoveMountData {
                    from_dfd: 5,
                    from_pathname,
                    to_dfd: 7,
                    to_pathname,
                    flags: 0,
                },
            },
        }
    },
    "1012 move_mount(from_dfd: 5, from_pathname: \"/mnt/source\", to_dfd: 7, to_pathname: \"/mnt/target\", flags: 0x0) = -1 (error)\n"
);

syscall_test!(
    parse_swapon_basic,
    {
        use pinchy_common::SwaponData;
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/tmp/swapfile\0";
        pathname[..path_bytes.len()].copy_from_slice(path_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_swapon,
            pid: 1013,
            tid: 1013,
            return_value: 0,
            data: SyscallEventData {
                swapon: SwaponData { pathname, flags: 0 },
            },
        }
    },
    "1013 swapon(pathname: \"/tmp/swapfile\", flags: 0x0) = 0 (success)\n"
);

syscall_test!(
    parse_swapon_with_flags,
    {
        use pinchy_common::SwaponData;
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/dev/sda2\0";
        pathname[..path_bytes.len()].copy_from_slice(path_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_swapon,
            pid: 1014,
            tid: 1014,
            return_value: 0,
            data: SyscallEventData {
                swapon: SwaponData {
                    pathname,
                    flags: 0x8005, // SWAP_FLAG_PREFER | priority 5
                },
            },
        }
    },
    "1014 swapon(pathname: \"/dev/sda2\", flags: 0x8005 (SWAP_FLAG_PREFER|PRIO=5)) = 0 (success)\n"
);

syscall_test!(
    parse_swapon_error,
    {
        use pinchy_common::SwaponData;
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/tmp/badfile\0";
        pathname[..path_bytes.len()].copy_from_slice(path_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_swapon,
            pid: 1015,
            tid: 1015,
            return_value: -1,
            data: SyscallEventData {
                swapon: SwaponData {
                    pathname,
                    flags: 0x10000, // SWAP_FLAG_DISCARD
                },
            },
        }
    },
    "1015 swapon(pathname: \"/tmp/badfile\", flags: 0x10000 (SWAP_FLAG_DISCARD)) = -1 (error)\n"
);

syscall_test!(
    parse_swapoff_success,
    {
        use pinchy_common::SwapoffData;
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/tmp/swapfile\0";
        pathname[..path_bytes.len()].copy_from_slice(path_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_swapoff,
            pid: 1016,
            tid: 1016,
            return_value: 0,
            data: SyscallEventData {
                swapoff: SwapoffData { pathname },
            },
        }
    },
    "1016 swapoff(pathname: \"/tmp/swapfile\") = 0 (success)\n"
);

syscall_test!(
    parse_swapoff_error,
    {
        use pinchy_common::SwapoffData;
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/dev/sda2\0";
        pathname[..path_bytes.len()].copy_from_slice(path_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_swapoff,
            pid: 1017,
            tid: 1017,
            return_value: -1,
            data: SyscallEventData {
                swapoff: SwapoffData { pathname },
            },
        }
    },
    "1017 swapoff(pathname: \"/dev/sda2\") = -1 (error)\n"
);

syscall_test!(
    parse_fstatfs_success,
    {
        use pinchy_common::{kernel_types::Statfs, FstatfsData};
        let mut event = SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_fstatfs,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: SyscallEventData {
                fstatfs: FstatfsData {
                    fd: 5,
                    statfs: Statfs::default(),
                },
            },
        };
        let statfs_data = unsafe { &mut event.data.fstatfs.statfs };
        statfs_data.f_type = 0xef53; // ext2/ext3/ext4
        statfs_data.f_bsize = 4096;
        statfs_data.f_blocks = 1048576;
        statfs_data.f_bfree = 524288;
        statfs_data.f_bavail = 524288;
        event
    },
    "123 fstatfs(fd: 5, buf: { type: EXT4_SUPER_MAGIC (0xef53), block_size: 4096, blocks: 1048576, blocks_free: 524288, blocks_available: 524288, files: 0, files_free: 0, fsid: [0, 0], name_max: 0, fragment_size: 0, mount_flags: 0x0 }) = 0 (success)\n"
);

syscall_test!(
    parse_fsopen_success,
    {
        use pinchy_common::FsopenData;
        let mut fsname = [0u8; DATA_READ_SIZE];
        let name_bytes = b"ext4\0";
        fsname[..name_bytes.len()].copy_from_slice(name_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_fsopen,
            pid: 456,
            tid: 456,
            return_value: 7,
            data: SyscallEventData {
                fsopen: FsopenData { fsname, flags: 0 },
            },
        }
    },
    "456 fsopen(fsname: \"ext4\", flags: 0) = 7 (fd)\n"
);

syscall_test!(
    parse_fsconfig_success,
    {
        use pinchy_common::FsconfigData;
        let mut key = [0u8; MEDIUM_READ_SIZE];
        let mut value = [0u8; DATA_READ_SIZE];
        let key_bytes = b"source\0";
        let value_bytes = b"/dev/sda1\0";
        key[..key_bytes.len()].copy_from_slice(key_bytes);
        value[..value_bytes.len()].copy_from_slice(value_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_fsconfig,
            pid: 789,
            tid: 789,
            return_value: 0,
            data: SyscallEventData {
                fsconfig: FsconfigData {
                    fd: 7,
                    cmd: 0,
                    key,
                    value,
                    aux: 0,
                },
            },
        }
    },
    "789 fsconfig(fd: 7, cmd: FSCONFIG_SET_FLAG, key: \"source\", value: \"/dev/sda1\", aux: 0) = 0 (success)\n"
);

syscall_test!(
    parse_fsmount_success,
    {
        use pinchy_common::FsmountData;
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_fsmount,
            pid: 101,
            tid: 101,
            return_value: 8,
            data: SyscallEventData {
                fsmount: FsmountData {
                    fd: 7,
                    flags: 0,
                    attr_flags: 0,
                },
            },
        }
    },
    "101 fsmount(fd: 7, flags: 0, attr_flags: 0) = 8 (fd)\n"
);

syscall_test!(
    parse_fspick_success,
    {
        use pinchy_common::FspickData;
        let mut path = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/mnt/test\0";
        path[..path_bytes.len()].copy_from_slice(path_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_fspick,
            pid: 202,
            tid: 202,
            return_value: 9,
            data: SyscallEventData {
                fspick: FspickData {
                    dfd: -100, // AT_FDCWD
                    path,
                    flags: 0,
                },
            },
        }
    },
    "202 fspick(dfd: AT_FDCWD, path: \"/mnt/test\", flags: 0) = 9 (fd)\n"
);

syscall_test!(
    parse_fsopen_with_flags,
    {
        use pinchy_common::FsopenData;

        use crate::format_helpers::fs_constants;
        let mut fsname = [0u8; DATA_READ_SIZE];
        let name_bytes = b"ext4\0";
        fsname[..name_bytes.len()].copy_from_slice(name_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_fsopen,
            pid: 456,
            tid: 456,
            return_value: 7,
            data: SyscallEventData {
                fsopen: FsopenData {
                    fsname,
                    flags: fs_constants::FSOPEN_CLOEXEC,
                },
            },
        }
    },
    "456 fsopen(fsname: \"ext4\", flags: 0x1 (FSOPEN_CLOEXEC)) = 7 (fd)\n"
);

syscall_test!(
    parse_fsconfig_with_string_cmd,
    {
        use pinchy_common::FsconfigData;
        use crate::format_helpers::fs_constants;
        let mut key = [0u8; MEDIUM_READ_SIZE];
        let mut value = [0u8; DATA_READ_SIZE];
        let key_bytes = b"source\0";
        let value_bytes = b"/dev/sda1\0";
        key[..key_bytes.len()].copy_from_slice(key_bytes);
        value[..value_bytes.len()].copy_from_slice(value_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_fsconfig,
            pid: 789,
            tid: 789,
            return_value: 0,
            data: SyscallEventData {
                fsconfig: FsconfigData {
                    fd: 7,
                    cmd: fs_constants::FSCONFIG_SET_STRING,
                    key,
                    value,
                    aux: 0,
                },
            },
        }
    },
    "789 fsconfig(fd: 7, cmd: FSCONFIG_SET_STRING, key: \"source\", value: \"/dev/sda1\", aux: 0) = 0 (success)\n"
);

syscall_test!(
    parse_fsmount_with_flags,
    {
        use pinchy_common::FsmountData;
        use crate::format_helpers::fs_constants;
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_fsmount,
            pid: 101,
            tid: 101,
            return_value: 8,
            data: SyscallEventData {
                fsmount: FsmountData {
                    fd: 7,
                    flags: fs_constants::FSMOUNT_CLOEXEC,
                    attr_flags: libc::MOUNT_ATTR_RDONLY as u32 | libc::MOUNT_ATTR_NOSUID as u32,
                },
            },
        }
    },
    "101 fsmount(fd: 7, flags: 0x1 (FSMOUNT_CLOEXEC), attr_flags: 0x3 (MOUNT_ATTR_RDONLY|MOUNT_ATTR_NOSUID)) = 8 (fd)\n"
);

syscall_test!(
    parse_fspick_with_flags,
    {
        use pinchy_common::FspickData;
        use crate::format_helpers::fs_constants;
        let mut path = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/mnt/test\0";
        path[..path_bytes.len()].copy_from_slice(path_bytes);
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_fspick,
            pid: 202,
            tid: 202,
            return_value: 9,
            data: SyscallEventData {
                fspick: FspickData {
                    dfd: -100, // AT_FDCWD
                    path,
                    flags: fs_constants::FSPICK_CLOEXEC | fs_constants::FSPICK_SYMLINK_NOFOLLOW,
                },
            },
        }
    },
    "202 fspick(dfd: AT_FDCWD, path: \"/mnt/test\", flags: 0x3 (FSPICK_CLOEXEC|FSPICK_SYMLINK_NOFOLLOW)) = 9 (fd)\n"
);

syscall_test!(
    parse_fallocate_default_mode,
    {
        SyscallEvent {
            syscall_nr: SYS_fallocate,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: SyscallEventData {
                fallocate: FallocateData {
                    fd: 5,
                    mode: 0,
                    offset: 1024,
                    size: 4096,
                },
            },
        }
    },
    "123 fallocate(fd: 5, mode: 0, offset: 1024, size: 4096) = 0 (success)\n"
);

syscall_test!(
    parse_fallocate_keep_size,
    {
        SyscallEvent {
            syscall_nr: SYS_fallocate,
            pid: 456,
            tid: 456,
            return_value: 0,
            data: SyscallEventData {
                fallocate: FallocateData {
                    fd: 8,
                    mode: libc::FALLOC_FL_KEEP_SIZE,
                    offset: 0,
                    size: 2048,
                },
            },
        }
    },
    "456 fallocate(fd: 8, mode: 0x1 (FALLOC_FL_KEEP_SIZE), offset: 0, size: 2048) = 0 (success)\n"
);

syscall_test!(
    parse_fallocate_punch_hole,
    {
        SyscallEvent {
            syscall_nr: SYS_fallocate,
            pid: 789,
            tid: 789,
            return_value: 0,
            data: SyscallEventData {
                fallocate: FallocateData {
                    fd: 12,
                    mode: libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                    offset: 512,
                    size: 1024,
                },
            },
        }
    },
    "789 fallocate(fd: 12, mode: 0x3 (FALLOC_FL_KEEP_SIZE|FALLOC_FL_PUNCH_HOLE), offset: 512, size: 1024) = 0 (success)\n"
);

syscall_test!(
    parse_fallocate_error,
    {
        SyscallEvent {
            syscall_nr: SYS_fallocate,
            pid: 999,
            tid: 999,
            return_value: -1,
            data: SyscallEventData {
                fallocate: FallocateData {
                    fd: 3,
                    mode: libc::FALLOC_FL_ZERO_RANGE,
                    offset: 100,
                    size: 500,
                },
            },
        }
    },
    "999 fallocate(fd: 3, mode: 0x10 (FALLOC_FL_ZERO_RANGE), offset: 100, size: 500) = -1 (error)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_link,
    {
        let mut oldpath = [0u8; SMALLISH_READ_SIZE];
        let mut newpath = [0u8; SMALLISH_READ_SIZE];
        let oldpath_bytes = b"/old/file\0";
        let newpath_bytes = b"/new/link\0";
        oldpath[..oldpath_bytes.len()].copy_from_slice(oldpath_bytes);
        newpath[..newpath_bytes.len()].copy_from_slice(newpath_bytes);
        SyscallEvent {
            syscall_nr: SYS_link,
            pid: 800,
            tid: 801,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                link: LinkData { oldpath, newpath },
            },
        }
    },
    "801 link(oldpath: \"/old/file\", newpath: \"/new/link\") = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_link_error,
    {
        let mut oldpath = [0u8; SMALLISH_READ_SIZE];
        let mut newpath = [0u8; SMALLISH_READ_SIZE];
        let oldpath_bytes = b"/nonexistent\0";
        let newpath_bytes = b"/link\0";
        oldpath[..oldpath_bytes.len()].copy_from_slice(oldpath_bytes);
        newpath[..newpath_bytes.len()].copy_from_slice(newpath_bytes);
        SyscallEvent {
            syscall_nr: SYS_link,
            pid: 800,
            tid: 801,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                link: LinkData { oldpath, newpath },
            },
        }
    },
    "801 link(oldpath: \"/nonexistent\", newpath: \"/link\") = -1 (error)\n"
);

syscall_test!(
    parse_linkat,
    {
        let mut oldpath = [0u8; SMALLISH_READ_SIZE];
        let mut newpath = [0u8; SMALLISH_READ_SIZE];
        let oldpath_bytes = b"file.txt\0";
        let newpath_bytes = b"link.txt\0";
        oldpath[..oldpath_bytes.len()].copy_from_slice(oldpath_bytes);
        newpath[..newpath_bytes.len()].copy_from_slice(newpath_bytes);
        SyscallEvent {
            syscall_nr: SYS_linkat,
            pid: 900,
            tid: 901,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                linkat: LinkatData {
                    olddirfd: libc::AT_FDCWD,
                    oldpath,
                    newdirfd: libc::AT_FDCWD,
                    newpath,
                    flags: 0,
                },
            },
        }
    },
    "901 linkat(olddirfd: AT_FDCWD, oldpath: \"file.txt\", newdirfd: AT_FDCWD, newpath: \"link.txt\", flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_linkat_with_flags,
    {
        let mut oldpath = [0u8; SMALLISH_READ_SIZE];
        let mut newpath = [0u8; SMALLISH_READ_SIZE];
        let oldpath_bytes = b"symlink\0";
        let newpath_bytes = b"hardlink\0";
        oldpath[..oldpath_bytes.len()].copy_from_slice(oldpath_bytes);
        newpath[..newpath_bytes.len()].copy_from_slice(newpath_bytes);
        SyscallEvent {
            syscall_nr: SYS_linkat,
            pid: 950,
            tid: 951,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                linkat: LinkatData {
                    olddirfd: 5,
                    oldpath,
                    newdirfd: 6,
                    newpath,
                    flags: libc::AT_SYMLINK_FOLLOW,
                },
            },
        }
    },
    "951 linkat(olddirfd: 5, oldpath: \"symlink\", newdirfd: 6, newpath: \"hardlink\", flags: AT_SYMLINK_FOLLOW (0x400)) = 0 (success)\n"
);

syscall_test!(
    parse_linkat_error,
    {
        let mut oldpath = [0u8; SMALLISH_READ_SIZE];
        let mut newpath = [0u8; SMALLISH_READ_SIZE];
        let oldpath_bytes = b"nonexistent\0";
        let newpath_bytes = b"link\0";
        oldpath[..oldpath_bytes.len()].copy_from_slice(oldpath_bytes);
        newpath[..newpath_bytes.len()].copy_from_slice(newpath_bytes);
        SyscallEvent {
            syscall_nr: SYS_linkat,
            pid: 900,
            tid: 901,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                linkat: LinkatData {
                    olddirfd: libc::AT_FDCWD,
                    oldpath,
                    newdirfd: libc::AT_FDCWD,
                    newpath,
                    flags: 0,
                },
            },
        }
    },
    "901 linkat(olddirfd: AT_FDCWD, oldpath: \"nonexistent\", newdirfd: AT_FDCWD, newpath: \"link\", flags: 0) = -1 (error)\n"
);

// Use fanotify constants directly from libc

syscall_test!(
    parse_fanotify_init_success,
    {
        SyscallEvent {
            syscall_nr: SYS_fanotify_init,
            pid: 9000,
            tid: 9000,
            return_value: 3,
            data: SyscallEventData {
                fanotify_init: FanotifyInitData {
                    flags: 0,
                    event_f_flags: libc::O_RDONLY as u32,
                },
            },
        }
    },
    "9000 fanotify_init(flags: 0, event_f_flags: 0x0 (O_RDONLY)) = 3 (fd)\n"
);

syscall_test!(
    parse_fanotify_init_with_flags,
    {
        SyscallEvent {
            syscall_nr: SYS_fanotify_init,
            pid: 9001,
            tid: 9001,
            return_value: 4,
            data: SyscallEventData {
                fanotify_init: FanotifyInitData {
                    flags: libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
                    event_f_flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u32,
                },
            },
        }
    },
    "9001 fanotify_init(flags: 0x3 (CLASS_NOTIF|CLOEXEC|NONBLOCK), event_f_flags: 0x80800 (O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NDELAY)) = 4 (fd)\n"
);

syscall_test!(
    parse_fanotify_init_error,
    {
        SyscallEvent {
            syscall_nr: SYS_fanotify_init,
            pid: 9002,
            tid: 9002,
            return_value: -1,
            data: SyscallEventData {
                fanotify_init: FanotifyInitData {
                    flags: 0,
                    event_f_flags: libc::O_RDONLY as u32,
                },
            },
        }
    },
    "9002 fanotify_init(flags: 0, event_f_flags: 0x0 (O_RDONLY)) = -1 (error)\n"
);

syscall_test!(
    parse_fanotify_mark_success,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/watch";
        pathname[..path.len()].copy_from_slice(path);

        SyscallEvent {
            syscall_nr: SYS_fanotify_mark,
            pid: 9100,
            tid: 9100,
            return_value: 0,
            data: SyscallEventData {
                fanotify_mark: FanotifyMarkData {
                    fanotify_fd: 3,
                    flags: libc::FAN_MARK_ADD,
                    mask: libc::FAN_ACCESS | libc::FAN_MODIFY,
                    dirfd: libc::AT_FDCWD,
                    pathname,
                },
            },
        }
    },
    "9100 fanotify_mark(fanotify_fd: 3, flags: 0x1 (INODE|ADD), mask: 0x3 (ACCESS|MODIFY), dirfd: AT_FDCWD, pathname: \"/tmp/watch\") = 0 (success)\n"
);

syscall_test!(
    parse_fanotify_mark_with_dirfd,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"subdir/file.txt";
        pathname[..path.len()].copy_from_slice(path);

        SyscallEvent {
            syscall_nr: SYS_fanotify_mark,
            pid: 9101,
            tid: 9101,
            return_value: 0,
            data: SyscallEventData {
                fanotify_mark: FanotifyMarkData {
                    fanotify_fd: 4,
                    flags: libc::FAN_MARK_ADD | libc::FAN_MARK_DONT_FOLLOW,
                    mask: libc::FAN_OPEN | libc::FAN_CLOSE_WRITE,
                    dirfd: 5,
                    pathname,
                },
            },
        }
    },
    "9101 fanotify_mark(fanotify_fd: 4, flags: 0x5 (INODE|ADD|DONT_FOLLOW), mask: 0x28 (CLOSE_WRITE|OPEN), dirfd: 5, pathname: \"subdir/file.txt\") = 0 (success)\n"
);

syscall_test!(
    parse_fanotify_mark_error,
    {
        let pathname = [0u8; DATA_READ_SIZE];

        SyscallEvent {
            syscall_nr: SYS_fanotify_mark,
            pid: 9102,
            tid: 9102,
            return_value: -9,
            data: SyscallEventData {
                fanotify_mark: FanotifyMarkData {
                    fanotify_fd: 999,
                    flags: libc::FAN_MARK_ADD,
                    mask: libc::FAN_ACCESS,
                    dirfd: libc::AT_FDCWD,
                    pathname,
                },
            },
        }
    },
    "9102 fanotify_mark(fanotify_fd: 999, flags: 0x1 (INODE|ADD), mask: 0x1 (ACCESS), dirfd: AT_FDCWD, pathname: (null)) = -9 (error)\n"
);

syscall_test!(
    parse_name_to_handle_at_success,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let p = b"/tmp/test_file.txt";
        pathname[..p.len()].copy_from_slice(p);

        SyscallEvent {
            syscall_nr: SYS_name_to_handle_at,
            pid: 9200,
            tid: 9200,
            return_value: 0,
            data: SyscallEventData {
                name_to_handle_at: NameToHandleAtData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    handle: 0x7fff12345678,
                    mount_id: 0x7fff87654321,
                    flags: libc::AT_SYMLINK_FOLLOW,
                },
            },
        }
    },
    "9200 name_to_handle_at(dirfd: AT_FDCWD, pathname: \"/tmp/test_file.txt\", handle: 0x7fff12345678, mount_id: 0x7fff87654321, flags: AT_SYMLINK_FOLLOW (0x400)) = 0 (success)\n"
);

syscall_test!(
    parse_name_to_handle_at_empty_path,
    {
        let pathname = [0u8; DATA_READ_SIZE];

        SyscallEvent {
            syscall_nr: SYS_name_to_handle_at,
            pid: 9201,
            tid: 9201,
            return_value: 0,
            data: SyscallEventData {
                name_to_handle_at: NameToHandleAtData {
                    dirfd: 5,
                    pathname,
                    handle: 0x7fff00000000,
                    mount_id: 0x7fff11111111,
                    flags: libc::AT_EMPTY_PATH,
                },
            },
        }
    },
    "9201 name_to_handle_at(dirfd: 5, pathname: (null), handle: 0x7fff00000000, mount_id: 0x7fff11111111, flags: AT_EMPTY_PATH (0x1000)) = 0 (success)\n"
);

syscall_test!(
    parse_name_to_handle_at_error,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let p = b"/nonexistent";
        pathname[..p.len()].copy_from_slice(p);

        SyscallEvent {
            syscall_nr: SYS_name_to_handle_at,
            pid: 9202,
            tid: 9202,
            return_value: -2,
            data: SyscallEventData {
                name_to_handle_at: NameToHandleAtData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    handle: 0,
                    mount_id: 0,
                    flags: 0,
                },
            },
        }
    },
    "9202 name_to_handle_at(dirfd: AT_FDCWD, pathname: \"/nonexistent\", handle: 0x0, mount_id: 0x0, flags: 0) = -2 (error)\n"
);

syscall_test!(
    parse_open_by_handle_at_success,
    {
        SyscallEvent {
            syscall_nr: SYS_open_by_handle_at,
            pid: 9300,
            tid: 9300,
            return_value: 7,
            data: SyscallEventData {
                open_by_handle_at: OpenByHandleAtData {
                    mount_fd: 3,
                    handle: 0x7fff12345678,
                    flags: libc::O_RDONLY,
                },
            },
        }
    },
    "9300 open_by_handle_at(mount_fd: 3, handle: 0x7fff12345678, flags: 0x0 (O_RDONLY)) = 7 (fd)\n"
);

syscall_test!(
    parse_open_by_handle_at_rdwr,
    {
        SyscallEvent {
            syscall_nr: SYS_open_by_handle_at,
            pid: 9301,
            tid: 9301,
            return_value: 8,
            data: SyscallEventData {
                open_by_handle_at: OpenByHandleAtData {
                    mount_fd: libc::AT_FDCWD,
                    handle: 0x7fff87654321,
                    flags: libc::O_RDWR | libc::O_CLOEXEC,
                },
            },
        }
    },
    "9301 open_by_handle_at(mount_fd: AT_FDCWD, handle: 0x7fff87654321, flags: 0x80002 (O_RDWR|O_CLOEXEC)) = 8 (fd)\n"
);

syscall_test!(
    parse_open_by_handle_at_error,
    {
        SyscallEvent {
            syscall_nr: SYS_open_by_handle_at,
            pid: 9302,
            tid: 9302,
            return_value: -1,
            data: SyscallEventData {
                open_by_handle_at: OpenByHandleAtData {
                    mount_fd: 999,
                    handle: 0xbadbadbad,
                    flags: libc::O_RDONLY,
                },
            },
        }
    },
    "9302 open_by_handle_at(mount_fd: 999, handle: 0xbadbadbad, flags: 0x0 (O_RDONLY)) = -1 (error)\n"
);

syscall_test!(
    parse_copy_file_range_success,
    {
        SyscallEvent {
            syscall_nr: SYS_copy_file_range,
            pid: 9400,
            tid: 9400,
            return_value: 4096,
            data: SyscallEventData {
                copy_file_range: CopyFileRangeData {
                    fd_in: 3,
                    off_in: 0x1000,
                    off_in_is_null: 0,
                    fd_out: 4,
                    off_out: 0x2000,
                    off_out_is_null: 0,
                    len: 4096,
                    flags: 0,
                },
            },
        }
    },
    "9400 copy_file_range(fd_in: 3, off_in: 4096, fd_out: 4, off_out: 8192, len: 4096, flags: 0) = 4096 (bytes)\n"
);

syscall_test!(
    parse_copy_file_range_null_offsets,
    {
        SyscallEvent {
            syscall_nr: SYS_copy_file_range,
            pid: 9401,
            tid: 9401,
            return_value: 1024,
            data: SyscallEventData {
                copy_file_range: CopyFileRangeData {
                    fd_in: 5,
                    off_in: 0,
                    off_in_is_null: 1,
                    fd_out: 6,
                    off_out: 0,
                    off_out_is_null: 1,
                    len: 8192,
                    flags: 0,
                },
            },
        }
    },
    "9401 copy_file_range(fd_in: 5, off_in: NULL, fd_out: 6, off_out: NULL, len: 8192, flags: 0) = 1024 (bytes)\n"
);

syscall_test!(
    parse_copy_file_range_error,
    {
        SyscallEvent {
            syscall_nr: SYS_copy_file_range,
            pid: 9402,
            tid: 9402,
            return_value: -1,
            data: SyscallEventData {
                copy_file_range: CopyFileRangeData {
                    fd_in: 999,
                    off_in: 0,
                    off_in_is_null: 1,
                    fd_out: 998,
                    off_out: 0,
                    off_out_is_null: 1,
                    len: 0,
                    flags: 0,
                },
            },
        }
    },
    "9402 copy_file_range(fd_in: 999, off_in: NULL, fd_out: 998, off_out: NULL, len: 0, flags: 0) = -1 (error)\n"
);

syscall_test!(
    parse_sync_file_range_success,
    {
        SyscallEvent {
            syscall_nr: SYS_sync_file_range,
            pid: 9500,
            tid: 9500,
            return_value: 0,
            data: SyscallEventData {
                sync_file_range: SyncFileRangeData {
                    fd: 3,
                    offset: 0,
                    nbytes: 4096,
                    flags: libc::SYNC_FILE_RANGE_WRITE,
                },
            },
        }
    },
    "9500 sync_file_range(fd: 3, offset: 0, nbytes: 4096, flags: 0x2 (SYNC_FILE_RANGE_WRITE)) = 0 (success)\n"
);

syscall_test!(
    parse_sync_file_range_all_flags,
    {
        SyscallEvent {
            syscall_nr: SYS_sync_file_range,
            pid: 9501,
            tid: 9501,
            return_value: 0,
            data: SyscallEventData {
                sync_file_range: SyncFileRangeData {
                    fd: 5,
                    offset: 1024,
                    nbytes: 8192,
                    flags: libc::SYNC_FILE_RANGE_WAIT_BEFORE
                        | libc::SYNC_FILE_RANGE_WRITE
                        | libc::SYNC_FILE_RANGE_WAIT_AFTER,
                },
            },
        }
    },
    "9501 sync_file_range(fd: 5, offset: 1024, nbytes: 8192, flags: 0x7 (SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE|SYNC_FILE_RANGE_WAIT_AFTER)) = 0 (success)\n"
);

syscall_test!(
    parse_sync_file_range_error,
    {
        SyscallEvent {
            syscall_nr: SYS_sync_file_range,
            pid: 9502,
            tid: 9502,
            return_value: -9,
            data: SyscallEventData {
                sync_file_range: SyncFileRangeData {
                    fd: 999,
                    offset: 0,
                    nbytes: 0,
                    flags: 0,
                },
            },
        }
    },
    "9502 sync_file_range(fd: 999, offset: 0, nbytes: 0, flags: 0) = -9 (error)\n"
);

syscall_test!(
    parse_syncfs_success,
    {
        SyscallEvent {
            syscall_nr: SYS_syncfs,
            pid: 9600,
            tid: 9600,
            return_value: 0,
            data: SyscallEventData {
                syncfs: SyncfsData { fd: 3 },
            },
        }
    },
    "9600 syncfs(fd: 3) = 0 (success)\n"
);

syscall_test!(
    parse_syncfs_error,
    {
        SyscallEvent {
            syscall_nr: SYS_syncfs,
            pid: 9601,
            tid: 9601,
            return_value: -9,
            data: SyscallEventData {
                syncfs: SyncfsData { fd: 999 },
            },
        }
    },
    "9601 syncfs(fd: 999) = -9 (error)\n"
);

syscall_test!(
    parse_utimensat_success,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let p = b"/tmp/file.txt";
        pathname[..p.len()].copy_from_slice(p);

        SyscallEvent {
            syscall_nr: SYS_utimensat,
            pid: 9700,
            tid: 9700,
            return_value: 0,
            data: SyscallEventData {
                utimensat: UtimensatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    times: [
                        Timespec { seconds: 1234567890, nanos: 123456789 },
                        Timespec { seconds: 1234567891, nanos: 987654321 },
                    ],
                    times_is_null: 0,
                    flags: 0,
                },
            },
        }
    },
    "9700 utimensat(dirfd: AT_FDCWD, pathname: \"/tmp/file.txt\", times: [{secs: 1234567890, nanos: 123456789}, {secs: 1234567891, nanos: 987654321}], flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_utimensat_null_times,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let p = b"/var/log/app.log";
        pathname[..p.len()].copy_from_slice(p);

        SyscallEvent {
            syscall_nr: SYS_utimensat,
            pid: 9701,
            tid: 9701,
            return_value: 0,
            data: SyscallEventData {
                utimensat: UtimensatData {
                    dirfd: 5,
                    pathname,
                    times: [Timespec::default(); 2],
                    times_is_null: 1,
                    flags: libc::AT_SYMLINK_NOFOLLOW,
                },
            },
        }
    },
    "9701 utimensat(dirfd: 5, pathname: \"/var/log/app.log\", times: NULL, flags: AT_SYMLINK_NOFOLLOW (0x100)) = 0 (success)\n"
);

syscall_test!(
    parse_utimensat_error,
    {
        use crate::format_helpers::time_constants;

        let mut pathname = [0u8; DATA_READ_SIZE];
        let p = b"/nonexistent";
        pathname[..p.len()].copy_from_slice(p);

        SyscallEvent {
            syscall_nr: SYS_utimensat,
            pid: 9702,
            tid: 9702,
            return_value: -2,
            data: SyscallEventData {
                utimensat: UtimensatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    times: [
                        Timespec { seconds: 0, nanos: time_constants::UTIME_NOW },
                        Timespec { seconds: 0, nanos: time_constants::UTIME_OMIT },
                    ],
                    times_is_null: 0,
                    flags: 0,
                },
            },
        }
    },
    "9702 utimensat(dirfd: AT_FDCWD, pathname: \"/nonexistent\", times: [UTIME_NOW, UTIME_OMIT], flags: 0) = -2 (error)\n"
);

syscall_test!(
    parse_quotactl_getquota,
    {
        use pinchy_common::{QuotactlData, MEDIUM_READ_SIZE};
        let mut event = SyscallEvent {
            syscall_nr: SYS_quotactl,
            pid: 10001,
            tid: 10001,
            return_value: 0,
            data: SyscallEventData {
                quotactl: QuotactlData {
                    op: crate::format_helpers::quota_constants::Q_GETQUOTA,
                    special: [0u8; MEDIUM_READ_SIZE],
                    id: 1000,
                    addr: 0x7fff87654321,
                },
            },
        };
        let special = b"/dev/sda1\0";
        let data = unsafe { &mut event.data.quotactl };
        data.special[..special.len()].copy_from_slice(special);
        event
    },
    "10001 quotactl(op: 0x800007 (QCMD(Q_GETQUOTA, USRQUOTA)), special: \"/dev/sda1\", id: 1000, addr: 0x7fff87654321) = 0 (success)\n"
);

syscall_test!(
    parse_quotactl_setquota_grp,
    {
        use pinchy_common::{QuotactlData, MEDIUM_READ_SIZE};
        let mut event = SyscallEvent {
            syscall_nr: SYS_quotactl,
            pid: 10002,
            tid: 10002,
            return_value: 0,
            data: SyscallEventData {
                quotactl: QuotactlData {
                    op: crate::format_helpers::quota_constants::Q_GETNEXTQUOTA,
                    special: [0u8; MEDIUM_READ_SIZE],
                    id: 100,
                    addr: 0x7fff00002000,
                },
            },
        };
        let special = b"/dev/sdb1\0";
        let data = unsafe { &mut event.data.quotactl };
        data.special[..special.len()].copy_from_slice(special);
        event
    },
    "10002 quotactl(op: 0x800009 (QCMD(Q_GETNEXTQUOTA, USRQUOTA)), special: \"/dev/sdb1\", id: 100, addr: 0x7fff00002000) = 0 (success)\n"
);

syscall_test!(
    parse_quotactl_sync,
    {
        use pinchy_common::{QuotactlData, MEDIUM_READ_SIZE};
        let mut event = SyscallEvent {
            syscall_nr: SYS_quotactl,
            pid: 10003,
            tid: 10003,
            return_value: 0,
            data: SyscallEventData {
                quotactl: QuotactlData {
                    op: crate::format_helpers::quota_constants::Q_SYNC,
                    special: [0u8; MEDIUM_READ_SIZE],
                    id: 0,
                    addr: 0,
                },
            },
        };
        let special = b"/\0";
        let data = unsafe { &mut event.data.quotactl };
        data.special[..special.len()].copy_from_slice(special);
        event
    },
    "10003 quotactl(op: 0x800001 (QCMD(Q_SYNC, USRQUOTA)), special: \"/\", id: 0, addr: 0x0) = 0 (success)\n"
);

syscall_test!(
    parse_quotactl_error,
    {
        use pinchy_common::{QuotactlData, MEDIUM_READ_SIZE};
        let mut event = SyscallEvent {
            syscall_nr: SYS_quotactl,
            pid: 10004,
            tid: 10004,
            return_value: -1,
            data: SyscallEventData {
                quotactl: QuotactlData {
                    op: crate::format_helpers::quota_constants::Q_GETINFO,
                    special: [0u8; MEDIUM_READ_SIZE],
                    id: 500,
                    addr: 0x7fff00003000,
                },
            },
        };
        let special = b"/dev/sdc1\0";
        let data = unsafe { &mut event.data.quotactl };
        data.special[..special.len()].copy_from_slice(special);
        event
    },
    "10004 quotactl(op: 0x800005 (QCMD(Q_GETINFO, USRQUOTA)), special: \"/dev/sdc1\", id: 500, addr: 0x7fff00003000) = -1 (error)\n"
);

syscall_test!(
    parse_quotactl_fd_getquota,
    {
        SyscallEvent {
            syscall_nr: SYS_quotactl_fd,
            pid: 10005,
            tid: 10005,
            return_value: 0,
            data: SyscallEventData {
                quotactl_fd: QuotactlFdData {
                    fd: 3,
                    cmd: crate::format_helpers::quota_constants::Q_GETQUOTA as u32,
                    id: 1000,
                    addr: 0x7fff12340000,
                },
            },
        }
    },
    "10005 quotactl_fd(fd: 3, cmd: 0x800007 (QCMD(Q_GETQUOTA, USRQUOTA)), id: 1000, addr: 0x7fff12340000) = 0 (success)\n"
);

syscall_test!(
    parse_quotactl_fd_xfs,
    {
        SyscallEvent {
            syscall_nr: SYS_quotactl_fd,
            pid: 10006,
            tid: 10006,
            return_value: 0,
            data: SyscallEventData {
                quotactl_fd: QuotactlFdData {
                    fd: 5,
                    cmd: crate::format_helpers::quota_constants::Q_XGETQUOTA as u32,
                    id: 2000,
                    addr: 0x7fff56780000,
                },
            },
        }
    },
    "10006 quotactl_fd(fd: 5, cmd: 0x5803 (Q_XGETQUOTA), id: 2000, addr: 0x7fff56780000) = 0 (success)\n"
);
