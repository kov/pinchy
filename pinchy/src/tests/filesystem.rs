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
        SYS_inotify_add_watch, SYS_inotify_init1, SYS_inotify_rm_watch, SYS_linkat,
        SYS_lookup_dcookie, SYS_mkdirat, SYS_name_to_handle_at, SYS_newfstatat, SYS_nfsservctl,
        SYS_open_by_handle_at, SYS_quotactl, SYS_quotactl_fd, SYS_readlinkat, SYS_renameat,
        SYS_renameat2, SYS_statfs, SYS_sync_file_range, SYS_syncfs, SYS_truncate, SYS_utimensat,
    },
    AcctData, CopyFileRangeData, FaccessatData, FallocateData, FanotifyInitData, FanotifyMarkData,
    FchmodData, FchmodatData, FchownData, FchownatData, FdatasyncData, FsyncData, FtruncateData,
    InotifyAddWatchData, InotifyInit1Data, InotifyRmWatchData, LinkatData, LookupDcookieData,
    MkdiratData, MknodatData, NameToHandleAtData, NfsservctlData, OpenByHandleAtData,
    QuotactlFdData, Renameat2Data, RenameatData, SyncFileRangeData, SyncfsData, UtimensatData,
    DATA_READ_SIZE, MEDIUM_READ_SIZE, SMALLISH_READ_SIZE,
};
#[cfg(target_arch = "x86_64")]
use pinchy_common::{
    kernel_types::{LinuxDirent, Stat},
    syscalls::{
        SYS_access, SYS_chmod, SYS_creat, SYS_futimesat, SYS_getdents, SYS_lstat, SYS_mkdir,
        SYS_readlink, SYS_stat, SYS_utime, SYS_utimes,
    },
    AccessData, ChmodData, CreatData, FutimesatData, GetdentsData, LstatData, MkdirData,
    ReadlinkData, StatData, UtimeData, UtimesData,
};

use crate::{syscall_test, tests::make_compact_test_data};

syscall_test!(
    parse_fstat_success,
    {
        use pinchy_common::{FstatData, kernel_types::Stat};

        let mut data = FstatData {
            fd: 5,
            stat: Stat::default(),
        };

        data.stat.st_mode = libc::S_IFREG | 0o644;
        data.stat.st_size = 12345;
        data.stat.st_uid = 1000;
        data.stat.st_gid = 1000;
        data.stat.st_blocks = 24;
        data.stat.st_blksize = 4096;
        data.stat.st_ino = 9876543;

        make_compact_test_data(SYS_fstat, 33, 0, &data)
    },
    "33 fstat(fd: 5, struct stat: { mode: 0o644 (rw-r--r--), ino: 9876543, dev: 0, nlink: 0, uid: 1000, gid: 1000, size: 12345, blksize: 4096, blocks: 24, atime: 0, mtime: 0, ctime: 0 }) = 0 (success)\n"
);

syscall_test!(
    parse_inotify_add_watch,
    {

        let mut pathname = [0u8; DATA_READ_SIZE];
        let p = b"/tmp/watch";
        pathname[..p.len()].copy_from_slice(p);

        let data = InotifyAddWatchData {
                    fd: 5,
                    pathname,
                    mask: (libc::IN_CREATE | libc::IN_DELETE | libc::IN_MODIFY),
                };

        crate::tests::make_compact_test_data(SYS_inotify_add_watch, 10, 3, &data)
    },
    "10 inotify_add_watch(fd: 5, pathname: \"/tmp/watch\", mask: 0x302 (IN_MODIFY|IN_CREATE|IN_DELETE)) = 3 (wd)\n"
);

syscall_test!(
    parse_inotify_rm_watch,
    {
        let data = InotifyRmWatchData { fd: 5, wd: 7 };

        crate::tests::make_compact_test_data(SYS_inotify_rm_watch, 11, 0, &data)
    },
    "11 inotify_rm_watch(fd: 5, wd: 7) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_inotify_init,
    {
        let data = pinchy_common::InotifyInitData {};

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_inotify_init,
            12,
            9,
            &data,
        )
    },
    "12 inotify_init() = 9 (fd)\n"
);

syscall_test!(
    parse_inotify_init1,
    {
        let data = InotifyInit1Data {
            flags: libc::IN_NONBLOCK | libc::IN_CLOEXEC,
        };

        crate::tests::make_compact_test_data(SYS_inotify_init1, 13, 10, &data)
    },
    "13 inotify_init1(flags: 0x80800 (IN_NONBLOCK|IN_CLOEXEC)) = 10 (fd)\n"
);

syscall_test!(
    parse_fstat_error,
    {
        use pinchy_common::{FstatData, kernel_types::Stat};

        let mut data = FstatData {
            fd: 5,
            stat: Stat::default(),
        };

        data.stat.st_mode = libc::S_IFREG | 0o644;
        data.stat.st_size = 12345;
        data.stat.st_uid = 1000;
        data.stat.st_gid = 1000;
        data.stat.st_blocks = 24;
        data.stat.st_blksize = 4096;
        data.stat.st_ino = 9876543;

        make_compact_test_data(SYS_fstat, 33, -1, &data)
    },
    "33 fstat(fd: 5, struct stat: { mode: 0o644 (rw-r--r--), ino: 9876543, dev: 0, nlink: 0, uid: 1000, gid: 1000, size: 12345, blksize: 4096, blocks: 24, atime: 0, mtime: 0, ctime: 0 }) = -1 (error)\n"
);

syscall_test!(
    parse_statfs_success,
    {
        use pinchy_common::{StatfsData, kernel_types::Statfs};

        let mut data = StatfsData {
            pathname: [0u8; DATA_READ_SIZE],
            statfs: Statfs::default(),
        };

        let path = c"/mnt/data".to_bytes_with_nul();
        data.pathname[..path.len()].copy_from_slice(path);
        data.statfs.f_type = libc::TMPFS_MAGIC;
        data.statfs.f_bsize = 4096;
        data.statfs.f_blocks = 1024000;
        data.statfs.f_bfree = 512000;
        data.statfs.f_bavail = 512000;
        data.statfs.f_files = 65536;
        data.statfs.f_ffree = 65000;
        data.statfs.f_namelen = 255;
        data.statfs.f_flags = (libc::ST_NOEXEC | libc::ST_RDONLY) as i64;

        make_compact_test_data(SYS_statfs, 44, 0, &data)
    },
    "44 statfs(pathname: \"/mnt/data\", buf: { type: TMPFS_MAGIC (0x1021994), block_size: 4096, blocks: 1024000, blocks_free: 512000, blocks_available: 512000, files: 65536, files_free: 65000, fsid: [0, 0], name_max: 255, fragment_size: 0, mount_flags: 0x9 (ST_RDONLY|ST_NOEXEC) }) = 0 (success)\n"
);

syscall_test!(
    parse_getdents64_populated,
    {
        use pinchy_common::{kernel_types::LinuxDirent64, Getdents64Data};
        let mut data = Getdents64Data {
            fd: 7,
            count: 1024,
            dirents: [LinuxDirent64::default(); 4],
            num_dirents: 3,
        };

        {
            data.dirents[0].d_ino = 123456;
            data.dirents[0].d_off = 1;
            data.dirents[0].d_reclen = 24;
            data.dirents[0].d_type = 4;
            let dot = c".".to_bytes_with_nul();
            data.dirents[0].d_name[..dot.len()].copy_from_slice(dot);
            data.dirents[1].d_ino = 123457;
            data.dirents[1].d_off = 2;
            data.dirents[1].d_reclen = 25;
            data.dirents[1].d_type = 4;
            let dot_dot = c"..".to_bytes_with_nul();
            data.dirents[1].d_name[..dot_dot.len()].copy_from_slice(dot_dot);
            data.dirents[2].d_ino = 123458;
            data.dirents[2].d_off = 3;
            data.dirents[2].d_reclen = 32;
            data.dirents[2].d_type = 8;
            let filename = c"file.txt".to_bytes();
            data.dirents[2].d_name[..filename.len()].copy_from_slice(filename);
        }

        crate::tests::make_compact_test_data(SYS_getdents64, 55, 3, &data)
    },
    &"55 getdents64(fd: 7, count: 1024, entries: [ dirent { ino: 123456, off: 1, reclen: 24, type: 4, name: \".\" }, dirent { ino: 123457, off: 2, reclen: 25, type: 4, name: \"..\" }, dirent { ino: 123458, off: 3, reclen: 32, type: 8, name: \"file.txt\" ... (truncated) } ]) = 3 (bytes)\n".to_string()
);

syscall_test!(
    parse_getdents64_empty,
    {
        use pinchy_common::{kernel_types::LinuxDirent64, Getdents64Data};

        let data = Getdents64Data {
            fd: 7,
            count: 1024,
            dirents: [LinuxDirent64::default(); 4],
            num_dirents: 0,
        };

        crate::tests::make_compact_test_data(SYS_getdents64, 55, 0, &data)
    },
    &"55 getdents64(fd: 7, count: 1024, entries: [  ]) = 0 (bytes)\n".to_string()
);

syscall_test!(
    parse_faccessat_success,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/etc/hosts.conf";
        pathname[0..path.len()].copy_from_slice(path);

        let data = FaccessatData {
            dirfd: libc::AT_FDCWD,
            pathname,
            mode: libc::R_OK | libc::W_OK,
            flags: 0,
        };

        make_compact_test_data(SYS_faccessat, 1001, 0, &data)
    },
    "1001 faccessat(dirfd: AT_FDCWD, pathname: \"/etc/hosts.conf\", mode: R_OK|W_OK) = 0 (success)\n"
);

syscall_test!(
    parse_faccessat_with_flags_error,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/etc/hosts";
        pathname[0..path.len()].copy_from_slice(path);

        let data = FaccessatData {
            dirfd: 3,
            pathname,
            mode: libc::F_OK,
            flags: libc::AT_SYMLINK_NOFOLLOW,
        };

        make_compact_test_data(SYS_faccessat, 1001, -1, &data)
    },
    "1001 faccessat(dirfd: 3, pathname: \"/etc/hosts\", mode: F_OK) = -1 (error)\n"
);

syscall_test!(
    parse_faccessat2_success,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/etc/hosts.conf";
        pathname[0..path.len()].copy_from_slice(path);
        let data = FaccessatData {
            dirfd: libc::AT_FDCWD,
            pathname,
            mode: libc::R_OK | libc::W_OK,
            flags: 0,
        };

        make_compact_test_data(syscalls::SYS_faccessat2, 1002, 0, &data)
    },
    "1002 faccessat2(dirfd: AT_FDCWD, pathname: \"/etc/hosts.conf\", mode: R_OK|W_OK, flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_faccessat2_with_flags_error,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/etc/hosts";
        pathname[0..path.len()].copy_from_slice(path);
        let data = FaccessatData {
            dirfd: 3,
            pathname,
            mode: libc::F_OK,
            flags: libc::AT_SYMLINK_NOFOLLOW,
        };

        make_compact_test_data(syscalls::SYS_faccessat2, 1003, -1, &data)
    },
    "1003 faccessat2(dirfd: 3, pathname: \"/etc/hosts\", mode: F_OK, flags: AT_SYMLINK_NOFOLLOW (0x100)) = -1 (error)\n"
);

syscall_test!(
    parse_newfstatat_success,
    {
        use pinchy_common::{NewfstatatData, kernel_types::Stat};

        let mut data = NewfstatatData {
            dirfd: libc::AT_FDCWD,
            pathname: [0u8; DATA_READ_SIZE],
            stat: Stat::default(),
            flags: libc::AT_SYMLINK_NOFOLLOW,
        };

        let pathname = b"test_file.txt\0";
        data.pathname[..pathname.len()].copy_from_slice(pathname);
        data.stat.st_mode = libc::S_IFREG | 0o755;
        data.stat.st_size = 54321;
        data.stat.st_uid = 500;
        data.stat.st_gid = 500;
        data.stat.st_blocks = 108;
        data.stat.st_blksize = 4096;
        data.stat.st_ino = 1234567;

        make_compact_test_data(SYS_newfstatat, 42, 0, &data)
    },
    "42 newfstatat(dirfd: AT_FDCWD, pathname: \"test_file.txt\", struct stat: { mode: 0o755 (rwxr-xr-x), ino: 1234567, dev: 0, nlink: 0, uid: 500, gid: 500, size: 54321, blksize: 4096, blocks: 108, atime: 0, mtime: 0, ctime: 0 }, flags: AT_SYMLINK_NOFOLLOW (0x100)) = 0 (success)\n"
);

syscall_test!(
    parse_newfstatat_error,
    {
        use pinchy_common::{NewfstatatData, kernel_types::Stat};

        let mut data = NewfstatatData {
            dirfd: libc::AT_FDCWD,
            pathname: [0u8; DATA_READ_SIZE],
            stat: Stat::default(),
            flags: libc::AT_SYMLINK_NOFOLLOW,
        };

        let pathname = b"test_file.txt\0";
        data.pathname[..pathname.len()].copy_from_slice(pathname);

        make_compact_test_data(SYS_newfstatat, 42, -1, &data)
    },
    "42 newfstatat(dirfd: AT_FDCWD, pathname: \"test_file.txt\", struct stat: <unavailable>, flags: AT_SYMLINK_NOFOLLOW (0x100)) = -1 (error)\n"
);

syscall_test!(
    parse_newfstatat_noflags,
    {
        use pinchy_common::{NewfstatatData, kernel_types::Stat};

        let mut data = NewfstatatData {
            dirfd: libc::AT_FDCWD,
            pathname: [0u8; DATA_READ_SIZE],
            stat: Stat::default(),
            flags: 0,
        };

        let pathname = b"test_file.txt\0";
        data.pathname[..pathname.len()].copy_from_slice(pathname);
        data.stat.st_mode = libc::S_IFREG | 0o755;
        data.stat.st_size = 54321;
        data.stat.st_uid = 500;
        data.stat.st_gid = 500;
        data.stat.st_blocks = 108;
        data.stat.st_blksize = 4096;
        data.stat.st_ino = 1234567;

        make_compact_test_data(SYS_newfstatat, 42, 0, &data)
    },
    "42 newfstatat(dirfd: AT_FDCWD, pathname: \"test_file.txt\", struct stat: { mode: 0o755 (rwxr-xr-x), ino: 1234567, dev: 0, nlink: 0, uid: 500, gid: 500, size: 54321, blksize: 4096, blocks: 108, atime: 0, mtime: 0, ctime: 0 }, flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_newfstatat_dirfd,
    {
        use pinchy_common::{NewfstatatData, kernel_types::Stat};

        let mut data = NewfstatatData {
            dirfd: 5,
            pathname: [0u8; DATA_READ_SIZE],
            stat: Stat::default(),
            flags: 0,
        };

        let pathname = b"test_file.txt\0";
        data.pathname[..pathname.len()].copy_from_slice(pathname);
        data.stat.st_mode = libc::S_IFREG | 0o755;
        data.stat.st_size = 54321;
        data.stat.st_uid = 500;
        data.stat.st_gid = 500;
        data.stat.st_blocks = 108;
        data.stat.st_blksize = 4096;
        data.stat.st_ino = 1234567;

        make_compact_test_data(SYS_newfstatat, 42, 0, &data)
    },
    "42 newfstatat(dirfd: 5, pathname: \"test_file.txt\", struct stat: { mode: 0o755 (rwxr-xr-x), ino: 1234567, dev: 0, nlink: 0, uid: 500, gid: 500, size: 54321, blksize: 4096, blocks: 108, atime: 0, mtime: 0, ctime: 0 }, flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_readlinkat_event,
    {
        let exe_link = b"/proc/self/exe\0";
        let bin_path = b"/usr/bin/pinchy\0";
        let mut data = pinchy_common::ReadlinkatData {
            dirfd: 3,
            pathname: [0u8; MEDIUM_READ_SIZE],
            buf: [0u8; MEDIUM_READ_SIZE],
            bufsiz: 16,
        };
        data.pathname[..exe_link.len()].copy_from_slice(exe_link);
        data.buf[..bin_path.len()].copy_from_slice(bin_path);

        make_compact_test_data(SYS_readlinkat, 5678, 15, &data)
    },
    "5678 readlinkat(dirfd: 3, pathname: \"/proc/self/exe\", buf: \"/usr/bin/pinchy\", bufsiz: 16) = 15\n"
);

syscall_test!(
    parse_flistxattr,
    {
        use pinchy_common::{kernel_types::XattrList, syscalls::SYS_flistxattr, FlistxattrData};

        let mut xattr_list = XattrList::default();
        let names = b"user.attr1\0user.attr2\0";
        xattr_list.data[..names.len()].copy_from_slice(names);
        xattr_list.size = names.len();

        let data = FlistxattrData {
            fd: 7,
            list: 0xdeadbeef,
            size: 256,
            xattr_list,
        };

        make_compact_test_data(SYS_flistxattr, 42, names.len() as i64, &data)
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

        let mut pathname = [0u8; pinchy_common::DATA_READ_SIZE];
        let path = b"/tmp/testfile\0";
        pathname[..path.len()].copy_from_slice(path);

        let data = ListxattrData {
            pathname,
            list: 0xabadcafe,
            size: 128,
            xattr_list,
        };

        make_compact_test_data(SYS_listxattr, 43, names.len() as i64, &data)
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

        let mut pathname = [0u8; pinchy_common::DATA_READ_SIZE];
        let path = b"/tmp/testlink\0";
        pathname[..path.len()].copy_from_slice(path);

        let data = LlistxattrData {
            pathname,
            list: 0xfeedface,
            size: 64,
            xattr_list,
        };

        make_compact_test_data(SYS_llistxattr, 44, names.len() as i64, &data)
    },
    "44 llistxattr(pathname: \"/tmp/testlink\", list: [ user.attr1, user.attr2 ], size: 64) = 22\n"
);

syscall_test!(
    parse_setxattr,
    {
        use pinchy_common::{
            DATA_READ_SIZE, MEDIUM_READ_SIZE, SetxattrData, syscalls::SYS_setxattr,
        };

        let mut pathname = [0u8; DATA_READ_SIZE];
        pathname[..12].copy_from_slice(b"/tmp/myfile\0");
        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..10].copy_from_slice(b"user.attr\0");
        let mut value = [0u8; DATA_READ_SIZE];
        value[..6].copy_from_slice(b"value\0");

        let data = SetxattrData {
            pathname,
            name,
            value,
            size: 6,
            flags: 0,
        };

        make_compact_test_data(SYS_setxattr, 45, 0, &data)
    },
    "45 setxattr(pathname: \"/tmp/myfile\", name: \"user.attr\", value: \"value\\0\", size: 6, flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_lsetxattr,
    {
        use pinchy_common::{
            DATA_READ_SIZE, LsetxattrData, MEDIUM_READ_SIZE, syscalls::SYS_lsetxattr,
        };

        let mut pathname = [0u8; DATA_READ_SIZE];
        pathname[..12].copy_from_slice(b"/tmp/mylink\0");
        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..10].copy_from_slice(b"user.test\0");
        let mut value = [0u8; DATA_READ_SIZE];
        value[..4].copy_from_slice(b"test");

        let data = LsetxattrData {
            pathname,
            name,
            value,
            size: 4,
            flags: libc::XATTR_CREATE,
        };

        make_compact_test_data(SYS_lsetxattr, 46, 0, &data)
    },
    "46 lsetxattr(pathname: \"/tmp/mylink\", name: \"user.test\", value: \"test\", size: 4, flags: 0x1 (XATTR_CREATE)) = 0 (success)\n"
);

syscall_test!(
    parse_fsetxattr,
    {
        use pinchy_common::{
            DATA_READ_SIZE, FsetxattrData, MEDIUM_READ_SIZE, syscalls::SYS_fsetxattr,
        };

        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..9].copy_from_slice(b"user.foo\0");
        let mut value = [0u8; DATA_READ_SIZE];
        value[..3].copy_from_slice(b"bar");

        let data = FsetxattrData {
            fd: 8,
            name,
            value,
            size: 3,
            flags: libc::XATTR_REPLACE,
        };

        make_compact_test_data(SYS_fsetxattr, 47, 0, &data)
    },
    "47 fsetxattr(fd: 8, name: \"user.foo\", value: \"bar\", size: 3, flags: 0x2 (XATTR_REPLACE)) = 0 (success)\n"
);

syscall_test!(
    parse_getxattr,
    {
        use pinchy_common::{
            DATA_READ_SIZE, GetxattrData, MEDIUM_READ_SIZE, syscalls::SYS_getxattr,
        };

        let mut pathname = [0u8; DATA_READ_SIZE];
        pathname[..12].copy_from_slice(b"/tmp/myfile\0");
        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..10].copy_from_slice(b"user.attr\0");
        let mut value = [0u8; DATA_READ_SIZE];
        value[..6].copy_from_slice(b"value\0");

        let data = GetxattrData {
            pathname,
            name,
            value,
            size: 100,
        };

        make_compact_test_data(SYS_getxattr, 48, 6, &data)
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

        let data = LgetxattrData {
            pathname,
            name,
            value,
            size: 50,
        };

        make_compact_test_data(SYS_lgetxattr, 49, 4, &data)
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

        let data = FgetxattrData {
            fd: 9,
            name,
            value,
            size: 10,
        };

        make_compact_test_data(SYS_fgetxattr, 50, 3, &data)
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

        let data = RemovexattrData { pathname, name };

        make_compact_test_data(SYS_removexattr, 51, 0, &data)
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

        let data = LremovexattrData { pathname, name };

        make_compact_test_data(SYS_lremovexattr, 52, 0, &data)
    },
    "52 lremovexattr(pathname: \"/tmp/mylink\", name: \"user.test\") = 0 (success)\n"
);

syscall_test!(
    parse_fremovexattr,
    {
        use pinchy_common::{syscalls::SYS_fremovexattr, FremovexattrData, MEDIUM_READ_SIZE};

        let mut name = [0u8; MEDIUM_READ_SIZE];
        name[..9].copy_from_slice(b"user.foo\0");

        let data = FremovexattrData { fd: 10, name };

        make_compact_test_data(SYS_fremovexattr, 53, 0, &data)
    },
    "53 fremovexattr(fd: 10, name: \"user.foo\") = 0 (success)\n"
);

syscall_test!(
    parse_getcwd,
    {
        use pinchy_common::GetcwdData;

        let mut path = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/home/user/work\0";
        path[..path_bytes.len()].copy_from_slice(path_bytes);

        let data = GetcwdData {
            buf: 0x7ffe12345000,
            size: 4096,
            path,
        };

        make_compact_test_data(SYS_getcwd, 55, 16, &data)
    },
    "55 getcwd(buf: 0x7ffe12345000, size: 4096, path: \"/home/user/work\") = 16\n"
);

syscall_test!(
    parse_getcwd_error,
    {
        use pinchy_common::GetcwdData;

        let mut path = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/home/user/work\0";
        path[..path_bytes.len()].copy_from_slice(path_bytes);

        let data = GetcwdData {
            buf: 0x7ffe12345000,
            size: 4096,
            path,
        };

        make_compact_test_data(SYS_getcwd, 55, -1, &data)
    },
    "55 getcwd(buf: 0x7ffe12345000, size: 4096) = -1 (error)\n"
);

syscall_test!(
    parse_chdir,
    {
        use pinchy_common::ChdirData;

        let mut path = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/home/user/newdir\0";
        path[..path_bytes.len()].copy_from_slice(path_bytes);

        let data = ChdirData { path };

        make_compact_test_data(SYS_chdir, 66, 0, &data)
    },
    "66 chdir(path: \"/home/user/newdir\") = 0 (success)\n"
);

syscall_test!(
    parse_chdir_error,
    {
        use pinchy_common::ChdirData;

        let mut path = [0u8; DATA_READ_SIZE];
        let path_bytes = b"/home/user/newdir\0";
        path[..path_bytes.len()].copy_from_slice(path_bytes);

        let data = ChdirData { path };

        make_compact_test_data(SYS_chdir, 66, -1, &data)
    },
    "66 chdir(path: \"/home/user/newdir\") = -1 (error)\n"
);

syscall_test!(
    parse_mkdirat,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/home/user/newdir\0";
        pathname[..path.len()].copy_from_slice(path);

        let data = MkdiratData {
            dirfd: libc::AT_FDCWD,
            pathname,
            mode: 0o755,
        };

        make_compact_test_data(SYS_mkdirat, 77, 0, &data)
    },
    "77 mkdirat(dirfd: AT_FDCWD, pathname: \"/home/user/newdir\", mode: 0o755 (rwxr-xr-x)) = 0 (success)\n"
);

syscall_test!(
    parse_mkdirat_dirfd,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/home/user/newdir\0";
        pathname[..path.len()].copy_from_slice(path);

        let data = MkdiratData {
            dirfd: 5,
            pathname,
            mode: 0o700,
        };

        make_compact_test_data(SYS_mkdirat, 77, 0, &data)
    },
    "77 mkdirat(dirfd: 5, pathname: \"/home/user/newdir\", mode: 0o700 (rwx------)) = 0 (success)\n"
);

syscall_test!(
    parse_mkdirat_error,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/home/user/newdir\0";
        pathname[..path.len()].copy_from_slice(path);

        let data = MkdiratData {
            dirfd: 5,
            pathname,
            mode: 0o700,
        };

        make_compact_test_data(SYS_mkdirat, 77, -1, &data)
    },
    "77 mkdirat(dirfd: 5, pathname: \"/home/user/newdir\", mode: 0o700 (rwx------)) = -1 (error)\n"
);

syscall_test!(
    parse_fsync,
    {
        let data = FsyncData { fd: 5 };

        make_compact_test_data(SYS_fsync, 123, 0, &data)
    },
    "123 fsync(fd: 5) = 0 (success)\n"
);

syscall_test!(
    parse_fdatasync,
    {
        let data = FdatasyncData { fd: 8 };

        make_compact_test_data(SYS_fdatasync, 124, 0, &data)
    },
    "124 fdatasync(fd: 8) = 0 (success)\n"
);

syscall_test!(
    parse_ftruncate,
    {
        let data = FtruncateData {
            fd: 3,
            length: 4096,
        };

        make_compact_test_data(SYS_ftruncate, 125, 0, &data)
    },
    "125 ftruncate(fd: 3, length: 4096) = 0 (success)\n"
);

syscall_test!(
    parse_ftruncate_error,
    {
        let data = FtruncateData {
            fd: 3,
            length: 4096,
        };

        make_compact_test_data(SYS_ftruncate, 125, -1, &data)
    },
    "125 ftruncate(fd: 3, length: 4096) = -1 (error)\n"
);

syscall_test!(
    parse_fchmod,
    {
        let data = FchmodData { fd: 3, mode: 0o644 };

        make_compact_test_data(SYS_fchmod, 126, 0, &data)
    },
    "126 fchmod(fd: 3, mode: 0o644 (rw-r--r--)) = 0 (success)\n"
);

syscall_test!(
    parse_fchmod_error,
    {
        let data = FchmodData { fd: 3, mode: 0o644 };

        make_compact_test_data(SYS_fchmod, 126, -1, &data)
    },
    "126 fchmod(fd: 3, mode: 0o644 (rw-r--r--)) = -1 (error)\n"
);

syscall_test!(
    parse_fchmod_mode_755,
    {
        let data = FchmodData { fd: 3, mode: 0o755 };

        make_compact_test_data(SYS_fchmod, 126, 0, &data)
    },
    "126 fchmod(fd: 3, mode: 0o755 (rwxr-xr-x)) = 0 (success)\n"
);

syscall_test!(
    parse_fchmodat,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/testfile";
        pathname[0..path.len()].copy_from_slice(path);

        let data = FchmodatData {
            dirfd: 3,
            pathname,
            mode: 0o755,
            flags: 0,
        };

        make_compact_test_data(SYS_fchmodat, 1001, 0, &data)
    },
    "1001 fchmodat(dirfd: 3, pathname: \"/tmp/testfile\", mode: 0o755 (rwxr-xr-x), flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_fchmodat_with_flags,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/testfile";
        pathname[0..path.len()].copy_from_slice(path);

        let data = FchmodatData {
            dirfd: 3,
            pathname,
            mode: 0o755,
            flags: libc::AT_SYMLINK_NOFOLLOW,
        };

        make_compact_test_data(SYS_fchmodat, 1001, 0, &data)
    },
    "1001 fchmodat(dirfd: 3, pathname: \"/tmp/testfile\", mode: 0o755 (rwxr-xr-x), flags: AT_SYMLINK_NOFOLLOW (0x100)) = 0 (success)\n"
);

syscall_test!(
    parse_fchown,
    {
        let data = FchownData {
            fd: 3,
            uid: 1000,
            gid: 1000,
        };

        make_compact_test_data(SYS_fchown, 1001, 0, &data)
    },
    "1001 fchown(fd: 3, uid: 1000, gid: 1000) = 0 (success)\n"
);

syscall_test!(
    parse_fchownat,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/etc/passwd";
        pathname[0..path.len()].copy_from_slice(path);

        let data = FchownatData {
            dirfd: libc::AT_FDCWD,
            pathname,
            uid: 1000,
            gid: 1000,
            flags: 0,
        };

        make_compact_test_data(SYS_fchownat, 1001, 0, &data)
    },
    "1001 fchownat(dirfd: AT_FDCWD, pathname: \"/etc/passwd\", uid: 1000, gid: 1000, flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_fchownat_with_flags,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/etc/passwd";
        pathname[0..path.len()].copy_from_slice(path);

        let data = FchownatData {
            dirfd: libc::AT_FDCWD,
            pathname,
            uid: 1000,
            gid: 1000,
            flags: libc::AT_SYMLINK_NOFOLLOW,
        };

        make_compact_test_data(SYS_fchownat, 1001, 0, &data)
    },
    "1001 fchownat(dirfd: AT_FDCWD, pathname: \"/etc/passwd\", uid: 1000, gid: 1000, flags: AT_SYMLINK_NOFOLLOW (0x100)) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_chown,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/home/user";
        pathname[0..path.len()].copy_from_slice(path);

        let data = pinchy_common::ChownData {
            pathname,
            uid: 1000,
            gid: 1000,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_chown, 2001, 0, &data)
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

        let data = pinchy_common::ChownData {
            pathname,
            uid: 2000,
            gid: 2000,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_lchown, 3001, 0, &data)
    },
    "3001 lchown(pathname: \"/var/log\", uid: 2000, gid: 2000) = 0 (success)\n"
);

syscall_test!(
    parse_truncate,
    {
        let path = b"/tmp/testfile\0";
        let mut pathname = [0u8; DATA_READ_SIZE];
        pathname[0..path.len()].copy_from_slice(path);

        let data = pinchy_common::TruncateData {
            pathname,
            length: 1024,
        };

        crate::tests::make_compact_test_data(SYS_truncate, 123, 0, &data)
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

        let data = pinchy_common::RenameData { oldpath, newpath };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_rename, 1001, 0, &data)
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

        let data = RenameatData {
            olddirfd: libc::AT_FDCWD,
            oldpath,
            newdirfd: libc::AT_FDCWD,
            newpath,
        };

        make_compact_test_data(SYS_renameat, 1001, 0, &data)
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

        let data = Renameat2Data {
            olddirfd: libc::AT_FDCWD,
            oldpath,
            newdirfd: libc::AT_FDCWD,
            newpath,
            flags: libc::RENAME_NOREPLACE,
        };

        make_compact_test_data(SYS_renameat2, 1001, 0, &data)
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

        let data = pinchy_common::RmdirData { pathname };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_rmdir, 1, 0, &data)
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

        let data = pinchy_common::UnlinkData { pathname };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_unlink, 201, 0, &data)
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

        let data = pinchy_common::UnlinkData { pathname };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_unlink, 301, -1, &data)
    },
    "301 unlink(pathname: \"/tmp/nonexistent\") = -1 (error)\n"
);

syscall_test!(
    parse_unlinkat,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/testdir\0";
        pathname[..path.len()].copy_from_slice(path);

        let data = pinchy_common::UnlinkatData {
            dirfd: libc::AT_FDCWD,
            pathname,
            flags: libc::AT_REMOVEDIR,
        };

        make_compact_test_data(pinchy_common::syscalls::SYS_unlinkat, 401, 0, &data)
    },
    "401 unlinkat(dirfd: AT_FDCWD, pathname: \"/tmp/testdir\", flags: AT_EACCESS|AT_REMOVEDIR (0x200)) = 0 (success)\n"
);

syscall_test!(
    parse_unlinkat_error,
    {
        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/nonexistent\0";
        pathname[..path.len()].copy_from_slice(path);

        let data = pinchy_common::UnlinkatData {
            dirfd: libc::AT_FDCWD,
            pathname,
            flags: 0,
        };

        make_compact_test_data(pinchy_common::syscalls::SYS_unlinkat, 501, -1, &data)
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

        let data = pinchy_common::SymlinkData { target, linkpath };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_symlink, 601, 0, &data)
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

        let data = pinchy_common::SymlinkData { target, linkpath };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_symlink, 601, -1, &data)
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

        let data = pinchy_common::SymlinkatData {
            target,
            newdirfd: libc::AT_FDCWD,
            linkpath,
        };

        make_compact_test_data(pinchy_common::syscalls::SYS_symlinkat, 701, 0, &data)
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

        let data = pinchy_common::SymlinkatData {
            target,
            newdirfd: libc::AT_FDCWD,
            linkpath,
        };

        make_compact_test_data(pinchy_common::syscalls::SYS_symlinkat, 701, -1, &data)
    },
    "701 symlinkat(target: \"/target\", newdirfd: AT_FDCWD, linkpath: \"/link\") = -1 (error)\n"
);

syscall_test!(
    parse_acct,
    {
        let mut filename = [0u8; DATA_READ_SIZE];
        let path = b"/var/log/account\0";
        filename[..path.len()].copy_from_slice(path);

        let data = AcctData { filename };

        crate::tests::make_compact_test_data(SYS_acct, 801, 0, &data)
    },
    "801 acct(filename: \"/var/log/account\") = 0 (success)\n"
);

syscall_test!(
    parse_acct_error,
    {
        let mut filename = [0u8; DATA_READ_SIZE];
        let path = b"/var/log/account\0";
        filename[..path.len()].copy_from_slice(path);

        let data = AcctData { filename };

        crate::tests::make_compact_test_data(SYS_acct, 901, -1, &data)
    },
    "901 acct(filename: \"/var/log/account\") = -1 (error)\n"
);

syscall_test!(
    parse_statx_success,
    {

        use pinchy_common::{StatxData, kernel_types::Statx};

        let data = StatxData {
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
                    },
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_statx, 42, 0, &data)
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

        let data = pinchy_common::MknodData {
                    pathname,
                    mode: libc::S_IFREG | 0o644,
                    dev: 0,
                };

        crate::tests::make_compact_test_data(syscalls::SYS_mknod, 100, 0, &data)
    },
    "100 mknod(pathname: \"/tmp/testfile\", mode: 0o644 (rw-r--r--) (S_IFREG), dev: 0) = 0 (success)\n"
);

syscall_test!(
    parse_mknodat_regular_file,
    {

        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/testfile\0";
        pathname[..path.len()].copy_from_slice(path);

        let data = MknodatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    mode: libc::S_IFREG | 0o644,
                    dev: 0,
                };

        crate::tests::make_compact_test_data(syscalls::SYS_mknodat, 200, 0, &data)
    },
    "200 mknodat(dirfd: AT_FDCWD, pathname: \"/tmp/testfile\", mode: 0o644 (rw-r--r--) (S_IFREG), dev: 0) = 0 (success)\n"
);

syscall_test!(
    parse_mknodat_device_file,
    {

        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/dev/mydevice\0";
        pathname[..path.len()].copy_from_slice(path);

        let data = MknodatData {
                    dirfd: 5,
                    pathname,
                    mode: libc::S_IFCHR | 0o666,
                    dev: (1 << 8) | 5,
                };

        crate::tests::make_compact_test_data(syscalls::SYS_mknodat, 201, 0, &data)
    },
    "201 mknodat(dirfd: 5, pathname: \"/dev/mydevice\", mode: 0o666 (rw-rw-rw-) (S_IFCHR), dev: 1:5) = 0 (success)\n"
);

syscall_test!(
    parse_mknodat_fifo,
    {

        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/myfifo\0";
        pathname[..path.len()].copy_from_slice(path);

        let data = MknodatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    mode: libc::S_IFIFO | 0o600,
                    dev: 0,
                };

        crate::tests::make_compact_test_data(syscalls::SYS_mknodat, 202, 0, &data)
    },
    "202 mknodat(dirfd: AT_FDCWD, pathname: \"/tmp/myfifo\", mode: 0o600 (rw-------) (S_IFIFO), dev: 0) = 0 (success)\n"
);

syscall_test!(
    parse_mknodat_error,
    {

        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/testfile\0";
        pathname[..path.len()].copy_from_slice(path);

        let data = MknodatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    mode: libc::S_IFREG | 0o644,
                    dev: 0,
                };

        crate::tests::make_compact_test_data(syscalls::SYS_mknodat, 203, -1, &data)
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

        let data = PivotRootData { new_root, put_old };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_pivot_root,
            1000,
            0,
            &data,
        )
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

        let data = PivotRootData { new_root, put_old };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_pivot_root,
            1001,
            -1,
            &data,
        )
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

        let data = ChrootData { path };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_chroot, 1002, 0, &data)
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

        let data = ChrootData { path };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_chroot, 1003, -1, &data)
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

        let data = OpenTreeData {
                    dfd: libc::AT_FDCWD,
                    pathname,
                    flags: 1,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_open_tree, 1004, 5, &data)
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

        let data = MountData {
                    source,
                    target,
                    filesystemtype,
                    mountflags: libc::MS_RDONLY,
                    data: 0,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mount, 1005, 0, &data)
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

        let data = MountData {
                    source,
                    target,
                    filesystemtype,
                    mountflags: libc::MS_NOSUID | libc::MS_NODEV,
                    data: 0x12345678,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mount, 1006, 0, &data)
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

        let data = MountData {
                    source,
                    target,
                    filesystemtype,
                    mountflags: 0,
                    data: 0,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mount, 1007, 0, &data)
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

        let data = Umount2Data {
            target,
            flags: libc::MNT_FORCE,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_umount2, 1008, 0, &data)
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

        let data = Umount2Data {
            target,
            flags: libc::MNT_DETACH,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_umount2, 1009, 0, &data)
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

        let data = MountSetattrData {
                    dfd: libc::AT_FDCWD,
                    path,
                    flags: 0x8000,
                    size: std::mem::size_of::<MountAttr>(),
                    has_attr: true,
                    attr: MountAttr {
                        attr_set: 0x1 | 0x2,
                        attr_clr: 0x4,
                        propagation: libc::MS_SHARED,
                        userns_fd: 42,
                    },
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mount_setattr, 1010, 0, &data)
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

        let data = MoveMountData {
                    from_dfd: libc::AT_FDCWD,
                    from_pathname,
                    to_dfd: libc::AT_FDCWD,
                    to_pathname,
                    flags: 0x00000001,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_move_mount, 1011, 0, &data)
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

        let data = MoveMountData {
                    from_dfd: 5,
                    from_pathname,
                    to_dfd: 7,
                    to_pathname,
                    flags: 0,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_move_mount, 1012, -1, &data)
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

        let data = SwaponData { pathname, flags: 0 };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_swapon, 1013, 0, &data)
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

        let data = SwaponData {
            pathname,
            flags: 0x8005,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_swapon, 1014, 0, &data)
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

        let data = SwaponData {
            pathname,
            flags: 0x10000,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_swapon, 1015, -1, &data)
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

        let data = SwapoffData { pathname };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_swapoff, 1016, 0, &data)
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

        let data = SwapoffData { pathname };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_swapoff, 1017, -1, &data)
    },
    "1017 swapoff(pathname: \"/dev/sda2\") = -1 (error)\n"
);

syscall_test!(
    parse_fstatfs_success,
    {
        use pinchy_common::{FstatfsData, kernel_types::Statfs};

        let mut data = FstatfsData {
            fd: 5,
            statfs: Statfs::default(),
        };

        data.statfs.f_type = libc::EXT4_SUPER_MAGIC;
        data.statfs.f_bsize = 4096;
        data.statfs.f_blocks = 1048576;
        data.statfs.f_bfree = 524288;
        data.statfs.f_bavail = 524288;

        make_compact_test_data(syscalls::SYS_fstatfs, 123, 0, &data)
    },
    "123 fstatfs(fd: 5, buf: { type: EXT4_SUPER_MAGIC (0xef53), block_size: 4096, blocks: 1048576, blocks_free: 524288, blocks_available: 524288, files: 0, files_free: 0, fsid: [0, 0], name_max: 0, fragment_size: 0, mount_flags: 0x0 }) = 0 (success)\n"
);

syscall_test!(
    parse_statfs_error,
    {
        use pinchy_common::{kernel_types::Statfs, StatfsData};

        let mut data = StatfsData {
            pathname: [0u8; DATA_READ_SIZE],
            statfs: Statfs::default(),
        };

        let path = c"/mnt/data".to_bytes_with_nul();
        data.pathname[..path.len()].copy_from_slice(path);
        data.statfs.f_type = libc::TMPFS_MAGIC;
        data.statfs.f_bsize = 4096;
        data.statfs.f_blocks = 1024000;
        data.statfs.f_bfree = 512000;
        data.statfs.f_bavail = 512000;
        data.statfs.f_files = 65536;
        data.statfs.f_ffree = 65000;
        data.statfs.f_namelen = 255;
        data.statfs.f_flags = (libc::ST_NOEXEC | libc::ST_RDONLY) as i64;

        make_compact_test_data(SYS_statfs, 44, -1, &data)
    },
    "44 statfs(pathname: \"/mnt/data\", buf: <unavailable>) = -1 (error)\n"
);

syscall_test!(
    parse_fsopen_success,
    {
        use pinchy_common::FsopenData;
        let mut fsname = [0u8; DATA_READ_SIZE];
        let name_bytes = b"ext4\0";
        fsname[..name_bytes.len()].copy_from_slice(name_bytes);

        let data = FsopenData { fsname, flags: 0 };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_fsopen, 456, 7, &data)
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

        let data = FsconfigData {
                    fd: 7,
                    cmd: 0,
                    key,
                    value,
                    aux: 0,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_fsconfig, 789, 0, &data)
    },
    "789 fsconfig(fd: 7, cmd: FSCONFIG_SET_FLAG, key: \"source\", value: \"/dev/sda1\", aux: 0) = 0 (success)\n"
);

syscall_test!(
    parse_fsmount_success,
    {
        use pinchy_common::FsmountData;

        let data = FsmountData {
            fd: 7,
            flags: 0,
            attr_flags: 0,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_fsmount, 101, 8, &data)
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

        let data = FspickData {
            dfd: -100,
            path,
            flags: 0,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_fspick, 202, 9, &data)
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

        let data = FsopenData {
            fsname,
            flags: fs_constants::FSOPEN_CLOEXEC,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_fsopen, 456, 7, &data)
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

        let data = FsconfigData {
                    fd: 7,
                    cmd: fs_constants::FSCONFIG_SET_STRING,
                    key,
                    value,
                    aux: 0,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_fsconfig, 789, 0, &data)
    },
    "789 fsconfig(fd: 7, cmd: FSCONFIG_SET_STRING, key: \"source\", value: \"/dev/sda1\", aux: 0) = 0 (success)\n"
);

syscall_test!(
    parse_fsmount_with_flags,
    {

        use pinchy_common::FsmountData;

        use crate::format_helpers::fs_constants;

        let data = FsmountData {
                    fd: 7,
                    flags: fs_constants::FSMOUNT_CLOEXEC,
                    attr_flags: libc::MOUNT_ATTR_RDONLY as u32 | libc::MOUNT_ATTR_NOSUID as u32,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_fsmount, 101, 8, &data)
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

        let data = FspickData {
                    dfd: -100,
                    path,
                    flags: fs_constants::FSPICK_CLOEXEC | fs_constants::FSPICK_SYMLINK_NOFOLLOW,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_fspick, 202, 9, &data)
    },
    "202 fspick(dfd: AT_FDCWD, path: \"/mnt/test\", flags: 0x3 (FSPICK_CLOEXEC|FSPICK_SYMLINK_NOFOLLOW)) = 9 (fd)\n"
);

syscall_test!(
    parse_fallocate_default_mode,
    {
        let data = FallocateData {
            fd: 5,
            mode: 0,
            offset: 1024,
            size: 4096,
        };

        crate::tests::make_compact_test_data(SYS_fallocate, 123, 0, &data)
    },
    "123 fallocate(fd: 5, mode: 0, offset: 1024, size: 4096) = 0 (success)\n"
);

syscall_test!(
    parse_fallocate_keep_size,
    {
        let data = FallocateData {
            fd: 8,
            mode: libc::FALLOC_FL_KEEP_SIZE,
            offset: 0,
            size: 2048,
        };

        crate::tests::make_compact_test_data(SYS_fallocate, 456, 0, &data)
    },
    "456 fallocate(fd: 8, mode: 0x1 (FALLOC_FL_KEEP_SIZE), offset: 0, size: 2048) = 0 (success)\n"
);

syscall_test!(
    parse_fallocate_punch_hole,
    {
        let data = FallocateData {
                    fd: 12,
                    mode: libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                    offset: 512,
                    size: 1024,
                };

        crate::tests::make_compact_test_data(SYS_fallocate, 789, 0, &data)
    },
    "789 fallocate(fd: 12, mode: 0x3 (FALLOC_FL_KEEP_SIZE|FALLOC_FL_PUNCH_HOLE), offset: 512, size: 1024) = 0 (success)\n"
);

syscall_test!(
    parse_fallocate_error,
    {
        let data = FallocateData {
                    fd: 3,
                    mode: libc::FALLOC_FL_ZERO_RANGE,
                    offset: 100,
                    size: 500,
                };

        crate::tests::make_compact_test_data(SYS_fallocate, 999, -1, &data)
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

        let data = LinkData { oldpath, newpath };

        crate::tests::make_compact_test_data(SYS_link, 801, 0, &data)
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

        let data = LinkData { oldpath, newpath };

        crate::tests::make_compact_test_data(SYS_link, 801, -1, &data)
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

        let data = LinkatData {
            olddirfd: libc::AT_FDCWD,
            oldpath,
            newdirfd: libc::AT_FDCWD,
            newpath,
            flags: 0,
        };

        make_compact_test_data(SYS_linkat, 901, 0, &data)
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

        let data = LinkatData {
            olddirfd: 5,
            oldpath,
            newdirfd: 6,
            newpath,
            flags: libc::AT_SYMLINK_FOLLOW,
        };

        make_compact_test_data(SYS_linkat, 951, 0, &data)
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

        let data = LinkatData {
            olddirfd: libc::AT_FDCWD,
            oldpath,
            newdirfd: libc::AT_FDCWD,
            newpath,
            flags: 0,
        };

        make_compact_test_data(SYS_linkat, 901, -1, &data)
    },
    "901 linkat(olddirfd: AT_FDCWD, oldpath: \"nonexistent\", newdirfd: AT_FDCWD, newpath: \"link\", flags: 0) = -1 (error)\n"
);

// Use fanotify constants directly from libc

syscall_test!(
    parse_fanotify_init_success,
    {
        let data = FanotifyInitData {
            flags: 0,
            event_f_flags: libc::O_RDONLY as u32,
        };

        crate::tests::make_compact_test_data(SYS_fanotify_init, 9000, 3, &data)
    },
    "9000 fanotify_init(flags: 0, event_f_flags: 0x0 (O_RDONLY)) = 3 (fd)\n"
);

syscall_test!(
    parse_fanotify_init_with_flags,
    {
        let data = FanotifyInitData {
                    flags: libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
                    event_f_flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u32,
                };

        crate::tests::make_compact_test_data(SYS_fanotify_init, 9001, 4, &data)
    },
    "9001 fanotify_init(flags: 0x3 (CLASS_NOTIF|CLOEXEC|NONBLOCK), event_f_flags: 0x80800 (O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NDELAY)) = 4 (fd)\n"
);

syscall_test!(
    parse_fanotify_init_error,
    {
        let data = FanotifyInitData {
            flags: 0,
            event_f_flags: libc::O_RDONLY as u32,
        };

        crate::tests::make_compact_test_data(SYS_fanotify_init, 9002, -1, &data)
    },
    "9002 fanotify_init(flags: 0, event_f_flags: 0x0 (O_RDONLY)) = -1 (error)\n"
);

syscall_test!(
    parse_fanotify_mark_success,
    {

        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"/tmp/watch";
        pathname[..path.len()].copy_from_slice(path);

        let data = FanotifyMarkData {
                    fanotify_fd: 3,
                    flags: libc::FAN_MARK_ADD,
                    mask: libc::FAN_ACCESS | libc::FAN_MODIFY,
                    dirfd: libc::AT_FDCWD,
                    pathname,
                };

        crate::tests::make_compact_test_data(SYS_fanotify_mark, 9100, 0, &data)
    },
    "9100 fanotify_mark(fanotify_fd: 3, flags: 0x1 (INODE|ADD), mask: 0x3 (ACCESS|MODIFY), dirfd: AT_FDCWD, pathname: \"/tmp/watch\") = 0 (success)\n"
);

syscall_test!(
    parse_fanotify_mark_with_dirfd,
    {

        let mut pathname = [0u8; DATA_READ_SIZE];
        let path = b"subdir/file.txt";
        pathname[..path.len()].copy_from_slice(path);

        let data = FanotifyMarkData {
                    fanotify_fd: 4,
                    flags: libc::FAN_MARK_ADD | libc::FAN_MARK_DONT_FOLLOW,
                    mask: libc::FAN_OPEN | libc::FAN_CLOSE_WRITE,
                    dirfd: 5,
                    pathname,
                };

        crate::tests::make_compact_test_data(SYS_fanotify_mark, 9101, 0, &data)
    },
    "9101 fanotify_mark(fanotify_fd: 4, flags: 0x5 (INODE|ADD|DONT_FOLLOW), mask: 0x28 (CLOSE_WRITE|OPEN), dirfd: 5, pathname: \"subdir/file.txt\") = 0 (success)\n"
);

syscall_test!(
    parse_fanotify_mark_error,
    {

        let pathname = [0u8; DATA_READ_SIZE];

        let data = FanotifyMarkData {
                    fanotify_fd: 999,
                    flags: libc::FAN_MARK_ADD,
                    mask: libc::FAN_ACCESS,
                    dirfd: libc::AT_FDCWD,
                    pathname,
                };

        crate::tests::make_compact_test_data(SYS_fanotify_mark, 9102, -9, &data)
    },
    "9102 fanotify_mark(fanotify_fd: 999, flags: 0x1 (INODE|ADD), mask: 0x1 (ACCESS), dirfd: AT_FDCWD, pathname: (null)) = -9 (error)\n"
);

syscall_test!(
    parse_name_to_handle_at_success,
    {

        let mut pathname = [0u8; DATA_READ_SIZE];
        let p = b"/tmp/test_file.txt";
        pathname[..p.len()].copy_from_slice(p);

        let data = NameToHandleAtData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    handle: 0x7fff12345678,
                    mount_id: 0x7fff87654321,
                    flags: libc::AT_SYMLINK_FOLLOW,
                };

        crate::tests::make_compact_test_data(SYS_name_to_handle_at, 9200, 0, &data)
    },
    "9200 name_to_handle_at(dirfd: AT_FDCWD, pathname: \"/tmp/test_file.txt\", handle: 0x7fff12345678, mount_id: 0x7fff87654321, flags: AT_SYMLINK_FOLLOW (0x400)) = 0 (success)\n"
);

syscall_test!(
    parse_name_to_handle_at_empty_path,
    {

        let pathname = [0u8; DATA_READ_SIZE];

        let data = NameToHandleAtData {
                    dirfd: 5,
                    pathname,
                    handle: 0x7fff00000000,
                    mount_id: 0x7fff11111111,
                    flags: libc::AT_EMPTY_PATH,
                };

        crate::tests::make_compact_test_data(SYS_name_to_handle_at, 9201, 0, &data)
    },
    "9201 name_to_handle_at(dirfd: 5, pathname: (null), handle: 0x7fff00000000, mount_id: 0x7fff11111111, flags: AT_EMPTY_PATH (0x1000)) = 0 (success)\n"
);

syscall_test!(
    parse_name_to_handle_at_error,
    {

        let mut pathname = [0u8; DATA_READ_SIZE];
        let p = b"/nonexistent";
        pathname[..p.len()].copy_from_slice(p);

        let data = NameToHandleAtData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    handle: 0,
                    mount_id: 0,
                    flags: 0,
                };

        crate::tests::make_compact_test_data(SYS_name_to_handle_at, 9202, -2, &data)
    },
    "9202 name_to_handle_at(dirfd: AT_FDCWD, pathname: \"/nonexistent\", handle: 0x0, mount_id: 0x0, flags: 0) = -2 (error)\n"
);

syscall_test!(
    parse_open_by_handle_at_success,
    {
        let data = OpenByHandleAtData {
            mount_fd: 3,
            handle: 0x7fff12345678,
            flags: libc::O_RDONLY,
        };

        crate::tests::make_compact_test_data(SYS_open_by_handle_at, 9300, 7, &data)
    },
    "9300 open_by_handle_at(mount_fd: 3, handle: 0x7fff12345678, flags: 0x0 (O_RDONLY)) = 7 (fd)\n"
);

syscall_test!(
    parse_open_by_handle_at_rdwr,
    {
        let data = OpenByHandleAtData {
                    mount_fd: libc::AT_FDCWD,
                    handle: 0x7fff87654321,
                    flags: libc::O_RDWR | libc::O_CLOEXEC,
                };

        crate::tests::make_compact_test_data(SYS_open_by_handle_at, 9301, 8, &data)
    },
    "9301 open_by_handle_at(mount_fd: AT_FDCWD, handle: 0x7fff87654321, flags: 0x80002 (O_RDWR|O_CLOEXEC)) = 8 (fd)\n"
);

syscall_test!(
    parse_open_by_handle_at_error,
    {
        let data = OpenByHandleAtData {
                    mount_fd: 999,
                    handle: 0xbadbadbad,
                    flags: libc::O_RDONLY,
                };

        crate::tests::make_compact_test_data(SYS_open_by_handle_at, 9302, -1, &data)
    },
    "9302 open_by_handle_at(mount_fd: 999, handle: 0xbadbadbad, flags: 0x0 (O_RDONLY)) = -1 (error)\n"
);

syscall_test!(
    parse_copy_file_range_success,
    {
        let data = CopyFileRangeData {
                    fd_in: 3,
                    off_in: 0x1000,
                    off_in_is_null: 0,
                    fd_out: 4,
                    off_out: 0x2000,
                    off_out_is_null: 0,
                    len: 4096,
                    flags: 0,
                };

        crate::tests::make_compact_test_data(SYS_copy_file_range, 9400, 4096, &data)
    },
    "9400 copy_file_range(fd_in: 3, off_in: 4096, fd_out: 4, off_out: 8192, len: 4096, flags: 0) = 4096 (bytes)\n"
);

syscall_test!(
    parse_copy_file_range_null_offsets,
    {
        let data = CopyFileRangeData {
                    fd_in: 5,
                    off_in: 0,
                    off_in_is_null: 1,
                    fd_out: 6,
                    off_out: 0,
                    off_out_is_null: 1,
                    len: 8192,
                    flags: 0,
                };

        crate::tests::make_compact_test_data(SYS_copy_file_range, 9401, 1024, &data)
    },
    "9401 copy_file_range(fd_in: 5, off_in: NULL, fd_out: 6, off_out: NULL, len: 8192, flags: 0) = 1024 (bytes)\n"
);

syscall_test!(
    parse_copy_file_range_error,
    {
        let data = CopyFileRangeData {
                    fd_in: 999,
                    off_in: 0,
                    off_in_is_null: 1,
                    fd_out: 998,
                    off_out: 0,
                    off_out_is_null: 1,
                    len: 0,
                    flags: 0,
                };

        crate::tests::make_compact_test_data(SYS_copy_file_range, 9402, -1, &data)
    },
    "9402 copy_file_range(fd_in: 999, off_in: NULL, fd_out: 998, off_out: NULL, len: 0, flags: 0) = -1 (error)\n"
);

syscall_test!(
    parse_sync_file_range_success,
    {
        let data = SyncFileRangeData {
                    fd: 3,
                    offset: 0,
                    nbytes: 4096,
                    flags: libc::SYNC_FILE_RANGE_WRITE,
                };

        crate::tests::make_compact_test_data(SYS_sync_file_range, 9500, 0, &data)
    },
    "9500 sync_file_range(fd: 3, offset: 0, nbytes: 4096, flags: 0x2 (SYNC_FILE_RANGE_WRITE)) = 0 (success)\n"
);

syscall_test!(
    parse_sync_file_range_all_flags,
    {
        let data = SyncFileRangeData {
                    fd: 5,
                    offset: 1024,
                    nbytes: 8192,
                    flags: libc::SYNC_FILE_RANGE_WAIT_BEFORE
                        | libc::SYNC_FILE_RANGE_WRITE
                        | libc::SYNC_FILE_RANGE_WAIT_AFTER,
                };

        crate::tests::make_compact_test_data(SYS_sync_file_range, 9501, 0, &data)
    },
    "9501 sync_file_range(fd: 5, offset: 1024, nbytes: 8192, flags: 0x7 (SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE|SYNC_FILE_RANGE_WAIT_AFTER)) = 0 (success)\n"
);

syscall_test!(
    parse_sync_file_range_error,
    {
        let data = SyncFileRangeData {
            fd: 999,
            offset: 0,
            nbytes: 0,
            flags: 0,
        };

        crate::tests::make_compact_test_data(SYS_sync_file_range, 9502, -9, &data)
    },
    "9502 sync_file_range(fd: 999, offset: 0, nbytes: 0, flags: 0) = -9 (error)\n"
);

syscall_test!(
    parse_syncfs_success,
    {
        let data = SyncfsData { fd: 3 };

        crate::tests::make_compact_test_data(SYS_syncfs, 9600, 0, &data)
    },
    "9600 syncfs(fd: 3) = 0 (success)\n"
);

syscall_test!(
    parse_syncfs_error,
    {
        let data = SyncfsData { fd: 999 };

        crate::tests::make_compact_test_data(SYS_syncfs, 9601, -9, &data)
    },
    "9601 syncfs(fd: 999) = -9 (error)\n"
);

syscall_test!(
    parse_utimensat_success,
    {

        let mut pathname = [0u8; DATA_READ_SIZE];
        let p = b"/tmp/file.txt";
        pathname[..p.len()].copy_from_slice(p);

        let data = UtimensatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    times: [
                        Timespec {
                            seconds: 1234567890,
                            nanos: 123456789,
                        },
                        Timespec {
                            seconds: 1234567891,
                            nanos: 987654321,
                        },
                    ],
                    times_is_null: 0,
                    flags: 0,
                };

        crate::tests::make_compact_test_data(SYS_utimensat, 9700, 0, &data)
    },
    "9700 utimensat(dirfd: AT_FDCWD, pathname: \"/tmp/file.txt\", times: [{secs: 1234567890, nanos: 123456789}, {secs: 1234567891, nanos: 987654321}], flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_utimensat_null_times,
    {

        let mut pathname = [0u8; DATA_READ_SIZE];
        let p = b"/var/log/app.log";
        pathname[..p.len()].copy_from_slice(p);

        let data = UtimensatData {
                    dirfd: 5,
                    pathname,
                    times: [Timespec::default(); 2],
                    times_is_null: 1,
                    flags: libc::AT_SYMLINK_NOFOLLOW,
                };

        crate::tests::make_compact_test_data(SYS_utimensat, 9701, 0, &data)
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

        let data = UtimensatData {
                    dirfd: libc::AT_FDCWD,
                    pathname,
                    times: [
                        Timespec {
                            seconds: 0,
                            nanos: time_constants::UTIME_NOW,
                        },
                        Timespec {
                            seconds: 0,
                            nanos: time_constants::UTIME_OMIT,
                        },
                    ],
                    times_is_null: 0,
                    flags: 0,
                };

        crate::tests::make_compact_test_data(SYS_utimensat, 9702, -2, &data)
    },
    "9702 utimensat(dirfd: AT_FDCWD, pathname: \"/nonexistent\", times: [UTIME_NOW, UTIME_OMIT], flags: 0) = -2 (error)\n"
);

syscall_test!(
    parse_quotactl_getquota,
    {
        use pinchy_common::{MEDIUM_READ_SIZE, QuotactlData};
        let mut data = QuotactlData {
            op: pinchy_common::Q_GETQUOTA,
            special: [0u8; MEDIUM_READ_SIZE],
            id: 1000,
            addr: 0x7fff87654321,
        };
        let special = b"/dev/sda1\0";
        data.special[..special.len()].copy_from_slice(special);

        crate::tests::make_compact_test_data(SYS_quotactl, 10001, 0, &data)
    },
    "10001 quotactl(op: 0x800007 (QCMD(Q_GETQUOTA, USRQUOTA)), special: \"/dev/sda1\", id: 1000, addr: 0x7fff87654321) = 0 (success)\n"
);

syscall_test!(
    parse_quotactl_getnextquota,
    {
        use pinchy_common::{MEDIUM_READ_SIZE, QuotactlData};
        let mut data = QuotactlData {
            op: pinchy_common::Q_GETNEXTQUOTA,
            special: [0u8; MEDIUM_READ_SIZE],
            id: 100,
            addr: 0x7fff00002000,
        };
        let special = b"/dev/sdb1\0";
        data.special[..special.len()].copy_from_slice(special);

        crate::tests::make_compact_test_data(SYS_quotactl, 10002, 0, &data)
    },
    "10002 quotactl(op: 0x800009 (QCMD(Q_GETNEXTQUOTA, USRQUOTA)), special: \"/dev/sdb1\", id: 100, addr: 0x7fff00002000) = 0 (success)\n"
);

syscall_test!(
    parse_quotactl_sync,
    {
        use pinchy_common::{MEDIUM_READ_SIZE, QuotactlData};
        let mut data = QuotactlData {
            op: pinchy_common::Q_SYNC,
            special: [0u8; MEDIUM_READ_SIZE],
            id: 0,
            addr: 0,
        };
        let special = b"/\0";
        data.special[..special.len()].copy_from_slice(special);

        crate::tests::make_compact_test_data(SYS_quotactl, 10003, 0, &data)
    },
    "10003 quotactl(op: 0x800001 (QCMD(Q_SYNC, USRQUOTA)), special: \"/\", id: 0, addr: 0x0) = 0 (success)\n"
);

syscall_test!(
    parse_quotactl_error,
    {
        use pinchy_common::{MEDIUM_READ_SIZE, QuotactlData};
        let mut data = QuotactlData {
            op: pinchy_common::Q_GETINFO,
            special: [0u8; MEDIUM_READ_SIZE],
            id: 500,
            addr: 0x7fff00003000,
        };
        let special = b"/dev/sdc1\0";
        data.special[..special.len()].copy_from_slice(special);

        crate::tests::make_compact_test_data(SYS_quotactl, 10004, -1, &data)
    },
    "10004 quotactl(op: 0x800005 (QCMD(Q_GETINFO, USRQUOTA)), special: \"/dev/sdc1\", id: 500, addr: 0x7fff00003000) = -1 (error)\n"
);

syscall_test!(
    parse_quotactl_fd_getquota,
    {
        let data = QuotactlFdData {
                    fd: 3,
                    cmd: pinchy_common::Q_GETQUOTA as u32,
                    id: 1000,
                    addr: 0x7fff12340000,
                };

        crate::tests::make_compact_test_data(SYS_quotactl_fd, 10005, 0, &data)
    },
    "10005 quotactl_fd(fd: 3, cmd: 0x800007 (QCMD(Q_GETQUOTA, USRQUOTA)), id: 1000, addr: 0x7fff12340000) = 0 (success)\n"
);

syscall_test!(
    parse_quotactl_fd_xfs,
    {
        let data = QuotactlFdData {
                    fd: 5,
                    cmd: pinchy_common::Q_XGETQUOTA as u32,
                    id: 2000,
                    addr: 0x7fff56780000,
                };

        crate::tests::make_compact_test_data(SYS_quotactl_fd, 10006, 0, &data)
    },
    "10006 quotactl_fd(fd: 5, cmd: 0x5803 (Q_XGETQUOTA), id: 2000, addr: 0x7fff56780000) = 0 (success)\n"
);

syscall_test!(
    parse_quotactl_getquota_grpquota,
    {
        use pinchy_common::{MEDIUM_READ_SIZE, QuotactlData};
        let mut data = QuotactlData {
            op: (((pinchy_common::Q_GETQUOTA as i64) << 8) | 1) as i32,
            special: [0u8; MEDIUM_READ_SIZE],
            id: 500,
            addr: 0x7fff11111111,
        };
        let special = b"/dev/sda1\0";
        data.special[..special.len()].copy_from_slice(special);

        crate::tests::make_compact_test_data(SYS_quotactl, 10007, 0, &data)
    },
    "10007 quotactl(op: 0x80000701 (QCMD(Q_GETQUOTA, GRPQUOTA)), special: \"/dev/sda1\", id: 500, addr: 0x7fff11111111) = 0 (success)\n"
);

syscall_test!(
    parse_quotactl_setquota_prjquota,
    {
        use pinchy_common::{MEDIUM_READ_SIZE, QuotactlData};
        let mut data = QuotactlData {
            op: (((pinchy_common::Q_SETQUOTA as i64) << 8) | 2) as i32,
            special: [0u8; MEDIUM_READ_SIZE],
            id: 1001,
            addr: 0x7fff22222222,
        };
        let special = b"/dev/sdc1\0";
        data.special[..special.len()].copy_from_slice(special);

        crate::tests::make_compact_test_data(SYS_quotactl, 10008, 0, &data)
    },
    "10008 quotactl(op: 0x80000802 (QCMD(Q_SETQUOTA, PRJQUOTA)), special: \"/dev/sdc1\", id: 1001, addr: 0x7fff22222222) = 0 (success)\n"
);

syscall_test!(
    parse_lookup_dcookie_success,
    {
        let data = LookupDcookieData {
                    cookie: 0x123456789abcdef0,
                    buffer: *b"/proc/sys\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    size: 64,
                };

        crate::tests::make_compact_test_data(SYS_lookup_dcookie, 123, 10, &data)
    },
    "123 lookup_dcookie(cookie: 1311768467463790320, buffer: \"/proc/sys\", size: 64) = 10 (bytes)\n"
);

syscall_test!(
    parse_lookup_dcookie_error,
    {
        let data = LookupDcookieData {
            cookie: 0x123456789abcdef0,
            buffer: [0; MEDIUM_READ_SIZE],
            size: 64,
        };

        crate::tests::make_compact_test_data(SYS_lookup_dcookie, 123, -1, &data)
    },
    "123 lookup_dcookie(cookie: 1311768467463790320, buffer: \"\", size: 64) = -1 (error)\n"
);

syscall_test!(
    parse_nfsservctl_success,
    {
        let data = NfsservctlData {
            cmd: 1,
            argp: 0x7fff1000,
            resp: 0x7fff2000,
        };

        crate::tests::make_compact_test_data(SYS_nfsservctl, 123, 0, &data)
    },
    "123 nfsservctl(cmd: 1, argp: 0x7fff1000, resp: 0x7fff2000) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_utime_with_times,
    {

        use pinchy_common::kernel_types::Utimbuf;

        let data = UtimeData {
                    filename: {
                        let mut filename = [0u8; DATA_READ_SIZE];
                        let name = b"/tmp/foo";
                        filename[..name.len()].copy_from_slice(name);

                        filename
                    },
                    times: Utimbuf {
                        actime: 1234567890,
                        modtime: 1234567900,
                    },
                    times_is_null: 0,
                };

        crate::tests::make_compact_test_data(SYS_utime, 123, 0, &data)
    },
    "123 utime(filename: \"/tmp/foo\", times: {actime: 1234567890, modtime: 1234567900}) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_utime_null_times,
    {
        use pinchy_common::kernel_types::Utimbuf;

        let data = UtimeData {
            filename: {
                let mut filename = [0u8; DATA_READ_SIZE];
                let name = b"/tmp/bar";
                filename[..name.len()].copy_from_slice(name);

                filename
            },
            times: Utimbuf::default(),
            times_is_null: 1,
        };

        crate::tests::make_compact_test_data(SYS_utime, 123, 0, &data)
    },
    "123 utime(filename: \"/tmp/bar\", times: NULL) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_access_success,
    {
        let data = AccessData {
            pathname: *b"/tmp/foo",
            mode: libc::R_OK | libc::W_OK,
        };

        crate::tests::make_compact_test_data(SYS_access, 123, 0, &data)
    },
    "123 access(pathname: \"/tmp/foo\" ... (truncated), mode: R_OK|W_OK) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_access_error,
    {
        let data = AccessData {
            pathname: *b"/root/.s",
            mode: libc::X_OK,
        };

        crate::tests::make_compact_test_data(SYS_access, 124, -1, &data)
    },
    "124 access(pathname: \"/root/.s\" ... (truncated), mode: X_OK) = -1 (error)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_access_f_ok,
    {
        let data = AccessData {
            pathname: *b"/tmp/tes",
            mode: libc::F_OK,
        };

        crate::tests::make_compact_test_data(SYS_access, 125, 0, &data)
    },
    "125 access(pathname: \"/tmp/tes\" ... (truncated), mode: F_OK) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_chmod_success,
    {
        let data = ChmodData {
            pathname: *b"/tmp/foo",
            mode: 0o755,
        };

        crate::tests::make_compact_test_data(SYS_chmod, 126, 0, &data)
    },
    "126 chmod(pathname: \"/tmp/foo\" ... (truncated), mode: 0o755 (rwxr-xr-x)) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_creat_success,
    {
        let data = CreatData {
            pathname: *b"/tmp/new",
            mode: 0o644,
        };

        crate::tests::make_compact_test_data(SYS_creat, 127, 3, &data)
    },
    "127 creat(pathname: \"/tmp/new\" ... (truncated), mode: 0o644 (rw-r--r--)) = 3 (fd)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_mkdir_success,
    {
        let data = MkdirData {
            pathname: *b"/tmp/dir",
            mode: 0o755,
        };

        crate::tests::make_compact_test_data(SYS_mkdir, 128, 0, &data)
    },
    "128 mkdir(pathname: \"/tmp/dir\" ... (truncated), mode: 0o755 (rwxr-xr-x)) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_readlink_success,
    {
        let data = ReadlinkData {
                    pathname: *b"/tmp/lnk",
                    buf: *b"/tmp/foo\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    bufsiz: 64,
                };

        crate::tests::make_compact_test_data(SYS_readlink, 128, 8, &data)
    },
    "128 readlink(pathname: \"/tmp/lnk\" ... (truncated), buf: \"/tmp/foo\", bufsiz: 64) = 8 (bytes)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_readlink_error,
    {
        let data = ReadlinkData {
            pathname: *b"/tmp/not",
            buf: [0; MEDIUM_READ_SIZE],
            bufsiz: 64,
        };

        crate::tests::make_compact_test_data(SYS_readlink, 129, -1, &data)
    },
    "129 readlink(pathname: \"/tmp/not\" ... (truncated), buf: \"\", bufsiz: 64) = -1 (error)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_stat_success,
    {
        let mut data = StatData {
            pathname: *b"/tmp/foo",
            statbuf: Stat::default(),
        };

        let stat_data = &mut data.statbuf;

        stat_data.st_mode = libc::S_IFREG | 0o644;
        stat_data.st_size = 1024;
        stat_data.st_uid = 1000;
        stat_data.st_gid = 1000;
        stat_data.st_blocks = 8;
        stat_data.st_blksize = 4096;
        stat_data.st_ino = 12345;

        crate::tests::make_compact_test_data(SYS_stat, 130, 0, &data)
    },
    &"130 stat(pathname: \"/tmp/foo\" ... (truncated), statbuf:, mode: 0o644 (rw-r--r--), ino: 12345, dev: 0, nlink: 0, uid: 1000, gid: 1000, size: 1024, blksize: 4096, blocks: 8, atime: 0, mtime: 0, ctime: 0) = 0 (success)\n".to_string()
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_lstat_success,
    {
        let mut data = LstatData {
            pathname: *b"/tmp/lnk",
            statbuf: Stat::default(),
        };

        let stat_data = &mut data.statbuf;

        stat_data.st_mode = libc::S_IFLNK | 0o777;
        stat_data.st_size = 8;
        stat_data.st_uid = 1000;
        stat_data.st_gid = 1000;
        stat_data.st_blocks = 0;
        stat_data.st_blksize = 4096;
        stat_data.st_ino = 54321;

        crate::tests::make_compact_test_data(SYS_lstat, 131, 0, &data)
    },
    &"131 lstat(pathname: \"/tmp/lnk\" ... (truncated), statbuf:, mode: 0o777 (rwxrwxrwx), ino: 54321, dev: 0, nlink: 0, uid: 1000, gid: 1000, size: 8, blksize: 4096, blocks: 0, atime: 0, mtime: 0, ctime: 0) = 0 (success)\n".to_string()
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_utimes_with_times,
    {

        use pinchy_common::kernel_types::Timeval;

        let data = UtimesData {
                    filename: *b"/tmp/foo",
                    times: [
                        Timeval {
                            tv_sec: 1234567890,
                            tv_usec: 123456,
                        },
                        Timeval {
                            tv_sec: 1234567900,
                            tv_usec: 654321,
                        },
                    ],
                    times_is_null: 0,
                };

        crate::tests::make_compact_test_data(SYS_utimes, 132, 0, &data)
    },
    "132 utimes(filename: \"/tmp/foo\" ... (truncated), times: [{tv_sec: 1234567890, tv_usec: 123456}, {tv_sec: 1234567900, tv_usec: 654321}]) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_utimes_null,
    {
        use pinchy_common::kernel_types::Timeval;

        let data = UtimesData {
            filename: *b"/tmp/bar",
            times: [Timeval::default(), Timeval::default()],
            times_is_null: 1,
        };

        crate::tests::make_compact_test_data(SYS_utimes, 133, 0, &data)
    },
    "133 utimes(filename: \"/tmp/bar\" ... (truncated), times: NULL) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_futimesat_with_times,
    {

        use pinchy_common::kernel_types::Timeval;

        let data = FutimesatData {
                    dirfd: libc::AT_FDCWD,
                    pathname: *b"/tmp/foo",
                    times: [
                        Timeval {
                            tv_sec: 1111111111,
                            tv_usec: 111111,
                        },
                        Timeval {
                            tv_sec: 2222222222,
                            tv_usec: 222222,
                        },
                    ],
                    times_is_null: 0,
                };

        crate::tests::make_compact_test_data(SYS_futimesat, 134, 0, &data)
    },
    "134 futimesat(dirfd: AT_FDCWD, pathname: \"/tmp/foo\" ... (truncated), times: [{tv_sec: 1111111111, tv_usec: 111111}, {tv_sec: 2222222222, tv_usec: 222222}]) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_futimesat_fd,
    {

        use pinchy_common::kernel_types::Timeval;

        let data = FutimesatData {
                    dirfd: 5,
                    pathname: *b"/tmp/foo",
                    times: [
                        Timeval {
                            tv_sec: 3333333333,
                            tv_usec: 333333,
                        },
                        Timeval {
                            tv_sec: 4444444444,
                            tv_usec: 444444,
                        },
                    ],
                    times_is_null: 0,
                };

        crate::tests::make_compact_test_data(SYS_futimesat, 135, 0, &data)
    },
    "135 futimesat(dirfd: 5, pathname: \"/tmp/foo\" ... (truncated), times: [{tv_sec: 3333333333, tv_usec: 333333}, {tv_sec: 4444444444, tv_usec: 444444}]) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_getdents_success,
    {
        let mut data = GetdentsData {
            fd: 3,
            count: 1024,
            dirents: [LinuxDirent::default(); 4],
            num_dirents: 2,
        };

        data.dirents[0].d_ino = 12345;
        data.dirents[0].d_off = 24;
        data.dirents[0].d_reclen = 24;
        data.dirents[0].d_name[0] = b'.';

        data.dirents[1].d_ino = 12346;
        data.dirents[1].d_off = 48;
        data.dirents[1].d_reclen = 24;
        data.dirents[1].d_name[0] = b'.';
        data.dirents[1].d_name[1] = b'.';

        crate::tests::make_compact_test_data(SYS_getdents, 200, 48, &data)
    },
    "200 getdents(fd: 3, count: 1024, entries: [ dirent { ino: 12345, off: 24, reclen: 24, name: \".\" }, dirent { ino: 12346, off: 48, reclen: 24, name: \"..\" } ]) = 48 (bytes)\n"
);
