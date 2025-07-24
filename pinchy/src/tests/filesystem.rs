// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::pin::Pin;

use pinchy_common::{
    syscalls::{
        SYS_faccessat, SYS_fstat, SYS_getcwd, SYS_getdents64, SYS_newfstatat, SYS_readlinkat,
        SYS_statfs,
    },
    FaccessatData, SyscallEvent, DATA_READ_SIZE, MEDIUM_READ_SIZE,
};

use crate::{
    events::handle_event,
    formatting::{Formatter, FormattingStyle},
};

#[tokio::test]
async fn parse_fstat() {
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

    // Set some representative values for the stat struct
    stat_data.st_mode = libc::S_IFREG | 0o644; // Regular file with rw-r--r-- permissions
    stat_data.st_size = 12345;
    stat_data.st_uid = 1000;
    stat_data.st_gid = 1000;
    stat_data.st_blocks = 24;
    stat_data.st_blksize = 4096;
    stat_data.st_ino = 9876543;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "33 fstat(fd: 5, struct stat: {{ mode: 0o644 (rw-r--r--), ino: 9876543, dev: 0, nlink: 0, uid: 1000, gid: 1000, size: 12345, blksize: 4096, blocks: 24, atime: 0, mtime: 0, ctime: 0 }}) = 0 (success)\n"
        )
    );

    // Test with an error return value
    event.return_value = -1;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "33 fstat(fd: 5, struct stat: {{ mode: 0o644 (rw-r--r--), ino: 9876543, dev: 0, nlink: 0, uid: 1000, gid: 1000, size: 12345, blksize: 4096, blocks: 24, atime: 0, mtime: 0, ctime: 0 }}) = -1 (error)\n"
        )
    );
}

#[tokio::test]
async fn parse_statfs() {
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

    // Setup pathname
    let path = c"/mnt/data".to_bytes_with_nul();
    statfs_data.pathname[..path.len()].copy_from_slice(path);

    // Set some representative values for the statfs struct
    statfs_data.statfs.f_type = 0x01021994; // TMPFS_MAGIC
    statfs_data.statfs.f_bsize = 4096;
    statfs_data.statfs.f_blocks = 1024000;
    statfs_data.statfs.f_bfree = 512000;
    statfs_data.statfs.f_bavail = 512000;
    statfs_data.statfs.f_files = 65536;
    statfs_data.statfs.f_ffree = 65000;
    statfs_data.statfs.f_namelen = 255;
    statfs_data.statfs.f_flags = (libc::ST_NOEXEC | libc::ST_RDONLY) as i64;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "44 statfs(pathname: \"/mnt/data\", buf: {{ type: TMPFS_MAGIC (0x1021994), block_size: 4096, blocks: 1024000, blocks_free: 512000, blocks_available: 512000, files: 65536, files_free: 65000, fsid: [0, 0], name_max: 255, fragment_size: 0, mount_flags: 0x9 (ST_RDONLY|ST_NOEXEC) }}) = 0\n"
        )
    );

    // Test with an error return value
    event.return_value = -1;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "44 statfs(pathname: \"/mnt/data\", buf: <unavailable>) = -1 (error)\n"
    );
}

#[tokio::test]
async fn parse_getdents64() {
    use pinchy_common::{kernel_types::LinuxDirent64, Getdents64Data};

    let mut event = SyscallEvent {
        syscall_nr: SYS_getdents64,
        pid: 55,
        tid: 55,
        return_value: 3, // Number of directory entries
        data: pinchy_common::SyscallEventData {
            getdents64: Getdents64Data {
                fd: 7,
                count: 1024,
                dirents: [LinuxDirent64::default(); 4],
                num_dirents: 3,
            },
        },
    };

    // Set up three directory entries
    {
        let getdents_data = unsafe { &mut event.data.getdents64 };

        // Set up first entry
        getdents_data.dirents[0].d_ino = 123456;
        getdents_data.dirents[0].d_off = 1;
        getdents_data.dirents[0].d_reclen = 24;
        getdents_data.dirents[0].d_type = 4; // DT_DIR

        // Add the "." directory name
        let dot = c".".to_bytes_with_nul();
        getdents_data.dirents[0].d_name[..dot.len()].copy_from_slice(dot);

        // Set up second entry
        getdents_data.dirents[1].d_ino = 123457;
        getdents_data.dirents[1].d_off = 2;
        getdents_data.dirents[1].d_reclen = 25;
        getdents_data.dirents[1].d_type = 4; // DT_DIR

        // Add the ".." directory name
        let dot_dot = c"..".to_bytes_with_nul();
        getdents_data.dirents[1].d_name[..dot_dot.len()].copy_from_slice(dot_dot);

        // Set up third entry
        getdents_data.dirents[2].d_ino = 123458;
        getdents_data.dirents[2].d_off = 3;
        getdents_data.dirents[2].d_reclen = 32;
        getdents_data.dirents[2].d_type = 8; // DT_REG - regular file

        // Add a filename
        let filename = c"file.txt".to_bytes();
        getdents_data.dirents[2].d_name[..filename.len()].copy_from_slice(filename);
    }

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "55 getdents64(fd: 7, count: 1024, entries: [ dirent {{ ino: 123456, off: 1, reclen: 24, type: 4, name: \".\" }}, dirent {{ ino: 123457, off: 2, reclen: 25, type: 4, name: \"..\" }}, dirent {{ ino: 123458, off: 3, reclen: 32, type: 8, name: \"file.txt\" ... (truncated) }} ]) = 3\n"
        )
    );

    // Test with zero entries
    event.return_value = 0;

    {
        let getdents_data = unsafe { &mut event.data.getdents64 };
        getdents_data.num_dirents = 0;
    }

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("55 getdents64(fd: 7, count: 1024, entries: [  ]) = 0\n")
    );
}

#[tokio::test]
async fn test_faccessat_syscall() {
    let mut pathname = [0u8; DATA_READ_SIZE];
    let path = b"/etc/hosts.conf";
    pathname[0..path.len()].copy_from_slice(path);

    let event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "1001 faccessat(dirfd: AT_FDCWD, pathname: \"/etc/hosts.conf\", mode: R_OK|W_OK, flags: 0) = 0 (success)\n"
        )
    );
}

#[tokio::test]
async fn test_faccessat_with_flags_syscall() {
    let mut pathname = [0u8; DATA_READ_SIZE];
    let path = b"/etc/hosts";
    pathname[0..path.len()].copy_from_slice(path);

    let event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1001 faccessat(dirfd: 3, pathname: \"/etc/hosts\", mode: F_OK, flags: AT_SYMLINK_NOFOLLOW (0x100)) = -1 (error)\n"
    );
}

#[tokio::test]
async fn parse_newfstatat() {
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

    // Set up a pathname
    let pathname = b"test_file.txt\0";
    let data = unsafe { &mut event.data.newfstatat };
    data.pathname[..pathname.len()].copy_from_slice(pathname);

    // Set some representative values for the stat struct
    let stat_data = unsafe { &mut event.data.newfstatat.stat };
    stat_data.st_mode = libc::S_IFREG | 0o755; // Regular file with rwxr-xr-x permissions
    stat_data.st_size = 54321;
    stat_data.st_uid = 500;
    stat_data.st_gid = 500;
    stat_data.st_blocks = 108;
    stat_data.st_blksize = 4096;
    stat_data.st_ino = 1234567;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "42 newfstatat(dirfd: AT_FDCWD, pathname: \"test_file.txt\", struct stat: {{ mode: 0o755 (rwxr-xr-x), ino: 1234567, dev: 0, nlink: 0, uid: 500, gid: 500, size: 54321, blksize: 4096, blocks: 108, atime: 0, mtime: 0, ctime: 0 }}, flags: AT_SYMLINK_NOFOLLOW (0x100)) = 0 (success)\n"
        )
    );

    // Test with an error return value
    event.return_value = -1;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "42 newfstatat(dirfd: AT_FDCWD, pathname: \"test_file.txt\", struct stat: <unavailable>, flags: AT_SYMLINK_NOFOLLOW (0x100)) = -1 (error)\n"
        )
    );

    // Test with different flags - no flags (0)
    event.return_value = 0;
    event.data.newfstatat.flags = 0;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "42 newfstatat(dirfd: AT_FDCWD, pathname: \"test_file.txt\", struct stat: {{ mode: 0o755 (rwxr-xr-x), ino: 1234567, dev: 0, nlink: 0, uid: 500, gid: 500, size: 54321, blksize: 4096, blocks: 108, atime: 0, mtime: 0, ctime: 0 }}, flags: 0) = 0 (success)\n"
        )
    );

    // Test with different dirfd - a regular file descriptor
    event.data.newfstatat.dirfd = 5;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "42 newfstatat(dirfd: 5, pathname: \"test_file.txt\", struct stat: {{ mode: 0o755 (rwxr-xr-x), ino: 1234567, dev: 0, nlink: 0, uid: 500, gid: 500, size: 54321, blksize: 4096, blocks: 108, atime: 0, mtime: 0, ctime: 0 }}, flags: 0) = 0 (success)\n"
        )
    );
}

#[tokio::test]
async fn test_readlinkat_event_parsing() {
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

    let event = SyscallEvent {
        syscall_nr: SYS_readlinkat,
        pid: 1234,
        tid: 5678,
        return_value: 0,
        data: pinchy_common::SyscallEventData { readlinkat },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "5678 readlinkat(dirfd: 3, pathname: \"/proc/self/exe\", buf: \"/usr/bin/pinchy\", bufsiz: 16) = 0\n"
        )
    );
}

#[tokio::test]
async fn parse_flistxattr() {
    use pinchy_common::{kernel_types::XattrList, syscalls::SYS_flistxattr, FlistxattrData};

    let mut xattr_list = XattrList::default();
    let names = b"user.attr1\0user.attr2\0";
    xattr_list.data[..names.len()].copy_from_slice(names);
    xattr_list.size = names.len();

    let event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    crate::events::handle_event(&event, formatter)
        .await
        .unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "42 flistxattr(fd: 7, list: [ user.attr1, user.attr2 ], size: 256) = 22\n"
    );
}

#[tokio::test]
async fn parse_listxattr() {
    use pinchy_common::{kernel_types::XattrList, syscalls::SYS_listxattr, ListxattrData};

    let mut xattr_list = XattrList::default();
    let names = b"user.attr1\0user.attr2\0";
    xattr_list.data[..names.len()].copy_from_slice(names);
    xattr_list.size = names.len();

    let event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    crate::events::handle_event(&event, formatter)
        .await
        .unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "43 listxattr(pathname: \"/tmp/testfile\", list: [ user.attr1, user.attr2 ], size: 128) = 22\n"
    );
}

#[tokio::test]
async fn parse_llistxattr() {
    use pinchy_common::{kernel_types::XattrList, syscalls::SYS_llistxattr, LlistxattrData};

    let mut xattr_list = XattrList::default();
    let names = b"user.attr1\0user.attr2\0";
    xattr_list.data[..names.len()].copy_from_slice(names);
    xattr_list.size = names.len();

    let event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    crate::events::handle_event(&event, formatter)
        .await
        .unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "44 llistxattr(pathname: \"/tmp/testlink\", list: [ user.attr1, user.attr2 ], size: 64) = 22\n"
    );
}

#[tokio::test]
async fn parse_getcwd() {
    use pinchy_common::GetcwdData;

    let mut event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "55 getcwd(buf: 0x7ffe12345000, size: 4096, path: \"/home/user/work\") = 16\n"
    );

    // Test with error return value
    event.return_value = -1;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "55 getcwd(buf: 0x7ffe12345000, size: 4096) = -1 (error)\n"
    );
}
