use std::pin::Pin;

use indoc::indoc;
use pinchy_common::{
    kernel_types::{EpollEvent, Rseq, RseqCs, Timespec, Utsname},
    CloseData, EpollPWaitData, ExecveData, FaccessatData, FutexData, IoctlData, LseekData,
    OpenAtData, PpollData, ReadData, SchedYieldData, SetRobustListData, SetTidAddressData,
    UnameData, WriteData, DATA_READ_SIZE, SMALL_READ_SIZE,
};

use super::*;
use crate::formatting::FormattingStyle;

#[tokio::test]
async fn parse_close() {
    let event = SyscallEvent {
        syscall_nr: SYS_close,
        pid: 1,
        tid: 1,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            close: CloseData { fd: 2 },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("1 close(fd: 2) = 0\n")
    );
}

#[tokio::test]
async fn parse_epoll_pwait() {
    let mut event = SyscallEvent {
        syscall_nr: SYS_epoll_pwait,
        pid: 1,
        tid: 1,
        return_value: 1,
        data: pinchy_common::SyscallEventData {
            epoll_pwait: EpollPWaitData {
                epfd: 4,
                events: [EpollEvent::default(); 8],
                max_events: 10,
                timeout: -1,
            },
        },
    };

    let epoll_events = unsafe { &mut event.data.epoll_pwait.events };
    epoll_events[0].data = 0xBEEF;
    epoll_events[0].events = (libc::POLLIN | libc::POLLERR | libc::POLLHUP) as u32;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("1 epoll_pwait(epfd: 4, events: [ epoll_event {{ events: POLLIN|POLLERR|POLLHUP, data: 0xbeef }} ], max_events: 10, timeout: -1, sigmask) = 1\n")
    );

    // Multi-line
    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::MultiLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        indoc! {"
                1
                \tepoll_pwait(
                \t    epfd: 4,
                \t    events: [
                \t        epoll_event {
                \t            events: POLLIN|POLLERR|POLLHUP,
                \t            data: 0xbeef
                \t        }
                \t    ],
                \t    max_events: 10,
                \t    timeout: -1,
                \t    sigmask
                \t) = 1
            "}
    );
}

#[tokio::test]
async fn parse_ppoll() {
    let mut event = SyscallEvent {
        syscall_nr: SYS_ppoll,
        pid: 22,
        tid: 22,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            ppoll: PpollData {
                fds: [0; 16],
                events: [0; 16],
                revents: [0; 16],
                nfds: 1,
                timeout: Timespec {
                    seconds: 0,
                    nanos: 0,
                },
            },
        },
    };

    let ppoll_data = unsafe { &mut event.data.ppoll };
    ppoll_data.fds[0] = 3;
    ppoll_data.events[0] = libc::POLLIN;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("22 ppoll(fds: [ {{ 3, POLLIN }} ], nfds: 1, timeout: {{ secs: 0, nanos: 0 }}, sigmask) = Timeout [0]\n")
    );
}

#[tokio::test]
async fn parse_read() {
    let mut event = SyscallEvent {
        syscall_nr: SYS_read,
        pid: 22,
        tid: 22,
        return_value: 8192,
        data: pinchy_common::SyscallEventData {
            read: ReadData {
                fd: 3,
                buf: [0u8; DATA_READ_SIZE],
                count: 8192,
            },
        },
    };

    let read_data = unsafe { &mut event.data.read };

    // A = 65
    read_data
        .buf
        .iter_mut()
        .zip((0..).flat_map(|n: u8| std::iter::repeat(n).take(10)))
        .for_each(|(b, i)| *b = (i + 65) as u8);

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("22 read(fd: 3, buf: \"AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFFGGGGGGGGGGHHHHHHHHHHIIIIIIIIIIJJJJJJJJJJKKKKKKKKKKLLLLLLLLLLMMMMMMMM\" ... (8064 more bytes), count: 8192) = 8192\n")
    );
}

#[tokio::test]
async fn parse_write() {
    let mut event = SyscallEvent {
        syscall_nr: SYS_write,
        pid: 22,
        tid: 22,
        return_value: 8192,
        data: pinchy_common::SyscallEventData {
            write: WriteData {
                fd: 3,
                buf: [0u8; DATA_READ_SIZE],
                count: 8192,
            },
        },
    };

    let write_data = unsafe { &mut event.data.write };

    // A = 65
    write_data
        .buf
        .iter_mut()
        .zip((0..).flat_map(|n: u8| std::iter::repeat(n).take(10)))
        .for_each(|(b, i)| *b = (i + 65) as u8);

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("22 write(fd: 3, buf: \"AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFFGGGGGGGGGGHHHHHHHHHHIIIIIIIIIIJJJJJJJJJJKKKKKKKKKKLLLLLLLLLLMMMMMMMM\" ... (8064 more bytes), count: 8192) = 8192\n")
    );
}

#[tokio::test]
async fn parse_lseek() {
    let event = SyscallEvent {
        syscall_nr: SYS_lseek,
        pid: 22,
        tid: 22,
        return_value: 18092,
        data: pinchy_common::SyscallEventData {
            lseek: LseekData {
                fd: 3,
                offset: 0,
                whence: libc::SEEK_END,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("22 lseek(fd: 3, offset: 0, whence: 2) = 18092\n")
    );
}

#[tokio::test]
async fn parse_sched_yield() {
    let event = SyscallEvent {
        syscall_nr: SYS_sched_yield,
        pid: 22,
        tid: 22,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            sched_yield: SchedYieldData {},
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("22 sched_yield() = 0\n")
    );
}

#[tokio::test]
async fn parse_openat() {
    let mut event = SyscallEvent {
        syscall_nr: SYS_openat,
        pid: 22,
        tid: 22,
        return_value: 3,
        data: pinchy_common::SyscallEventData {
            openat: OpenAtData {
                dfd: libc::AT_FDCWD,
                pathname: [0u8; DATA_READ_SIZE],
                flags: libc::O_RDONLY | libc::O_CLOEXEC,
                mode: 0o666,
            },
        },
    };

    let openat_data = unsafe { &mut event.data.openat };
    let path = c"/etc/passwd".to_bytes_with_nul();
    openat_data.pathname[..path.len()].copy_from_slice(&path);

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("22 openat(dfd: AT_FDCWD, pathname: \"/etc/passwd\", flags: 0x80000 (O_RDONLY|O_CLOEXEC), mode: 0o666 (rw-rw-rw-)) = 3\n")
    );
}

#[tokio::test]
async fn parse_futex() {
    let event = SyscallEvent {
        syscall_nr: SYS_futex,
        pid: 22,
        tid: 22,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            futex: FutexData {
                uaddr: 0xbeef,
                op: 10,
                val: 11,
                uaddr2: 0xbeef2,
                val3: 12,
                timeout: Timespec {
                    seconds: 13,
                    nanos: 14,
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
        format!("22 futex(uaddr: 0xbeef, op: 10, val: 11, uaddr2: 0xbeef2, val3: 12, timeout: {{ secs: 13, nanos: 14 }}) = 0\n")
    );
}

#[tokio::test]
async fn parse_ioctl() {
    let event = SyscallEvent {
        syscall_nr: SYS_ioctl,
        pid: 22,
        tid: 22,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            ioctl: IoctlData {
                fd: 4,
                request: 0x4332,
                arg: 0x0,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("22 ioctl(fd: 4, request: SNDRV_COMPRESS_START::sound, arg: 0x0) = 0\n")
    );
}

#[tokio::test]
async fn parse_execve() {
    let mut event = SyscallEvent {
        syscall_nr: SYS_execve,
        pid: 22,
        tid: 22,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            execve: ExecveData {
                filename: [0u8; SMALL_READ_SIZE * 4],
                filename_truncated: false,
                argv: [[0u8; SMALL_READ_SIZE]; 4],
                argv_len: [0u16; 4],
                argc: 0,
                envp: [[0u8; SMALL_READ_SIZE]; 2],
                envp_len: [0u16; 2],
                envc: 0,
            },
        },
    };

    let execve_data = unsafe { &mut event.data.execve };
    let filename = c"/bin/find".to_bytes_with_nul();
    execve_data.filename[..filename.len()].copy_from_slice(filename);

    let argv = [
        c"/etc".to_bytes_with_nul(),
        c"-name".to_bytes_with_nul(),
        c"org.pinc".to_bytes(),
    ];
    execve_data.argv[0][..argv[0].len()].copy_from_slice(argv[0]);
    execve_data.argv_len[0] = argv[0].len() as u16;

    execve_data.argv[1][..argv[1].len()].copy_from_slice(argv[1]);
    execve_data.argv_len[1] = argv[1].len() as u16;

    execve_data.argv[2][..argv[2].len()].copy_from_slice(argv[2]);
    execve_data.argv_len[2] = argv[2].len() as u16;

    execve_data.argc = 3;

    let envp = [c"HOME=/ro".to_bytes(), c"WAYLAND=".to_bytes()];
    execve_data.envp[0][..SMALL_READ_SIZE].copy_from_slice(&envp[0][..SMALL_READ_SIZE]);
    execve_data.envp_len[0] = envp[0].len() as u16;

    execve_data.envp[1][..SMALL_READ_SIZE].copy_from_slice(&envp[1][..SMALL_READ_SIZE]);
    execve_data.envp_len[1] = envp[1].len() as u16;

    execve_data.envc = 30;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("22 execve(filename: \"/bin/find\", argv: [/etc\0, -name\0, org.pinc], envp: [HOME=/ro, WAYLAND=, ... (28 more)]) = 0\n")
    );
}

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
            "33 fstat(fd: 5, struct stat: {{ mode: 0o644 (rw-r--r--), ino: 9876543, dev: 0, nlink: 0, uid: 1000, gid: 1000, size: 12345, blksize: 4096, blocks: 24, atime: 0, mtime: 0, ctime: 0 }}) = 0\n"
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
            "33 fstat(fd: 5, struct stat: {{ mode: 0o644 (rw-r--r--), ino: 9876543, dev: 0, nlink: 0, uid: 1000, gid: 1000, size: 12345, blksize: 4096, blocks: 24, atime: 0, mtime: 0, ctime: 0 }}) = -1\n"
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
    statfs_data.pathname[..path.len()].copy_from_slice(&path);

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
        format!("44 statfs(pathname: \"/mnt/data\", buf: <unavailable>) = -1\n")
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
        getdents_data.dirents[0].d_name[..dot.len()].copy_from_slice(&dot);

        // Set up second entry
        getdents_data.dirents[1].d_ino = 123457;
        getdents_data.dirents[1].d_off = 2;
        getdents_data.dirents[1].d_reclen = 25;
        getdents_data.dirents[1].d_type = 4; // DT_DIR

        // Add the ".." directory name
        let dot_dot = c"..".to_bytes_with_nul();
        getdents_data.dirents[1].d_name[..dot_dot.len()].copy_from_slice(&dot_dot);

        // Set up third entry
        getdents_data.dirents[2].d_ino = 123458;
        getdents_data.dirents[2].d_off = 3;
        getdents_data.dirents[2].d_reclen = 32;
        getdents_data.dirents[2].d_type = 8; // DT_REG - regular file

        // Add a filename
        let filename = c"file.txt".to_bytes();
        getdents_data.dirents[2].d_name[..filename.len()].copy_from_slice(&filename);
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
async fn parse_mmap() {
    use pinchy_common::MmapData;

    let event = SyscallEvent {
        syscall_nr: SYS_mmap,
        pid: 66,
        tid: 66,
        return_value: 0x7f1234567000, // A typical memory address returned by mmap
        data: pinchy_common::SyscallEventData {
            mmap: MmapData {
                addr: 0,
                length: 4096,
                prot: libc::PROT_READ | libc::PROT_WRITE,
                flags: libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                fd: -1,
                offset: 0,
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
            "66 mmap(addr: 0x0, length: 4096, prot: 0x3 (PROT_READ|PROT_WRITE), flags: 0x22 (MAP_PRIVATE|MAP_ANONYMOUS), fd: -1, offset: 0x0) = 0x7f1234567000\n"
        )
    );

    // Test with error return
    let event_error = SyscallEvent {
        syscall_nr: SYS_mmap,
        pid: 66,
        tid: 66,
        return_value: -1, // Error
        data: pinchy_common::SyscallEventData {
            mmap: MmapData {
                addr: 0x7f0000000000,
                length: 8192,
                prot: libc::PROT_EXEC,
                flags: libc::MAP_SHARED,
                fd: 5,
                offset: 4096,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event_error, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "66 mmap(addr: 0x7f0000000000, length: 8192, prot: 0x4 (PROT_EXEC), flags: 0x1 (MAP_SHARED), fd: 5, offset: 0x1000) = -1 (error)\n"
        )
    );
}

#[tokio::test]
async fn test_munmap_syscall() {
    use std::pin::Pin;

    use pinchy_common::{syscalls::SYS_munmap, MunmapData, SyscallEvent, SyscallEventData};

    use crate::formatting::{Formatter, FormattingStyle};

    let mut event = SyscallEvent {
        syscall_nr: SYS_munmap,
        pid: 123,
        tid: 123,
        return_value: 0, // Success
        data: SyscallEventData {
            munmap: MunmapData {
                addr: 0xffff8a9c2000,
                length: 57344,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("123 munmap(addr: 0xffff8a9c2000, length: 57344) = 0\n")
    );

    // Test with error return
    event.return_value = -1;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("123 munmap(addr: 0xffff8a9c2000, length: 57344) = -1\n")
    );
}

#[tokio::test]
async fn parse_mprotect() {
    use pinchy_common::MprotectData;

    let event = SyscallEvent {
        syscall_nr: SYS_mprotect,
        pid: 77,
        tid: 77,
        return_value: 0, // Success
        data: pinchy_common::SyscallEventData {
            mprotect: MprotectData {
                addr: 0x7f5678901000,
                length: 8192,
                prot: libc::PROT_READ | libc::PROT_EXEC,
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
            "77 mprotect(addr: 0x7f5678901000, length: 8192, prot: 0x5 (PROT_READ|PROT_EXEC)) = 0\n"
        )
    );

    // Test with error return value
    let event_error = SyscallEvent {
        syscall_nr: SYS_mprotect,
        pid: 77,
        tid: 77,
        return_value: -22, // EINVAL
        data: pinchy_common::SyscallEventData {
            mprotect: MprotectData {
                addr: 0x1000, // Invalid address (not page-aligned)
                length: 4096,
                prot: libc::PROT_WRITE,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event_error, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("77 mprotect(addr: 0x1000, length: 4096, prot: 0x2 (PROT_WRITE)) = -22\n")
    );
}

#[tokio::test]
async fn parse_getrandom() {
    use pinchy_common::GetrandomData;

    // Test successful getrandom call
    let mut event = SyscallEvent {
        syscall_nr: SYS_getrandom,
        pid: 555,
        tid: 555,
        return_value: 32, // Number of bytes written
        data: pinchy_common::SyscallEventData {
            getrandom: GetrandomData {
                buf: 0x7f5678901000, // Buffer address
                buflen: 32,
                flags: 0, // No flags
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x0) = 32\n")
    );

    // Test with GRND_RANDOM flag
    event.data.getrandom.flags = libc::GRND_RANDOM;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x2 (GRND_RANDOM)) = 32\n")
    );

    // Test with GRND_RANDOM flag
    event.data.getrandom.flags = libc::GRND_NONBLOCK;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x1 (GRND_NONBLOCK)) = 32\n"
        )
    );

    // Test with combined flags
    unsafe { event.data.getrandom.flags |= libc::GRND_RANDOM };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x3 (GRND_NONBLOCK|GRND_RANDOM)) = 32\n")
    );

    // Test error case (would happen if entropy pool not initialized yet)
    event.return_value = -11;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "555 getrandom(buf: 0x7f5678901000, buflen: 32, flags: 0x3 (GRND_NONBLOCK|GRND_RANDOM)) = -11\n"
        )
    );
}

#[tokio::test]
async fn parse_brk() {
    use pinchy_common::BrkData;

    // Test with a new program break address
    let event = SyscallEvent {
        syscall_nr: SYS_brk,
        pid: 888,
        tid: 888,
        return_value: 0x7f1234570000, // New program break
        data: pinchy_common::SyscallEventData {
            brk: BrkData {
                addr: 0x7f1234560000, // Requested address
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("888 brk(addr: 0x7f1234560000) = 0x7f1234570000\n")
    );

    // Test with NULL address - used to get the current program break
    let event = SyscallEvent {
        syscall_nr: SYS_brk,
        pid: 888,
        tid: 888,
        return_value: 0x7f1234500000, // Current program break
        data: pinchy_common::SyscallEventData {
            brk: BrkData {
                addr: 0, // NULL address (get current brk)
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("888 brk(addr: 0x0) = 0x7f1234500000\n")
    );
}

#[tokio::test]
async fn parse_prctl() {
    use pinchy_common::{syscalls::SYS_prctl, GenericSyscallData, SyscallEvent, SyscallEventData};

    // Test standard prctl operation - PR_SET_NAME
    let event = SyscallEvent {
        syscall_nr: SYS_prctl,
        pid: 999,
        tid: 999,
        return_value: 0, // Success
        data: SyscallEventData {
            generic: GenericSyscallData {
                args: [
                    libc::PR_SET_NAME as usize,
                    0x7fffffff0000, // Pointer to name string
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("999 prctl(PR_SET_NAME, 0x7fffffff0000) = 0\n")
    );

    // Test prctl with error return value - PR_CAPBSET_DROP
    let event = SyscallEvent {
        syscall_nr: SYS_prctl,
        pid: 999,
        tid: 999,
        return_value: -1, // Error
        data: SyscallEventData {
            generic: GenericSyscallData {
                args: [
                    libc::PR_CAPBSET_DROP as usize,
                    10, // CAP_NET_BIND_SERVICE capability
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("999 prctl(PR_CAPBSET_DROP, 0xa) = -1\n")
    );

    // Test PR_CAP_AMBIENT with PR_CAP_AMBIENT_CLEAR_ALL sub-operation
    let event = SyscallEvent {
        syscall_nr: SYS_prctl,
        pid: 999,
        tid: 999,
        return_value: 0, // Success
        data: SyscallEventData {
            generic: GenericSyscallData {
                args: [
                    libc::PR_CAP_AMBIENT as usize,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL as usize,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("999 prctl(PR_CAP_AMBIENT, 0x4, 0x0) = 0\n")
    );
}

#[tokio::test]
async fn parse_generic_syscall() {
    use pinchy_common::{
        syscalls::SYS_generic_parse_test, GenericSyscallData, SyscallEvent, SyscallEventData,
    };

    // Test the generic syscall handler using a fake syscall
    let event = SyscallEvent {
        syscall_nr: SYS_generic_parse_test,
        pid: 1234,
        tid: 1234,
        return_value: 42,
        data: SyscallEventData {
            generic: GenericSyscallData {
                args: [0, 1, 2, 3, 4, 5],
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("1234 generic_parse_test(0, 1, 2, 3, 4, 5) = 42 <STUB>\n")
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
        format!("1001 faccessat(dirfd: AT_FDCWD, pathname: \"/etc/hosts.conf\", mode: R_OK|W_OK, flags: 0) = 0\n")
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
        format!("1001 faccessat(dirfd: 3, pathname: \"/etc/hosts\", mode: F_OK, flags: AT_SYMLINK_NOFOLLOW (0x100)) = -1\n")
    );
}

#[tokio::test]
async fn parse_set_robust_list() {
    let event = SyscallEvent {
        syscall_nr: SYS_set_robust_list,
        pid: 1234,
        tid: 1234,
        return_value: 0, // Success
        data: pinchy_common::SyscallEventData {
            set_robust_list: SetRobustListData {
                head: 0x7f1234560000, // Robust list head address
                len: 24,              // Standard size for 64-bit systems
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("1234 set_robust_list(head: 0x7f1234560000, len: 24) = 0\n")
    );

    // Test with an error
    let event = SyscallEvent {
        syscall_nr: SYS_set_robust_list,
        pid: 1234,
        tid: 1234,
        return_value: -22, // -EINVAL
        data: pinchy_common::SyscallEventData {
            set_robust_list: SetRobustListData {
                head: 0x7f1234560000,
                len: 0, // Invalid size, which would trigger EINVAL
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("1234 set_robust_list(head: 0x7f1234560000, len: 0) = -22\n")
    );
}

#[tokio::test]
async fn parse_set_tid_address() {
    // Test with a non-NULL address
    let event = SyscallEvent {
        syscall_nr: SYS_set_tid_address,
        pid: 5678,
        tid: 5678,
        return_value: 5678, // Returns the thread ID
        data: pinchy_common::SyscallEventData {
            set_tid_address: SetTidAddressData {
                tidptr: 0x7f1234560000, // Address to store the thread ID
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("5678 set_tid_address(tidptr: 0x7f1234560000) = 5678\n")
    );

    // Test with NULL address
    let event = SyscallEvent {
        syscall_nr: SYS_set_tid_address,
        pid: 5678,
        tid: 5678,
        return_value: 5678, // Returns the thread ID
        data: pinchy_common::SyscallEventData {
            set_tid_address: SetTidAddressData {
                tidptr: 0, // NULL address
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("5678 set_tid_address(tidptr: 0x0) = 5678\n")
    );
}

#[tokio::test]
async fn parse_prlimit64() {
    use pinchy_common::{
        kernel_types::Rlimit, syscalls::SYS_prlimit64, PrlimitData, SyscallEvent, SyscallEventData,
    };

    // Test with new_limit and old_limit both provided
    let event = SyscallEvent {
        syscall_nr: SYS_prlimit64,
        pid: 9876,
        tid: 9876,
        return_value: 0, // Success
        data: SyscallEventData {
            prlimit: PrlimitData {
                pid: 1234,
                resource: 7, // RLIMIT_NOFILE
                has_old: true,
                has_new: true,
                old_limit: Rlimit {
                    rlim_cur: 1024,
                    rlim_max: 4096,
                },
                new_limit: Rlimit {
                    rlim_cur: 2048,
                    rlim_max: 4096,
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
        format!("9876 prlimit64(pid: 1234, resource: RLIMIT_NOFILE, new_limit: {{ rlim_cur: 2048, rlim_max: 4096 }}, old_limit: {{ rlim_cur: 1024, rlim_max: 4096 }}) = 0\n")
    );

    // Test with only old_limit (query case)
    let event = SyscallEvent {
        syscall_nr: SYS_prlimit64,
        pid: 9876,
        tid: 9876,
        return_value: 0, // Success
        data: SyscallEventData {
            prlimit: PrlimitData {
                pid: 0,      // Current process
                resource: 3, // RLIMIT_STACK
                has_old: true,
                has_new: false,
                old_limit: Rlimit {
                    rlim_cur: 8 * 1024 * 1024, // 8MB
                    rlim_max: u64::MAX,        // RLIM_INFINITY
                },
                new_limit: Rlimit::default(),
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("9876 prlimit64(pid: 0, resource: RLIMIT_STACK, new_limit: NULL, old_limit: {{ rlim_cur: 8388608, rlim_max: RLIM_INFINITY }}) = 0\n")
    );

    // Test with only new_limit (set case) and error
    let event = SyscallEvent {
        syscall_nr: SYS_prlimit64,
        pid: 9876,
        tid: 9876,
        return_value: -1, // Error
        data: SyscallEventData {
            prlimit: PrlimitData {
                pid: 5678,
                resource: 9, // RLIMIT_AS
                has_old: false,
                has_new: true,
                old_limit: Rlimit::default(),
                new_limit: Rlimit {
                    rlim_cur: 4 * 1024 * 1024 * 1024, // 4GB
                    rlim_max: 8 * 1024 * 1024 * 1024, // 8GB
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
        format!("9876 prlimit64(pid: 5678, resource: RLIMIT_AS, new_limit: {{ rlim_cur: 4294967296, rlim_max: 8589934592 }}, old_limit: NULL) = -1\n")
    );
}

#[tokio::test]
async fn parse_rseq() {
    // Test with valid rseq argument and valid rseq_cs
    let event = SyscallEvent {
        syscall_nr: SYS_rseq,
        pid: 1234,
        tid: 1234,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            rseq: pinchy_common::RseqData {
                rseq_ptr: 0x7f1234560000,
                rseq_len: 32,
                flags: 0,
                signature: 0xabcdef12,
                rseq: Rseq {
                    cpu_id_start: 0,
                    cpu_id: 0xffffffff, // -1 value
                    rseq_cs: 0x7f1234570000,
                    flags: 0,
                    node_id: 0,
                    mm_cid: 0,
                },
                has_rseq: true,
                rseq_cs: RseqCs {
                    version: 0,
                    flags: 1, // RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT
                    start_ip: 0x7f1234580000,
                    post_commit_offset: 0x100,
                    abort_ip: 0x7f1234590000,
                },
                has_rseq_cs: true,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("1234 rseq(rseq: 0x7f1234560000, rseq_len: 32, flags: 0, signature: 0xabcdef12, rseq content: {{ cpu_id_start: 0, cpu_id: -1, rseq_cs: {{ version: 0, flags: RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT, start_ip: 0x7f1234580000, post_commit_offset: 0x100, abort_ip: 0x7f1234590000 }}, flags: 0, node_id: 0, mm_cid: 0 }}) = 0\n")
    );

    // Test with NULL rseq argument
    let event = SyscallEvent {
        syscall_nr: SYS_rseq,
        pid: 1234,
        tid: 1234,
        return_value: -22, // EINVAL
        data: pinchy_common::SyscallEventData {
            rseq: pinchy_common::RseqData {
                rseq_ptr: 0,
                rseq_len: 32,
                flags: 0,
                signature: 0xabcdef12,
                rseq: Rseq::default(),
                has_rseq: false,
                rseq_cs: RseqCs::default(),
                has_rseq_cs: true,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("1234 rseq(rseq: NULL, rseq_len: 32, flags: 0, signature: 0xabcdef12) = -22\n")
    );

    // Test with unregister flag
    let event = SyscallEvent {
        syscall_nr: SYS_rseq,
        pid: 1234,
        tid: 1234,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            rseq: pinchy_common::RseqData {
                rseq_ptr: 0x7f1234560000,
                rseq_len: 32,
                flags: 1, // RSEQ_FLAG_UNREGISTER
                signature: 0xabcdef12,
                rseq: Rseq {
                    cpu_id_start: 0,
                    cpu_id: 2,
                    rseq_cs: 0,
                    flags: 0,
                    node_id: 0,
                    mm_cid: 0,
                },
                has_rseq: true,
                rseq_cs: RseqCs {
                    version: 0,
                    flags: 1, // RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT
                    start_ip: 0x7f1234580000,
                    post_commit_offset: 0x100,
                    abort_ip: 0x7f1234590000,
                },
                has_rseq_cs: true,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("1234 rseq(rseq: 0x7f1234560000, rseq_len: 32, flags: RSEQ_FLAG_UNREGISTER, signature: 0xabcdef12, rseq content: {{ cpu_id_start: 0, cpu_id: 2, rseq_cs: {{ version: 0, flags: RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT, start_ip: 0x7f1234580000, post_commit_offset: 0x100, abort_ip: 0x7f1234590000 }}, flags: 0, node_id: 0, mm_cid: 0 }}) = 0\n")
    );
}

#[tokio::test]
async fn parse_uname() {
    // Create a mock utsname with typical Linux system information
    let mut utsname = Utsname::default();

    // Simulate typical system info (strings will be null-terminated)
    let sysname = b"Linux";
    let nodename = b"jabuticaba";
    let release = b"6.15.4-200.fc42.aarch64";
    let version = b"#1 SMP PREEMPT_DYNAMIC";
    let machine = b"aarch64";
    let domainname = b"(none)";

    utsname.sysname[..sysname.len()].copy_from_slice(sysname);
    utsname.nodename[..nodename.len()].copy_from_slice(nodename);
    utsname.release[..release.len()].copy_from_slice(release);
    utsname.version[..version.len()].copy_from_slice(version);
    utsname.machine[..machine.len()].copy_from_slice(machine);
    utsname.domainname[..domainname.len()].copy_from_slice(domainname);

    let event = SyscallEvent {
        syscall_nr: SYS_uname,
        pid: 1234,
        tid: 1234,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            uname: UnameData { utsname },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1234 uname(struct utsname: { sysname: \"Linux\", nodename: \"jabuticaba\", release: \"6.15.4-200.fc42.aarch64\", version: \"#1 SMP PREEMPT_DYNAMIC\", machine: \"aarch64\", domainname: \"(none)\" }) = 0\n"
    );
}

#[tokio::test]
async fn parse_uname_truncated() {
    // Test with a very long version string that gets truncated
    let mut utsname = Utsname::default();

    let sysname = b"Linux";
    let nodename = b"jabuticaba";
    let release = b"6.15.4-200.fc42.aarch64";
    let version = b"#1 SMP PREEMPT_DYNAMIC Fri Jun 27 15:55:20 UTC 2025 aarch64 GNU/L";
    let machine = b"aarch64";
    let domainname = b"(none)";

    utsname.sysname[..sysname.len()].copy_from_slice(sysname);
    utsname.nodename[..nodename.len()].copy_from_slice(nodename);
    utsname.release[..release.len()].copy_from_slice(release);
    utsname.version.copy_from_slice(version);
    utsname.machine[..machine.len()].copy_from_slice(machine);
    utsname.domainname[..domainname.len()].copy_from_slice(domainname);

    let event = SyscallEvent {
        syscall_nr: SYS_uname,
        pid: 1234,
        tid: 1234,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            uname: UnameData { utsname },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1234 uname(struct utsname: { sysname: \"Linux\", nodename: \"jabuticaba\", release: \"6.15.4-200.fc42.aarch64\", version: \"#1 SMP PREEMPT_DYNAMIC Fri Jun 27 15:55:20 UTC 2025 aarch64 GNU/L ... (truncated)\", machine: \"aarch64\", domainname: \"(none)\" }) = 0\n"
    );
}
