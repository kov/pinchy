// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::pin::Pin;

use indoc::indoc;
use pinchy_common::{
    kernel_types::{
        AioSigset, EpollEvent, IoCb, IoEvent, IoUringParams, Iovec, OpenHow, Sigset, Timespec,
    },
    syscalls::{
        SYS_close, SYS_close_range, SYS_dup, SYS_dup3, SYS_epoll_create1, SYS_epoll_pwait,
        SYS_epoll_pwait2, SYS_fcntl, SYS_flock, SYS_io_cancel, SYS_io_destroy, SYS_io_getevents,
        SYS_io_pgetevents, SYS_io_setup, SYS_io_submit, SYS_io_uring_enter, SYS_io_uring_register,
        SYS_io_uring_setup, SYS_lseek, SYS_openat, SYS_openat2, SYS_pipe2, SYS_ppoll, SYS_pread64,
        SYS_preadv2, SYS_pwrite64, SYS_read, SYS_readv, SYS_splice, SYS_tee, SYS_vmsplice,
        SYS_write, SYS_writev,
    },
    CloseData, CloseRangeData, Dup3Data, DupData, EpollCreate1Data, EpollPWait2Data,
    EpollPWaitData, FcntlData, FlockData, IoCancelData, IoDestroyData, IoGeteventsData,
    IoPgeteventsData, IoSetupData, IoSubmitData, IoUringEnterData, IoUringRegisterData,
    IoUringSetupData, LseekData, OpenAt2Data, OpenAtData, PpollData, PreadData, PwriteData,
    ReadData, SpliceData, SyscallEvent, SyscallEventData, TeeData, VectorIOData, VmspliceData,
    WriteData, DATA_READ_SIZE, IOV_COUNT, LARGER_READ_SIZE,
};
#[cfg(target_arch = "x86_64")]
use pinchy_common::{
    syscalls::{SYS_dup2, SYS_epoll_create, SYS_poll},
    Dup2Data, EpollCreateData, PollData,
};

use crate::{
    events::handle_event,
    format_helpers::{aio_constants, io_uring_constants},
    formatting::{Formatter, FormattingStyle},
    syscall_test,
};

syscall_test!(
    parse_close,
    {
        SyscallEvent {
            syscall_nr: SYS_close,
            pid: 1,
            tid: 1,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                close: CloseData { fd: 2 },
            },
        }
    },
    "1 close(fd: 2) = 0 (success)\n"
);

syscall_test!(
    parse_dup3,
    {
        SyscallEvent {
            syscall_nr: SYS_dup3,
            pid: 1,
            tid: 1,
            return_value: 4,
            data: pinchy_common::SyscallEventData {
                dup3: Dup3Data {
                    oldfd: 3,
                    newfd: 4,
                    flags: 0,
                },
            },
        }
    },
    "1 dup3(oldfd: 3, newfd: 4, flags: 0) = 4 (fd)\n"
);

syscall_test!(
    parse_dup3_with_flags,
    {
        SyscallEvent {
            syscall_nr: SYS_dup3,
            pid: 1,
            tid: 1,
            return_value: 5,
            data: pinchy_common::SyscallEventData {
                dup3: Dup3Data {
                    oldfd: 3,
                    newfd: 5,
                    flags: libc::O_CLOEXEC,
                },
            },
        }
    },
    "1 dup3(oldfd: 3, newfd: 5, flags: 0x80000 (O_CLOEXEC)) = 5 (fd)\n"
);

#[tokio::test]
async fn parse_epoll_pwait_multiline() {
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

syscall_test!(
        parse_epoll_pwait,
        {
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
            event
        },
        "1 epoll_pwait(epfd: 4, events: [ epoll_event { events: POLLIN|POLLERR|POLLHUP, data: 0xbeef } ], max_events: 10, timeout: -1, sigmask) = 1\n"
    );

syscall_test!(
    parse_ppoll,
    {
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
        event
    },
    "22 ppoll(fds: [ { 3, POLLIN } ], nfds: 1, timeout: { secs: 0, nanos: 0 }, sigmask) = 0 (timeout)\n"
);

syscall_test!(
    parse_ppoll_ready,
    {
        let mut event_ready = SyscallEvent {
            syscall_nr: SYS_ppoll,
            pid: 22,
            tid: 22,
            return_value: 1, // 1 fd ready
            data: pinchy_common::SyscallEventData {
                ppoll: PpollData {
                    fds: [0; 16],
                    events: [0; 16],
                    revents: [0; 16],
                    nfds: 1,
                    timeout: Timespec {
                        seconds: 1,
                        nanos: 0,
                    },
                },
            },
        };
        let ppoll_data_ready = unsafe { &mut event_ready.data.ppoll };
        ppoll_data_ready.fds[0] = 5;
        ppoll_data_ready.events[0] = libc::POLLIN;
        ppoll_data_ready.revents[0] = libc::POLLIN; // Ready for reading
        event_ready
    },
    "22 ppoll(fds: [ { 5, POLLIN } ], nfds: 1, timeout: { secs: 1, nanos: 0 }, sigmask) = 1 (ready) [5 = POLLIN]\n"
);

syscall_test!(
    parse_read,
    {
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
        read_data
            .buf
            .iter_mut()
            .zip((0..).flat_map(|n: u8| std::iter::repeat_n(n, 10)))
            .for_each(|(b, i)| *b = i + 65);
        event
    },
    "22 read(fd: 3, buf: \"AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFFGGGGGGGGGGHHHHHHHHHHIIIIIIIIIIJJJJJJJJJJKKKKKKKKKKLLLLLLLLLLMMMMMMMM\" ... (8064 more bytes), count: 8192) = 8192 (bytes)\n"
);

syscall_test!(
    parse_write,
    {
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
        write_data
            .buf
            .iter_mut()
            .zip((0..).flat_map(|n: u8| std::iter::repeat_n(n, 10)))
            .for_each(|(b, i)| *b = i + 65);
        event
    },
    "22 write(fd: 3, buf: \"AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFFGGGGGGGGGGHHHHHHHHHHIIIIIIIIIIJJJJJJJJJJKKKKKKKKKKLLLLLLLLLLMMMMMMMM\" ... (8064 more bytes), count: 8192) = 8192 (bytes)\n"
);

syscall_test!(
    parse_lseek,
    {
        SyscallEvent {
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
        }
    },
    "22 lseek(fd: 3, offset: 0, whence: 2) = 18092\n"
);

syscall_test!(
    parse_openat,
    {
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
        openat_data.pathname[..path.len()].copy_from_slice(path);
        event
    },
    "22 openat(dfd: AT_FDCWD, pathname: \"/etc/passwd\", flags: 0x80000 (O_RDONLY|O_CLOEXEC), mode: 0o666 (rw-rw-rw-)) = 3 (fd)\n"
);

syscall_test!(
    parse_openat2,
    {
        let mut event = SyscallEvent {
            syscall_nr: SYS_openat2,
            pid: 22,
            tid: 22,
            return_value: 3,
            data: pinchy_common::SyscallEventData {
                openat2: OpenAt2Data {
                    dfd: libc::AT_FDCWD,
                    pathname: [0u8; DATA_READ_SIZE],
                    how: OpenHow {
                        flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                        mode: 0o666,
                        resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS,
                    },
                    size: 24, // size of struct open_how
                },
            },
        };
        let openat2_data = unsafe { &mut event.data.openat2 };
        let path = c"/etc/passwd".to_bytes_with_nul();
        openat2_data.pathname[..path.len()].copy_from_slice(path);
        event
    },
    "22 openat2(dfd: AT_FDCWD, pathname: \"/etc/passwd\", how: { flags: 0x80000 (O_RDONLY|O_CLOEXEC), mode: 0o666 (rw-rw-rw-), resolve: 0xc (RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) }, size: 24) = 3 (fd)\n"
);

syscall_test!(
    parse_openat2_no_resolve_flags,
    {
        let mut event = SyscallEvent {
            syscall_nr: SYS_openat2,
            pid: 22,
            tid: 22,
            return_value: 4,
            data: pinchy_common::SyscallEventData {
                openat2: OpenAt2Data {
                    dfd: libc::AT_FDCWD,
                    pathname: [0u8; DATA_READ_SIZE],
                    how: OpenHow {
                        flags: libc::O_WRONLY as u64,
                        mode: 0o644,
                        resolve: 0, // No resolve flags
                    },
                    size: 24,
                },
            },
        };
        let openat2_data = unsafe { &mut event.data.openat2 };
        let path = c"/tmp/test".to_bytes_with_nul();
        openat2_data.pathname[..path.len()].copy_from_slice(path);
        event
    },
    "22 openat2(dfd: AT_FDCWD, pathname: \"/tmp/test\", how: { flags: 0x1 (O_WRONLY), mode: 0o644 (rw-r--r--), resolve: 0 }, size: 24) = 4 (fd)\n"
);

syscall_test!(
    parse_fcntl,
    {
        SyscallEvent {
            syscall_nr: SYS_fcntl,
            pid: 22,
            tid: 22,
            return_value: 2, // O_RDWR
            data: pinchy_common::SyscallEventData {
                fcntl: FcntlData {
                    fd: 3,
                    cmd: libc::F_GETFL,
                    arg: 0,
                },
            },
        }
    },
    "22 fcntl(fd: 3, cmd: F_GETFL, arg: 0x0) = 2\n"
);

syscall_test!(
    parse_fcntl_setfl,
    {
        SyscallEvent {
            syscall_nr: SYS_fcntl,
            pid: 42,
            tid: 42,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                fcntl: FcntlData {
                    fd: 5,
                    cmd: libc::F_SETFL,
                    arg: libc::O_NONBLOCK as usize,
                },
            },
        }
    },
    "42 fcntl(fd: 5, cmd: F_SETFL, arg: 0x800) = 0 (success)\n"
);

syscall_test!(
    parse_fcntl_dupfd,
    {
        SyscallEvent {
            syscall_nr: SYS_fcntl,
            pid: 100,
            tid: 100,
            return_value: 7, // New file descriptor
            data: pinchy_common::SyscallEventData {
                fcntl: FcntlData {
                    fd: 3,
                    cmd: libc::F_DUPFD,
                    arg: 4, // Minimum fd number
                },
            },
        }
    },
    "100 fcntl(fd: 3, cmd: F_DUPFD, arg: 0x4) = 7\n"
);

syscall_test!(
    parse_pipe2,
    {
        SyscallEvent {
            syscall_nr: SYS_pipe2,
            pid: 1,
            tid: 1,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                pipe2: pinchy_common::Pipe2Data {
                    pipefd: [3, 4],
                    flags: libc::O_CLOEXEC,
                },
            },
        }
    },
    "1 pipe2(pipefd: [ 3, 4 ], flags: 0x80000 (O_CLOEXEC)) = 0 (success)\n"
);

syscall_test!(
    parse_dup,
    {
        SyscallEvent {
            syscall_nr: SYS_dup,
            pid: 1,
            tid: 1,
            return_value: 4, // new fd
            data: pinchy_common::SyscallEventData {
                dup: DupData { oldfd: 3 },
            },
        }
    },
    "1 dup(oldfd: 3) = 4 (fd)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_dup2,
    {
        SyscallEvent {
            syscall_nr: SYS_dup2,
            pid: 1,
            tid: 1,
            return_value: 5, // new fd
            data: pinchy_common::SyscallEventData {
                dup2: Dup2Data { oldfd: 3, newfd: 5 },
            },
        }
    },
    "1 dup2(oldfd: 3, newfd: 5) = 5 (fd)\n"
);

syscall_test!(
    parse_close_range,
    {
        SyscallEvent {
            syscall_nr: SYS_close_range,
            pid: 1,
            tid: 1,
            return_value: 0, // success
            data: pinchy_common::SyscallEventData {
                close_range: CloseRangeData {
                    fd: 3,
                    max_fd: 10,
                    flags: 0,
                },
            },
        }
    },
    "1 close_range(fd: 3, max_fd: 10, flags: 0x0) = 0 (success)\n"
);

syscall_test!(
    parse_pread,
    {
        let mut event = SyscallEvent {
            syscall_nr: SYS_pread64,
            pid: 22,
            tid: 22,
            return_value: 4096,
            data: pinchy_common::SyscallEventData {
                pread: PreadData {
                    fd: 3,
                    buf: [0u8; DATA_READ_SIZE],
                    count: 4096,
                    offset: 1024,
                },
            },
        };
        let pread_data = unsafe { &mut event.data.pread };
        pread_data
            .buf
            .iter_mut()
            .zip((0..).flat_map(|n: u8| std::iter::repeat_n(n, 10)))
            .for_each(|(b, i)| *b = i + 65);
        event
    },
    "22 pread64(fd: 3, buf: \"AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFFGGGGGGGGGGHHHHHHHHHHIIIIIIIIIIJJJJJJJJJJKKKKKKKKKKLLLLLLLLLLMMMMMMMM\" ... (3968 more bytes), count: 4096, offset: 1024) = 4096 (bytes)\n"
);

syscall_test!(
    parse_pwrite,
    {
        let mut event = SyscallEvent {
            syscall_nr: SYS_pwrite64,
            pid: 22,
            tid: 22,
            return_value: 4096,
            data: pinchy_common::SyscallEventData {
                pwrite: PwriteData {
                    fd: 3,
                    buf: [0u8; DATA_READ_SIZE],
                    count: 4096,
                    offset: 2048,
                },
            },
        };
        let pwrite_data = unsafe { &mut event.data.pwrite };
        pwrite_data
            .buf
            .iter_mut()
            .zip((0..).flat_map(|n: u8| std::iter::repeat_n(n, 10)))
            .for_each(|(b, i)| *b = i + 65);
        event
    },
    "22 pwrite64(fd: 3, buf: \"AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFFGGGGGGGGGGHHHHHHHHHHIIIIIIIIIIJJJJJJJJJJKKKKKKKKKKLLLLLLLLLLMMMMMMMM\" ... (3968 more bytes), count: 4096, offset: 2048) = 4096 (bytes)\n"
);

syscall_test!(
    parse_readv,
    {
        let mut data = VectorIOData {
            fd: 3,
            iovecs: [Iovec {
                iov_base: 0x1000,
                iov_len: 4,
            }; pinchy_common::IOV_COUNT],
            iov_lens: [4; pinchy_common::IOV_COUNT],
            iov_bufs: [[0u8; pinchy_common::LARGER_READ_SIZE]; pinchy_common::IOV_COUNT],
            iovcnt: 2,
            offset: 0,
            flags: 0,
            read_count: 2,
        };
        data.iov_bufs[0][..4].copy_from_slice(b"test");
        data.iov_bufs[1][..4].copy_from_slice(b"data");
        SyscallEvent {
            syscall_nr: SYS_readv,
            pid: 1,
            tid: 1,
            return_value: 8,
            data: pinchy_common::SyscallEventData { vector_io: data },
        }
    },
    "1 readv(fd: 3, iov: [ iovec { base: 0x1000, len: 4, buf: \"test\" }, iovec { base: 0x1000, len: 4, buf: \"data\" } ], iovcnt: 2) = 8 (bytes)\n"
);

syscall_test!(
    parse_writev,
    {
        let mut data = VectorIOData {
            fd: 4,
            iovecs: [Iovec {
                iov_base: 0x2000,
                iov_len: 3,
            }; pinchy_common::IOV_COUNT],
            iov_lens: [3; pinchy_common::IOV_COUNT],
            iov_bufs: [[0u8; pinchy_common::LARGER_READ_SIZE]; pinchy_common::IOV_COUNT],
            iovcnt: 1,
            offset: 0,
            flags: 0,
            read_count: 1,
        };
        data.iov_bufs[0][..3].copy_from_slice(b"abc");
        SyscallEvent {
            syscall_nr: SYS_writev,
            pid: 2,
            tid: 2,
            return_value: 3,
            data: pinchy_common::SyscallEventData { vector_io: data },
        }
    },
    "2 writev(fd: 4, iov: [ iovec { base: 0x2000, len: 3, buf: \"abc\" } ], iovcnt: 1) = 3 (bytes)\n"
);

syscall_test!(
    parse_preadv2,
    {
        let mut data = VectorIOData {
            fd: 5,
            iovecs: [Iovec {
                iov_base: 0x3000,
                iov_len: 5,
            }; pinchy_common::IOV_COUNT],
            iov_lens: [5; pinchy_common::IOV_COUNT],
            iov_bufs: [[0u8; pinchy_common::LARGER_READ_SIZE]; pinchy_common::IOV_COUNT],
            iovcnt: 1,
            offset: 1234,
            flags: 0x10,
            read_count: 1,
        };
        data.iov_bufs[0][..5].copy_from_slice(b"hello");
        SyscallEvent {
            syscall_nr: SYS_preadv2,
            pid: 3,
            tid: 3,
            return_value: 5,
            data: pinchy_common::SyscallEventData { vector_io: data },
        }
    },
    "3 preadv2(fd: 5, iov: [ iovec { base: 0x3000, len: 5, buf: \"hello\" } ], iovcnt: 1, offset: 1234, flags: 0x10) = 5\n"
);

syscall_test!(
    test_epoll_create1,
    {
        SyscallEvent {
            syscall_nr: SYS_epoll_create1,
            pid: 1001,
            tid: 1001,
            return_value: 5, // epoll fd
            data: pinchy_common::SyscallEventData {
                epoll_create1: EpollCreate1Data {
                    flags: libc::EPOLL_CLOEXEC,
                },
            },
        }
    },
    "1001 epoll_create1(flags: EPOLL_CLOEXEC) = 5 (fd)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_epoll_create,
    {
        SyscallEvent {
            syscall_nr: SYS_epoll_create,
            pid: 1001,
            tid: 1001,
            return_value: 5, // epoll fd
            data: pinchy_common::SyscallEventData {
                epoll_create: EpollCreateData { size: 10 },
            },
        }
    },
    "1001 epoll_create(size: 10) = 5 (fd)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_epoll_wait,
    {
        let mut event = SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_epoll_wait,
            pid: 42,
            tid: 42,
            return_value: 1,
            data: pinchy_common::SyscallEventData {
                epoll_wait: EpollPWaitData {
                    epfd: 7,
                    events: [EpollEvent::default(); 8],
                    max_events: 8,
                    timeout: 1000,
                },
            },
        };
        let epoll_events = unsafe { &mut event.data.epoll_wait.events };
        epoll_events[0].data = 0x1234;
        epoll_events[0].events = libc::POLLIN as u32;
        event
    },
    "42 epoll_wait(epfd: 7, events: [ epoll_event { events: POLLIN, data: 0x1234 } ], max_events: 8, timeout: 1000) = 1\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    test_poll,
    {
        use pinchy_common::kernel_types::Pollfd;
        let mut fds = [Pollfd::default(); 16];
        fds[0] = Pollfd {
            fd: 0,
            events: libc::POLLIN as i16,
            revents: libc::POLLIN as i16,
        };
        fds[1] = Pollfd {
            fd: 1,
            events: libc::POLLOUT as i16,
            revents: libc::POLLOUT as i16,
        };
        SyscallEvent {
            syscall_nr: SYS_poll,
            pid: 1001,
            tid: 1001,
            return_value: 2, // number of ready fds
            data: pinchy_common::SyscallEventData {
                poll: PollData {
                    fds,
                    nfds: 2,
                    timeout: 1000,
                    actual_nfds: 2,
                },
            },
        }
    },
    "1001 poll(fds: [ pollfd { fd: 0, events: POLLIN, revents: POLLIN }, pollfd { fd: 1, events: POLLOUT, revents: POLLOUT } ], nfds: 2, timeout: 1000) = 2 (ready)\n"
);

syscall_test!(
    parse_epoll_pwait2,
    {
        let mut events = [EpollEvent::default(); 8];
        events[0] = EpollEvent { events: libc::POLLHUP as u32, data: 0x2 };
        SyscallEvent {
            syscall_nr: SYS_epoll_pwait2,
            pid: 1,
            tid: 1,
            return_value: 1,
            data: pinchy_common::SyscallEventData {
                epoll_pwait2: EpollPWait2Data {
                    epfd: 3,
                    events,
                    max_events: 1,
                    timeout: Timespec { seconds: 5, nanos: 0 },
                    sigmask: 0,
                    sigsetsize: 0,
                },
            },
        }
    },
    "1 epoll_pwait2(epfd: 3, events: [ epoll_event { events: POLLHUP, data: 0x2 } ], max_events: 1, timeout: { secs: 5, nanos: 0 }, sigmask: 0x0, sigsetsize: 0) = 1\n"
);

syscall_test!(
    parse_epoll_ctl,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_epoll_ctl,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                epoll_ctl: pinchy_common::EpollCtlData {
                    epfd: 5,
                    op: libc::EPOLL_CTL_ADD,
                    fd: 10,
                    event: pinchy_common::kernel_types::EpollEvent {
                        events: libc::EPOLLIN as u32 | libc::EPOLLOUT as u32,
                        data: 0xdeadbeef,
                    },
                },
            },
        }
    },
    "123 epoll_ctl(epfd: 5, op: EPOLL_CTL_ADD, fd: 10, event: epoll_event { events: POLLIN|POLLOUT, data: 0xdeadbeef }) = 0 (success)\n"
);

syscall_test!(
    parse_splice,
    {
        SyscallEvent {
            syscall_nr: SYS_splice,
            pid: 10,
            tid: 10,
            return_value: 42,
            data: pinchy_common::SyscallEventData {
                splice: SpliceData {
                    fd_in: 3,
                    off_in: 0x1000,
                    fd_out: 4,
                    off_out: 0x2000,
                    len: 4096,
                    flags: libc::SPLICE_F_MOVE,
                },
            },
        }
    },
    "10 splice(fd_in: 3, off_in: 0x1000, fd_out: 4, off_out: 0x2000, len: 4096, flags: 0x1 (SPLICE_F_MOVE)) = 42 (bytes)\n"
);

syscall_test!(
    parse_tee,
    {
        SyscallEvent {
            syscall_nr: SYS_tee,
            pid: 20,
            tid: 20,
            return_value: 128,
            data: pinchy_common::SyscallEventData {
                tee: TeeData {
                    fd_in: 5,
                    fd_out: 6,
                    len: 128,
                    flags: libc::SPLICE_F_NONBLOCK,
                },
            },
        }
    },
    "20 tee(fd_in: 5, fd_out: 6, len: 128, flags: 0x2 (SPLICE_F_NONBLOCK)) = 128 (bytes)\n"
);

syscall_test!(
    parse_vmsplice,
    {
        let mut iov_bufs = [[0u8; LARGER_READ_SIZE]; IOV_COUNT];
        iov_bufs[0][..4].copy_from_slice(b"test");
        iov_bufs[1][..4].copy_from_slice(b"data");
        SyscallEvent {
            syscall_nr: SYS_vmsplice,
            pid: 1,
            tid: 1,
            return_value: 8,
            data: pinchy_common::SyscallEventData {
                vmsplice: VmspliceData {
                    fd: 3,
                    iovecs: [
                        Iovec { iov_base: 0x1000, iov_len: 4 },
                        Iovec { iov_base: 0x2000, iov_len: 4 },
                        Iovec { iov_base: 0, iov_len: 0 },
                        Iovec { iov_base: 0, iov_len: 0 },
                        Iovec { iov_base: 0, iov_len: 0 },
                        Iovec { iov_base: 0, iov_len: 0 },
                        Iovec { iov_base: 0, iov_len: 0 },
                        Iovec { iov_base: 0, iov_len: 0 }
                    ],
                    iov_lens: [4, 4, 0, 0, 0, 0, 0, 0],
                    iov_bufs,
                    iovcnt: 2,
                    flags: libc::SPLICE_F_GIFT,
                    read_count: 2,
                },
            },
        }
    },
    "1 vmsplice(fd: 3, iov: [ iovec { base: 0x1000, len: 4, buf: \"test\" }, iovec { base: 0x2000, len: 4, buf: \"data\" } ], iovcnt: 2, flags: 0x8 (SPLICE_F_GIFT)) = 8 (bytes)\n"
);

syscall_test!(
    parse_flock,
    {
        SyscallEvent {
            syscall_nr: SYS_flock,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: SyscallEventData {
                flock: FlockData {
                    fd: 4,
                    operation: libc::LOCK_EX | libc::LOCK_NB,
                },
            },
        }
    },
    "123 flock(fd: 4, operation: 0x6 (LOCK_EX|LOCK_NB)) = 0 (success)\n"
);

syscall_test!(
    parse_flock_unlock,
    {
        SyscallEvent {
            syscall_nr: SYS_flock,
            pid: 456,
            tid: 456,
            return_value: 0,
            data: SyscallEventData {
                flock: FlockData {
                    fd: 7,
                    operation: libc::LOCK_UN,
                },
            },
        }
    },
    "456 flock(fd: 7, operation: 0x8 (LOCK_UN)) = 0 (success)\n"
);

syscall_test!(
    parse_io_setup,
    {
        SyscallEvent {
            syscall_nr: SYS_io_setup,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: SyscallEventData {
                io_setup: IoSetupData {
                    nr_events: 1024,
                    ctx_idp: 0x7ffe12345678,
                },
            },
        }
    },
    "123 io_setup(nr_events: 1024, ctx_idp: 0x7ffe12345678) = 0 (success)\n"
);

syscall_test!(
    parse_io_destroy,
    {
        SyscallEvent {
            syscall_nr: SYS_io_destroy,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: SyscallEventData {
                io_destroy: IoDestroyData { ctx_id: 0x12345678 },
            },
        }
    },
    "123 io_destroy(ctx_id: 0x12345678) = 0 (success)\n"
);

syscall_test!(
    parse_io_submit,
    {
        let iocb1 = IoCb {
            aio_data: 0xdead,
            aio_key: 1,
            aio_rw_flags: libc::RWF_HIPRI as u32,
            aio_lio_opcode: aio_constants::IOCB_CMD_PREAD,
            aio_reqprio: 0,
            aio_fildes: 3,
            aio_buf: 0x7ffe87654321,
            aio_nbytes: 4096,
            aio_offset: 0,
            aio_flags: aio_constants::IOCB_FLAG_RESFD,
            aio_resfd: 4,
            ..Default::default()
        };

        let iocb2 = IoCb {
            aio_data: 0xbeef,
            aio_lio_opcode: aio_constants::IOCB_CMD_PWRITE,
            aio_fildes: 5,
            aio_buf: 0x7ffe11111111,
            aio_nbytes: 2048,
            aio_offset: 1024,
            ..Default::default()
        };

        SyscallEvent {
            syscall_nr: SYS_io_submit,
            pid: 123,
            tid: 123,
            return_value: 2,
            data: SyscallEventData {
                io_submit: IoSubmitData {
                    ctx_id: 0x12345678,
                    nr: 2,
                    iocbpp: 0x7ffe22222222,
                    iocbs: [iocb1, iocb2, IoCb::default(), IoCb::default()],
                    iocb_count: 2,
                },
            },
        }
    },
    "123 io_submit(ctx_id: 0x12345678, nr: 2, iocbpp: 0x7ffe22222222, iocbs: [ iocb { data: 0xdead, key: 1, rw_flags: 0x1 (RWF_HIPRI), lio_opcode: IOCB_CMD_PREAD, reqprio: 0, fildes: 3, buf: 0x7ffe87654321, nbytes: 4096, offset: 0, flags: 0x1 (IOCB_FLAG_RESFD), resfd: 4 }, iocb { data: 0xbeef, key: 0, rw_flags: 0, lio_opcode: IOCB_CMD_PWRITE, reqprio: 0, fildes: 5, buf: 0x7ffe11111111, nbytes: 2048, offset: 1024, flags: 0 } ]) = 2 (requests)\n"
);

syscall_test!(
    parse_io_cancel,
    {
        let result_event = IoEvent {
            data: 0xdead,
            obj: 0x12345678,
            res: -125, // -ECANCELED
            res2: 0,
        };

        SyscallEvent {
            syscall_nr: SYS_io_cancel,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: SyscallEventData {
                io_cancel: IoCancelData {
                    ctx_id: 0x12345678,
                    iocb: 0x7ffe11111111,
                    result: 0x7ffe22222222,
                    has_result: true,
                    result_event,
                },
            },
        }
    },
    "123 io_cancel(ctx_id: 0x12345678, iocb: 0x7ffe11111111, result: 0x7ffe22222222, result_event: { data: 0xdead, obj: 0x12345678, res: -125, res2: 0 }) = 0 (success)\n"
);

syscall_test!(
    parse_io_getevents,
    {
        let event1 = IoEvent {
            data: 0xdead,
            obj: 0x11111111,
            res: 4096,
            res2: 0,
        };

        let event2 = IoEvent {
            data: 0xbeef,
            obj: 0x22222222,
            res: 2048,
            res2: 0,
        };

        SyscallEvent {
            syscall_nr: SYS_io_getevents,
            pid: 123,
            tid: 123,
            return_value: 2,
            data: SyscallEventData {
                io_getevents: IoGeteventsData {
                    ctx_id: 0x12345678,
                    min_nr: 1,
                    nr: 4,
                    events: 0x7ffe33333333,
                    timeout: 0x7ffe44444444,
                    event_array: [event1, event2, IoEvent::default(), IoEvent::default()],
                    event_count: 2,
                    has_timeout: true,
                    timeout_data: Timespec { seconds: 1, nanos: 500000000 },
                },
            },
        }
    },
    "123 io_getevents(ctx_id: 0x12345678, min_nr: 1, nr: 4, events: 0x7ffe33333333, timeout: { secs: 1, nanos: 500000000 }, events_returned: [ event { data: 0xdead, obj: 0x11111111, res: 4096, res2: 0 }, event { data: 0xbeef, obj: 0x22222222, res: 2048, res2: 0 } ]) = 2 (events)\n"
);

syscall_test!(
    parse_io_pgetevents_with_sigset,
    {
        let event1 = IoEvent {
            data: 0xcafe,
            obj: 0x55555555,
            res: 1024,
            res2: 0,
        };

        let mut sigset = Sigset::default();
        // Set SIGUSR1 (signal 10) in the sigset - bit 9 (0-indexed)
        sigset.bytes[1] = 0x02; // bit 9 = byte 1, bit 1

        SyscallEvent {
            syscall_nr: SYS_io_pgetevents,
            pid: 123,
            tid: 123,
            return_value: 1,
            data: SyscallEventData {
                io_pgetevents: IoPgeteventsData {
                    ctx_id: 0x12345678,
                    min_nr: 1,
                    nr: 2,
                    events: 0x7ffe55555555,
                    timeout: 0,
                    usig: 0x7ffe66666666,
                    event_array: [event1, IoEvent::default(), IoEvent::default(), IoEvent::default()],
                    event_count: 1,
                    has_timeout: false,
                    timeout_data: Timespec::default(),
                    has_usig: true,
                    usig_data: AioSigset {
                        sigmask: 0x7ffe77777777,
                        sigsetsize: 8,
                    },
                    sigset_data: sigset,
                },
            },
        }
    },
    "123 io_pgetevents(ctx_id: 0x12345678, min_nr: 1, nr: 2, events: 0x7ffe55555555, timeout: NULL, usig: { sigmask: 0x7ffe77777777, sigsetsize: 8, sigset: [SIGUSR1] }, events_returned: [ event { data: 0xcafe, obj: 0x55555555, res: 1024, res2: 0 } ]) = 1 (events)\n"
);

syscall_test!(
    parse_io_uring_setup,
    {
        let params = IoUringParams {
            sq_entries: 256,
            cq_entries: 256,
            flags: io_uring_constants::IORING_SETUP_SQPOLL | io_uring_constants::IORING_SETUP_SQE128,
            sq_thread_cpu: 2,
            sq_thread_idle: 20,
            features: io_uring_constants::IORING_FEAT_SINGLE_MMAP | io_uring_constants::IORING_FEAT_FAST_POLL,
            wq_fd: 5,
            ..Default::default()
        };

        SyscallEvent {
            syscall_nr: SYS_io_uring_setup,
            pid: 321,
            tid: 321,
            return_value: 7,
            data: SyscallEventData {
                io_uring_setup: IoUringSetupData {
                    entries: 256,
                    params_ptr: 0x7ffeabcd1000,
                    has_params: true,
                    params,
                },
            },
        }
    },
    "321 io_uring_setup(entries: 256, params_ptr: 0x7ffeabcd1000, params: { sq_entries: 256, cq_entries: 256, flags: 0x402 (IORING_SETUP_SQPOLL|IORING_SETUP_SQE128), sq_thread_cpu: 2, sq_thread_idle: 20, features: 0x21 (IORING_FEAT_SINGLE_MMAP|IORING_FEAT_FAST_POLL), wq_fd: 5 }) = 7 (fd)\n"
);

syscall_test!(
    parse_io_uring_enter,
    {
        SyscallEvent {
            syscall_nr: SYS_io_uring_enter,
            pid: 222,
            tid: 222,
            return_value: 1,
            data: SyscallEventData {
                io_uring_enter: IoUringEnterData {
                    fd: 7,
                    to_submit: 2,
                    min_complete: 1,
                    flags: io_uring_constants::IORING_ENTER_GETEVENTS
                        | io_uring_constants::IORING_ENTER_SQ_WAIT,
                    sig: 0x7ffeabcd2000,
                    sigsz: 8,
                },
            },
        }
    },
    "222 io_uring_enter(fd: 7, to_submit: 2, min_complete: 1, flags: 0x5 (IORING_ENTER_GETEVENTS|IORING_ENTER_SQ_WAIT), sig: 0x7ffeabcd2000, sigsz: 8) = 1 (submitted)\n"
);

syscall_test!(
    parse_io_uring_register,
    {
        SyscallEvent {
            syscall_nr: SYS_io_uring_register,
            pid: 444,
            tid: 444,
            return_value: 0,
            data: SyscallEventData {
                io_uring_register: IoUringRegisterData {
                    fd: 4,
                    opcode: io_uring_constants::IORING_REGISTER_PROBE,
                    arg: 0x7ffeabcd3000,
                    nr_args: 4 | io_uring_constants::IORING_REGISTER_USE_REGISTERED_RING,
                },
            },
        }
    },
    "444 io_uring_register(fd: 4, opcode: IORING_REGISTER_PROBE, arg: 0x7ffeabcd3000, nr_args: 0x80000004 (4|IORING_REGISTER_USE_REGISTERED_RING)) = 0 (success)\n"
);
