// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::pin::Pin;

use indoc::indoc;
use pinchy_common::{
    kernel_types::{EpollEvent, Iovec, Timespec},
    syscalls::{
        SYS_close, SYS_close_range, SYS_dup, SYS_dup3, SYS_epoll_create1, SYS_epoll_pwait,
        SYS_fcntl, SYS_lseek, SYS_openat, SYS_pipe2, SYS_ppoll, SYS_pread64, SYS_preadv2,
        SYS_pwrite64, SYS_read, SYS_readv, SYS_write, SYS_writev,
    },
    CloseData, CloseRangeData, Dup3Data, DupData, EpollCreate1Data, EpollPWaitData, FcntlData,
    LseekData, OpenAtData, PpollData, PreadData, PwriteData, ReadData, SyscallEvent, VectorIOData,
    WriteData, DATA_READ_SIZE,
};
#[cfg(target_arch = "x86_64")]
use pinchy_common::{
    syscalls::{SYS_dup2, SYS_epoll_create, SYS_poll},
    Dup2Data, EpollCreateData, PollData,
};

use crate::{
    events::handle_event,
    formatting::{Formatter, FormattingStyle},
};

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
        format!("1 close(fd: 2) = 0 (success)\n")
    );
}

#[tokio::test]
async fn parse_dup3() {
    let event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("1 dup3(oldfd: 3, newfd: 4, flags: 0) = 4 (fd)\n")
    );
}

#[tokio::test]
async fn parse_dup3_with_flags() {
    let event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("1 dup3(oldfd: 3, newfd: 5, flags: 0x80000 (O_CLOEXEC)) = 5 (fd)\n")
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
        format!(
            "1 epoll_pwait(epfd: 4, events: [ epoll_event {{ events: POLLIN|POLLERR|POLLHUP, data: 0xbeef }} ], max_events: 10, timeout: -1, sigmask) = 1\n"
        )
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
        format!(
            "22 ppoll(fds: [ {{ 3, POLLIN }} ], nfds: 1, timeout: {{ secs: 0, nanos: 0 }}, sigmask) = 0 (timeout)\n"
        )
    );

    // Test ppoll with ready results and detailed output
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

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event_ready, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "22 ppoll(fds: [ { 5, POLLIN } ], nfds: 1, timeout: { secs: 1, nanos: 0 }, sigmask) = 1 (ready) [5 = POLLIN]\n"
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
        .zip((0..).flat_map(|n: u8| std::iter::repeat_n(n, 10)))
        .for_each(|(b, i)| *b = i + 65);

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "22 read(fd: 3, buf: \"AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFFGGGGGGGGGGHHHHHHHHHHIIIIIIIIIIJJJJJJJJJJKKKKKKKKKKLLLLLLLLLLMMMMMMMM\" ... (8064 more bytes), count: 8192) = 8192 (bytes)\n"
        )
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
        .zip((0..).flat_map(|n: u8| std::iter::repeat_n(n, 10)))
        .for_each(|(b, i)| *b = i + 65);

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "22 write(fd: 3, buf: \"AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFFGGGGGGGGGGHHHHHHHHHHIIIIIIIIIIJJJJJJJJJJKKKKKKKKKKLLLLLLLLLLMMMMMMMM\" ... (8064 more bytes), count: 8192) = 8192 (bytes)\n"
        )
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
    openat_data.pathname[..path.len()].copy_from_slice(path);

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "22 openat(dfd: AT_FDCWD, pathname: \"/etc/passwd\", flags: 0x80000 (O_RDONLY|O_CLOEXEC), mode: 0o666 (rw-rw-rw-)) = 3 (fd)\n"
    );
}

#[tokio::test]
async fn parse_fcntl() {
    // Test F_GETFL command
    let event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("22 fcntl(fd: 3, cmd: F_GETFL, arg: 0x0) = 2\n")
    );
}

#[tokio::test]
async fn parse_fcntl_setfl() {
    // Test F_SETFL command with O_NONBLOCK
    let event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("42 fcntl(fd: 5, cmd: F_SETFL, arg: 0x800) = 0\n")
    );
}

#[tokio::test]
async fn parse_fcntl_dupfd() {
    // Test F_DUPFD command
    let event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("100 fcntl(fd: 3, cmd: F_DUPFD, arg: 0x4) = 7\n")
    );
}

#[tokio::test]
async fn parse_pipe2() {
    let event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "1 pipe2(pipefd: [ 3, 4 ], flags: 0x{:x}) = 0\n",
            libc::O_CLOEXEC
        )
    );
}

#[tokio::test]
async fn parse_dup() {
    let event = SyscallEvent {
        syscall_nr: SYS_dup,
        pid: 1,
        tid: 1,
        return_value: 4, // new fd
        data: pinchy_common::SyscallEventData {
            dup: DupData { oldfd: 3 },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1 dup(oldfd: 3) = 4 (fd)\n"
    );
}

#[cfg(target_arch = "x86_64")]
#[tokio::test]
async fn parse_dup2() {
    let event = SyscallEvent {
        syscall_nr: SYS_dup2,
        pid: 1,
        tid: 1,
        return_value: 5, // new fd
        data: pinchy_common::SyscallEventData {
            dup2: Dup2Data { oldfd: 3, newfd: 5 },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1 dup2(oldfd: 3, newfd: 5) = 5 (fd)\n"
    );
}

#[tokio::test]
async fn parse_close_range() {
    let event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1 close_range(fd: 3, max_fd: 10, flags: 0x0) = 0 (success)\n"
    );
}

#[tokio::test]
async fn parse_pread() {
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

    // A = 65
    pread_data
        .buf
        .iter_mut()
        .zip((0..).flat_map(|n: u8| std::iter::repeat_n(n, 10)))
        .for_each(|(b, i)| *b = i + 65);

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "22 pread64(fd: 3, buf: \"AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFFGGGGGGGGGGHHHHHHHHHHIIIIIIIIIIJJJJJJJJJJKKKKKKKKKKLLLLLLLLLLMMMMMMMM\" ... (3968 more bytes), count: 4096, offset: 1024) = 4096 (bytes)\n"
        )
    );
}

#[tokio::test]
async fn parse_pwrite() {
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

    // A = 65
    pwrite_data
        .buf
        .iter_mut()
        .zip((0..).flat_map(|n: u8| std::iter::repeat_n(n, 10)))
        .for_each(|(b, i)| *b = i + 65);

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "22 pwrite64(fd: 3, buf: \"AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFFGGGGGGGGGGHHHHHHHHHHIIIIIIIIIIJJJJJJJJJJKKKKKKKKKKLLLLLLLLLLMMMMMMMM\" ... (3968 more bytes), count: 4096, offset: 2048) = 4096 (bytes)\n"
        )
    );
}

#[tokio::test]
async fn parse_readv() {
    let mut data = VectorIOData {
        fd: 3,
        iovecs: [Iovec {
            iov_base: 0x1000,
            iov_len: 4,
        }; pinchy_common::IOV_COUNT],
        iov_lens: [4; pinchy_common::IOV_COUNT],
        iov_bufs: [[0u8; pinchy_common::MEDIUM_READ_SIZE]; pinchy_common::IOV_COUNT],
        iovcnt: 2,
        offset: 0,
        flags: 0,
        read_count: 2,
    };

    data.iov_bufs[0][..4].copy_from_slice(b"test");
    data.iov_bufs[1][..4].copy_from_slice(b"data");

    let event = SyscallEvent {
        syscall_nr: SYS_readv,
        pid: 1,
        tid: 1,
        return_value: 8,
        data: pinchy_common::SyscallEventData { vector_io: data },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1 readv(fd: 3, iov: [ iovec { base: \"test\", len: 4 }, iovec { base: \"data\", len: 4 } ], iovcnt: 2) = 8 (bytes)\n"
    );
}

#[tokio::test]
async fn parse_writev() {
    let mut data = VectorIOData {
        fd: 4,
        iovecs: [Iovec {
            iov_base: 0x2000,
            iov_len: 3,
        }; pinchy_common::IOV_COUNT],
        iov_lens: [3; pinchy_common::IOV_COUNT],
        iov_bufs: [[0u8; pinchy_common::MEDIUM_READ_SIZE]; pinchy_common::IOV_COUNT],
        iovcnt: 1,
        offset: 0,
        flags: 0,
        read_count: 1,
    };

    data.iov_bufs[0][..3].copy_from_slice(b"abc");

    let event = SyscallEvent {
        syscall_nr: SYS_writev,
        pid: 2,
        tid: 2,
        return_value: 3,
        data: pinchy_common::SyscallEventData { vector_io: data },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "2 writev(fd: 4, iov: [ iovec { base: \"abc\", len: 3 } ], iovcnt: 1) = 3 (bytes)\n"
    );
}

#[tokio::test]
async fn parse_preadv2() {
    let mut data = VectorIOData {
        fd: 5,
        iovecs: [Iovec {
            iov_base: 0x3000,
            iov_len: 5,
        }; pinchy_common::IOV_COUNT],
        iov_lens: [5; pinchy_common::IOV_COUNT],
        iov_bufs: [[0u8; pinchy_common::MEDIUM_READ_SIZE]; pinchy_common::IOV_COUNT],
        iovcnt: 1,
        offset: 1234,
        flags: 0x10,
        read_count: 1,
    };

    data.iov_bufs[0][..5].copy_from_slice(b"hello");

    let event = SyscallEvent {
        syscall_nr: SYS_preadv2,
        pid: 3,
        tid: 3,
        return_value: 5,
        data: pinchy_common::SyscallEventData { vector_io: data },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "3 preadv2(fd: 5, iov: [ iovec { base: \"hello\", len: 5 } ], iovcnt: 1, offset: 1234, flags: 0x10) = 5\n"
    );
}

#[tokio::test]
async fn test_epoll_create1() {
    let event = SyscallEvent {
        syscall_nr: SYS_epoll_create1,
        pid: 1001,
        tid: 1001,
        return_value: 5, // epoll fd
        data: pinchy_common::SyscallEventData {
            epoll_create1: EpollCreate1Data {
                flags: libc::EPOLL_CLOEXEC,
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1001 epoll_create1(flags: EPOLL_CLOEXEC) = 5 (fd)\n"
    );
}

#[cfg(target_arch = "x86_64")]
#[tokio::test]
async fn test_epoll_create() {
    let event = SyscallEvent {
        syscall_nr: SYS_epoll_create,
        pid: 1001,
        tid: 1001,
        return_value: 5, // epoll fd
        data: pinchy_common::SyscallEventData {
            epoll_create: EpollCreateData { size: 10 },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1001 epoll_create(size: 10) = 5 (fd)\n"
    );
}

#[cfg(target_arch = "x86_64")]
#[tokio::test]
async fn test_poll() {
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

    let event = SyscallEvent {
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
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1001 poll(fds: [ pollfd { fd: 0, events: POLLIN, revents: POLLIN }, pollfd { fd: 1, events: POLLOUT, revents: POLLOUT } ], nfds: 2, timeout: 1000) = 2 (ready)\n"
    );
}
