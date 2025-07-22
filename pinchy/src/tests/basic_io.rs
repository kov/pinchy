// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::pin::Pin;

use indoc::indoc;
use pinchy_common::{
    kernel_types::{EpollEvent, Timespec},
    syscalls::{
        SYS_close, SYS_dup3, SYS_epoll_pwait, SYS_fcntl, SYS_lseek, SYS_openat, SYS_pipe2,
        SYS_ppoll, SYS_read, SYS_write,
    },
    CloseData, Dup3Data, EpollPWaitData, FcntlData, LseekData, OpenAtData, PpollData, ReadData,
    SyscallEvent, WriteData, DATA_READ_SIZE,
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
