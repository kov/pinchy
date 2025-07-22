// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

//! Tests for return value formatting functionality

use pinchy_common::syscalls;

use crate::util::format_return_value;

#[test]
fn test_error_return_values() {
    // All syscalls should show -1 as error
    assert_eq!(
        format_return_value(syscalls::SYS_openat, -1).as_ref(),
        "-1 (error)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_read, -1).as_ref(),
        "-1 (error)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_close, -1).as_ref(),
        "-1 (error)"
    );
}

#[test]
fn test_file_descriptor_returning_syscalls() {
    // File descriptor syscalls should show fd number on success
    assert_eq!(
        format_return_value(syscalls::SYS_openat, 3).as_ref(),
        "3 (fd)"
    );
    assert_eq!(format_return_value(syscalls::SYS_dup, 5).as_ref(), "5 (fd)");
    assert_eq!(
        format_return_value(syscalls::SYS_socket, 7).as_ref(),
        "7 (fd)"
    );
}

#[test]
fn test_byte_count_returning_syscalls() {
    // Byte count syscalls should show bytes on success
    assert_eq!(
        format_return_value(syscalls::SYS_read, 42).as_ref(),
        "42 (bytes)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_write, 128).as_ref(),
        "128 (bytes)"
    );

    // Zero bytes is valid
    assert_eq!(
        format_return_value(syscalls::SYS_read, 0).as_ref(),
        "0 (bytes)"
    );
}

#[test]
fn test_boolean_like_syscalls() {
    // Boolean-like syscalls should show success for 0
    assert_eq!(
        format_return_value(syscalls::SYS_close, 0).as_ref(),
        "0 (success)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_mkdirat, 0).as_ref(),
        "0 (success)"
    );

    // Non-zero is error
    assert_eq!(
        format_return_value(syscalls::SYS_close, -2).as_ref(),
        "-2 (error)"
    );
}

#[test]
fn test_poll_syscalls() {
    // Poll syscalls have special timeout/ready semantics
    assert_eq!(
        format_return_value(syscalls::SYS_ppoll, 0).as_ref(),
        "0 (timeout)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_ppoll, 3).as_ref(),
        "3 (ready)"
    );
}

#[test]
fn test_pid_returning_syscalls() {
    // PID syscalls should show pid on success
    assert_eq!(
        format_return_value(syscalls::SYS_getpid, 1234).as_ref(),
        "1234 (pid)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_clone, 5678).as_ref(),
        "5678 (pid)"
    );
}

#[test]
fn test_uid_gid_syscalls() {
    // UID/GID syscalls should show id on success
    assert_eq!(
        format_return_value(syscalls::SYS_getuid, 1000).as_ref(),
        "1000 (id)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_getgid, 1000).as_ref(),
        "1000 (id)"
    );
}

#[test]
fn test_memory_syscalls() {
    // Memory address returning syscalls
    assert_eq!(
        format_return_value(syscalls::SYS_mmap, 0x7f0000000000).as_ref(),
        "0x7f0000000000 (addr)"
    );

    // Memory protection syscalls
    assert_eq!(
        format_return_value(syscalls::SYS_mprotect, 0).as_ref(),
        "0 (success)"
    );
}

#[test]
fn test_default_syscall_handling() {
    // Unknown syscalls should show raw value or error
    let unknown_syscall = 9999;
    assert_eq!(format_return_value(unknown_syscall, 42).as_ref(), "42");
    assert_eq!(
        format_return_value(unknown_syscall, -5).as_ref(),
        "-5 (error)"
    );
}
