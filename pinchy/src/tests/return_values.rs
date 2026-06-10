// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

//! Tests for return value formatting functionality

use pinchy_common::syscalls;

use crate::format_helpers::format_return_value;

#[test]
fn test_error_return_values() {
    // All syscalls should show -1 as error
    assert_eq!(
        format_return_value(syscalls::SYS_openat, -1).as_ref(),
        "-1 (EPERM: Operation not permitted)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_read, -1).as_ref(),
        "-1 (EPERM: Operation not permitted)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_close, -1).as_ref(),
        "-1 (EPERM: Operation not permitted)"
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

    // Socket syscalls should show success for 0
    assert_eq!(
        format_return_value(syscalls::SYS_bind, 0).as_ref(),
        "0 (success)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_listen, 0).as_ref(),
        "0 (success)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_connect, 0).as_ref(),
        "0 (success)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_shutdown, 0).as_ref(),
        "0 (success)"
    );

    // Non-zero is error
    assert_eq!(
        format_return_value(syscalls::SYS_close, -2).as_ref(),
        "-2 (ENOENT: No such file or directory)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_bind, -1).as_ref(),
        "-1 (EPERM: Operation not permitted)"
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
        "-5 (EIO: Input/output error)"
    );
}

#[test]
fn test_adjtimex_return_values() {
    // Test adjtimex return values - should show time state
    assert_eq!(
        format_return_value(syscalls::SYS_adjtimex, 0).as_ref(),
        "0 (TIME_OK)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_adjtimex, 1).as_ref(),
        "1 (TIME_INS)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_adjtimex, 2).as_ref(),
        "2 (TIME_DEL)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_adjtimex, 3).as_ref(),
        "3 (TIME_OOP)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_adjtimex, 4).as_ref(),
        "4 (TIME_WAIT)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_adjtimex, 5).as_ref(),
        "5 (TIME_ERROR)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_adjtimex, -22).as_ref(),
        "-22 (EINVAL: Invalid argument)"
    );
}

#[test]
fn test_clock_adjtime_return_values() {
    // Test clock_adjtime return values - should show time state
    assert_eq!(
        format_return_value(syscalls::SYS_clock_adjtime, 0).as_ref(),
        "0 (TIME_OK)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_clock_adjtime, 1).as_ref(),
        "1 (TIME_INS)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_clock_adjtime, 5).as_ref(),
        "5 (TIME_ERROR)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_clock_adjtime, -95).as_ref(),
        "-95 (EOPNOTSUPP: Operation not supported)"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_deprecated_syscall_return_values() {
    assert_eq!(
        format_return_value(syscalls::SYS_tuxcall, 0).as_ref(),
        "0 (success)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_tuxcall, -38).as_ref(),
        "-38 (ENOSYS: Function not implemented)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_sysfs, 2).as_ref(),
        "2 (success)"
    );
}

#[test]
fn test_raw_errno_return_values() {
    // Raw sys_exit values are -errno, not just -1; any negative value is an
    // error for these syscalls
    assert_eq!(
        format_return_value(syscalls::SYS_ppoll, -(libc::EINTR as i64)).as_ref(),
        "-4 (EINTR: Interrupted system call)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_mmap, -(libc::ENOMEM as i64)).as_ref(),
        "-12 (ENOMEM: Cannot allocate memory)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_mremap, -(libc::EFAULT as i64)).as_ref(),
        "-14 (EFAULT: Bad address)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_shmat, -(libc::EACCES as i64)).as_ref(),
        "-13 (EACCES: Permission denied)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_shmget, -(libc::ENOENT as i64)).as_ref(),
        "-2 (ENOENT: No such file or directory)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_msgget, -(libc::ENOENT as i64)).as_ref(),
        "-2 (ENOENT: No such file or directory)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_semget, -(libc::ENOENT as i64)).as_ref(),
        "-2 (ENOENT: No such file or directory)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_inotify_add_watch, -(libc::ENOSPC as i64)).as_ref(),
        "-28 (ENOSPC: No space left on device)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_membarrier, -(libc::EINVAL as i64)).as_ref(),
        "-22 (EINVAL: Invalid argument)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_pkey_alloc, -(libc::ENOSPC as i64)).as_ref(),
        "-28 (ENOSPC: No space left on device)"
    );
    assert_eq!(
        format_return_value(syscalls::SYS_rt_sigtimedwait, -(libc::EAGAIN as i64)).as_ref(),
        "-11 (EAGAIN: Resource temporarily unavailable)"
    );

    // brk returns the new break, never an errno
    assert_eq!(
        format_return_value(syscalls::SYS_brk, 0x5500000000).as_ref(),
        "0x5500000000"
    );
}
