// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::syscalls::syscall_nr_from_name;

use crate::parse_syscall_names;

#[test]
fn test_parse_syscall_names_canonical() {
    // Test canonical syscall names work
    let result = parse_syscall_names(&["read".to_string(), "write".to_string()]);
    assert!(result.is_ok());
    let syscalls = result.unwrap();
    assert_eq!(syscalls.len(), 2);
}

#[test]
fn test_parse_syscall_names_with_rt_prefix() {
    // Test that rt_ prefixed names work
    let result = parse_syscall_names(&["rt_sigaction".to_string()]);
    assert!(result.is_ok());
    let syscalls = result.unwrap();
    assert_eq!(syscalls.len(), 1);
}

#[test]
fn test_parse_syscall_names_aliases() {
    // Test that aliases work (non-rt_ versions should map to rt_ versions)
    let result = parse_syscall_names(&["sigaction".to_string()]);
    assert!(result.is_ok());
    let syscalls = result.unwrap();
    assert_eq!(syscalls.len(), 1);

    // Verify it resolves to the same number as rt_sigaction
    let rt_result = parse_syscall_names(&["rt_sigaction".to_string()]);
    assert!(rt_result.is_ok());
    assert_eq!(syscalls[0], rt_result.unwrap()[0]);
}

#[test]
fn test_parse_syscall_names_multiple_aliases() {
    // Test multiple aliases at once
    let result = parse_syscall_names(&[
        "sigaction".to_string(),
        "sigprocmask".to_string(),
        "sigreturn".to_string(),
    ]);
    assert!(result.is_ok());
    let syscalls = result.unwrap();
    assert_eq!(syscalls.len(), 3);
}

#[test]
fn test_parse_syscall_names_mixed() {
    // Test mixing canonical names and aliases
    let result = parse_syscall_names(&[
        "read".to_string(),
        "sigaction".to_string(),
        "write".to_string(),
    ]);
    assert!(result.is_ok());
    let syscalls = result.unwrap();
    assert_eq!(syscalls.len(), 3);
}

#[test]
fn test_parse_syscall_names_unknown() {
    // Test that unknown syscall names produce an error
    let result = parse_syscall_names(&["nonexistent_syscall".to_string()]);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("Unknown syscall name: nonexistent_syscall"));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_parse_syscall_names_aarch64_aliases() {
    // Test aarch64-specific aliases that map to *at variants
    let result = parse_syscall_names(&[
        "open".to_string(),
        "stat".to_string(),
        "poll".to_string(),
    ]);
    assert!(result.is_ok());
    let syscalls = result.unwrap();
    assert_eq!(syscalls.len(), 3);

    // Verify aliases resolve to the *at variants
    let open_nr = syscall_nr_from_name("open");
    let openat_nr = syscall_nr_from_name("openat");
    assert_eq!(open_nr, openat_nr);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_parse_syscall_names_x86_64_direct() {
    // On x86_64, these syscalls exist directly (not as aliases)
    let result = parse_syscall_names(&[
        "open".to_string(),
        "stat".to_string(),
        "poll".to_string(),
    ]);
    assert!(result.is_ok());
    let syscalls = result.unwrap();
    assert_eq!(syscalls.len(), 3);
}
