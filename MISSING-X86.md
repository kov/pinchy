# x86_64 Syscall Coverage Gap Analysis

This document analyzes the gap between syscalls defined in `pinchy-common/src/syscalls/x86_64.rs` and those implemented in the eBPF layer.

## Summary

- **x86_64 syscall table**: 346 syscalls defined
- **eBPF implementation**: ~321 unique syscalls handled (shared with ARM64)
- **Missing**: ~25 syscalls not yet implemented in pinchy

## Missing Syscalls

| # | Syscall | Status | Priority | Notes |
|---|---------|--------|----------|-------|
| 1 | `SYS_afs_syscall` | Legacy | Low | AFS filesystem syscall, rarely used |
| 2 | `SYS_arch_prctl` | **Active** | **High** | Architecture-specific prctl, still actively used by programs like glibc and musl |
| 3 | `SYS_create_module` | Deprecated | Low | Module loading via syscall (use init_module/finit_module instead) |
| 4 | `SYS_epoll_ctl_old` | Deprecated | Low | Old epoll API, superseded by epoll_ctl |
| 5 | `SYS_epoll_wait_old` | Deprecated | Low | Old epoll API, superseded by epoll_pwait/epoll_wait |
| 6 | `SYS_fadvise` | **Active** | **High** | POSIX file advice (fadvise64), commonly used |
| 7 | `SYS_get_kernel_syms` | Deprecated | Low | Kernel symbol table access, rarely used directly |
| 8 | `SYS_getpmsg` | Deprecated | Low | POSIX message passing, obsolete |
| 9 | `SYS_get_thread_area` | Legacy | Medium | Thread-local storage area (legacy alternative to arch_prctl) |
| 10 | `SYS_ioperm` | Rarely used | Medium | I/O port permissions, requires root, x86-specific |
| 11 | `SYS_iopl` | Rarely used | Medium | I/O privilege level, requires root, x86-specific |
| 12 | `SYS_kexec_file_load` | Active but rare | Medium-High | Kernel exec via file (security-sensitive, requires CAP_SYS_BOOT) |
| 13 | `SYS_modify_ldt` | Deprecated | Low-Low | LDT modification, deprecated in favor of arch_prctl |
| 14 | `SYS_open` | **Active** | **High** | Classic open syscall - should be aliased to openat with AT_FDCWD (like ARM64) |
| 15 | `SYS_putpmsg` | Deprecated | Low | POSIX message passing, obsolete |
| 16 | `SYS_query_module` | Deprecated | Low | Module information query (use finit_module instead) |
| 17 | `SYS_security` | LSM hook | Low | Security module hook, rarely used directly by applications |
| 18 | `SYS_set_thread_area` | Legacy | Medium | Thread-local storage area (legacy alternative to arch_prctl) |
| 19 | `SYS__sysctl` | Deprecated | Low-Low | Old sysctl interface (use /proc/sys or new sysctl API instead) |
| 20 | `SYS_sysfs` | Deprecated | Low-Low | Sysfs operations, obsolete |
| 21 | `SYS_time` | Deprecated | Low | Old time syscall (use clock_gettime/clock_getres instead) |
| 22 | `SYS_tuxcall` | Abandoned | Low | TUX network stack syscall, kernel feature long abandoned |
| 23 | `SYS_uselib` | Deprecated | Low-Low | Library loading at runtime, obsolete (link time linking preferred) |
| 24 | `SYS_ustat` | Deprecated | Low | Filesystem usage stats, obsolete |
| 25 | `SYS_vserver` | Abandoned | Low | VServer virtualization syscall, feature abandoned |

## High Priority Items

These syscalls should be implemented first as they are actively used:

### 1. `SYS_open` (Classic open)
- **Why**: Many programs still use the classic `open()` syscall directly
- **How**: Add alias mapping similar to ARM64 in `pinchy-common/src/syscalls/x86_64.rs`:
  ```rust
  "open" => SYS_openat,
  ```
- **Implementation**: Trivial handler (just pass through to openat logic)

### 2. `SYS_fadvise` / `SYS_fadvise64`
- **Why**: POSIX file advice used by databases and performance-sensitive applications
- **Man page**: https://man7.org/linux/man-pages/man2/fadvise.2.html
- **Complexity**: Complex - has pointer arguments for advice range
- **Implementation path**: Add to consolidated handler, parse advisory flags

### 3. `SYS_arch_prctl`
- **Why**: Actively used by glibc, musl, and other standard libraries on x86_64
- **Man page**: https://man7.org/linux/man-pages/man2/arch_prctl.2.html
- **Complexity**: Complex - pointer argument for control data
- **Implementation path**: Separate handler for arch_prctl with control code dispatch

## Medium Priority Items

These may be encountered in practice but are less common:

### 4. `SYS_ioperm` / `SYS_iopl`
- **Why**: x86-specific, used by low-level programs (emulators, debuggers)
- **Complexity**: Trivial - no pointer arguments
- **Implementation path**: Trivial handler

### 5. `SYS_kexec_file_load`
- **Why**: Used for secure boot and system management tools
- **Complexity**: Complex - multiple file descriptor arguments
- **Security note**: Requires CAP_SYS_BOOT, rare in normal workloads

## Low Priority Items (Legacy/Deprecated)

These are deprecated or obsolete but may appear when tracing old binaries:

| Syscall | Reason for low priority |
|---------|------------------------|
| `SYS_create_module` | Use `init_module` or `finit_module` instead |
| `SYS_epoll_ctl_old` / `SYS_epoll_wait_old` | Old epoll API, superseded by modern variants |
| `SYS_modify_ldt` | Deprecated in favor of `arch_prctl` |
| `SYS__sysctl` | Use `/proc/sys` or new sysctl interface instead |
| `SYS_sysfs`, `SYS_uselib`, `SYS_ustat` | Obsolete interfaces, rarely encountered |

## Implementation Checklist

For each syscall to be added:

1. **Confirm** `SYS_<name>` exists in x86_64 syscall file ✓ (already defined)
2. **Read man page** to understand pointer args and complexity
3. **Classify** as trivial or complex
4. **Wire eBPF handling**:
   - Trivial: add to `syscall_exit_trivial` in `pinchy-ebpf/src/main.rs`
   - Complex: add case to appropriate consolidated handler in `pinchy-ebpf/src/`
5. **Register tailcalls** in `pinchy/src/server.rs`:
   - `TRIVIAL_SYSCALLS` for trivial, or matching category array for complex
6. **Add/update `<Syscall>Data`** in `pinchy-common/src/lib.rs`
7. **Register payload size** in `compact_payload_size()` in `pinchy-common/src/lib.rs`
8. **Update parsing** in `pinchy/src/events.rs`, reusing existing format helpers
9. **Update `format_return_value`** handling in `pinchy/src/format_helpers.rs`
10. **Add tests** for parsing and formatting behavior

## Related Files

- **Syscall definitions**: `pinchy-common/src/syscalls/x86_64.rs`
- **Trivial handler**: `pinchy-ebpf/src/main.rs` (syscall_exit_trivial)
- **Consolidated handlers**: `pinchy-ebpf/src/*.rs`
- **Tailcall registration**: `pinchy/src/server.rs`
- **Event parsing**: `pinchy/src/events.rs`
- **Format helpers**: `pinchy/src/format_helpers.rs`
- **Tests**: `pinchy/src/tests/mod.rs`, `pinchy/tests/integration.rs`
