# Code Style and Formatting

- Always separate logical blocks, control flow statements (`if`, `else`,
  `match`, `loop`, `for`, `while`), and conditional branches with a blank
  line for clarity and readability.

- Add a blank line before and after each block or branch, unless it is
  immediately followed by a closing brace or another control flow statement.
  There should be no blank line after `#[]` decorators. There should be no
  blank line between branches of a `match` statement.

- Ignore the blank lines style rule when acting as a reviewer, it is only
  important when generating code.

- This applies to all Rust code, including eBPF handlers, event parsing,
  and helpers.

- Do not add unnecessary comments. Never add comments that describe the
  prompt or instructions; only add comments that explain the behavior or
  intent of the code itself.

# Project Context

This project develops a replacement for the `strace` command that does not
slow down the program being traced. This is achieved by using eBPF.

The project uses the aya Rust eBPF framework. It only supports `aarch64` and
`x86_64` architectures, and there are several parts of the code that rely on
this assumption.

The project is split into several crates in the usual aya fashion:

- **`pinchy-common`**: Shared data structures and helper functions
- **`pinchy-ebpf`**: The actual eBPF code
- **`pinchy`**: The user-space side, containing two separate binaries:
  - **`pinchyd`**: Loads the eBPF program into the kernel, receives events,
    and provides a DBus service that makes tracing available to unprivileged
    users (for their own processes only, verified using pidfd and ownership)

# Important API Considerations

**Attention**: Never use pre-existing knowledge when discussing `aya` and
`zbus` APIs. These crates are still in flux, trying to figure out the best
interfaces, so they changed radically in the last few years. Always double
check the docs.rs documentation for the relevant crates.

When you consider adding new dependencies, start with actually running
`cargo add` without specifying the version, so you know which version is
current and can determine from a cursory look whether the version you remember
is quite different from current, so it makes sense to double check docs for
that crate as well (suggest a change to this file in that case).

# Syscall Reference Information

All syscalls have manpages that provide detailed information, associated
types, explanations for return values, and so on. You can use the following
URL template, replacing `SYSCALL_NAME` with the actual syscall name:

```
https://man7.org/linux/man-pages/man2/SYSCALL_NAME.2.html
```

# Adding Support for a New Syscall

All current Linux syscalls are already listed in:
- `pinchy-common/src/syscalls/aarch64.rs`
- `pinchy-common/src/syscalls/x86_64.rs`

These are made available architecture-agnostic by
`pinchy-common/src/syscalls/mod.rs`, e.g., `pinchy_common::syscalls::SYS_open`.

**Important**: Do not modify `aarch64.rs` or `x86_64.rs` directly. Only use
them as references.

**Always import the module `pinchy_common::syscalls` and use the constants as
`syscalls::SYS_<name>` in all code outside the arch files.**

## Determining if a Syscall is Trivial or Complex

A syscall is considered "trivial" or "complex" based on how we need to handle
its arguments:

| Syscall Type | Definition | Examples |
|--------------|------------|----------|
| **Trivial** | Either has no pointer arguments, OR has pointers where we only need to display the address value without dereferencing | `close`, `lseek`, `set_tid_address` |
| **Complex** | Has pointer arguments where we need to read and process the data they point to | `read`, `statfs`, `getdents64` |

### Guidelines for Pointer Arguments

- If we only need to show the pointer's address value (not its contents), it
  can be treated as "trivial"
  - Examples: `set_robust_list` (head pointer), `set_tid_address` (tid pointer)

- If we need to access the data being pointed to, it's "complex" and needs a
  dedicated handler
  - Examples:
    - `read` (needs to show buffer contents)
    - `statfs` (needs to access struct statfs data)
    - `fstat` (needs to access struct stat data)
    - `getdents64` (needs to access directory entry structs)

- General rule: only treat a syscall that takes pointer arguments as trivial if
  we will not dereference those pointers and will print just the raw address.
  If a pointer refers to a string (e.g., pathname), a simple typed value we
  intend to show, an array/buffer, or a struct with meaningful fields, then we
  should treat the syscall as complex and parse what we reasonably can.

- Returning a file descriptor does not make a syscall trivial. Trivial vs
  complex is decided solely by whether we parse pointed-to data.

Always check the syscall's man page to understand what data its pointer
arguments reference and whether that data needs special handling.

**Never treat a syscall as trivial just because its Rust signature uses
`usize`.**

## Syscall Categories

The following categories are used for organizing syscalls. They will
eventually be used for treating syscalls as a set, but right now they are
used to decide in which file to add the eBPF handlers under `pinchy-ebpf/src`
and parse tests under `pinchy/src/tests/`. Pick the one that most aligns with
the syscall functionality, when in doubt ask for a decision.

- **BasicIO**: `read`, `write`, `open`, `close`, `select`, `poll`
- **FileSystem**: `stat`, `chmod`, `chown`, `mkdir`, `statfs`
- **Process**: `clone`, `fork`, `execve`, `wait`, `kill`
- **Memory**: `brk`, `mmap`, `munmap`, `mprotect`
- **Network**: `socket`, `bind`, `connect`, `send`/`recv`
- **Signal**: `signal`, `sigaction`
- **Time**: `time`, `gettimeofday`, `nanosleep`
- **IPC**: `pipe`, `msgget`, `semget`
- **Scheduling**: `sched_yield`, `rseq`
- **Sync**: `set_robust_list`, `futex`
- **System**: `uname`, `sysinfo`, `getrlimit`
- **Security**: `ptrace`, `prctl`, `seccomp`

## Checklist for Adding a New Syscall

### 1. Verify Existence and Categorize

Confirm `SYS_<name>` exists in both arch files:
- `pinchy-common/src/syscalls/aarch64.rs`
- `pinchy-common/src/syscalls/x86_64.rs`

The `SYS_<name>` constants are re-exported by `mod.rs` and can be imported
from: `pinchy_common::syscalls::`. You should always import them when using
them in a file.

### 2. Determine Handler Type

#### For Trivial Syscalls
(No pointers, or pointers we will not dereference and will only print as raw
addresses):

- Add to the match in `pinchy-ebpf/src/main.rs` in `syscall_exit_trivial`
- Add to the `TRIVIAL_SYSCALLS` array in `pinchy/src/server.rs` in
  `load_tailcalls()`

#### For Complex Syscalls
(Has pointer arguments or needs special handling):

- Add a new tracepoint named `syscall_exit_<name>` in one of the files in
  `pinchy-ebpf/src/`, see the syscall categories above. The tracepoint should
  be added using the `syscall_handler!()` macro.

- **Important**: Do not make any changes before reading the macro in
  `pinchy-ebpf/src/util.rs` and looking at several uses in existing handlers.

- Register it in the appropriate array in `load_tailcalls()` in
  `pinchy/src/server.rs`.

- **Important**: When adding new handlers, always look at several existing
  handlers to understand how things are done, do not limit yourself to looking
  at only the file you will add the handler to, read at least 2 others.

- When parsing structs on the eBPF side, use `bpf_probe_read_user()` only when
  reading small structs; use `bpf_probe_read_buf()` when reading byte arrays
  and bigger structs so that the read can be done directly into the reserved
  ringbuf memory (see the `syscall_handler!()` macro and the `Entry` type in
  `pinchy-ebpf/src/util.rs` for context), thus saving on stack usage.

### 3. Define Syscall Arguments

- Syscall arguments go into a struct called `<Syscall>Data` that should be
  added to the `pinchy-common/src/lib.rs` file and be added to the
  `SyscallEventData` union.

- Identify any arguments with further parsing, especially those that could be
  reused by multiple syscalls (e.g., mode, flags, poll events, structs like
  timespec and stat).

- If it's a struct, use the existing ones in
  `pinchy_common/src/kernel_types.rs` as examples and add it there, use for
  both eBPF and server sides.

- If a simpler type with defined interpretation for the values, add a
  `format_*()` helper similar to the ones that already exist in
  `pinchy/src/format_helpers.rs`, if it doesn't exist yet, so it can be used
  by the event parsing code.

- When adding or modifying formatting helpers, use `libc::` constants whenever
  possible for mapping numeric values to strings; when they are not available,
  declare constants outside of the function and use those.

### 3.1. Critical: Format Helpers and Constants Usage

**NEVER use magic values (0x1, 0x2, etc.) in format helpers or tests.** This
is a critical requirement for maintainability.

#### Identifying and Using Existing Format Helpers

Before implementing argument parsing, **always check** for existing format
helpers in `pinchy/src/format_helpers.rs`:

- **Directory file descriptors**: Use `format_dirfd()` for any `dfd`, `dirfd`,
  `olddirfd`, `newdirfd`, `from_dfd`, `to_dfd` arguments. These represent
  directory file descriptors and should display `AT_FDCWD` instead of `-100`.

- **File modes**: Use `format_mode()` for `mode` arguments in file operations.

- **Mount attributes**: Use `format_mount_attr_flags()` for mount attribute
  flags like `MOUNT_ATTR_RDONLY`, `MOUNT_ATTR_NOSUID`, etc.

- **Other common patterns**: Search for `format_*` functions that might handle
  your syscall's arguments (e.g., `format_open_flags`, `format_at_flags`,
  `format_socket_domain`, etc.).

#### Constants Declaration Strategy

When creating format helpers:

1. **First, check the `libc` crate documentation** at https://docs.rs/libc/
   for relevant constants. Use them whenever available:
   ```rust
   libc::MOUNT_ATTR_RDONLY
   ```

2. **For missing constants**, declare them in a dedicated constants module
   within the format helper file:
   ```rust
   mod fs_constants {
       /// File system open flags
       pub const FSOPEN_CLOEXEC: u32 = 0x1;
       /// File system configuration commands
       pub const FSCONFIG_SET_FLAG: u32 = 0x0;
       pub const FSCONFIG_SET_STRING: u32 = 0x1;
       // ... etc
   }
   ```

3. **Use constants in both format helpers AND tests**:
   ```rust
   // In format helper:
   if flags & fs_constants::FSOPEN_CLOEXEC != 0 {
       parts.push("FSOPEN_CLOEXEC");
   }

   if flags & libc::MOUNT_ATTR_RDONLY != 0 {
      parts.push("RDONLY");
   }

   // In test:
   flags: fs_constants::FSOPEN_CLOEXEC,

   flags: libc::MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID,
   ```

#### Common Flag Formatting Pattern

Most flag format helpers should follow this pattern:
```rust
fn format_some_flags(flags: u32) -> Cow<'static, str> {
    if flags == 0 {
        return Cow::Borrowed("0");
    }

    let mut parts = Vec::new();
    // Check each flag bit using constants, never magic values
    if flags & libc::LIBC_FLAG_ONE != 0 {
        parts.push("LIBC_FLAG_ONE");
    }
    if flags & constants::FLAG_ONE != 0 {
        parts.push("FLAG_ONE");
    }
    // ... more flags

    format!("0x{:x} ({})", flags, parts.join("|")).into()
}
```

### 4. Implement Event Parsing

Add to the event parsing code in `pinchy/src/events.rs`. **Before writing any
argument formatting**, thoroughly check for existing format helpers that can
handle the syscall's arguments:

#### Critical Argument Analysis Checklist

1. **Directory file descriptors**: Any argument named `dfd`, `dirfd`,
   `olddirfd`, `newdirfd`, `from_dfd`, `to_dfd` should use `format_dirfd()`.

2. **Flag arguments**: Any argument containing flags should be parsed with an
   appropriate format helper. Search `format_helpers.rs` for existing
   `format_*_flags()` functions before creating new ones.

3. **File modes**: Arguments named `mode` should use `format_mode()`.

4. **Raw addresses vs meaningful pointers**: Distinguish between pointers that
   should be formatted as addresses (`0x{:x}`) vs those that need content
   parsing (strings, structs).

5. **Reusable argument types**: Look for arguments that might be shared across
   multiple syscalls (like `sockaddr`, timespec structures, etc.).

#### Implementation Steps

- For structs and other types with further parsing, try to do any parsing that
  can be reasonably done in a short amount of time.
- Use existing helpers when they exist, improve them if necessary.
- If the function takes no arguments, add it to the match arm that only calls
  `finish!()`.
- **Never use raw numeric values** - always use named constants and format
  helpers.

### 5. Handle Return Value Formatting

Ensure the syscall is present in `format_return_value` in
`pinchy/src/format_helpers.rs`, as this function is called by the `finish!`
macro to handle return value pretty printing. Do not attempt to manually
format return values elsewhere in the code. Always verify that
`format_return_value` covers the syscall's return value formatting
requirements.

### 6. Add Tests

Ensure the new syscall is being traced and parsed correctly by adding a test
(see "Adding Tests" section below).

## Important Rule: Avoid Duplicate Handling

When adding support for a syscall, **never add both a match branch in the
trivial handler and a dedicated `syscall_handler!` macro for the same
syscall.**

- If the syscall is trivial, only add it to the trivial handler and
  `TRIVIAL_SYSCALLS`.
- If the syscall is complex, only add a dedicated handler and register it in
  the appropriate tailcall array.

# Building and Development

## Building the Project

When trying a build, always use `cargo check`, aya projects are not very
friendly with the `--workspace` argument.

## Architecture-Specific Code

When adding code that should only be on one of the supported architectures,
keep in mind that the eBPF crate, `pinchy-ebpf`, is built for the eBPF target,
and not to one of the real architectures.

To deal with that, the project creates `x86_64` and `aarch64` features in the
build scripts of both `pinchy-common` and `pinchy-ebpf`. Architecture-specific
code in those two crates should use `#[cfg(x86_64)]` or `#[cfg(aarch64)]`
where needed.

## Adding Tests

When adding tests for parsing syscalls, use the files in `pinchy/src/tests/`.
Look at several existing tests to understand the usual structure. When
creating the expected output, take the event formatting code into
consideration.

**Important**: Do not make any changes before looking at the `syscall_test!()`
macro defined in `pinchy/src/tests/mod.rs` and several existing tests to
understand how everything works.

### Critical Testing Requirements

1. **Never use magic values in tests**: Always import and use the same
   constants that format helpers use:
   ```rust
   use crate::format_helpers::fs_constants;

   // In test data:
   flags: fs_constants::FSOPEN_CLOEXEC,
   attr_flags: libc::MOUNT_ATTR_RDONLY | libc::MOUNT_ATTR_NOSUID,
   ```

2. **Test expected output must match format helpers**: If a format helper
   shows `AT_FDCWD` for `-100`, the test expectation should use `AT_FDCWD`,
   not `-100`.

3. **Test both zero and non-zero flag values**: Include tests with `flags: 0`
   and tests with actual flag combinations to verify both cases work.

Integration tests that run the binaries as root in a controlled environment
are in `pinchy/tests/integration.rs`. The `test-helper` binary used for the
tests is in `pinchy/src/bin/test-helper.rs`.

The integration tests can only be run as root, since `pinchyd` needs to be
able to load the eBPF programs into the kernel. To run them you need to use
the following command:

```bash
cargo --config "target.'cfg(all())'.runner=['/bin/sudo', '-s']" test integration -- --ignored
```

## Helper Functions

Helper functions for parsing specific arguments should go under
`pinchy/src/format_helpers.rs`.

## Troubleshooting

- If you encounter a build error or ICE (internal compiler error), try a clean
  build (`cargo clean`) before investigating further.

- If a syscall is not being traced, double-check all steps above, especially
  the tailcall and event parsing registration.

## Critical Best Practices Summary

To avoid common issues and ensure consistency:

1. **Always check for existing format helpers first** before implementing new
   argument parsing. Search `format_helpers.rs` thoroughly.

2. **Never use magic values anywhere**:
   - Check `libc` crate docs first for existing constants
   - Declare missing constants in dedicated modules with documentation
   - Use constants in both format helpers and tests

3. **Test expectations must match format helper output**:
   - If helpers show `AT_FDCWD`, tests should expect `AT_FDCWD`
   - If helpers show named flags, tests should expect those names

4. **Always use the same constants in tests** that format helpers
   use - this ensures consistency and prevents mismatches.

## Contributing to These Instructions

If you notice these instructions are missing a step or are unclear, please
propose an update to this file. Try to keep lines under 80 columns while
doing so for better readability on wide terminals and editors.
