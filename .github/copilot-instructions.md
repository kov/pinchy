# Code Style and Formatting

- Always separate logical blocks, control flow statements (such as if,
  else, match, loop, for, while), and conditional branches with a blank
  line for clarity and readability.
- Add a blank line before and after each block or branch, unless it is
  immediately followed by a closing brace or another control flow
  statement.
- This applies to all Rust code, including eBPF handlers, event parsing,
  and helpers.
- Do not add unnecessary comments. Never add comments that describe the
  prompt or instructions; only add comments that explain the behaviour or
  intent of the code itself.

# Project context

This project is trying to develop a replacement for the strace command that
does not slow down the program being traced. This is achieved by using eBPF.

The project uses the aya Rust eBPF framework. It only supports aarch64 and
x86_64, for now, and there are several parts of the code that rely on this
assumption.

It is split into several crates in the usual aya fashion: pinchy-common is
just for sharing common data structures and helper functions. pinchy-ebpf
contains the actual eBPF code, and pinchy has the user-space side. pinchy
contains 2 separate binaries, pinchyd, which loads the eBPF program into the
kernel, receives the events, and also provides a DBus service that makes
tracing available to unprivileged users - for their own processes only,
for now, checked by using a pidfd and verifying ownership.

# Risk of outdated knowledge

Atention: never use pre-existing knowledge when discussing aya and zbus APIs.
Their crates are still in flux, trying to figure out the best interfaces,
so they changed radically in the last few years. Always double check
the docs.rs documentation for the relevant crates.

When you consider adding new dependencies, start with actually running
cargo add without specifying the version, so you know which version is current
and can know from a cursory look whether the version you remember is quite
different from current, so it makes sense to double check docs for that crate
as well (suggest a change to this file in that case).

# Getting details about a syscall

All syscalls should have manpages that provide a lot of detailed information,
associated types, explanations for return values, and so on. You can use
the following URL, replacing <syscall> with the name:

  https://man7.org/linux/man-pages/man2/<syscall>.2.html

# Adding support for a new syscall

All current Linux syscalls are already listed in
`pinchy-common/src/syscalls/aarch64.rs` and
`pinchy-common/src/syscalls/x86_64.rs` and are made available
architecture-agnostic by `pinchy-common/src/syscalls/mod.rs`, e.g.
`pinchy_common::syscalls::SYS_open`.

**Do not modify `aarch64.rs` or `x86_64.rs` directly. Only use them as
references.**

**Always import SYS_* constants from `pinchy_common::syscalls` in all
code outside the arch files.**

## Determining if a syscall is trivial or complex

A syscall is considered "trivial" or "complex" based on how we need to handle its arguments:

| Syscall type | Definition | Examples |
|-------------|------------|---------|
| **Trivial** | Either has no pointer arguments, OR has pointers where we only need to display the address value without dereferencing | `close`, `lseek`, `set_tid_address` |
| **Complex** | Has pointer arguments where we need to read and process the data they point to | `read`, `statfs`, `getdents64` |

For syscalls with pointer arguments:
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

Always check the syscall's man page to understand what data its pointer
arguments reference and whether that data needs special handling.

**Never treat a syscall as trivial just because its Rust signature uses `usize`.**

## Checklist for Adding a New Syscall

1. **Verify existence and categorize:** Confirm `SYS_<name>` exists in both arch files
   (see `pinchy-common/src/syscalls/aarch64.rs` and
   `pinchy-common/src/syscalls/x86_64.rs`). The `SYS_<name>` constants are
   re-exported by `mod.rs` and can be imported from the following path:
   `pinchy_common::syscalls::`. You should always import them when using them
   on a file.

   The following are the categories we use for syscalls. They will eventually be used
   for treating syscalls as a set, but right now they are used to decide in which file
   to add the eBPF handlers under `pinchy-ebpf/src` and parse tests under
   `pinchy/src/tests/`. Pick the one that most aligns with the syscall functionality,
   when in doubt ask for a decision.

   pub enum SyscallCategory {
     BasicIO,        // read, write, open, close, select, poll
     FileSystem,     // stat, chmod, chown, mkdir, statfs
     Process,        // clone, fork, execve, wait,  kill
     Memory,         // brk, mmap, munmap, mprotect
     Network,        // socket, bind, connect, send/recv
     Signal,         // signal, sigaction
     Time,           // time, gettimeofday, nanosleep
     IPC,            // pipe, msgget, semget
     Scheduling,     // sched_yield, rseq
     Sync,           // set_robust_list, futex
     System,         // uname, sysinfo, getrlimit
     Security,       // ptrace, prctl, seccomp
   }

2. **Trivial or complex:**
   - If trivial (no pointers, all arguments are plain integers):
     - Add to the match in `pinchy-ebpf/src/main.rs` in
       `try_syscall_exit_trivial`.
     - Add to the `TRIVIAL_SYSCALLS` array in
       `pinchy/src/server.rs` in `load_tailcalls()`.
   - If complex (has pointer arguments or needs special handling):
     - Add a new tracepoint named `syscall_exit_<name>` in one of the files in
       `pinchy-ebpf/src/`, see the discussion on categories above.
     - Register it in the appropriate array in `load_tailcalls()` in
       `pinchy/src/server.rs`.
     - When adding new handlers, always look at several existing handlers to
       understand how things are done, do not limit yourself to looking at only
       the file you will add the handler to, read at least 2 others.
     - When parsing structs on the eBPF side, use `bpf_probe_read_user()`;
       only use `bpf_probe_read_buf()` when reading byte arrays.
3. **Syscall arguments:**
   - Syscall arguments go into a struct called `<Syscall>Data` that should be
   added to the `pinchy-common/src/lib.rs` file and be added to the SyscallEventData
   union.
   - Identify any arguments with further parsing, especially those that
   could be reused by multiple syscalls (e.g. mode, flags, poll events,
   structs like timespec and stat).
   - If it's a struct, use the existing ones in `pinchy_common/src/kernel_types.rs`
   as examples and add it there, use for both eBPF and server sides.
   - If a simpler type with defined interpretation for the values, add a format_*()
   helper similar to the ones that already exist in `pinchy_common/src/util.rs`,
   if it doesn't exist yet, so it can be used by the event parsing code.
   - When adding or modifying formatting helpers, use `libc::` constants whenever
   possible for mapping numeric values to strings; when they are not available,
   declare constants outside of the function and use those.
4. **Event parsing:** Add to the event parsing code in
   `pinchy/src/events.rs`. For structs and other types with further parsing, try
   to do any parsing that can be reasonably done in a short amount of time, use
   existing helpers when they exist, improve them if necessary.
5. **Test:** Ensure the new syscall is being traced and parsed
   correctly by adding a test (see Adding tests below).

## Building
When trying a build, always use `cargo check`, aya projects are not
very friendly with `cargo build` or `cargo build --workspace`.

## Adding tests
When adding tests for parsing syscalls, use the files in `pinchy/src/tests/`.
Look at several existing tests to understand the usual structure. When creating
the expected output, take the event formatting code into consideration.

Integration tests that run the binaries as root in a controlled environment
are in `pinchy/tests/integration.rs`.

## Helper functions
Helper functions for parsing specific arguments should go under
`pinchy/src/util.rs`.

## Troubleshooting
- If you encounter a build error or ICE (internal compiler error), try
  a clean build (`cargo clean`) before investigating further.
- If a syscall is not being traced, double-check all steps above,
  especially the tailcall and event parsing registration.

## Note
If you notice these instructions are missing a step or are unclear,
please propose an update to this file. Try to keep it under 80 columns
while doing so for better readability on wide terminals / editors.
