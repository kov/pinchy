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

**Important:**
A syscall is only "trivial" if *all* its arguments are plain integers and
*none* are pointers, buffers, or addresses. If any argument is a pointer
(even if it appears as `usize` in Rust), the syscall is complex and needs
a dedicated handler.

- Always check the syscall's man page or kernel signature for pointer arguments.
- Common complex syscalls: `futex`, `read`, `write`, `openat`, etc.

| Any pointer/buffer/struct argument? | Handler type   |
|-------------------------------------|---------------|
| Yes                                 | Complex       |
| No                                  | Trivial       |

**Never treat a syscall as trivial just because its Rust signature uses `usize`.**

## Checklist for Adding a New Syscall

1. **Verify existence:** Confirm `SYS_<name>` exists in both arch files
   (see `pinchy-common/src/syscalls/aarch64.rs` and
   `pinchy-common/src/syscalls/x86_64.rs`).
2. **Trivial or complex:**
   - If trivial (no pointers, all arguments are plain integers):
     - Add to the match in `pinchy-ebpf/src/main.rs` in
       `try_syscall_exit_trivial`.
     - Add to the `TRIVIAL_SYSCALLS` array in
       `pinchy/src/server.rs` in `load_tailcalls()`.
   - If complex (has pointer arguments or needs special handling):
     - Add a new tracepoint named `syscall_exit_<name>` in
       `pinchy-ebpf/src/main.rs`.
     - Register it in the appropriate array in `load_tailcalls()` in
       `pinchy/src/server.rs`.
3. **Syscall arguments:**
   - Identify any arguments with further parsing, especially those that
   could be reused by multiple syscalls (e.g. mode, flags, poll events,
   structs like timespec and stat).
   - If it's a struct, use the existing ones in `pinchy_common/src/kernel_types.rs`
   as examples and add it there, use for both eBPF and server sides.
   - If a simpler type with defined interpretation for the values, add a format_*()
   helper similar to the ones that already exist in `pinchy_common/src/events.rs`,
   if it doesn't exist yet, so it can be used by the event parsing code.
4. **Event parsing:** Add to the event parsing code in
   `pinchy/src/events.rs`. For structs and other types with further parsing, try
   to do any parsing that can be reasonably done in a short amount of time, use
   existing helpers when they exist, improve them if necessary.
5. **Test:** Ensure the new syscall is being traced and parsed
   correctly.

## Building
When trying a build, always use `cargo check`, aya projects are not
very friendly with `cargo build` or `cargo build --workspace`.

## Troubleshooting
- If you encounter a build error or ICE (internal compiler error), try
  a clean build (`cargo clean`) before investigating further.
- If a syscall is not being traced, double-check all steps above,
  especially the tailcall and event parsing registration.

## Note
If you notice these instructions are missing a step or are unclear,
please propose an update to this file. Try to keep it under 80 columns
while doing so for better readability on wide terminals / editors.
