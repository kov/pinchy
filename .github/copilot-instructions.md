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

# Adding support for a new syscall

All current Linux syscalls are already listed in pinchy-common's aarch64.rs
and x86_64.rs files and are made available architecture-agnostic by its
syscalls/mod.rs, e.g. pinchy_common::syscalls::SYS_open.

There is no need to change those files, you can use them as a reference
to know what syscalls there are and to double check the SYS_<name> exists
so you can import where necessary. To add support for parsing a new one these
 steps need to be taken:

1. import it and list it in the ALL_SUPPORTED_SYSCALLS constant in 
   pinchy-common/src/syscalls/mod.rs
2. if it's a trivial syscall (no pointers), add it to the match statement
   in try_syscall_exit_trivial
   if it's a more complex syscall, add a new tracepoint named like this:
   syscall_exit_<name>
3. if it's a trivial syscall (no pointers), import it and add it to the
   appropriate array in load_tailcalls() in pinchy/src/server.rs
   if it's a more complex syscall, import it and add it to the
   appropriate array in load_tailcalls() in pinchy/src/server.rs
4. import it and add it to the event parsing code in pinchy/src/events.rs
