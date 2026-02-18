# Pinchy

![Pinchy](pinchy.png)

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly-2025-06-13 --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

IMPORTANT: note that we depend on a specific version of nightly to avoid breakage caused by LLVM or rust changes. You can use the latest nightly, but you need to change `pinchy/build.rs`.

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## UML Efficiency Benchmark

You can run the UML efficiency benchmark with any traced command:

```shell
BENCH_COMMAND='find "$HOME/.local"' EVENTS='' ./scripts/measure-command-efficiency.sh
```

Useful parameters:

- `BENCH_COMMAND`: command to run under tracing inside UML
- `EVENTS`: comma-separated syscall filter (empty string means all supported events)
- `RUNS`: latency samples (default `15`)
- `THROUGHPUT_RUNS`: throughput loop count (default `3`)

Example:

```shell
RUNS=1 THROUGHPUT_RUNS=1 EVENTS='' BENCH_COMMAND='cat /etc/passwd' \
  ./scripts/measure-command-efficiency.sh
```

## Usage

Pinchy can trace syscalls for a running process or launch a new process and trace it. You can specify which syscalls to trace using the `-e` or `--event` option.

### Basic Examples

Trace all syscalls for a command:
```shell
pinchy ls /tmp
```

Trace specific syscalls:
```shell
pinchy -e read,write,open ls /tmp
```

Attach to a running process:
```shell
pinchy -p <PID> -e open,close
```

### Syscall Aliases

Pinchy supports common syscall aliases that users might be familiar with from `libc` or other tools.

#### Signal Syscalls

On x86_64 and aarch64, signal-related syscalls use `rt_*` prefixes in the kernel, but you can use the more familiar names without the prefix:

```shell
# These are equivalent:
pinchy -e sigaction,sigprocmask ./myprogram
pinchy -e rt_sigaction,rt_sigprocmask ./myprogram
```

Supported signal aliases (all architectures):
- `sigaction` → `rt_sigaction`
- `sigprocmask` → `rt_sigprocmask`
- `sigreturn` → `rt_sigreturn`
- `sigpending` → `rt_sigpending`
- `sigtimedwait` → `rt_sigtimedwait`
- `sigqueueinfo` → `rt_sigqueueinfo`
- `sigsuspend` → `rt_sigsuspend`

#### Architecture-Specific Aliases

On **aarch64**, many traditional syscalls don't exist in the kernel but are provided by glibc as wrappers around newer `*at` variants. Pinchy supports these for convenience:

```shell
# On aarch64, these are equivalent:
pinchy -e open,stat ./myprogram
pinchy -e openat,newfstatat ./myprogram
```

Supported aarch64 aliases:
- `open` → `openat`
- `stat` → `newfstatat`
- `lstat` → `newfstatat`
- `poll` → `ppoll`
- `dup2` → `dup3`
- `pipe` → `pipe2`
- `access` → `faccessat`
- `chmod` → `fchmodat`
- `chown` → `fchownat`
- `link` → `linkat`
- `mkdir` → `mkdirat`
- `mknod` → `mknodat`
- `rename` → `renameat`
- `rmdir` → `unlinkat`
- `symlink` → `symlinkat`
- `unlink` → `unlinkat`

On **x86_64**, these traditional syscalls exist directly in the kernel, so no aliases are needed.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package pinchy --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/pinchy` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, pinchy is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
