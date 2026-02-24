# Project Guidance

This file is project-wide guidance for agents. Keep it short and focused on
high-impact constraints.

## Code Style and Formatting

- In Rust code, separate logical blocks and control-flow branches with blank
  lines for readability.
- Keep no blank line after `#[]` attributes and no blank line between `match`
  arms.
- Ignore the blank-line style rule when acting purely as a reviewer.
- Do not add unnecessary comments; only add comments that explain behavior or
  intent.

## Project Context

Pinchy is an eBPF-based syscall tracer intended as a lower-overhead alternative
to `strace`.

Crates:
- `pinchy-common`: shared structs/helpers
- `pinchy-ebpf`: eBPF programs
- `pinchy`: userspace daemon and formatting/parsing

Supported architectures are `aarch64` and `x86_64`.

## API and Dependencies

- Do not rely on memory for `aya` and `zbus` APIs. Verify current APIs in
  docs.rs before using them.
- When adding a dependency, start with `cargo add <crate>` (no pinned version)
  to discover the current stable version first.

## Durable Invariants

- Do not modify `pinchy-common/src/syscalls/aarch64.rs` or
  `pinchy-common/src/syscalls/x86_64.rs` directly. Use them as references only.
  Outside these files, import `pinchy_common::syscalls` and use
  `syscalls::SYS_<name>`.

- Classify each syscall as either trivial or complex:
  - Trivial: no pointer args, or pointers printed as raw addresses only.
  - Complex: any pointer data must be dereferenced/parsed.

- Never treat a syscall as trivial just because its Rust signature uses
  `usize`.

- Never handle the same syscall in both places:
  - trivial handler (`syscall_exit_trivial` + `TRIVIAL_SYSCALLS`), and
  - any consolidated category handler.

- For eBPF user-memory reads:
  - use `bpf_probe_read_user()` for small structs,
  - use `bpf_probe_read_buf()` for byte arrays/larger structs to avoid stack
    pressure by reading directly into compact payload ringbuf memory.

- Never use magic values in format helpers or tests. Prefer `libc::` constants;
  declare named constants when `libc` does not provide one.

- Before adding new formatting logic, check and reuse existing
  `format_*` helpers. In particular:
  - use `format_dirfd()` for `dfd`/`dirfd`/`olddirfd`/`newdirfd`/`from_dfd`/
    `to_dfd`,
  - use `format_mode()` for file modes.

- Ensure syscall return formatting is covered in `format_return_value` in
  `pinchy/src/format_helpers.rs`.

- For architecture-specific code in `pinchy-common` and `pinchy-ebpf`, use
  `#[cfg(x86_64)]` / `#[cfg(aarch64)]` feature-gated paths used by this
  project.

## Adding a Syscall Checklist

1. Confirm `SYS_<name>` exists in both arch syscall files.
2. Read the man page to understand pointer args and whether dereference is
   required:
   `https://man7.org/linux/man-pages/man2/SYSCALL_NAME.2.html`
3. Decide trivial vs complex.
4. Wire eBPF handling:
   - Trivial: add to `syscall_exit_trivial` in `pinchy-ebpf/src/main.rs`.
   - Complex: add a case to the appropriate consolidated handler in
     `pinchy-ebpf/src/`.
5. Register tailcalls in `pinchy/src/server.rs`:
   - `TRIVIAL_SYSCALLS` for trivial,
   - matching category array for complex.
6. Add/update `<Syscall>Data` in `pinchy-common/src/lib.rs`.
7. Register payload size in `compact_payload_size()` in
   `pinchy-common/src/lib.rs`.
8. Update parsing in `pinchy/src/events.rs`, reusing existing format helpers.
9. Update `format_return_value` handling in `pinchy/src/format_helpers.rs`.
10. Add tests for parsing and formatting behavior.
11. If syscall category or complexity is ambiguous, ask for a decision.

## Testing and Verification Minimum

- Build check: use `cargo check` (avoid `--workspace` for this project).
- Add/adjust syscall parsing tests under `pinchy/src/tests/`.
- Run relevant integration test(s) when syscall behavior crosses userspace and
  eBPF boundaries.

Integration tests and helpers live in:
- `pinchy/tests/integration.rs`
- `pinchy/tests/auto_quit.rs`
- `pinchy/tests/common.rs`
- `pinchy/src/bin/test-helper.rs`

`escaped_regex()` markers used by tests:

| Marker | Matches |
|--------|---------|
| `@PID@` | `\d+` |
| `@ADDR@` | `0x[0-9a-f]+` |
| `@HEXNUMBER@` | `[0-9a-f]+` |
| `@SIGNEDNUMBER@` | `-?[0-9]+` |
| `@NUMBER@` | `[0-9]+` |
| `@MODE@` | `[rwx-]+` |
| `@ALPHANUM@` | `[^ "]+` |
| `@QUOTEDSTRING@` | `"[^"]*"` |
| `@MAYBEITEM_@` | `([^ "]+ )?` |
| `@MAYBETRUNCATED@` | `( ... (truncated))?` |
| `@GROUPLIST@` | `[0-9, ]*` |
| `@ANY@` | `.+` |

## Canonical References

- `pinchy-ebpf/src/` consolidated syscall handlers
- `pinchy-ebpf/src/main.rs` trivial handler entry points
- `pinchy-ebpf/src/util.rs` compact payload helpers
- `pinchy/src/server.rs` tailcall registration arrays
- `pinchy/src/events.rs` userspace event parsing
- `pinchy/src/format_helpers.rs` argument/return-value formatting
- `pinchy/src/tests/mod.rs` (`syscall_test!` macro)
- `pinchy/tests/common.rs` integration helpers

## Contributing to This File

- Keep guidance short, durable, and repo-wide.
- Prefer linking to canonical code over embedding long implementation examples.
- Remove duplicated or task-specific instructions.
