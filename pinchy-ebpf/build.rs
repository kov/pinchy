// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());

    println!("cargo::rustc-check-cfg=cfg(aarch64)");
    println!("cargo::rustc-check-cfg=cfg(x86_64)");

    #[cfg(target_arch = "aarch64")]
    println!("cargo::rustc-cfg=aarch64");

    #[cfg(target_arch = "x86_64")]
    println!("cargo::rustc-cfg=x86_64");

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    compile_error!("Unsupported architecture. We only support aarch64 and x86_64, for now.");
}
