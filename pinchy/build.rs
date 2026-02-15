// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

fn main() -> anyhow::Result<()> {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "pinchy-ebpf",
            root_dir: "../pinchy-ebpf",
            no_default_features: false,
            features: &[],
        }],
        aya_build::Toolchain::Custom("nightly-2025-12-12"),
    )?;

    Ok(())
}
