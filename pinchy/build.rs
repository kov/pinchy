// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_EFFICIENCY_METRICS");

    let mut features = Vec::new();

    if std::env::var_os("CARGO_FEATURE_EFFICIENCY_METRICS").is_some() {
        features.push("efficiency-metrics");
    }

    aya_build::build_ebpf(
        [aya_build::Package {
            name: "pinchy-ebpf",
            root_dir: "../pinchy-ebpf",
            no_default_features: false,
            features: &features,
        }],
        aya_build::Toolchain::Custom("nightly-2025-12-12"),
    )?;

    Ok(())
}
