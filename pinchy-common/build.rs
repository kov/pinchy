fn main() {
    println!("cargo::rustc-check-cfg=cfg(aarch64)");
    println!("cargo::rustc-check-cfg=cfg(x86_64)");

    #[cfg(target_arch = "aarch64")]
    println!("cargo::rustc-cfg=aarch64");

    #[cfg(target_arch = "x86_64")]
    println!("cargo::rustc-cfg=x86_64");

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    compile_error!("Unsupported architecture. We only support aarch64 and x86_64, for now.");
}
