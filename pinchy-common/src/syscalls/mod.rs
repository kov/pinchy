#[cfg(aarch64)]
mod aarch64;
#[cfg(aarch64)]
pub use aarch64::*;

#[cfg(x86_64)]
mod x86_64;
#[cfg(x86_64)]
pub use x86_64::*;

#[cfg(not(any(aarch64, x86_64)))]
compile_error!("Unsupported architecture. Currently only aarch64 and x86_64 are supported.");
