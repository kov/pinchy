// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

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

#[macro_export]
macro_rules! declare_syscalls {
    (
        $( $name:ident = $num:expr ),* $(,)?
    ) => {
        $(pub const $name: i64 = $num;)*
        pub fn syscall_nr_from_name(name: &str) -> Option<i64> {
            match name {
                $( x if x == &stringify!($name)[4..] => Some($name), )*
                _ => None,
            }
        }
        pub fn syscall_name_from_nr(nr: i64) -> Option<&'static str> {
            match nr {
                $( $name => Some(&stringify!($name)[4..]), )*
                _ => None,
            }
        }
        pub const ALL_SYSCALLS: &[i64] = &[$($name),*];
    };
}
