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

pub const ALL_SUPPORTED_SYSCALLS: &[i64] = &[
    SYS_close,
    SYS_futex,
    SYS_read,
    SYS_epoll_pwait,
    SYS_ppoll,
    SYS_lseek,
    SYS_openat,
    SYS_sched_yield,
    SYS_ioctl,
];

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
    };
}
