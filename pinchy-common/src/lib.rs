#![no_std]

use crate::kernel_types::{EpollEvent, Timespec};

pub mod kernel_types;
pub mod syscalls;

pub const DATA_READ_SIZE: usize = 128;

#[repr(C)]
pub struct SyscallEvent {
    pub syscall_nr: i64,
    pub pid: u32,
    pub tid: u32,
    pub return_value: i64,
    pub data: SyscallEventData,
}

#[repr(C)]
pub union SyscallEventData {
    pub epoll_pwait: EpollPWaitData,
    pub ppoll: PpollData,
    pub read: ReadData,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PpollData {
    pub fds: [i32; 16],
    pub events: [i16; 16],
    pub revents: [i16; 16],
    pub nfds: u32,
    pub timeout: Timespec,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EpollPWaitData {
    pub epfd: i32,
    pub events: [EpollEvent; 8],
    pub max_events: i32,
    pub timeout: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadData {
    pub fd: i32,
    pub buf: [u8; DATA_READ_SIZE],
    pub count: usize,
}
