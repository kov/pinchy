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
    pub close: CloseData,
    pub epoll_pwait: EpollPWaitData,
    pub ppoll: PpollData,
    pub read: ReadData,
    pub lseek: LseekData,
    pub openat: OpenAtData,
    pub futex: FutexData,
    pub sched_yield: SchedYieldData,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CloseData {
    pub fd: i32,
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LseekData {
    pub fd: i32,
    pub offset: i64,
    pub whence: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenAtData {
    pub dfd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
    pub flags: i32,
    pub mode: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FutexData {
    pub uaddr: usize,
    pub op: u32,
    pub val: u32,
    pub uaddr2: usize,
    pub val3: u32,
    pub timeout: Timespec,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SchedYieldData;
