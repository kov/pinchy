// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#![no_std]

use crate::kernel_types::{EpollEvent, Timespec};

pub mod kernel_types;
pub mod syscalls;

pub const DATA_READ_SIZE: usize = 128;
pub const SMALL_READ_SIZE: usize = 8;

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
    pub write: WriteData,
    pub lseek: LseekData,
    pub openat: OpenAtData,
    pub futex: FutexData,
    pub sched_yield: SchedYieldData,
    pub ioctl: IoctlData,
    pub execve: ExecveData,
    pub fstat: FstatData,
    pub getdents64: Getdents64Data,
    pub mmap: MmapData,
    pub munmap: MunmapData,
    pub brk: BrkData,
    pub mprotect: MprotectData,
    pub generic: GenericSyscallData,
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
pub struct WriteData {
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoctlData {
    pub fd: i32,
    pub request: u32,
    pub arg: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveData {
    pub filename: [u8; SMALL_READ_SIZE * 4],
    pub filename_truncated: bool,
    pub argv: [[u8; SMALL_READ_SIZE]; 4],
    pub argv_len: [u16; 4],
    pub argc: u8,
    pub envp: [[u8; SMALL_READ_SIZE]; 2],
    pub envp_len: [u16; 2],
    pub envc: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FstatData {
    pub fd: i32,
    pub stat: crate::kernel_types::Stat,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Getdents64Data {
    pub fd: i32,
    pub count: usize,
    pub dirents: [crate::kernel_types::LinuxDirent64; 4],
    pub num_dirents: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MmapData {
    pub addr: usize,
    pub length: usize,
    pub prot: i32,
    pub flags: i32,
    pub fd: i32,
    pub offset: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MprotectData {
    pub addr: usize,
    pub length: usize,
    pub prot: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MunmapData {
    pub addr: usize,
    pub length: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BrkData {
    pub addr: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GenericSyscallData {
    pub args: [usize; 6],
}
