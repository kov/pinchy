// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use crate::SMALL_READ_SIZE;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Pollfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Timespec {
    pub seconds: i64,
    pub nanos: i64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct EpollEvent {
    pub events: u32,
    pub data: usize,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub _pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_mtime: i64,
    pub st_ctime: i64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct LinuxDirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [u8; SMALL_READ_SIZE],
}
