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

/// Filesystem statistics structure, matching the kernel's struct statfs
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Statfs {
    pub f_type: i64,       /* Type of filesystem */
    pub f_bsize: i64,      /* Optimal transfer block size */
    pub f_blocks: u64,     /* Total data blocks in filesystem */
    pub f_bfree: u64,      /* Free blocks in filesystem */
    pub f_bavail: u64,     /* Free blocks available to unprivileged user */
    pub f_files: u64,      /* Total inodes in filesystem */
    pub f_ffree: u64,      /* Free inodes in filesystem */
    pub f_fsid: [i32; 2],  /* Filesystem ID */
    pub f_namelen: i64,    /* Maximum length of filenames */
    pub f_frsize: i64,     /* Fragment size */
    pub f_flags: i64,      /* Mount flags of filesystem */
    pub f_spare: [i64; 4], /* Padding bytes reserved for future use */
}

/// Resource limit structure, matching the kernel's struct rlimit
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Rlimit {
    pub rlim_cur: u64, /* Soft limit */
    pub rlim_max: u64, /* Hard limit */
}

/// Restartable sequence critical section structure
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct RseqCs {
    pub version: u32,
    pub flags: u32,
    pub start_ip: u64,
    pub post_commit_offset: u64,
    pub abort_ip: u64,
}

/// Restartable sequence structure
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Rseq {
    pub cpu_id_start: u32,
    pub cpu_id: u32,
    pub rseq_cs: u64, // This is a pointer to RseqCs in user space
    pub flags: u32,
    pub node_id: u32,
    pub mm_cid: u32,
}
