// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use crate::{DATA_READ_SIZE, SMALL_READ_SIZE};

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

/// Time value structure for rusage
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Timeval {
    pub tv_sec: i64,  // seconds
    pub tv_usec: i64, // microseconds
}

/// Timezone structure for gettimeofday/settimeofday
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Timezone {
    pub tz_minuteswest: i32, // minutes west of Greenwich
    pub tz_dsttime: i32,     // type of DST correction
}

/// System information structure for sysinfo syscall
/// Note: we ignore old kernel version differences and padding
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Sysinfo {
    pub uptime: i64,     // Seconds since boot
    pub loads: [u64; 3], // 1, 5, and 15 minute load averages
    pub totalram: u64,   // Total usable main memory size
    pub freeram: u64,    // Available memory size
    pub sharedram: u64,  // Amount of shared memory
    pub bufferram: u64,  // Memory used by buffers
    pub totalswap: u64,  // Total swap space size
    pub freeswap: u64,   // Swap space still available
    pub procs: u16,      // Number of current processes
    pub totalhigh: u64,  // Total high memory size
    pub freehigh: u64,   // Available high memory size
    pub mem_unit: u32,   // Memory unit size in bytes
}

/// Clock ticks information structure for times syscall
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Tms {
    pub tms_utime: i64,  // User CPU time
    pub tms_stime: i64,  // System CPU time
    pub tms_cutime: i64, // User CPU time of children
    pub tms_cstime: i64, // System CPU time of children
}

/// Resource usage structure, matching the kernel's struct rusage
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Rusage {
    pub ru_utime: Timeval, // user CPU time used
    pub ru_stime: Timeval, // system CPU time used
    pub ru_maxrss: i64,    // maximum resident set size
    pub ru_ixrss: i64,     // integral shared memory size
    pub ru_idrss: i64,     // integral unshared data size
    pub ru_isrss: i64,     // integral unshared stack size
    pub ru_minflt: i64,    // page reclaims (soft page faults)
    pub ru_majflt: i64,    // page faults (hard page faults)
    pub ru_nswap: i64,     // swaps
    pub ru_inblock: i64,   // block input operations
    pub ru_oublock: i64,   // block output operations
    pub ru_msgsnd: i64,    // IPC messages sent
    pub ru_msgrcv: i64,    // IPC messages received
    pub ru_nsignals: i64,  // signals received
    pub ru_nvcsw: i64,     // voluntary context switches
    pub ru_nivcsw: i64,    // involuntary context switches
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

/// Note: some fields are truncated to fit within eBPF stack limits
pub const SYSNAME_READ_SIZE: usize = 16;
pub const NODENAME_READ_SIZE: usize = 32;
pub const RELEASE_READ_SIZE: usize = 32;
pub const VERSION_READ_SIZE: usize = 65;
pub const MACHINE_READ_SIZE: usize = 16;
pub const DOMAIN_READ_SIZE: usize = 16;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Utsname {
    pub sysname: [u8; SYSNAME_READ_SIZE], // Operating system name (e.g., "Linux")
    pub nodename: [u8; NODENAME_READ_SIZE], // Name within network
    pub release: [u8; RELEASE_READ_SIZE], // Operating system release
    pub version: [u8; VERSION_READ_SIZE], // Operating system version
    pub machine: [u8; MACHINE_READ_SIZE], // Hardware type identifier
    pub domainname: [u8; DOMAIN_READ_SIZE], // NIS or YP domain name
}

impl Default for Utsname {
    fn default() -> Self {
        Self {
            sysname: [0; SYSNAME_READ_SIZE],
            nodename: [0; NODENAME_READ_SIZE],
            release: [0; RELEASE_READ_SIZE],
            version: [0; VERSION_READ_SIZE],
            machine: [0; MACHINE_READ_SIZE],
            domainname: [0; DOMAIN_READ_SIZE],
        }
    }
}

/// Clone arguments structure for clone3() syscall
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct CloneArgs {
    pub flags: u64,        // Flags bit mask
    pub pidfd: u64,        // Where to store PID file descriptor (int *)
    pub child_tid: u64,    // Where to store child TID, in child's memory (pid_t *)
    pub parent_tid: u64,   // Where to store child TID, in parent's memory (pid_t *)
    pub exit_signal: u64,  // Signal to deliver to parent on child termination
    pub stack: u64,        // Pointer to lowest byte of stack
    pub stack_size: u64,   // Size of stack
    pub tls: u64,          // Location of new TLS
    pub set_tid: u64,      // Pointer to a pid_t array (since Linux 5.5)
    pub set_tid_size: u64, // Number of elements in set_tid (since Linux 5.5)
    pub cgroup: u64,       // File descriptor for target cgroup of child (since Linux 5.7)
}

/// Socket address structure for generic socket addresses
/// Note: we capture enough data to handle IPv6 addresses and most other
/// address families, though some may still be truncated
pub const SOCKADDR_DATA_SIZE: usize = 26; // Sufficient for IPv6 (26 bytes needed)
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Sockaddr {
    pub sa_family: u16,                    // Address family (AF_INET, AF_UNIX, etc.)
    pub sa_data: [u8; SOCKADDR_DATA_SIZE], // Address data
}

/// I/O vector structure for scatter-gather operations
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Iovec {
    pub iov_base: u64, // Base address of buffer
    pub iov_len: u64,  // Length of buffer
}

/// Message header structure for socket message operations
/// Note: we only capture essential fields and a subset of the control message data
/// due to eBPF stack limitations
pub const MSG_IOV_COUNT: usize = 4; // Number of iovec structures to capture
pub const MSG_CONTROL_SIZE: usize = 64; // Size of control message data to capture
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Msghdr {
    pub msg_name: u64,                        // Optional address pointer
    pub msg_namelen: u32,                     // Size of address
    pub msg_iov: [Iovec; MSG_IOV_COUNT],      // Scatter/gather array (truncated)
    pub msg_iovlen: u32,                      // Number of elements in msg_iov
    pub msg_control: u64,                     // Ancillary data pointer
    pub msg_controllen: u32,                  // Ancillary data buffer size
    pub msg_flags: i32,                       // Flags on received message
    pub has_name: bool,                       // Whether we captured the name/address
    pub name: Sockaddr,                       // The captured address (if any)
    pub control_data: [u8; MSG_CONTROL_SIZE], // Captured control message data
}

impl Default for Msghdr {
    fn default() -> Self {
        Self {
            msg_name: 0,
            msg_namelen: 0,
            msg_iov: [Iovec::default(); MSG_IOV_COUNT],
            msg_iovlen: 0,
            msg_control: 0,
            msg_controllen: 0,
            msg_flags: 0,
            has_name: false,
            name: Sockaddr::default(),
            control_data: [0; MSG_CONTROL_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct XattrList {
    pub data: [u8; DATA_READ_SIZE],
    pub size: usize,
}

impl Default for XattrList {
    fn default() -> Self {
        Self {
            data: [0u8; DATA_READ_SIZE],
            size: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct SchedParam {
    pub sched_priority: i32,
}
