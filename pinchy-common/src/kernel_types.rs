// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use crate::{DATA_READ_SIZE, SMALL_READ_SIZE};

// Sigevent notification method constants
pub const SIGEV_SIGNAL: i32 = 0; // notify via signal
pub const SIGEV_NONE: i32 = 1; // other notification: meaningless
pub const SIGEV_THREAD: i32 = 2; // deliver via thread creation
pub const SIGEV_THREAD_ID: i32 = 4; // deliver to thread (Linux-specific)

// AIO constants for IO control block commands
pub const IOCB_CMD_PREAD: u16 = 0;
pub const IOCB_CMD_PWRITE: u16 = 1;
pub const IOCB_CMD_FSYNC: u16 = 2;
pub const IOCB_CMD_FDSYNC: u16 = 3;
pub const IOCB_CMD_POLL: u16 = 5;
pub const IOCB_CMD_NOOP: u16 = 6;
pub const IOCB_CMD_PREADV: u16 = 7;
pub const IOCB_CMD_PWRITEV: u16 = 8;

// AIO flags for IO control blocks
pub const IOCB_FLAG_RESFD: u32 = 1 << 0; // aio_resfd is valid
pub const IOCB_FLAG_IOPRIO: u32 = 1 << 1; // aio_reqprio is valid

// Constants for bounded arrays in AIO data structures
pub const AIO_IOCB_ARRAY_CAP: usize = 4;
pub const AIO_EVENT_ARRAY_CAP: usize = 4;

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

/// Structure for openat2 syscall, matching the kernel's struct open_how
/// See: https://man7.org/linux/man-pages/man2/openat2.2.html
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct OpenHow {
    pub flags: u64,   // File creation and status flags (O_* constants)
    pub mode: u64,    // File mode (when creating files)
    pub resolve: u64, // Path resolution flags (RESOLVE_* constants)
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Itimerspec {
    pub it_interval: Timespec, // Timer interval
    pub it_value: Timespec,    // Initial expiration
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union Sigval {
    pub sival_int: i32,
    pub sival_ptr: u64, // void* represented as u64 for 64-bit architectures
}

impl Default for Sigval {
    fn default() -> Self {
        Sigval { sival_int: 0 }
    }
}

impl core::fmt::Debug for Sigval {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Safe to access sival_int as both variants have the same size or smaller
        write!(f, "Sigval {{ sival_int: {} }}", unsafe { self.sival_int })
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union SigeventUn {
    pub pad: [i32; 13],               // Padding array (largest member)
    pub tid: i32,                     // Thread ID for SIGEV_THREAD_ID
    pub sigev_thread: SigeventThread, // Thread function and attributes for SIGEV_THREAD
}

impl Default for SigeventUn {
    fn default() -> Self {
        SigeventUn { pad: [0; 13] }
    }
}

impl core::fmt::Debug for SigeventUn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Safe to access tid as it's the smallest member
        write!(f, "SigeventUn {{ tid: {} }}", unsafe { self.tid })
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct SigeventThread {
    pub function: u64,  // void (*)(sigval_t) - function pointer
    pub attribute: u64, // pthread_attr_t* - thread attributes pointer
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Sigevent {
    pub sigev_value: Sigval,  // Signal value (union sigval)
    pub sigev_signo: i32,     // Signal number
    pub sigev_notify: i32, // Notification method (SIGEV_SIGNAL, SIGEV_NONE, SIGEV_THREAD, SIGEV_THREAD_ID)
    pub sigev_un: SigeventUn, // Union containing different notification configurations
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
    pub st_dev: u64,   // Device
    pub st_ino: u64,   // File serial number
    pub st_mode: u32,  // File mode
    pub st_nlink: u32, // Link count
    pub st_uid: u32,   // User ID of the file's owner
    pub st_gid: u32,   // Group ID of the file's group
    pub st_rdev: u64,  // Device number, if device
    pub __pad1: u64,
    pub st_size: i64,    // Size of file, in bytes
    pub st_blksize: i32, // Optimal block size for I/O
    pub __pad2: i32,
    pub st_blocks: i64, // Number 512-byte blocks allocated
    pub st_atime: i64,
    pub st_atime_nsec: u64,
    pub st_mtime: i64,
    pub st_mtime_nsec: u64,
    pub st_ctime: i64,
    pub st_ctime_nsec: u64,
    pub __unused4: u32,
    pub __unused5: u32,
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

/// Timex structure for adjtimex/clock_adjtime syscalls
/// Note: we capture the main fields, padding is omitted for eBPF compatibility
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Timex {
    pub modes: u32,     // mode selector
    pub offset: i64,    // time offset (usec)
    pub freq: i64,      // frequency offset (scaled ppm)
    pub maxerror: i64,  // maximum error (usec)
    pub esterror: i64,  // estimated error (usec)
    pub status: i32,    // clock command/status
    pub constant: i64,  // pll time constant
    pub precision: i64, // clock precision (usec) (read only)
    pub tolerance: i64, // clock frequency tolerance (ppm) (read only)
    pub time: Timeval,  // current time (read only, except for ADJ_SETOFFSET)
    pub tick: i64,      // (modified) usecs between clock ticks
    pub ppsfreq: i64,   // pps frequency (scaled ppm) (ro)
    pub jitter: i64,    // pps jitter (us) (ro)
    pub shift: i32,     // interval duration (s) (shift) (ro)
    pub stabil: i64,    // pps stability (scaled ppm) (ro)
    pub jitcnt: i64,    // jitter limit exceeded (ro)
    pub calcnt: i64,    // calibration intervals (ro)
    pub errcnt: i64,    // calibration errors (ro)
    pub stbcnt: i64,    // stability limit exceeded (ro)
    pub tai: i32,       // TAI offset (ro)
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
pub const MSG_CONTROL_SIZE: usize = 64; // Size of control message data to capture
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Msghdr {
    pub msg_name: u64,                        // Optional address pointer
    pub msg_namelen: u32,                     // Size of address
    pub msg_iov: [Iovec; crate::IOV_COUNT],   // Scatter/gather array (truncated)
    pub msg_iovlen: u32,                      // Number of elements in msg_iov
    pub msg_control: u64,                     // Ancillary data pointer
    pub msg_controllen: u32,                  // Ancillary data buffer size
    pub msg_flags: i32,                       // Flags on received message
    pub has_name: bool,                       // Whether we captured the name/address
    pub name: Sockaddr,                       // The captured address (if any)
    pub control_data: [u8; MSG_CONTROL_SIZE], // Captured control message data
}

/// Multiple message header structure for sendmmsg/recvmmsg operations
/// Note: We capture a limited number of messages due to eBPF stack constraints
pub const MMSGHDR_COUNT: usize = 64; // Number of mmsghdr structures to capture
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct Mmsghdr {
    pub msg_hdr: Msghdr, // Message header
    pub msg_len: u32,    // Number of bytes sent/received for this message
}

impl Default for Msghdr {
    fn default() -> Self {
        Self {
            msg_name: 0,
            msg_namelen: 0,
            msg_iov: [Iovec::default(); crate::IOV_COUNT],
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

/// File descriptor set for select/pselect operations
/// fd_set is a bitmap representing file descriptors.
/// We'll store the raw bytes and decode them in userspace for better eBPF compatibility.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FdSet {
    /// Raw bytes from the fd_set bitmap
    pub bytes: [u8; 16], // 128 bits = 128 file descriptors
    /// Number of bytes that are valid/meaningful
    pub len: u32,
}

/// System V shared memory segment data structure, matching the kernel's struct shmid_ds.
/// See: https://man7.org/linux/man-pages/man2/shmctl.2.html
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ShmidDs {
    pub shm_perm: IpcPerm, // Operation permissions
    pub shm_segsz: usize,  // Size of segment (bytes)
    pub shm_atime: i64,    // Last attach time
    pub shm_dtime: i64,    // Last detach time
    pub shm_ctime: i64,    // Last change time
    pub shm_cpid: i32,     // PID of creator
    pub shm_lpid: i32,     // PID of last shmat/shmdt
    pub shm_nattch: usize, // Number of current attaches
}

/// System V message queue data structure, matching the kernel's struct msqid_ds.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct MsqidDs {
    pub msg_perm: IpcPerm, // Operation permissions
    pub msg_stime: i64,    // Last msgsnd time
    pub msg_rtime: i64,    // Last msgrcv time
    pub msg_ctime: i64,    // Last change time
    pub msg_cbytes: usize, // Current number of bytes on queue
    pub msg_qnum: usize,   // Number of messages in queue
    pub msg_qbytes: usize, // Max number of bytes allowed on queue
    pub msg_lspid: i32,    // PID of last msgsnd
    pub msg_lrpid: i32,    // PID of last msgrcv
}

/// System V semaphore data structure, matching the kernel's struct semid_ds.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct SemidDs {
    pub sem_perm: IpcPerm, // Operation permissions
    pub sem_otime: i64,    // Last semop time
    pub sem_ctime: i64,    // Last change time
    pub sem_nsems: usize,  // Number of semaphores in set
}

/// System V semaphore info structure, matching the kernel's struct seminfo.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Seminfo {
    pub semmap: i32,
    pub semmni: i32,
    pub semmns: i32,
    pub semmnu: i32,
    pub semmsl: i32,
    pub semopm: i32,
    pub semume: i32,
    pub semusz: i32,
    pub semvmx: i32,
    pub semaem: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union Semun {
    pub val: i32,
    pub array: usize,
    pub buf: SemidDs,
    pub info: Seminfo,
}

impl Default for Semun {
    fn default() -> Self {
        Semun { val: 0 }
    }
}

/// System V IPC permissions structure, matching the kernel's struct ipc_perm.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IpcPerm {
    pub key: u32,    // IPC key
    pub uid: u32,    // Owner's user ID
    pub gid: u32,    // Owner's group ID
    pub cuid: u32,   // Creator's user ID
    pub cgid: u32,   // Creator's group ID
    pub mode: u16,   // Read/write permission
    pub __pad1: u16, // Padding
    pub seq: u16,    // Sequence number
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Siginfo {
    pub si_signo: i32,       // Signal number
    pub si_errno: i32,       // An errno value
    pub si_code: i32,        // Signal code
    pub si_trapno: i32,      // Trap number (unused on most archs)
    pub si_pid: i32,         // Sending process ID
    pub si_uid: u32,         // Real user ID of sending process
    pub si_status: i32,      // Exit value or signal
    pub si_utime: i64,       // User time consumed
    pub si_stime: i64,       // System time consumed
    pub si_value: usize,     // Signal value (union sigval)
    pub si_int: i32,         // POSIX.1b signal
    pub si_ptr: usize,       // POSIX.1b signal (pointer)
    pub si_overrun: i32,     // Timer overrun count
    pub si_timerid: i32,     // Timer ID
    pub si_addr: usize,      // Memory location which caused fault
    pub si_band: i64,        // Band event
    pub si_fd: i32,          // File descriptor
    pub si_addr_lsb: i16,    // Least significant bit of address
    pub si_lower: usize,     // Lower bound when address violation occurred
    pub si_upper: usize,     // Upper bound when address violation occurred
    pub si_pkey: i32,        // Protection key on PTE that caused fault
    pub si_call_addr: usize, // Address of system call instruction
    pub si_syscall: i32,     // Number of attempted system call
    pub si_arch: u32,        // Architecture of attempted system call
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Statx {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub __spare0: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime_sec: i64,
    pub stx_atime_nsec: u32,
    pub stx_btime_sec: i64,
    pub stx_btime_nsec: u32,
    pub stx_ctime_sec: i64,
    pub stx_ctime_nsec: u32,
    pub stx_mtime_sec: i64,
    pub stx_mtime_nsec: u32,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub __spare2: [u64; 14],
}

/// Linux capability version constants for capget/capset
pub const LINUX_CAPABILITY_VERSION_1: u32 = 0x19980330;
pub const LINUX_CAPABILITY_VERSION_2: u32 = 0x20071026;
pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct CapUserHeader {
    pub version: u32,
    pub pid: i32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct CapUserData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct SchedAttr {
    pub size: u32,
    pub sched_policy: u32,
    pub sched_flags: u64,
    pub sched_nice: i32,
    pub sched_priority: u32,
    pub sched_runtime: u64,
    pub sched_deadline: u64,
    pub sched_period: u64,
    pub sched_util_min: u32, // since Linux 6.2
    pub sched_util_max: u32, // since Linux 6.2
}

/// Mount attribute structure for mount_setattr syscall
/// See: https://man7.org/linux/man-pages/man2/mount_setattr.2.html
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct MountAttr {
    pub attr_set: u64,
    pub attr_clr: u64,
    pub propagation: u64,
    pub userns_fd: u64,
}

/// Signal set representation for signal-related syscalls.
/// On Linux (x86_64 and aarch64), sigset_t is a bitmask covering signals 1-64,
/// so it is always 8 bytes (64 bits).
pub const SIGSET_SIZE: usize = 8;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Sigset {
    pub bytes: [u8; SIGSET_SIZE],
}

/// Alternate signal stack descriptor (stack_t)
/// Matches Linux's struct stack_t layout on 64-bit archs
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct StackT {
    pub ss_sp: u64,    // stack base pointer (void*)
    pub ss_flags: i32, // flags (SS_DISABLE, SS_ONSTACK, SS_AUTODISARM)
    pub ss_size: u64,  // size of stack
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FutexWaitv {
    pub val: u64,
    pub uaddr: u64,
    pub flags: u32,
    pub __reserved: u32,
}

/// Async I/O control block structure, matching the kernel's struct iocb
/// See: https://man7.org/linux/man-pages/man2/io_submit.2.html
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IoCb {
    pub aio_data: u64, // data to be returned in event's data

    // Byte order handling for aio_key/aio_rw_flags
    #[cfg(target_endian = "little")]
    pub aio_key: u32, // the kernel sets aio_key to the req #
    #[cfg(target_endian = "little")]
    pub aio_rw_flags: u32, // RWF_* flags

    #[cfg(target_endian = "big")]
    pub aio_rw_flags: u32, // RWF_* flags
    #[cfg(target_endian = "big")]
    pub aio_key: u32, // the kernel sets aio_key to the req #

    // common fields
    pub aio_lio_opcode: u16, // see IOCB_CMD_* constants
    pub aio_reqprio: i16,
    pub aio_fildes: u32,

    pub aio_buf: u64,    // buffer pointer
    pub aio_nbytes: u64, // number of bytes
    pub aio_offset: i64, // file offset

    // extra parameters
    pub aio_reserved2: u64, // TODO: use this for a (struct sigevent *)

    // flags for the "struct iocb"
    pub aio_flags: u32,

    // if the IOCB_FLAG_RESFD flag of "aio_flags" is set, this is an
    // eventfd to signal AIO readiness to
    pub aio_resfd: u32,
}

/// Async I/O event structure, matching the kernel's struct io_event
/// See: https://man7.org/linux/man-pages/man2/io_getevents.2.html
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IoEvent {
    pub data: u64, // the data field from the iocb
    pub obj: u64,  // what iocb this event came from
    pub res: i64,  // result code for this event
    pub res2: i64, // secondary result
}

/// Async I/O sigset structure for io_pgetevents
/// Contains signal mask and signal set size
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct AioSigset {
    pub sigmask: u64,    // pointer to sigset_t
    pub sigsetsize: u64, // size of signal set
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IoSqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IoCqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: IoSqringOffsets,
    pub cq_off: IoCqringOffsets,
}

/// Landlock path_beneath rule attribute
/// Used with LANDLOCK_RULE_PATH_BENEATH rule type
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct LandlockPathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

/// Landlock net_port rule attribute
/// Used with LANDLOCK_RULE_NET_PORT rule type
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct LandlockNetPortAttr {
    pub allowed_access: u64,
    pub port: u64,
}

/// Union to hold either path_beneath or net_port rule attributes
/// Only one is valid depending on the rule_type field in LandlockAddRuleData
#[repr(C)]
#[derive(Copy, Clone)]
pub union LandlockRuleAttrUnion {
    pub path_beneath: LandlockPathBeneathAttr,
    pub net_port: LandlockNetPortAttr,
}

impl Default for LandlockRuleAttrUnion {
    fn default() -> Self {
        LandlockRuleAttrUnion {
            path_beneath: LandlockPathBeneathAttr::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct MqAttr {
    pub mq_flags: i64,
    pub mq_maxmsg: i64,
    pub mq_msgsize: i64,
    pub mq_curmsgs: i64,
}

/// Perf event attribute structure for perf_event_open syscall
/// Note: we only capture the most important fields for traceability
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct PerfEventAttr {
    pub type_: u32,         // Event type (hardware, software, tracepoint, etc.)
    pub size: u32,          // Size of the attr structure
    pub config: u64,        // Event-specific configuration
    pub sample_period: u64, // Sample period or frequency
    pub sample_type: u64,   // Sample type bitfield
    pub read_format: u64,   // Read format bitfield
    pub flags: u64,         // Event configuration flags (bitfield)
    pub wakeup_events: u32, // Wakeup every n events
    pub bp_type: u32,       // Breakpoint type
    pub bp_addr: u64,       // Breakpoint address or config1
    pub bp_len: u64,        // Breakpoint length or config2
}

/// BPF map creation attributes for BPF_MAP_CREATE command
/// Note: simplified version capturing key fields only
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct BpfMapCreateAttr {
    pub map_type: u32,    // Map type (hash, array, etc.)
    pub key_size: u32,    // Size of key in bytes
    pub value_size: u32,  // Size of value in bytes
    pub max_entries: u32, // Maximum number of entries
    pub map_flags: u32,   // Map creation flags
}

/// BPF program load attributes for BPF_PROG_LOAD command
/// Note: simplified version capturing key fields only
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct BpfProgLoadAttr {
    pub prog_type: u32, // Program type (socket filter, kprobe, etc.)
    pub insn_cnt: u32,  // Number of instructions
    pub license: u64,   // Pointer to license string in user memory
}

/// BPF command constants
pub mod bpf_cmd {
    pub const MAP_CREATE: i32 = 0;
    pub const PROG_LOAD: i32 = 5;
}
