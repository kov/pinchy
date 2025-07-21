// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#![no_std]

use crate::kernel_types::{EpollEvent, Timespec};

pub mod kernel_types;
pub mod syscalls;

pub const DATA_READ_SIZE: usize = 128;
pub const MEDIUM_READ_SIZE: usize = 64;
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
    pub newfstatat: NewfstatatData,
    pub getdents64: Getdents64Data,
    pub mmap: MmapData,
    pub munmap: MunmapData,
    pub brk: BrkData,
    pub faccessat: FaccessatData,
    pub mprotect: MprotectData,
    pub getrandom: GetrandomData,
    pub statfs: StatfsData,
    pub set_robust_list: SetRobustListData,
    pub set_tid_address: SetTidAddressData,
    pub rt_sigprocmask: RtSigprocmaskData,
    pub rt_sigaction: RtSigactionData,
    pub prlimit: PrlimitData,
    pub rseq: RseqData,
    pub uname: UnameData,
    pub generic: GenericSyscallData,
    pub fcntl: FcntlData,
    pub fchdir: FchdirData,
    pub readlinkat: ReadlinkatData,
    pub recvmsg: RecvmsgData,
    pub recvfrom: RecvfromData,
    pub sendmsg: SendmsgData,
    pub accept4: Accept4Data,
    pub wait4: Wait4Data,
    pub getrusage: GetrusageData,
    pub clone3: Clone3Data,
    pub getpid: GetpidData,
    pub gettid: GettidData,
    pub getuid: GetuidData,
    pub geteuid: GeteuidData,
    pub getgid: GetgidData,
    pub getegid: GetegidData,
    pub getppid: GetppidData,
    pub dup3: Dup3Data,
    pub clone: CloneData,
    pub exit_group: ExitGroupData,
    pub rt_sigreturn: RtSigreturnData,
    pub pipe2: Pipe2Data,
    pub flistxattr: FlistxattrData,
    pub listxattr: ListxattrData,
    pub llistxattr: LlistxattrData,
    pub madvise: MadviseData,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Pipe2Data {
    pub pipefd: [i32; 2],
    pub flags: i32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FlistxattrData {
    pub fd: i32,
    pub list: u64,
    pub size: usize,
    pub xattr_list: crate::kernel_types::XattrList,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ListxattrData {
    pub pathname: [u8; crate::DATA_READ_SIZE],
    pub list: u64,
    pub size: usize,
    pub xattr_list: crate::kernel_types::XattrList,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LlistxattrData {
    pub pathname: [u8; crate::DATA_READ_SIZE],
    pub list: u64,
    pub size: usize,
    pub xattr_list: crate::kernel_types::XattrList,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CloseData {
    pub fd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Dup3Data {
    pub oldfd: i32,
    pub newfd: i32,
    pub flags: i32,
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
pub struct RtSigreturnData {}

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
pub struct GetpidData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GettidData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetuidData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GeteuidData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetgidData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetegidData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetppidData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoctlData {
    pub fd: i32,
    pub request: u32,
    pub arg: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FcntlData {
    pub fd: i32,
    pub cmd: i32,
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
pub struct NewfstatatData {
    pub dirfd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
    pub stat: crate::kernel_types::Stat,
    pub flags: i32,
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
pub struct GetrandomData {
    pub buf: usize,
    pub buflen: usize,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatfsData {
    pub pathname: [u8; DATA_READ_SIZE],
    pub statfs: kernel_types::Statfs,
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
pub struct SetRobustListData {
    pub head: usize,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetTidAddressData {
    pub tidptr: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtSigprocmaskData {
    pub how: i32,
    pub set: usize,
    pub oldset: usize,
    pub sigsetsize: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtSigactionData {
    pub signum: i32,
    pub act: usize,
    pub oldact: usize,
    pub sigsetsize: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GenericSyscallData {
    pub args: [usize; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FaccessatData {
    pub dirfd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
    pub mode: i32,
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrlimitData {
    pub pid: i32,
    pub resource: i32,
    pub has_old: bool,
    pub has_new: bool,
    pub old_limit: kernel_types::Rlimit,
    pub new_limit: kernel_types::Rlimit,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RseqData {
    pub rseq_ptr: u64,
    pub rseq_len: u32,
    pub flags: i32,
    pub signature: u32,
    pub rseq: kernel_types::Rseq,
    pub has_rseq: bool, // Whether rseq pointer was valid and could be read
    pub rseq_cs: kernel_types::RseqCs,
    pub has_rseq_cs: bool, // Whether rseq_cs pointer was valid and could be read
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnameData {
    pub utsname: kernel_types::Utsname,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FchdirData {
    pub fd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadlinkatData {
    pub dirfd: i32,
    pub pathname: [u8; MEDIUM_READ_SIZE],
    pub buf: [u8; MEDIUM_READ_SIZE],
    pub bufsiz: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RecvmsgData {
    pub sockfd: i32,
    pub flags: i32,
    pub msghdr: crate::kernel_types::Msghdr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SendmsgData {
    pub sockfd: i32,
    pub flags: i32,
    pub msghdr: crate::kernel_types::Msghdr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RecvfromData {
    pub sockfd: i32,
    pub size: usize,
    pub flags: i32,
    pub has_addr: bool,
    pub addr: crate::kernel_types::Sockaddr,
    pub addrlen: u32,
    pub received_data: [u8; crate::DATA_READ_SIZE],
    pub received_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Accept4Data {
    pub sockfd: i32,
    pub flags: i32,
    pub has_addr: bool,
    pub addr: crate::kernel_types::Sockaddr,
    pub addrlen: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Wait4Data {
    pub pid: i32,
    pub wstatus: i32,
    pub options: i32,
    pub has_rusage: bool,
    pub rusage: kernel_types::Rusage,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetrusageData {
    pub who: i32,
    pub rusage: kernel_types::Rusage,
}

pub const CLONE_SET_TID_MAX: usize = 8; // Maximum set_tid array elements to capture

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Clone3Data {
    pub cl_args: kernel_types::CloneArgs,
    pub size: u64,
    pub set_tid_count: u32, // Number of PIDs captured in set_tid_array
    pub set_tid_array: [i32; CLONE_SET_TID_MAX], // Captured set_tid PIDs
}

impl Default for Clone3Data {
    fn default() -> Self {
        Self {
            cl_args: kernel_types::CloneArgs::default(),
            size: 0,
            set_tid_count: 0,
            set_tid_array: [0; CLONE_SET_TID_MAX],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CloneData {
    pub flags: u64,
    pub stack: usize,
    pub parent_tid: i32,
    pub child_tid: i32,
    pub tls: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitGroupData {
    pub status: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MadviseData {
    pub addr: usize,
    pub length: usize,
    pub advice: i32,
}
