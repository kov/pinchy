// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

#![no_std]

use crate::kernel_types::{EpollEvent, LandlockRuleAttrUnion, Timespec};

pub mod kernel_types;
pub mod syscalls;

pub const LARGER_READ_SIZE: usize = 256;
pub const DATA_READ_SIZE: usize = 128;
pub const MEDIUM_READ_SIZE: usize = 64;
pub const SMALLISH_READ_SIZE: usize = 32;
pub const SMALL_READ_SIZE: usize = 8;

// Landlock constants - from uapi/linux/landlock.h
// Landlock ruleset creation flags
pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

// Landlock rule types
pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
pub const LANDLOCK_RULE_NET_PORT: u32 = 2;

// Landlock file access rights
pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 8;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 10;
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_CHOWN: u64 = 1 << 12;
pub const LANDLOCK_ACCESS_FS_CHMOD: u64 = 1 << 13;
pub const LANDLOCK_ACCESS_FS_CHGRP: u64 = 1 << 14;

// Landlock network access rights
pub const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

// io_uring constants - from uapi/linux/io_uring.h
pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;
pub const IORING_ENTER_SQ_WAIT: u32 = 1 << 2;
pub const IORING_REGISTER_PROBE: u32 = 8;

// NUMA memory policy constants - from uapi/linux/mempolicy.h
// Memory policy modes
pub const MPOL_DEFAULT: i32 = 0;
pub const MPOL_PREFERRED: i32 = 1;
pub const MPOL_BIND: i32 = 2;
pub const MPOL_INTERLEAVE: i32 = 3;
pub const MPOL_LOCAL: i32 = 4;
pub const MPOL_PREFERRED_MANY: i32 = 5;
pub const MPOL_WEIGHTED_INTERLEAVE: i32 = 6;

// Mode flags (bitwise OR'd with mode)
pub const MPOL_F_STATIC_NODES: i32 = 1 << 15;
pub const MPOL_F_RELATIVE_NODES: i32 = 1 << 14;
pub const MPOL_F_NUMA_BALANCING: i32 = 1 << 13;

// mbind/move_pages flags
pub const MPOL_MF_STRICT: u32 = 1 << 0;
pub const MPOL_MF_MOVE: u32 = 1 << 1;
pub const MPOL_MF_MOVE_ALL: u32 = 1 << 2;

// get_mempolicy flags
pub const MPOL_F_NODE: u64 = 1 << 0;
pub const MPOL_F_ADDR: u64 = 1 << 1;
pub const MPOL_F_MEMS_ALLOWED: u64 = 1 << 2;

// Quota management constants - from uapi/linux/quota.h
pub const Q_SYNC: i32 = 0x800001;
pub const Q_QUOTAON: i32 = 0x800002;
pub const Q_QUOTAOFF: i32 = 0x800003;
pub const Q_GETFMT: i32 = 0x800004;
pub const Q_GETINFO: i32 = 0x800005;
pub const Q_SETINFO: i32 = 0x800006;
pub const Q_GETQUOTA: i32 = 0x800007;
pub const Q_SETQUOTA: i32 = 0x800008;
pub const Q_GETNEXTQUOTA: i32 = 0x800009;

// XFS quota commands - from uapi/linux/dqblk_xfs.h
// XQM_CMD(x) = ('X'<<8)+(x) where 'X' = 0x58
pub const Q_XQUOTAON: i32 = 0x5801;
pub const Q_XQUOTAOFF: i32 = 0x5802;
pub const Q_XGETQUOTA: i32 = 0x5803;
pub const Q_XSETQLIM: i32 = 0x5804;
pub const Q_XGETQSTAT: i32 = 0x5805;
pub const Q_XQUOTARM: i32 = 0x5806;
pub const Q_XQUOTASYNC: i32 = 0x5807;
pub const Q_XGETQSTATV: i32 = 0x5808;
pub const Q_XGETNEXTQUOTA: i32 = 0x5809;

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
    pub epoll_wait: EpollPWaitData,
    pub ppoll: PpollData,
    pub read: ReadData,
    pub write: WriteData,
    pub pread: PreadData,
    pub pwrite: PwriteData,
    pub lseek: LseekData,
    pub openat: OpenAtData,
    pub openat2: OpenAt2Data,
    pub futex: FutexData,
    pub futex_waitv: FutexWaitvData,
    pub sched_yield: SchedYieldData,
    pub ioctl: IoctlData,
    pub sched_getattr: SchedGetattrData,
    pub sched_setattr: SchedSetattrData,
    pub epoll_ctl: EpollCtlData,
    pub execve: ExecveData,
    pub execveat: ExecveatData,
    pub fstat: FstatData,
    pub newfstatat: NewfstatatData,
    pub getdents64: Getdents64Data,
    pub mmap: MmapData,
    pub munmap: MunmapData,
    pub brk: BrkData,
    pub faccessat: FaccessatData,
    pub fallocate: FallocateData,
    pub mprotect: MprotectData,
    pub getrandom: GetrandomData,
    pub statfs: StatfsData,
    pub set_robust_list: SetRobustListData,
    pub get_robust_list: GetRobustListData,
    pub set_tid_address: SetTidAddressData,
    pub rt_sigprocmask: RtSigprocmaskData,
    pub rt_sigaction: RtSigactionData,
    pub rt_sigpending: RtSigpendingData,
    pub rt_sigqueueinfo: RtSigqueueinfoData,
    pub rt_sigsuspend: RtSigsuspendData,
    pub rt_sigtimedwait: RtSigtimedwaitData,
    pub rt_tgsigqueueinfo: RtTgsigqueueinfoData,
    pub prlimit: PrlimitData,
    pub rlimit: RlimitData,
    pub rseq: RseqData,
    pub uname: UnameData,
    pub generic: GenericSyscallData,
    pub fcntl: FcntlData,
    pub fchdir: FchdirData,
    pub readlinkat: ReadlinkatData,
    pub recvmsg: RecvmsgData,
    pub recvfrom: RecvfromData,
    pub sendto: SendtoData,
    pub sendmsg: SendmsgData,
    pub accept: AcceptData,
    pub accept4: Accept4Data,
    pub wait4: Wait4Data,
    pub waitid: WaitidData,
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
    pub setxattr: SetxattrData,
    pub lsetxattr: LsetxattrData,
    pub fsetxattr: FsetxattrData,
    pub getxattr: GetxattrData,
    pub lgetxattr: LgetxattrData,
    pub fgetxattr: FgetxattrData,
    pub removexattr: RemovexattrData,
    pub lremovexattr: LremovexattrData,
    pub fremovexattr: FremovexattrData,
    pub madvise: MadviseData,
    pub dup: DupData,
    pub dup2: Dup2Data,
    pub sync: SyncData,
    pub setsid: SetsidData,
    pub setuid: SetuidData,
    pub setgid: SetgidData,
    pub close_range: CloseRangeData,
    pub getpgid: GetpgidData,
    pub getsid: GetsidData,
    pub sched_getaffinity: SchedGetaffinityData,
    pub sched_setaffinity: SchedSetaffinityData,
    pub sched_getparam: SchedGetparamData,
    pub sched_setparam: SchedSetparamData,
    pub sched_rr_get_interval: SchedRrGetIntervalData,
    pub setpgid: SetpgidData,
    pub umask: UmaskData,
    pub vhangup: VhangupData,
    pub ioprio_get: IoprioGetData,
    pub ioprio_set: IoprioSetData,
    pub setregid: SetregidData,
    pub setresgid: SetresgidData,
    pub setresuid: SetresuidData,
    pub setreuid: SetreuidData,
    pub alarm: AlarmData,
    pub pause: PauseData,
    pub getpgrp: GetpgrpData,
    pub times: TimesData,
    pub personality: PersonalityData,
    pub sysinfo: SysinfoData,
    pub gettimeofday: GettimeofdayData,
    pub settimeofday: SettimeofdayData,
    pub getpriority: GetpriorityData,
    pub setpriority: SetpriorityData,
    pub tkill: TkillData,
    pub tgkill: TgkillData,
    pub kill: KillData,
    pub exit: ExitData,
    pub sched_getscheduler: SchedGetschedulerData,
    pub sched_setscheduler: SchedSetschedulerData,
    pub splice: SpliceData,
    pub setfsuid: SetfsuidData,
    pub setfsgid: SetfsgidData,
    pub sched_get_priority_max: SchedGetPriorityMaxData,
    pub sched_get_priority_min: SchedGetPriorityMinData,
    pub vector_io: VectorIOData,
    pub sockaddr: SockaddrData,
    pub socket: SocketData,
    pub listen: ListenData,
    pub shutdown: ShutdownData,
    pub socketpair: SocketpairData,
    pub getsockname: GetSocknameData,
    pub getpeername: GetpeernameData,
    pub setsockopt: SetsockoptData,
    pub getsockopt: GetsockoptData,
    pub process_vm: ProcessVmData,
    pub recvmmsg: RecvMmsgData,
    pub sendmmsg: SendMmsgData,
    pub select: SelectData,
    pub pselect6: Pselect6Data,
    pub getcwd: GetcwdData,
    pub chdir: ChdirData,
    pub mkdirat: MkdiratData,
    pub nanosleep: NanosleepData,
    pub clock_nanosleep: ClockNanosleepData,
    pub adjtimex: AdjtimexData,
    pub clock_adjtime: ClockAdjtimeData,
    pub fsync: FsyncData,
    pub fdatasync: FdatasyncData,
    pub ftruncate: FtruncateData,
    pub fchmod: FchmodData,
    pub fchmodat: FchmodatData,
    pub fchown: FchownData,
    pub fchownat: FchownatData,
    pub chown: ChownData,
    pub truncate: TruncateData,
    pub rename: RenameData,
    pub renameat: RenameatData,
    pub renameat2: Renameat2Data,
    pub poll: PollData,
    pub epoll_create: EpollCreateData,
    pub epoll_create1: EpollCreate1Data,
    pub epoll_pwait2: EpollPWait2Data,
    pub tee: TeeData,
    pub vmsplice: VmspliceData,
    pub rmdir: RmdirData,
    pub unlink: UnlinkData,
    pub unlinkat: UnlinkatData,
    pub symlink: SymlinkData,
    pub symlinkat: SymlinkatData,
    pub link: LinkData,
    pub linkat: LinkatData,
    pub shmat: ShmatData,
    pub shmdt: ShmdtData,
    pub shmget: ShmgetData,
    pub shmctl: ShmctlData,
    pub msgget: MsggetData,
    pub msgsnd: MsgsndData,
    pub msgrcv: MsgrcvData,
    pub msgctl: MsgctlData,
    pub semget: SemgetData,
    pub semop: SemopData,
    pub semctl: SemctlData,
    pub mq_open: MqOpenData,
    pub mq_unlink: MqUnlinkData,
    pub mq_timedsend: MqTimedsendData,
    pub mq_timedreceive: MqTimedreceiveData,
    pub mq_notify: MqNotifyData,
    pub mq_getsetattr: MqGetsetattrData,
    pub acct: AcctData,
    pub getcpu: GetcpuData,
    pub pidfd_open: PidfdOpenData,
    pub pidfd_send_signal: PidfdSendSignalData,
    pub pidfd_getfd: PidfdGetfdData,
    pub process_mrelease: ProcessMreleaseData,
    pub process_madvise: ProcessMadviseData,
    pub mlock: MlockData,
    pub mlock2: Mlock2Data,
    pub mlockall: MlockallData,
    pub membarrier: MembarrierData,
    pub mremap: MremapData,
    pub msync: MsyncData,
    pub munlock: MunlockData,
    pub munlockall: MunlockallData,
    pub readahead: ReadaheadData,
    pub setns: SetnsData,
    pub unshare: UnshareData,
    pub memfd_secret: MemfdSecretData,
    pub userfaultfd: UserfaultfdData,
    pub pkey_alloc: PkeyAllocData,
    pub pkey_free: PkeyFreeData,
    pub eventfd: EventfdData,
    pub eventfd2: Eventfd2Data,
    pub clock_time: ClockTimeData,
    pub timer_create: TimerCreateData,
    pub timer_delete: TimerDeleteData,
    pub timer_gettime: TimerGettimeData,
    pub timer_settime: TimerSettimeData,
    pub timer_getoverrun: TimerGetoverrunData,
    pub timerfd_create: TimerfdCreateData,
    pub timerfd_gettime: TimerfdGettimeData,
    pub timerfd_settime: TimerfdSettimeData,
    pub statx: StatxData,
    pub capsetget: CapsetgetData,
    pub flock: FlockData,
    pub mknod: MknodData,
    pub mknodat: MknodatData,
    pub pivot_root: PivotRootData,
    pub chroot: ChrootData,
    pub open_tree: OpenTreeData,
    pub mount: MountData,
    pub umount2: Umount2Data,
    pub mount_setattr: MountSetattrData,
    pub move_mount: MoveMountData,
    pub reboot: RebootData,
    pub inotify_add_watch: InotifyAddWatchData,
    pub inotify_rm_watch: InotifyRmWatchData,
    pub inotify_init1: InotifyInit1Data,
    pub inotify_init: InotifyInitData,
    pub sigaltstack: SigaltstackData,
    pub signalfd: SignalfdData,
    pub signalfd4: Signalfd4Data,
    pub swapon: SwaponData,
    pub swapoff: SwapoffData,
    pub fstatfs: FstatfsData,
    pub fsopen: FsopenData,
    pub fsconfig: FsconfigData,
    pub fsmount: FsmountData,
    pub fspick: FspickData,
    pub init_module: InitModuleData,
    pub finit_module: FinitModuleData,
    pub delete_module: DeleteModuleData,
    pub sethostname: SethostnameData,
    pub setdomainname: SetdomainnameData,
    pub io_setup: IoSetupData,
    pub io_destroy: IoDestroyData,
    pub io_submit: IoSubmitData,
    pub io_cancel: IoCancelData,
    pub io_getevents: IoGeteventsData,
    pub io_pgetevents: IoPgeteventsData,
    pub io_uring_setup: IoUringSetupData,
    pub io_uring_enter: IoUringEnterData,
    pub io_uring_register: IoUringRegisterData,
    pub landlock_create_ruleset: LandlockCreateRulesetData,
    pub landlock_add_rule: LandlockAddRuleData,
    pub landlock_restrict_self: LandlockRestrictSelfData,
    pub add_key: AddKeyData,
    pub request_key: RequestKeyData,
    pub keyctl: KeyctlData,
    pub mbind: MbindData,
    pub get_mempolicy: GetMempolicyData,
    pub set_mempolicy: SetMempolicyData,
    pub set_mempolicy_home_node: SetMempolicyHomeNodeData,
    pub migrate_pages: MigratePagesData,
    pub move_pages: MovePagesData,
    pub mincore: MincoreData,
    pub perf_event_open: PerfEventOpenData,
    pub bpf: BpfData,
    pub fanotify_init: FanotifyInitData,
    pub fanotify_mark: FanotifyMarkData,
    pub name_to_handle_at: NameToHandleAtData,
    pub open_by_handle_at: OpenByHandleAtData,
    pub copy_file_range: CopyFileRangeData,
    pub sync_file_range: SyncFileRangeData,
    pub syncfs: SyncfsData,
    pub utimensat: UtimensatData,
    pub getitimer: GetItimerData,
    pub setitimer: SetItimerData,
    pub syslog: SyslogData,
    pub ptrace: PtraceData,
    pub seccomp: SeccompData,
    pub quotactl: QuotactlData,
    pub quotactl_fd: QuotactlFdData,
    pub kcmp: KcmpData,
    pub getgroups: GetgroupsData,
    pub setgroups: SetgroupsData,
    pub getresuid: GetresuidData,
    pub getresgid: GetresgidData,
    pub memfd_create: MemfdCreateData,
    pub pkey_mprotect: PkeyMprotectData,
    pub mseal: MsealData,
    pub remap_file_pages: RemapFilePagesData,
    pub restart_syscall: RestartSyscallData,
    pub kexec_load: KexecLoadData,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FchownData {
    pub fd: i32,
    pub uid: u32,
    pub gid: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FchownatData {
    pub dirfd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
    pub uid: u32,
    pub gid: u32,
    pub flags: i32,
}

impl Default for FchownatData {
    fn default() -> Self {
        Self {
            dirfd: 0,
            pathname: [0; DATA_READ_SIZE],
            uid: 0,
            gid: 0,
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ChownData {
    pub pathname: [u8; DATA_READ_SIZE],
    pub uid: u32,
    pub gid: u32,
}

impl Default for ChownData {
    fn default() -> Self {
        Self {
            pathname: [0; DATA_READ_SIZE],
            uid: 0,
            gid: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
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
#[derive(Debug, Copy, Clone)]
pub struct SetxattrData {
    pub pathname: [u8; crate::DATA_READ_SIZE],
    pub name: [u8; crate::MEDIUM_READ_SIZE],
    pub value: [u8; crate::DATA_READ_SIZE],
    pub size: usize,
    pub flags: i32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LsetxattrData {
    pub pathname: [u8; crate::DATA_READ_SIZE],
    pub name: [u8; crate::MEDIUM_READ_SIZE],
    pub value: [u8; crate::DATA_READ_SIZE],
    pub size: usize,
    pub flags: i32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FsetxattrData {
    pub fd: i32,
    pub name: [u8; crate::MEDIUM_READ_SIZE],
    pub value: [u8; crate::DATA_READ_SIZE],
    pub size: usize,
    pub flags: i32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GetxattrData {
    pub pathname: [u8; crate::DATA_READ_SIZE],
    pub name: [u8; crate::MEDIUM_READ_SIZE],
    pub value: [u8; crate::DATA_READ_SIZE],
    pub size: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LgetxattrData {
    pub pathname: [u8; crate::DATA_READ_SIZE],
    pub name: [u8; crate::MEDIUM_READ_SIZE],
    pub value: [u8; crate::DATA_READ_SIZE],
    pub size: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FgetxattrData {
    pub fd: i32,
    pub name: [u8; crate::MEDIUM_READ_SIZE],
    pub value: [u8; crate::DATA_READ_SIZE],
    pub size: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RemovexattrData {
    pub pathname: [u8; crate::DATA_READ_SIZE],
    pub name: [u8; crate::MEDIUM_READ_SIZE],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LremovexattrData {
    pub pathname: [u8; crate::DATA_READ_SIZE],
    pub name: [u8; crate::MEDIUM_READ_SIZE],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FremovexattrData {
    pub fd: i32,
    pub name: [u8; crate::MEDIUM_READ_SIZE],
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

// Alias for epoll_wait, which has the same structure as epoll_pwait but no sigmask
pub type EpollWaitData = EpollPWaitData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadData {
    pub fd: i32,
    pub buf: [u8; DATA_READ_SIZE],
    pub count: usize,
}

/// Data for vector I/O syscalls (readv, writev, preadv, pwritev, preadv2, pwritev2)
pub const IOV_COUNT: usize = 8;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VectorIOData {
    pub fd: i32,
    pub iovecs: [crate::kernel_types::Iovec; IOV_COUNT],
    pub iov_lens: [usize; IOV_COUNT],
    pub iov_bufs: [[u8; crate::LARGER_READ_SIZE]; IOV_COUNT],
    pub iovcnt: usize,
    pub offset: i64, // Only used for preadv/pwritev variants
    pub flags: u32,  // Only used for preadv2/pwritev2
    pub read_count: usize,
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
pub struct PreadData {
    pub fd: i32,
    pub buf: [u8; DATA_READ_SIZE],
    pub count: usize,
    pub offset: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PwriteData {
    pub fd: i32,
    pub buf: [u8; DATA_READ_SIZE],
    pub count: usize,
    pub offset: i64,
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
pub struct OpenAt2Data {
    pub dfd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
    pub how: kernel_types::OpenHow, // struct open_how
    pub size: usize,                // size argument
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

pub const FUTEX_WAITV_MAX: usize = 4;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FutexWaitvData {
    pub waiters: [crate::kernel_types::FutexWaitv; FUTEX_WAITV_MAX],
    pub nr_waiters: u32,
    pub flags: u32,
    pub has_timeout: bool,
    pub timeout: Timespec,
    pub clockid: i32,
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
#[derive(Clone, Copy, Default)]
pub struct PidfdOpenData {
    pub pid: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PidfdGetfdData {
    pub pidfd: i32,
    pub targetfd: i32,
    pub flags: u32,
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
pub struct ExecveatData {
    pub dirfd: i32,
    pub pathname: [u8; SMALL_READ_SIZE * 4],
    pub pathname_truncated: bool,
    pub argv: [[u8; SMALL_READ_SIZE]; 4],
    pub argv_len: [u16; 4],
    pub argc: u8,
    pub envp: [[u8; SMALL_READ_SIZE]; 2],
    pub envp_len: [u16; 2],
    pub envc: u8,
    pub flags: i32,
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
#[derive(Clone, Copy, Default)]
pub struct GetRobustListData {
    pub pid: i32,
    pub head: usize,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetTidAddressData {
    pub tidptr: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RtSigprocmaskData {
    pub how: i32,
    pub set: usize,
    pub oldset: usize,
    pub sigsetsize: usize,
    pub set_data: crate::kernel_types::Sigset,
    pub oldset_data: crate::kernel_types::Sigset,
    pub has_set_data: bool,
    pub has_oldset_data: bool,
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
#[derive(Clone, Copy, Default)]
pub struct RtSigpendingData {
    pub set: usize,
    pub sigsetsize: usize,
    pub set_data: crate::kernel_types::Sigset,
    pub has_set_data: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtSigqueueinfoData {
    pub tgid: i32,
    pub sig: i32,
    pub uinfo: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RtSigsuspendData {
    pub mask: usize,
    pub sigsetsize: usize,
    pub mask_data: crate::kernel_types::Sigset,
    pub has_mask_data: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RtSigtimedwaitData {
    pub set: usize,
    pub info: usize,
    pub timeout: usize,
    pub sigsetsize: usize,
    pub set_data: crate::kernel_types::Sigset,
    pub has_set_data: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtTgsigqueueinfoData {
    pub tgid: i32,
    pub tid: i32,
    pub sig: i32,
    pub uinfo: usize,
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
pub struct FallocateData {
    pub fd: i32,
    pub mode: i32,
    pub offset: i64,
    pub size: i64,
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
pub struct RlimitData {
    pub resource: i32,
    pub has_limit: bool,
    pub limit: kernel_types::Rlimit,
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
pub struct SendtoData {
    pub sockfd: i32,
    pub size: usize,
    pub flags: i32,
    pub has_addr: bool,
    pub addr: crate::kernel_types::Sockaddr,
    pub addrlen: u32,
    pub sent_data: [u8; crate::DATA_READ_SIZE],
    pub sent_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AcceptData {
    pub sockfd: i32,
    pub has_addr: bool,
    pub addr: crate::kernel_types::Sockaddr,
    pub addrlen: u32,
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
pub struct WaitidData {
    pub idtype: u32,
    pub id: u32,
    pub infop: kernel_types::Siginfo,
    pub options: i32,
    pub has_infop: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetrusageData {
    pub who: i32,
    pub rusage: kernel_types::Rusage,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockaddrData {
    pub sockfd: i32,
    pub addr: crate::kernel_types::Sockaddr,
    pub addrlen: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketData {
    pub domain: i32,
    pub type_: i32,
    pub protocol: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListenData {
    pub sockfd: i32,
    pub backlog: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShutdownData {
    pub sockfd: i32,
    pub how: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketpairData {
    pub domain: i32,
    pub type_: i32,
    pub protocol: i32,
    pub sv: [i32; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetSocknameData {
    pub sockfd: i32,
    pub has_addr: bool,
    pub addr: crate::kernel_types::Sockaddr,
    pub addrlen: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetpeernameData {
    pub sockfd: i32,
    pub has_addr: bool,
    pub addr: crate::kernel_types::Sockaddr,
    pub addrlen: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetsockoptData {
    pub sockfd: i32,
    pub level: i32,
    pub optname: i32,
    pub optval: [u8; MEDIUM_READ_SIZE],
    pub optlen: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetsockoptData {
    pub sockfd: i32,
    pub level: i32,
    pub optname: i32,
    pub optval: [u8; MEDIUM_READ_SIZE],
    pub optlen: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SelectData {
    pub nfds: i32,
    pub readfds: kernel_types::FdSet,
    pub writefds: kernel_types::FdSet,
    pub exceptfds: kernel_types::FdSet,
    pub timeout: kernel_types::Timeval,
    pub has_readfds: bool,
    pub has_writefds: bool,
    pub has_exceptfds: bool,
    pub has_timeout: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Pselect6Data {
    pub nfds: i32,
    pub readfds: kernel_types::FdSet,
    pub writefds: kernel_types::FdSet,
    pub exceptfds: kernel_types::FdSet,
    pub timeout: Timespec,
    pub has_readfds: bool,
    pub has_writefds: bool,
    pub has_exceptfds: bool,
    pub has_timeout: bool,
    pub has_sigmask: bool,
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DupData {
    pub oldfd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Dup2Data {
    pub oldfd: i32,
    pub newfd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyncData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetsidData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetuidData {
    pub uid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetgidData {
    pub gid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CloseRangeData {
    pub fd: u32,
    pub max_fd: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetpgidData {
    pub pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetsidData {
    pub pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetpgidData {
    pub pid: i32,
    pub pgid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UmaskData {
    pub mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VhangupData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoprioGetData {
    pub which: i32,
    pub who: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoprioSetData {
    pub which: i32,
    pub who: i32,
    pub ioprio: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetregidData {
    pub rgid: u32,
    pub egid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetresgidData {
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetresuidData {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetreuidData {
    pub ruid: u32,
    pub euid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AlarmData {
    pub seconds: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PauseData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetpgrpData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TimesData {
    pub buf: crate::kernel_types::Tms,
    pub has_buf: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PersonalityData {
    pub persona: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SysinfoData {
    pub info: crate::kernel_types::Sysinfo,
    pub has_info: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GettimeofdayData {
    pub tv: crate::kernel_types::Timeval,
    pub tz: crate::kernel_types::Timezone,
    pub has_tv: bool,
    pub has_tz: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SettimeofdayData {
    pub tv: crate::kernel_types::Timeval,
    pub tz: crate::kernel_types::Timezone,
    pub has_tv: bool,
    pub has_tz: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetpriorityData {
    pub which: i32,
    pub who: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetpriorityData {
    pub which: i32,
    pub who: i32,
    pub prio: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TkillData {
    pub pid: i32,
    pub signal: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TgkillData {
    pub tgid: i32,
    pub pid: i32,
    pub signal: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KillData {
    pub pid: i32,
    pub signal: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PidfdSendSignalData {
    pub pidfd: i32,
    pub sig: i32,
    pub info: crate::kernel_types::Siginfo,
    pub info_ptr: usize,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitData {
    pub status: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SchedGetschedulerData {
    pub pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SchedSetschedulerData {
    pub pid: i32,
    pub policy: i32,
    pub param: kernel_types::SchedParam,
    pub has_param: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetfsuidData {
    pub uid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetfsgidData {
    pub gid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SchedGetPriorityMaxData {
    pub policy: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SchedGetPriorityMinData {
    pub policy: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetcwdData {
    pub buf: u64,                   // Pointer to the buffer
    pub size: usize,                // Size of the buffer
    pub path: [u8; DATA_READ_SIZE], // The actual current working directory path
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChdirData {
    pub path: [u8; DATA_READ_SIZE], // The directory path to change to
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MkdiratData {
    pub dirfd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
    pub mode: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NanosleepData {
    pub req: Timespec,
    pub rem: Timespec,
    pub has_rem: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClockNanosleepData {
    pub clockid: i32,
    pub flags: i32,
    pub req: Timespec,
    pub rem: Timespec,
    pub has_rem: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AdjtimexData {
    pub timex: crate::kernel_types::Timex,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClockAdjtimeData {
    pub clockid: i32,
    pub timex: crate::kernel_types::Timex,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsyncData {
    pub fd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FdatasyncData {
    pub fd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FtruncateData {
    pub fd: i32,
    pub length: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FchmodData {
    pub fd: i32,
    pub mode: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FchmodatData {
    pub dirfd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
    pub mode: u32,
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RenameData {
    pub oldpath: [u8; SMALLISH_READ_SIZE],
    pub newpath: [u8; SMALLISH_READ_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RenameatData {
    pub olddirfd: i32,
    pub oldpath: [u8; SMALLISH_READ_SIZE],
    pub newdirfd: i32,
    pub newpath: [u8; SMALLISH_READ_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RebootData {
    pub magic1: i32,
    pub magic2: i32,
    pub cmd: i32,
    pub arg: u64,
    pub has_restart2: bool,
    pub restart2: [u8; DATA_READ_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InotifyAddWatchData {
    pub fd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
    pub mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InotifyRmWatchData {
    pub fd: i32,
    pub wd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InotifyInit1Data {
    pub flags: i32,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct InotifyInitData {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Renameat2Data {
    pub olddirfd: i32,
    pub oldpath: [u8; SMALLISH_READ_SIZE],
    pub newdirfd: i32,
    pub newpath: [u8; SMALLISH_READ_SIZE],
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TruncateData {
    pub pathname: [u8; DATA_READ_SIZE],
    pub length: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PollData {
    pub fds: [kernel_types::Pollfd; 16],
    pub nfds: u32,
    pub timeout: i32,
    pub actual_nfds: u32, // How many we actually read
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EpollCreateData {
    pub size: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EpollCreate1Data {
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EpollPWait2Data {
    pub epfd: i32,
    pub events: [crate::kernel_types::EpollEvent; 8],
    pub max_events: i32,
    pub timeout: crate::kernel_types::Timespec,
    pub sigmask: usize,
    pub sigsetsize: usize,
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct EpollCtlData {
    pub epfd: i32,
    pub op: i32,
    pub fd: i32,
    pub event: kernel_types::EpollEvent,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SpliceData {
    pub fd_in: i32,
    pub off_in: u64,
    pub fd_out: i32,
    pub off_out: u64,
    pub len: usize,
    pub flags: u32,
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct TeeData {
    pub fd_in: i32,
    pub fd_out: i32,
    pub len: usize,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VmspliceData {
    pub fd: i32,
    pub iovecs: [kernel_types::Iovec; IOV_COUNT],
    pub iov_lens: [usize; IOV_COUNT],
    pub iov_bufs: [[u8; crate::LARGER_READ_SIZE]; IOV_COUNT],
    pub iovcnt: usize,
    pub flags: u32,
    pub read_count: usize,
}

#[derive(Debug, Copy, Clone)]
pub struct RmdirData {
    pub pathname: [u8; DATA_READ_SIZE],
}

impl Default for RmdirData {
    fn default() -> Self {
        RmdirData {
            pathname: [0u8; DATA_READ_SIZE],
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct UnlinkData {
    pub pathname: [u8; DATA_READ_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnlinkatData {
    pub dirfd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AcctData {
    pub filename: [u8; DATA_READ_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SymlinkData {
    pub target: [u8; DATA_READ_SIZE],
    pub linkpath: [u8; DATA_READ_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SymlinkatData {
    pub target: [u8; DATA_READ_SIZE],
    pub newdirfd: i32,
    pub linkpath: [u8; DATA_READ_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinkData {
    pub oldpath: [u8; SMALLISH_READ_SIZE],
    pub newpath: [u8; SMALLISH_READ_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinkatData {
    pub olddirfd: i32,
    pub oldpath: [u8; SMALLISH_READ_SIZE],
    pub newdirfd: i32,
    pub newpath: [u8; SMALLISH_READ_SIZE],
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ShmatData {
    pub shmid: i32,
    pub shmaddr: usize,
    pub shmflg: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MsggetData {
    pub key: i32,
    pub msgflg: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MsgsndData {
    pub msqid: i32,
    pub msgp: usize,
    pub msgsz: usize,
    pub msgflg: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MsgrcvData {
    pub msqid: i32,
    pub msgp: usize,
    pub msgsz: usize,
    pub msgtyp: i64,
    pub msgflg: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MsgctlData {
    pub msqid: i32,
    pub op: i32,
    pub buf: crate::kernel_types::MsqidDs,
    pub has_buf: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SemgetData {
    pub key: i32,
    pub nsems: i32,
    pub semflg: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SemopData {
    pub semid: i32,
    pub sops: usize,
    pub nsops: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SemctlData {
    pub semid: i32,
    pub semnum: i32,
    pub op: i32,
    pub has_arg: bool,
    pub arg: kernel_types::Semun,
    pub array: [u16; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ShmdtData {
    pub shmaddr: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ShmgetData {
    pub key: i32,
    pub size: usize,
    pub shmflg: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ShmctlData {
    pub shmid: i32,
    pub cmd: i32,
    pub buf: crate::kernel_types::ShmidDs,
    pub has_buf: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GetcpuData {
    pub cpu: u32,
    pub has_cpu: bool,
    pub node: u32,
    pub has_node: bool,
    pub tcache: usize, // address as in syscall argument
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessMreleaseData {
    pub pidfd: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessMadviseData {
    pub pidfd: i32,
    pub iovecs: [crate::kernel_types::Iovec; IOV_COUNT],
    pub iov_lens: [usize; IOV_COUNT],
    pub iov_bufs: [[u8; crate::LARGER_READ_SIZE]; IOV_COUNT],
    pub iovcnt: usize,
    pub advice: i32,
    pub flags: u32,
    pub read_count: usize,
}

impl Default for ProcessMadviseData {
    fn default() -> Self {
        Self {
            pidfd: 0,
            iovecs: [crate::kernel_types::Iovec::default(); IOV_COUNT],
            iov_lens: [0; IOV_COUNT],
            iov_bufs: [[0; crate::LARGER_READ_SIZE]; IOV_COUNT],
            iovcnt: 0,
            advice: 0,
            flags: 0,
            read_count: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MlockData {
    pub addr: usize,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Mlock2Data {
    pub addr: usize,
    pub len: usize,
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MlockallData {
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MembarrierData {
    pub cmd: i32,
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MremapData {
    pub old_address: usize,
    pub old_size: usize,
    pub new_size: usize,
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MsyncData {
    pub addr: usize,
    pub length: usize,
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MunlockData {
    pub addr: usize,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MunlockallData;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadaheadData {
    pub fd: i32,
    pub offset: usize,
    pub count: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetnsData {
    pub fd: i32,
    pub nstype: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnshareData {
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemfdSecretData {
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UserfaultfdData {
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PkeyAllocData {
    pub flags: u32,
    pub access_rights: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PkeyFreeData {
    pub pkey: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventfdData {
    pub initval: u32,
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Eventfd2Data {
    pub initval: u32,
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ClockTimeData {
    pub clockid: i32,
    pub tp: crate::kernel_types::Timespec,
    pub has_tp: bool,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StatxData {
    pub dirfd: i32,
    pub pathname: [u8; crate::DATA_READ_SIZE],
    pub flags: i32,
    pub mask: u32,
    pub statxbuf: u64, // user pointer
    pub statx: crate::kernel_types::Statx,
}

impl Default for StatxData {
    fn default() -> Self {
        Self {
            dirfd: 0,
            pathname: [0; crate::DATA_READ_SIZE],
            flags: 0,
            mask: 0,
            statxbuf: 0,
            statx: crate::kernel_types::Statx::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct CapsetgetData {
    pub header: crate::kernel_types::CapUserHeader,

    // The number of valid elements in the data array (1 for V1, 2 for V2, 3 for V3)
    pub data_count: u8,

    // The actual capability data structs (up to 3 for version 3)
    pub data: [crate::kernel_types::CapUserData; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SchedGetaffinityData {
    pub pid: i32,
    pub cpusetsize: usize,
    pub mask: usize, // pointer value only
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SchedGetattrData {
    pub pid: u32,
    pub attr: crate::kernel_types::SchedAttr,
    pub size: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SchedSetattrData {
    pub pid: u32,
    pub attr: crate::kernel_types::SchedAttr,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SchedSetaffinityData {
    pub pid: i32,
    pub cpusetsize: usize,
    pub mask: usize, // pointer value only
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SchedGetparamData {
    pub pid: i32,
    pub param: crate::kernel_types::SchedParam,
    pub has_param: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SchedSetparamData {
    pub pid: i32,
    pub param: crate::kernel_types::SchedParam,
    pub has_param: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SchedRrGetIntervalData {
    pub pid: i32,
    pub interval: Timespec,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FlockData {
    pub fd: i32,
    pub operation: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MknodData {
    pub pathname: [u8; DATA_READ_SIZE],
    pub mode: u32,
    pub dev: u64, // dev_t, using u64 to cover both architectures
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MknodatData {
    pub dirfd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
    pub mode: u32,
    pub dev: u64, // dev_t, using u64 to cover both architectures
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PivotRootData {
    pub new_root: [u8; DATA_READ_SIZE],
    pub put_old: [u8; DATA_READ_SIZE],
}

impl Default for PivotRootData {
    fn default() -> Self {
        Self {
            new_root: [0; DATA_READ_SIZE],
            put_old: [0; DATA_READ_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChrootData {
    pub path: [u8; DATA_READ_SIZE],
}

impl Default for ChrootData {
    fn default() -> Self {
        Self {
            path: [0; DATA_READ_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenTreeData {
    pub dfd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
    pub flags: u32,
}

impl Default for OpenTreeData {
    fn default() -> Self {
        Self {
            dfd: 0,
            pathname: [0; DATA_READ_SIZE],
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MountData {
    pub source: [u8; DATA_READ_SIZE],
    pub target: [u8; DATA_READ_SIZE],
    pub filesystemtype: [u8; SMALL_READ_SIZE],
    pub mountflags: u64,
    pub data: u64, // void* pointer address
}

impl Default for MountData {
    fn default() -> Self {
        Self {
            source: [0; DATA_READ_SIZE],
            target: [0; DATA_READ_SIZE],
            filesystemtype: [0; SMALL_READ_SIZE],
            mountflags: 0,
            data: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Umount2Data {
    pub target: [u8; DATA_READ_SIZE],
    pub flags: i32,
}

impl Default for Umount2Data {
    fn default() -> Self {
        Self {
            target: [0; DATA_READ_SIZE],
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MountSetattrData {
    pub dfd: i32,
    pub path: [u8; DATA_READ_SIZE],
    pub flags: u32,
    pub size: usize,
    pub attr: kernel_types::MountAttr,
    pub has_attr: bool,
}

impl Default for MountSetattrData {
    fn default() -> Self {
        Self {
            dfd: 0,
            path: [0; DATA_READ_SIZE],
            flags: 0,
            size: 0,
            attr: kernel_types::MountAttr::default(),
            has_attr: false,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MoveMountData {
    pub from_dfd: i32,
    pub from_pathname: [u8; DATA_READ_SIZE],
    pub to_dfd: i32,
    pub to_pathname: [u8; DATA_READ_SIZE],
    pub flags: u32,
}

impl Default for MoveMountData {
    fn default() -> Self {
        Self {
            from_dfd: 0,
            from_pathname: [0; DATA_READ_SIZE],
            to_dfd: 0,
            to_pathname: [0; DATA_READ_SIZE],
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SigaltstackData {
    pub ss_ptr: usize,     // user pointer value
    pub old_ss_ptr: usize, // user pointer value
    pub ss: crate::kernel_types::StackT,
    pub old_ss: crate::kernel_types::StackT,
    pub has_ss: bool,
    pub has_old_ss: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SignalfdData {
    pub fd: i32,
    pub flags: i32,
    pub mask: crate::kernel_types::Sigset,
    pub has_mask: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Signalfd4Data {
    pub fd: i32,
    pub flags: i32,
    pub mask: crate::kernel_types::Sigset,
    pub has_mask: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SwaponData {
    pub pathname: [u8; DATA_READ_SIZE],
    pub flags: i32,
}

impl Default for SwaponData {
    fn default() -> Self {
        Self {
            pathname: [0; DATA_READ_SIZE],
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SwapoffData {
    pub pathname: [u8; DATA_READ_SIZE],
}

impl Default for SwapoffData {
    fn default() -> Self {
        Self {
            pathname: [0; DATA_READ_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimerCreateData {
    pub clockid: i32,
    pub has_sevp: bool,
    pub sevp: crate::kernel_types::Sigevent,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimerDeleteData {
    pub timerid: usize, // timer_t is typically a pointer or handle
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimerGettimeData {
    pub timerid: usize,
    pub curr_value: crate::kernel_types::Itimerspec,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimerSettimeData {
    pub timerid: usize,
    pub flags: i32,
    pub has_new_value: bool,
    pub new_value: crate::kernel_types::Itimerspec,
    pub has_old_value: bool,
    pub old_value: crate::kernel_types::Itimerspec,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimerGetoverrunData {
    pub timerid: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimerfdCreateData {
    pub clockid: i32,
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimerfdGettimeData {
    pub fd: i32,
    pub curr_value: crate::kernel_types::Itimerspec,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimerfdSettimeData {
    pub fd: i32,
    pub flags: i32,
    pub has_new_value: bool,
    pub new_value: crate::kernel_types::Itimerspec,
    pub has_old_value: bool,
    pub old_value: crate::kernel_types::Itimerspec,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FstatfsData {
    pub fd: i32,
    pub statfs: kernel_types::Statfs,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsopenData {
    pub fsname: [u8; DATA_READ_SIZE],
    pub flags: u32,
}

impl Default for FsopenData {
    fn default() -> Self {
        Self {
            fsname: [0; DATA_READ_SIZE],
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsconfigData {
    pub fd: i32,
    pub cmd: u32,
    pub key: [u8; MEDIUM_READ_SIZE],
    pub value: [u8; DATA_READ_SIZE],
    pub aux: i32,
}

impl Default for FsconfigData {
    fn default() -> Self {
        Self {
            fd: 0,
            cmd: 0,
            key: [0; MEDIUM_READ_SIZE],
            value: [0; DATA_READ_SIZE],
            aux: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FsmountData {
    pub fd: i32,
    pub flags: u32,
    pub attr_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FspickData {
    pub dfd: i32,
    pub path: [u8; DATA_READ_SIZE],
    pub flags: u32,
}

impl Default for FspickData {
    fn default() -> Self {
        Self {
            dfd: 0,
            path: [0; DATA_READ_SIZE],
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InitModuleData {
    pub module_image: usize, // pointer to module image
    pub len: usize,
    pub param_values: [u8; DATA_READ_SIZE], // module parameters string
}

impl Default for InitModuleData {
    fn default() -> Self {
        Self {
            module_image: 0,
            len: 0,
            param_values: [0; DATA_READ_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FinitModuleData {
    pub fd: i32,
    pub param_values: [u8; DATA_READ_SIZE], // module parameters string
    pub flags: u32,
}

impl Default for FinitModuleData {
    fn default() -> Self {
        Self {
            fd: 0,
            param_values: [0; DATA_READ_SIZE],
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DeleteModuleData {
    pub name: [u8; MEDIUM_READ_SIZE], // module name
    pub flags: i32,
}

impl Default for DeleteModuleData {
    fn default() -> Self {
        Self {
            name: [0; MEDIUM_READ_SIZE],
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SethostnameData {
    pub name: [u8; MEDIUM_READ_SIZE], // hostname (max 64 bytes according to man page)
    pub len: usize,
}

impl Default for SethostnameData {
    fn default() -> Self {
        Self {
            name: [0; MEDIUM_READ_SIZE],
            len: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetdomainnameData {
    pub name: [u8; MEDIUM_READ_SIZE], // domain name (max 64 bytes according to man page)
    pub len: usize,
}

impl Default for SetdomainnameData {
    fn default() -> Self {
        Self {
            name: [0; MEDIUM_READ_SIZE],
            len: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RecvMmsgData {
    pub sockfd: i32,
    pub flags: i32,
    pub vlen: u32,                              // Number of messages
    pub timeout: crate::kernel_types::Timespec, // For recvmmsg only
    pub has_timeout: bool,                      // Whether timeout was provided
    pub msgs: [crate::kernel_types::Mmsghdr; crate::kernel_types::MMSGHDR_COUNT], // Array of messages
    pub msgs_count: u32, // How many messages we captured
}

impl Default for RecvMmsgData {
    fn default() -> Self {
        Self {
            sockfd: 0,
            flags: 0,
            vlen: 0,
            timeout: crate::kernel_types::Timespec::default(),
            has_timeout: false,
            msgs: [crate::kernel_types::Mmsghdr::default(); crate::kernel_types::MMSGHDR_COUNT],
            msgs_count: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SendMmsgData {
    pub sockfd: i32,
    pub flags: i32,
    pub vlen: u32, // Number of messages
    pub msgs: [crate::kernel_types::Mmsghdr; crate::kernel_types::MMSGHDR_COUNT], // Array of messages
    pub msgs_count: u32, // How many messages we captured
}

impl Default for SendMmsgData {
    fn default() -> Self {
        Self {
            sockfd: 0,
            flags: 0,
            vlen: 0,
            msgs: [crate::kernel_types::Mmsghdr::default(); crate::kernel_types::MMSGHDR_COUNT],
            msgs_count: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessVmData {
    pub pid: i32,
    pub local_iovecs: [kernel_types::Iovec; IOV_COUNT],
    pub local_iov_lens: [usize; IOV_COUNT],
    pub local_iovcnt: usize,
    pub remote_iovecs: [kernel_types::Iovec; IOV_COUNT],
    pub remote_iov_lens: [usize; IOV_COUNT],
    pub remote_iovcnt: usize,
    pub flags: u64,
    pub local_read_count: usize,
    pub remote_read_count: usize,
    pub local_iov_bufs: [[u8; LARGER_READ_SIZE]; IOV_COUNT],
}

impl Default for ProcessVmData {
    fn default() -> Self {
        Self {
            pid: 0,
            local_iovecs: [kernel_types::Iovec::default(); IOV_COUNT],
            local_iov_lens: [0; IOV_COUNT],
            local_iovcnt: 0,
            remote_iovecs: [kernel_types::Iovec::default(); IOV_COUNT],
            remote_iov_lens: [0; IOV_COUNT],
            remote_iovcnt: 0,
            flags: 0,
            local_read_count: 0,
            remote_read_count: 0,
            local_iov_bufs: [[0; LARGER_READ_SIZE]; IOV_COUNT],
        }
    }
}

impl Default for LinkData {
    fn default() -> Self {
        Self {
            oldpath: [0; SMALLISH_READ_SIZE],
            newpath: [0; SMALLISH_READ_SIZE],
        }
    }
}

impl Default for LinkatData {
    fn default() -> Self {
        Self {
            olddirfd: 0,
            oldpath: [0; SMALLISH_READ_SIZE],
            newdirfd: 0,
            newpath: [0; SMALLISH_READ_SIZE],
            flags: 0,
        }
    }
}

// Async I/O data structures

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoSetupData {
    pub nr_events: u32,
    pub ctx_idp: u64, // pointer to aio_context_t
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoDestroyData {
    pub ctx_id: u64, // aio_context_t
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoSubmitData {
    pub ctx_id: u64, // aio_context_t
    pub nr: i64,     // number of iocbs
    pub iocbpp: u64, // pointer to iocb array

    // Bounded snapshot of IOCBs
    pub iocbs: [kernel_types::IoCb; kernel_types::AIO_IOCB_ARRAY_CAP],
    pub iocb_count: u32, // How many IOCBs we actually captured
}

impl Default for IoSubmitData {
    fn default() -> Self {
        Self {
            ctx_id: 0,
            nr: 0,
            iocbpp: 0,
            iocbs: [kernel_types::IoCb::default(); kernel_types::AIO_IOCB_ARRAY_CAP],
            iocb_count: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoCancelData {
    pub ctx_id: u64,                         // aio_context_t
    pub iocb: u64,                           // pointer to iocb to cancel
    pub result: u64,                         // pointer to io_event result
    pub has_result: bool,                    // whether result pointer was valid
    pub result_event: kernel_types::IoEvent, // captured result event
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoGeteventsData {
    pub ctx_id: u64,  // aio_context_t
    pub min_nr: i64,  // minimum number of events
    pub nr: i64,      // maximum number of events
    pub events: u64,  // pointer to io_event array
    pub timeout: u64, // pointer to timespec

    // Bounded snapshot of events
    pub event_array: [kernel_types::IoEvent; kernel_types::AIO_EVENT_ARRAY_CAP],
    pub event_count: u32,       // How many events we actually captured
    pub has_timeout: bool,      // whether timeout was provided
    pub timeout_data: Timespec, // captured timeout data
}

impl Default for IoGeteventsData {
    fn default() -> Self {
        Self {
            ctx_id: 0,
            min_nr: 0,
            nr: 0,
            events: 0,
            timeout: 0,
            event_array: [kernel_types::IoEvent::default(); kernel_types::AIO_EVENT_ARRAY_CAP],
            event_count: 0,
            has_timeout: false,
            timeout_data: Timespec::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoPgeteventsData {
    pub ctx_id: u64,  // aio_context_t
    pub min_nr: i64,  // minimum number of events
    pub nr: i64,      // maximum number of events
    pub events: u64,  // pointer to io_event array
    pub timeout: u64, // pointer to timespec
    pub usig: u64,    // pointer to aio_sigset

    // Bounded snapshot of events
    pub event_array: [kernel_types::IoEvent; kernel_types::AIO_EVENT_ARRAY_CAP],
    pub event_count: u32,       // How many events we actually captured
    pub has_timeout: bool,      // whether timeout was provided
    pub timeout_data: Timespec, // captured timeout data
    pub has_usig: bool,         // whether usig was provided
    pub usig_data: kernel_types::AioSigset, // captured sigset data
    pub sigset_data: kernel_types::Sigset, // captured signal set
}

impl Default for IoPgeteventsData {
    fn default() -> Self {
        Self {
            ctx_id: 0,
            min_nr: 0,
            nr: 0,
            events: 0,
            timeout: 0,
            usig: 0,
            event_array: [kernel_types::IoEvent::default(); kernel_types::AIO_EVENT_ARRAY_CAP],
            event_count: 0,
            has_timeout: false,
            timeout_data: Timespec::default(),
            has_usig: false,
            usig_data: kernel_types::AioSigset::default(),
            sigset_data: kernel_types::Sigset::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoUringSetupData {
    pub entries: u32,
    pub params_ptr: u64,
    pub has_params: bool,
    pub params: kernel_types::IoUringParams,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoUringEnterData {
    pub fd: i32,
    pub to_submit: u32,
    pub min_complete: u32,
    pub flags: u32,
    pub sig: u64,
    pub sigsz: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoUringRegisterData {
    pub fd: i32,
    pub opcode: u32,
    pub arg: u64,
    pub nr_args: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MbindData {
    pub addr: u64,
    pub len: u64,
    pub mode: i32,
    pub maxnode: u64,
    pub flags: u32,
    pub nodemask: [u64; 2],
    pub nodemask_read_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GetMempolicyData {
    pub maxnode: u64,
    pub addr: u64,
    pub flags: u64,
    pub mode_out: i32,
    pub mode_valid: bool,
    pub nodemask_out: [u64; 2],
    pub nodemask_read_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SetMempolicyData {
    pub mode: i32,
    pub maxnode: u64,
    pub nodemask: [u64; 2],
    pub nodemask_read_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SetMempolicyHomeNodeData {
    pub start: u64,
    pub len: u64,
    pub home_node: u64,
    pub flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MigratePagesData {
    pub pid: i32,
    pub maxnode: u64,
    pub old_nodes: [u64; 2],
    pub new_nodes: [u64; 2],
    pub old_nodes_read_count: u32,
    pub new_nodes_read_count: u32,
}

const PAGE_ARRAY_CAP: usize = 8;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MovePagesData {
    pub pid: i32,
    pub count: u64,
    pub flags: i32,
    pub pages: [u64; PAGE_ARRAY_CAP],
    pub nodes: [i32; PAGE_ARRAY_CAP],
    pub status: [i32; PAGE_ARRAY_CAP],
    pub pages_read_count: u32,
    pub nodes_read_count: u32,
    pub status_read_count: u32,
}

impl Default for MovePagesData {
    fn default() -> Self {
        Self {
            pid: 0,
            count: 0,
            flags: 0,
            pages: [0; PAGE_ARRAY_CAP],
            nodes: [0; PAGE_ARRAY_CAP],
            status: [0; PAGE_ARRAY_CAP],
            pages_read_count: 0,
            nodes_read_count: 0,
            status_read_count: 0,
        }
    }
}

const VEC_ARRAY_CAP: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MincoreData {
    pub addr: u64,
    pub length: u64,
    pub vec: [u8; VEC_ARRAY_CAP],
    pub vec_read_count: u32,
}

impl Default for MincoreData {
    fn default() -> Self {
        Self {
            addr: 0,
            length: 0,
            vec: [0; VEC_ARRAY_CAP],
            vec_read_count: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MqOpenData {
    pub name: usize,
    pub flags: i32,
    pub mode: u32,
    pub attr: kernel_types::MqAttr,
    pub has_attr: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MqUnlinkData {
    pub name: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MqTimedsendData {
    pub mqdes: i32,
    pub msg_ptr: usize,
    pub msg_len: usize,
    pub msg_prio: u32,
    pub abs_timeout: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MqTimedreceiveData {
    pub mqdes: i32,
    pub msg_ptr: usize,
    pub msg_len: usize,
    pub msg_prio: u32,
    pub abs_timeout: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MqNotifyData {
    pub mqdes: i32,
    pub sevp: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MqGetsetattrData {
    pub mqdes: i32,
    pub newattr: kernel_types::MqAttr,
    pub oldattr: kernel_types::MqAttr,
    pub has_newattr: bool,
    pub has_oldattr: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LandlockCreateRulesetData {
    pub attr: u64,   // pointer to landlock_ruleset_attr
    pub size: usize, // size of attr
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LandlockAddRuleData {
    pub ruleset_fd: i32,
    pub rule_type: u32,
    pub rule_attr: u64, // pointer to rule attribute
    pub flags: u32,
    pub rule_attr_data: LandlockRuleAttrUnion,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LandlockRestrictSelfData {
    pub ruleset_fd: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AddKeyData {
    pub key_type: [u8; SMALLISH_READ_SIZE],
    pub description: [u8; LARGER_READ_SIZE],
    pub payload: [u8; MEDIUM_READ_SIZE],
    pub payload_len: usize,
    pub keyring: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RequestKeyData {
    pub key_type: [u8; SMALLISH_READ_SIZE],
    pub description: [u8; LARGER_READ_SIZE],
    pub callout_info: [u8; MEDIUM_READ_SIZE],
    pub callout_info_len: usize,
    pub dest_keyring: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KeyctlData {
    pub operation: i32,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
}

// Batch 6: Observability & Notifications

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PerfEventOpenData {
    pub attr: kernel_types::PerfEventAttr, // Parsed perf_event_attr structure
    pub pid: i32,
    pub cpu: i32,
    pub group_fd: i32,
    pub flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct BpfData {
    pub cmd: i32,
    pub size: u32,
    pub which_attr: u8, // 0=none, 1=map_create, 2=prog_load
    pub map_create_attr: kernel_types::BpfMapCreateAttr,
    pub prog_load_attr: kernel_types::BpfProgLoadAttr,
    pub license_str: [u8; 32], // Captured license string from user memory
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FanotifyInitData {
    pub flags: u32,
    pub event_f_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FanotifyMarkData {
    pub fanotify_fd: i32,
    pub flags: u32,
    pub mask: u64,
    pub dirfd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
}

impl Default for FanotifyMarkData {
    fn default() -> Self {
        Self {
            fanotify_fd: 0,
            flags: 0,
            mask: 0,
            dirfd: 0,
            pathname: [0; DATA_READ_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NameToHandleAtData {
    pub dirfd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
    /// Pointer to struct file_handle (output parameter)
    pub handle: u64,
    /// Pointer to mount_id (output parameter)
    pub mount_id: u64,
    pub flags: i32,
}

impl Default for NameToHandleAtData {
    fn default() -> Self {
        Self {
            dirfd: 0,
            pathname: [0; DATA_READ_SIZE],
            handle: 0,
            mount_id: 0,
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OpenByHandleAtData {
    pub mount_fd: i32,
    pub handle: u64,
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CopyFileRangeData {
    pub fd_in: i32,
    pub off_in: u64,
    pub off_in_is_null: u8,
    pub fd_out: i32,
    pub off_out: u64,
    pub off_out_is_null: u8,
    pub len: usize,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SyncFileRangeData {
    pub fd: i32,
    pub offset: i64,
    pub nbytes: i64,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SyncfsData {
    pub fd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UtimensatData {
    pub dirfd: i32,
    pub pathname: [u8; DATA_READ_SIZE],
    pub times: [kernel_types::Timespec; 2],
    pub times_is_null: u8,
    pub flags: i32,
}

impl Default for UtimensatData {
    fn default() -> Self {
        Self {
            dirfd: 0,
            pathname: [0; DATA_READ_SIZE],
            times: [kernel_types::Timespec::default(); 2],
            times_is_null: 0,
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GetItimerData {
    pub which: i32,
    pub curr_value: kernel_types::Itimerval,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SetItimerData {
    pub which: i32,
    pub new_value: kernel_types::Itimerval,
    pub has_old_value: bool,
    pub old_value: kernel_types::Itimerval,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SyslogData {
    pub type_: i32,
    pub bufp: u64,
    pub size: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PtraceData {
    pub request: i32,
    pub pid: i32,
    pub addr: u64,
    pub data: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SeccompData {
    pub operation: u32,
    pub flags: u32,
    pub args: u64,
    // Parsed argument data based on operation
    pub action_avail: u32,     // For GET_ACTION_AVAIL: the action value
    pub action_read_ok: u8,    // 1 if action_avail was successfully read, 0 otherwise
    pub filter_len: u16,       // For SET_MODE_FILTER: number of BPF instructions
    pub notif_sizes: [u16; 3], // For GET_NOTIF_SIZES: [notif, resp, data] sizes
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QuotactlData {
    pub op: i32,
    pub special: [u8; MEDIUM_READ_SIZE],
    pub id: i32,
    pub addr: u64,
}

impl Default for QuotactlData {
    fn default() -> Self {
        Self {
            op: 0,
            special: [0; MEDIUM_READ_SIZE],
            id: 0,
            addr: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct QuotactlFdData {
    pub fd: i32,
    pub cmd: u32,
    pub id: i32,
    pub addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KcmpData {
    pub pid1: i32,
    pub pid2: i32,
    pub type_: i32,
    pub idx1: u64,
    pub idx2: u64,
}

pub const GROUP_ARRAY_CAP: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetgroupsData {
    pub size: i32,
    pub groups: [u32; GROUP_ARRAY_CAP],
    pub groups_read_count: u32,
}

impl Default for GetgroupsData {
    fn default() -> Self {
        Self {
            size: 0,
            groups: [0; GROUP_ARRAY_CAP],
            groups_read_count: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetgroupsData {
    pub size: usize,
    pub groups: [u32; GROUP_ARRAY_CAP],
    pub groups_read_count: u32,
}

impl Default for SetgroupsData {
    fn default() -> Self {
        Self {
            size: 0,
            groups: [0; GROUP_ARRAY_CAP],
            groups_read_count: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GetresuidData {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GetresgidData {
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemfdCreateData {
    pub name: [u8; SMALL_READ_SIZE],
    pub flags: u32,
}

impl Default for MemfdCreateData {
    fn default() -> Self {
        Self {
            name: [0; SMALL_READ_SIZE],
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PkeyMprotectData {
    pub addr: u64,
    pub len: u64,
    pub prot: i32,
    pub pkey: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MsealData {
    pub addr: u64,
    pub len: u64,
    pub flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RemapFilePagesData {
    pub addr: u64,
    pub size: u64,
    pub prot: i32,
    pub pgoff: u64,
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RestartSyscallData {
    // No arguments
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KexecLoadData {
    pub entry: u64,
    pub nr_segments: u64,
    pub segments: u64,
    pub flags: u64,
    pub segments_read: u64,
    pub parsed_segments: [kernel_types::KexecSegment; kernel_types::KEXEC_SEGMENT_ARRAY_CAP],
}
