// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::kernel_types::{Stat, Timespec};

use crate::{argf, formatting::SyscallFormatter, with_struct};

pub fn poll_bits_to_strs(event: &i16) -> Vec<&'static str> {
    let mut strs = vec![];

    if event & libc::POLLIN != 0 {
        strs.push("POLLIN");
    }

    if event & libc::POLLPRI != 0 {
        strs.push("POLLPRI");
    }

    if event & libc::POLLOUT != 0 {
        strs.push("POLLOUT");
    }

    if event & libc::POLLRDHUP != 0 {
        strs.push("POLLRDHUP");
    }

    if event & libc::POLLERR != 0 {
        strs.push("POLLERR");
    }

    if event & libc::POLLHUP != 0 {
        strs.push("POLLHUP");
    }

    if event & libc::POLLNVAL != 0 {
        strs.push("POLLNVAL");
    }

    if event & libc::POLLRDNORM != 0 {
        strs.push("POLLRDNORM");
    }

    if event & libc::POLLRDBAND != 0 {
        strs.push("POLLRDBAND");
    }

    if event & libc::POLLWRNORM != 0 {
        strs.push("POLLWRNORM");
    }

    if event & libc::POLLWRBAND != 0 {
        strs.push("POLLWRBAND");
    }

    strs
}

/// Formats a path for display, including truncation indication if needed
pub fn format_path(path_bytes: &[u8], known_truncated: bool) -> String {
    let null_pos = path_bytes.iter().position(|&b| b == 0);

    let detected_truncated = null_pos.is_none();

    let end_idx = null_pos.unwrap_or(path_bytes.len());
    let path_slice = &path_bytes[..end_idx];

    let path_str = String::from_utf8_lossy(path_slice);

    if known_truncated || detected_truncated {
        format!("{:?} ... (truncated)", path_str)
    } else {
        format!("{:?}", path_str)
    }
}

pub fn old_format_stat(stat: &Stat) -> String {
    format!("{{ mode: {}, ino: {}, dev: {}, nlink: {}, uid: {}, gid: {}, size: {}, blksize: {}, blocks: {}, atime: {}, mtime: {}, ctime: {} }}",  
                format_mode(stat.st_mode),
                stat.st_ino,
                stat.st_dev,
                stat.st_nlink,
                stat.st_uid,
                stat.st_gid,
                stat.st_size,
                stat.st_blksize,
                stat.st_blocks,
                stat.st_atime,
                stat.st_mtime,
                stat.st_ctime,
    )
}

pub async fn format_stat(sf: &mut SyscallFormatter<'_>, stat: &Stat) -> anyhow::Result<()> {
    argf!(sf, "mode: {}", format_mode(stat.st_mode));
    argf!(sf, "ino: {}", stat.st_ino);
    argf!(sf, "dev: {}", stat.st_dev);
    argf!(sf, "nlink: {}", stat.st_nlink);
    argf!(sf, "uid: {}", stat.st_uid);
    argf!(sf, "gid: {}", stat.st_gid);
    argf!(sf, "size: {}", stat.st_size);
    argf!(sf, "blksize: {}", stat.st_blksize);
    argf!(sf, "blocks: {}", stat.st_blocks);
    argf!(sf, "atime: {}", stat.st_atime);
    argf!(sf, "mtime: {}", stat.st_mtime);
    argf!(sf, "ctime: {}", stat.st_ctime);
    Ok(())
}
pub fn old_format_timespec(timespec: Timespec) -> String {
    format!(
        "{{ secs: {}, nanos: {} }}",
        timespec.seconds, timespec.nanos
    )
}

pub async fn format_timespec(
    sf: &mut SyscallFormatter<'_>,
    timespec: Timespec,
) -> anyhow::Result<()> {
    with_struct!(sf, {
        argf!(sf, "secs: {}", timespec.seconds);
        argf!(sf, "nanos: {}", timespec.nanos);
    });
    Ok(())
}

pub fn format_bytes(bytes: &[u8]) -> String {
    if let Ok(s) = str::from_utf8(bytes) {
        format!("{:?}", s)
    } else {
        bytes
            .iter()
            .map(|b| format!("{:>2x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub fn format_dirfd(dfd: i32) -> String {
    const AT_FDCWD: i32 = -100;
    if dfd == AT_FDCWD {
        "AT_FDCWD".to_string()
    } else {
        dfd.to_string()
    }
}

pub fn format_mode(mode: u32) -> String {
    // Only show if nonzero (O_CREAT was used)
    if mode == 0 {
        return "0".to_string();
    }
    // Show as octal and symbolic (e.g. rwxr-xr-x)
    let mut s = format!("0o{:03o}", mode & 0o777);
    s.push_str(" (");
    let perms = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    for (bit, chr) in perms.iter() {
        s.push(if (mode & bit) != 0 { *chr } else { '-' });
    }
    s.push(')');
    s
}

pub fn format_flags(flags: i32) -> String {
    // Access mode (lowest two bits)
    let access = match flags & 0b11 {
        0 => "O_RDONLY",
        1 => "O_WRONLY",
        2 => "O_RDWR",
        _ => "<invalid>",
    };
    let mut parts = vec![access.to_string()];
    // Common open(2) flags
    let flag_defs = [
        (libc::O_CREAT, "O_CREAT"),
        (libc::O_EXCL, "O_EXCL"),
        (libc::O_NOCTTY, "O_NOCTTY"),
        (libc::O_TRUNC, "O_TRUNC"),
        (libc::O_APPEND, "O_APPEND"),
        (libc::O_NONBLOCK, "O_NONBLOCK"),
        (libc::O_SYNC, "O_SYNC"),
        (libc::O_DSYNC, "O_DSYNC"),
        (libc::O_RSYNC, "O_RSYNC"),
        (libc::O_DIRECTORY, "O_DIRECTORY"),
        (libc::O_NOFOLLOW, "O_NOFOLLOW"),
        (libc::O_CLOEXEC, "O_CLOEXEC"),
        (libc::O_ASYNC, "O_ASYNC"),
        (libc::O_LARGEFILE, "O_LARGEFILE"),
        (libc::O_DIRECT, "O_DIRECT"),
        (libc::O_TMPFILE, "O_TMPFILE"),
        (libc::O_PATH, "O_PATH"),
        (libc::O_NDELAY, "O_NDELAY"), // alias for O_NONBLOCK
        (libc::O_NOATIME, "O_NOATIME"),
    ];
    for (bit, name) in flag_defs.iter() {
        if (flags as u32) & (*bit as u32) != 0 {
            parts.push(name.to_string());
        }
    }
    format!("0x{:x} ({})", flags, parts.join("|"))
}

pub fn format_mmap_flags(flags: i32) -> String {
    let defs = [
        (libc::MAP_SHARED, "MAP_SHARED"),
        (libc::MAP_PRIVATE, "MAP_PRIVATE"),
        (libc::MAP_FIXED, "MAP_FIXED"),
        (libc::MAP_ANONYMOUS, "MAP_ANONYMOUS"),
        #[cfg(target_arch = "x86_64")]
        (libc::MAP_32BIT, "MAP_32BIT"),
        (libc::MAP_GROWSDOWN, "MAP_GROWSDOWN"),
        (libc::MAP_DENYWRITE, "MAP_DENYWRITE"),
        (libc::MAP_EXECUTABLE, "MAP_EXECUTABLE"),
        (libc::MAP_LOCKED, "MAP_LOCKED"),
        (libc::MAP_NORESERVE, "MAP_NORESERVE"),
        (libc::MAP_POPULATE, "MAP_POPULATE"),
        (libc::MAP_NONBLOCK, "MAP_NONBLOCK"),
        (libc::MAP_STACK, "MAP_STACK"),
        (libc::MAP_HUGETLB, "MAP_HUGETLB"),
        (libc::MAP_SYNC, "MAP_SYNC"),
        (libc::MAP_FIXED_NOREPLACE, "MAP_FIXED_NOREPLACE"),
    ];
    let mut parts = Vec::new();
    for (bit, name) in defs.iter() {
        if (flags as u32) & (*bit as u32) != 0 {
            parts.push(*name);
        }
    }
    if parts.is_empty() {
        format!("0x{:x}", flags)
    } else {
        format!("0x{:x} ({})", flags, parts.join("|"))
    }
}

pub fn format_mmap_prot(prot: i32) -> String {
    let defs = [
        (libc::PROT_READ, "PROT_READ"),
        (libc::PROT_WRITE, "PROT_WRITE"),
        (libc::PROT_EXEC, "PROT_EXEC"),
        (libc::PROT_NONE, "PROT_NONE"),
        (libc::PROT_GROWSDOWN, "PROT_GROWSDOWN"),
        (libc::PROT_GROWSUP, "PROT_GROWSUP"),
    ];
    let mut parts = Vec::new();
    for (bit, name) in defs.iter() {
        if (prot as u32) & (*bit as u32) != 0 {
            parts.push(*name);
        }
    }
    if parts.is_empty() {
        format!("0x{:x}", prot)
    } else {
        format!("0x{:x} ({})", prot, parts.join("|"))
    }
}

pub fn format_getrandom_flags(flags: u32) -> String {
    let defs = [
        (libc::GRND_NONBLOCK, "GRND_NONBLOCK"), // Don't block if no entropy available
        (libc::GRND_RANDOM, "GRND_RANDOM"),     // Use random source instead of urandom
        (libc::GRND_INSECURE, "GRND_INSECURE"), // Use uninitialized bytes for early boot
    ];
    let mut parts = Vec::new();
    for (bit, name) in defs.iter() {
        if flags & bit != 0 {
            parts.push(*name);
        }
    }
    if parts.is_empty() {
        format!("0x{:x}", flags)
    } else {
        format!("0x{:x} ({})", flags, parts.join("|"))
    }
}

// Constants for prctl operations not available in libc
const PR_SVE_SET_VL: i32 = 50;
const PR_SVE_GET_VL: i32 = 51;
const PR_GET_SPECULATION_CTRL: i32 = 52;
const PR_SET_SPECULATION_CTRL: i32 = 53;
const PR_SET_TAGGED_ADDR_CTRL: i32 = 55;
const PR_GET_TAGGED_ADDR_CTRL: i32 = 56;
const PR_SET_IO_FLUSHER: i32 = 57;
const PR_GET_IO_FLUSHER: i32 = 58;
const PR_SET_SYSCALL_USER_DISPATCH: i32 = 59;
const PR_PAC_SET_ENABLED_KEYS: i32 = 60;
const PR_PAC_GET_ENABLED_KEYS: i32 = 61;
const PR_SCHED_CORE: i32 = 62;
const PR_SME_SET_VL: i32 = 63;
const PR_SME_GET_VL: i32 = 64;
const PR_SET_MDWE: i32 = 65;
const PR_GET_MDWE: i32 = 66;
const PR_SET_VMA: i32 = 67;
const PR_GET_AUXV: i32 = 68;
const PR_RISCV_SET_ICACHE_FLUSH_CTX: i32 = 69;

/// Format prctl operation into human-readable string
pub fn format_prctl_op(op: i32) -> String {
    match op {
        // PR_* constants from libc
        libc::PR_SET_PDEATHSIG => "PR_SET_PDEATHSIG",
        libc::PR_GET_PDEATHSIG => "PR_GET_PDEATHSIG",
        libc::PR_GET_DUMPABLE => "PR_GET_DUMPABLE",
        libc::PR_SET_DUMPABLE => "PR_SET_DUMPABLE",
        libc::PR_GET_UNALIGN => "PR_GET_UNALIGN",
        libc::PR_SET_UNALIGN => "PR_SET_UNALIGN",
        libc::PR_GET_KEEPCAPS => "PR_GET_KEEPCAPS",
        libc::PR_SET_KEEPCAPS => "PR_SET_KEEPCAPS",
        libc::PR_GET_FPEMU => "PR_GET_FPEMU",
        libc::PR_SET_FPEMU => "PR_SET_FPEMU",
        libc::PR_GET_FPEXC => "PR_GET_FPEXC",
        libc::PR_SET_FPEXC => "PR_SET_FPEXC",
        libc::PR_GET_TIMING => "PR_GET_TIMING",
        libc::PR_SET_TIMING => "PR_SET_TIMING",
        libc::PR_SET_NAME => "PR_SET_NAME",
        libc::PR_GET_NAME => "PR_GET_NAME",
        libc::PR_GET_ENDIAN => "PR_GET_ENDIAN",
        libc::PR_SET_ENDIAN => "PR_SET_ENDIAN",
        libc::PR_GET_SECCOMP => "PR_GET_SECCOMP",
        libc::PR_SET_SECCOMP => "PR_SET_SECCOMP",
        libc::PR_CAPBSET_READ => "PR_CAPBSET_READ",
        libc::PR_CAPBSET_DROP => "PR_CAPBSET_DROP",
        libc::PR_GET_TSC => "PR_GET_TSC",
        libc::PR_SET_TSC => "PR_SET_TSC",
        libc::PR_GET_SECUREBITS => "PR_GET_SECUREBITS",
        libc::PR_SET_SECUREBITS => "PR_SET_SECUREBITS",
        libc::PR_SET_TIMERSLACK => "PR_SET_TIMERSLACK",
        libc::PR_GET_TIMERSLACK => "PR_GET_TIMERSLACK",
        libc::PR_TASK_PERF_EVENTS_DISABLE => "PR_TASK_PERF_EVENTS_DISABLE",
        libc::PR_TASK_PERF_EVENTS_ENABLE => "PR_TASK_PERF_EVENTS_ENABLE",
        libc::PR_MCE_KILL => "PR_MCE_KILL",
        libc::PR_MCE_KILL_GET => "PR_MCE_KILL_GET",
        libc::PR_SET_MM => "PR_SET_MM",
        libc::PR_GET_TID_ADDRESS => "PR_GET_TID_ADDRESS",
        libc::PR_SET_CHILD_SUBREAPER => "PR_SET_CHILD_SUBREAPER",
        libc::PR_GET_CHILD_SUBREAPER => "PR_GET_CHILD_SUBREAPER",
        libc::PR_SET_NO_NEW_PRIVS => "PR_SET_NO_NEW_PRIVS",
        libc::PR_GET_NO_NEW_PRIVS => "PR_GET_NO_NEW_PRIVS",
        libc::PR_GET_THP_DISABLE => "PR_GET_THP_DISABLE",
        libc::PR_SET_THP_DISABLE => "PR_SET_THP_DISABLE",
        libc::PR_MPX_ENABLE_MANAGEMENT => "PR_MPX_ENABLE_MANAGEMENT",
        libc::PR_MPX_DISABLE_MANAGEMENT => "PR_MPX_DISABLE_MANAGEMENT",
        libc::PR_SET_FP_MODE => "PR_SET_FP_MODE",
        libc::PR_GET_FP_MODE => "PR_GET_FP_MODE",
        libc::PR_CAP_AMBIENT => "PR_CAP_AMBIENT",
        #[cfg(target_arch = "aarch64")]
        libc::PR_PAC_RESET_KEYS => "PR_PAC_RESET_KEYS",
        // Constants not yet available in our libc version
        PR_SVE_SET_VL => "PR_SVE_SET_VL",
        PR_SVE_GET_VL => "PR_SVE_GET_VL",
        PR_GET_SPECULATION_CTRL => "PR_GET_SPECULATION_CTRL",
        PR_SET_SPECULATION_CTRL => "PR_SET_SPECULATION_CTRL",
        #[cfg(target_arch = "aarch64")]
        PR_SET_TAGGED_ADDR_CTRL => "PR_SET_TAGGED_ADDR_CTRL",
        #[cfg(target_arch = "aarch64")]
        PR_GET_TAGGED_ADDR_CTRL => "PR_GET_TAGGED_ADDR_CTRL",
        PR_SET_IO_FLUSHER => "PR_SET_IO_FLUSHER",
        PR_GET_IO_FLUSHER => "PR_GET_IO_FLUSHER",
        PR_SET_SYSCALL_USER_DISPATCH => "PR_SET_SYSCALL_USER_DISPATCH",
        #[cfg(target_arch = "aarch64")]
        PR_PAC_SET_ENABLED_KEYS => "PR_PAC_SET_ENABLED_KEYS",
        #[cfg(target_arch = "aarch64")]
        PR_PAC_GET_ENABLED_KEYS => "PR_PAC_GET_ENABLED_KEYS",
        PR_SCHED_CORE => "PR_SCHED_CORE",
        PR_SME_SET_VL => "PR_SME_SET_VL",
        PR_SME_GET_VL => "PR_SME_GET_VL",
        PR_SET_MDWE => "PR_SET_MDWE",
        PR_GET_MDWE => "PR_GET_MDWE",
        PR_SET_VMA => "PR_SET_VMA",
        PR_GET_AUXV => "PR_GET_AUXV",
        PR_RISCV_SET_ICACHE_FLUSH_CTX => "PR_RISCV_SET_ICACHE_FLUSH_CTX",
        _ => return format!("UNKNOWN (0x{:x})", op),
    }
    .to_string()
}

/// Get the number of arguments used by a prctl operation based on documentation
/// Different prctl operations take different numbers of arguments.
/// Note that some operations have unused arguments that are set to 0L.
pub fn prctl_op_arg_count(op: i32) -> usize {
    match op {
        // GET operations that take NO additional arguments (just the opcode)
        #[cfg(target_arch = "aarch64")]
        PR_PAC_GET_ENABLED_KEYS => 1,

        libc::PR_GET_DUMPABLE
        | libc::PR_GET_UNALIGN
        | libc::PR_GET_KEEPCAPS
        | libc::PR_GET_FPEMU
        | libc::PR_GET_FPEXC
        | libc::PR_GET_TIMING
        | libc::PR_GET_ENDIAN
        | libc::PR_GET_SECCOMP
        | libc::PR_GET_TSC
        | libc::PR_GET_SECUREBITS
        | libc::PR_GET_TIMERSLACK
        | libc::PR_MCE_KILL_GET
        | libc::PR_GET_CHILD_SUBREAPER
        | libc::PR_GET_NO_NEW_PRIVS
        | libc::PR_GET_THP_DISABLE
        | libc::PR_GET_FP_MODE
        | PR_SVE_GET_VL
        | PR_SME_GET_VL
        | PR_GET_MDWE => 1,

        // Operations that need a pointer to receive data (op + pointer)
        libc::PR_GET_NAME
        | libc::PR_GET_TID_ADDRESS
        | PR_GET_AUXV
        | libc::PR_GET_PDEATHSIG
        | PR_GET_TAGGED_ADDR_CTRL
        | PR_GET_IO_FLUSHER
        | PR_GET_SPECULATION_CTRL => 2,

        // Operations with an input parameter (op + param)
        libc::PR_CAPBSET_READ | libc::PR_CAPBSET_DROP => 2,

        // Task performance control operations
        libc::PR_TASK_PERF_EVENTS_DISABLE | libc::PR_TASK_PERF_EVENTS_ENABLE => 1,

        // PR_SET_MM has variable arguments depending on the suboperation
        libc::PR_SET_MM => 3, // op + sub_op + addr, though some use more

        // PR_SET_VMA requires 5 args
        PR_SET_VMA => 5,

        // Most SET operations take 2 arguments (op and value)
        #[cfg(target_arch = "aarch64")]
        PR_PAC_SET_ENABLED_KEYS | libc::PR_PAC_RESET_KEYS => 2,

        libc::PR_SET_PDEATHSIG
        | libc::PR_SET_DUMPABLE
        | libc::PR_SET_UNALIGN
        | libc::PR_SET_KEEPCAPS
        | libc::PR_SET_FPEMU
        | libc::PR_SET_FPEXC
        | libc::PR_SET_TIMING
        | libc::PR_SET_NAME
        | libc::PR_SET_ENDIAN
        | libc::PR_SET_TSC
        | libc::PR_SET_SECUREBITS
        | libc::PR_SET_TIMERSLACK
        | libc::PR_SET_CHILD_SUBREAPER
        | libc::PR_SET_NO_NEW_PRIVS
        | libc::PR_SET_THP_DISABLE
        | libc::PR_SET_FP_MODE
        | PR_SVE_SET_VL
        | PR_SET_SPECULATION_CTRL
        | PR_SET_TAGGED_ADDR_CTRL
        | PR_SET_IO_FLUSHER
        | PR_SCHED_CORE
        | PR_SME_SET_VL
        | PR_SET_MDWE
        | PR_RISCV_SET_ICACHE_FLUSH_CTX
        | libc::PR_MPX_ENABLE_MANAGEMENT
        | libc::PR_MPX_DISABLE_MANAGEMENT => 2,

        // PR_SET_SECCOMP takes different args depending on mode
        // Basic mode: 2 args, Filter mode: 3 args
        libc::PR_SET_SECCOMP => 3, // Conservatively show 3 args

        // PR_SET_SYSCALL_USER_DISPATCH takes 5 args
        PR_SET_SYSCALL_USER_DISPATCH => 5,

        // PR_CAP_AMBIENT requires sub-operation argument
        libc::PR_CAP_AMBIENT => 3, // op + sub_op + cap (if needed)

        // PR_MCE_KILL has 3 arguments total
        libc::PR_MCE_KILL => 3, // op + type + flags

        // Default to showing all 5 possible arguments when unsure
        _ => 5,
    }
}

/// Format filesystem type based on f_type value
pub fn format_fs_type(fs_type: i64) -> String {
    let type_name = match fs_type {
        0x0000002f => "QNX4_SUPER_MAGIC",
        0x00011954 => "UFS_MAGIC",
        0x0001aabb => "CRAMFS_MAGIC",
        0x0001dfc6 => "ROMFS_MAGIC",
        0x00414a53 => "EFS_SUPER_MAGIC",
        0x00c36400 => "CEPH_SUPER_MAGIC",
        0x01021994 => "TMPFS_MAGIC",
        0x01021997 => "V9FS_MAGIC",
        0x012ff7b4 => "XENIX_SUPER_MAGIC",
        0x012ff7b5 => "SYSV4_SUPER_MAGIC",
        0x012ff7b6 => "SYSV2_SUPER_MAGIC",
        0x012ff7b7 => "COH_SUPER_MAGIC",
        0x012fd16d => "XIAFS_SUPER_MAGIC",
        0x0187 => "AUTOFS_SUPER_MAGIC",
        0x01b6 => "VXFS_SUPER_MAGIC",
        0x02011994 => "BALLOON_KVM_MAGIC",
        0x02295a52 => "OCFS2_SUPER_MAGIC",
        0x023abcde => "CGROUP2_SUPER_MAGIC",
        0x0534d5f3 => "PPC_CMM_MAGIC",
        0x09041934 => "ANON_INODE_FS_MAGIC",
        0x0bad1dea => "FUTEXFS_SUPER_MAGIC",
        0x0bd00bd0 => "LUSTRE_SUPER_MAGIC",
        0x11307854 => "MTD_INODE_FS_MAGIC",
        0x13661366 => "BALLOON_MAGIC",
        0x137d => "EXT_SUPER_MAGIC",
        0x137f => "MINIX_SUPER_MAGIC",
        0x138f => "MINIX_SUPER_MAGIC2",
        0x1cd1 => "DEVPTS_SUPER_MAGIC",
        0x1c36400 => "CEPH_SUPER_MAGIC",
        0x1face => "FUSE_CTL_SUPER_MAGIC",
        0x1badface => "BFS_MAGIC",
        0x2468 => "MINIX2_SUPER_MAGIC",
        0x2478 => "MINIX2_SUPER_MAGIC2",
        0x27e0eb => "CGROUP_SUPER_MAGIC",
        0x28cd3d45 => "CRAMFS_MAGIC",
        0x3153464a => "JFS_SUPER_MAGIC",
        0x42465331 => "BEFS_SUPER_MAGIC",
        0x42494e4d => "BINFMTFS_MAGIC",
        0x4244 => "HFS_SUPER_MAGIC",
        0x4d44 => "MSDOS_SUPER_MAGIC",
        0x4d5a => "MINIX3_SUPER_MAGIC",
        0x517b => "SMB_SUPER_MAGIC",
        0x52654973 => "REISERFS_SUPER_MAGIC",
        0x534f434b => "SOCKFS_MAGIC",
        0x534f => "AX25_SUPER_MAGIC",
        0x5346544e => "NTFS_SB_MAGIC",
        0x5346414f => "AFS_SUPER_MAGIC",
        0x5a3c69f0 => "AAFS_MAGIC",
        0x58295829 => "XENFS_SUPER_MAGIC",
        0x58464552 => "XREFS_MAGIC",
        0x58465342 => "XFS_SUPER_MAGIC",
        0x5df5 => "OVERLAYFS_SUPER_MAGIC",
        0x61636673 => "ACFS_SUPER_MAGIC",
        0x6163 => "ASYNCFS_MAGIC",
        0x62646576 => "BDEVFS_MAGIC",
        0x62656570 => "CONFIGFS_MAGIC", // Added based on mount output
        0x62656572 => "SYSFS_MAGIC",
        0x63677270 => "CGROUP2_SUPER_MAGIC",
        0x64626720 => "DEBUGFS_MAGIC",
        0x65735546 => "FUSE_SUPER_MAGIC",
        0x676e6973 => "CONFIGFS_MAGIC",
        0x68191122 => "QNX6_SUPER_MAGIC",
        0x6969 => "NFS_SUPER_MAGIC",
        0x6165676c => "PSTORE_MAGIC",     // Added based on mount output
        0x73636673 => "SECURITYFS_MAGIC", // Added based on mount output
        0x73717368 => "SQUASHFS_MAGIC",
        0x73727279 => "BTRFS_TEST_MAGIC",
        0x73757245 => "CODA_SUPER_MAGIC",
        0x74726163 => "TRACEFS_MAGIC", // Added based on mount output
        0x7461636f => "OCFS2_SUPER_MAGIC",
        0x74736e6d => "NSFS_SUPER_MAGIC",
        0x794c7630 => "OVERLAYFS_SUPER_MAGIC",
        0x858458f6 => "RAMFS_MAGIC",
        0x9660 => "ISOFS_SUPER_MAGIC",
        0x9fa0 => "PROC_SUPER_MAGIC",
        0x9fa1 => "OPENPROM_SUPER_MAGIC",
        0x9fa2 => "USBDEVICE_SUPER_MAGIC",
        0x9123683e => "BTRFS_SUPER_MAGIC",
        0xadf5 => "ADFS_SUPER_MAGIC",
        0xadff => "AFFS_SUPER_MAGIC",
        0xabba1974 => "XENFS_SUPER_MAGIC",
        0xb550ca10 => "BTRFS_TEST_MAGIC",
        0xbacbacbc => "CGROUP_SUPER_MAGIC",
        0xcafe4a11 => "BPF_FS_MAGIC",
        0xcab007f5 => "DMA_BUF_MAGIC",
        0xc7578268 => "CGROUP2_SUPER_MAGIC",
        0xde5e81e4 => "EFIVARFS_MAGIC",
        0xef51 => "EXT2_OLD_SUPER_MAGIC",
        0xef53 => "EXT4_SUPER_MAGIC", // Also EXT2_SUPER_MAGIC, EXT3_SUPER_MAGIC
        0xf15f => "ECRYPTFS_SUPER_MAGIC",
        0xf2f52010 => "F2FS_SUPER_MAGIC",
        0xf97cff8c => "SELINUXFS_MAGIC", // Added based on mount output
        0xf995e849 => "HPFS_SUPER_MAGIC",
        0xfe534d42 => "SMB2_MAGIC_NUMBER",
        0xff534d42 => "CIFS_MAGIC_NUMBER",
        0x958458f6 => "HUGETLBFS_MAGIC", // Added based on mount output
        _ => return format!("UNKNOWN (0x{:x})", fs_type),
    };
    format!("{} (0x{:x})", type_name, fs_type)
}

/// Format mount flags from f_flags
pub fn format_mount_flags(flags: i64) -> String {
    let flag_defs = [
        (0x0001, "ST_RDONLY"),      // 1
        (0x0002, "ST_NOSUID"),      // 2
        (0x0004, "ST_NODEV"),       // 4
        (0x0008, "ST_NOEXEC"),      // 8
        (0x0010, "ST_SYNCHRONOUS"), // 16
        (0x0020, "ST_MANDLOCK"),    // 32
        (0x0040, "ST_WRITE"),       // 64
        (0x0080, "ST_APPEND"),      // 128
        (0x0100, "ST_IMMUTABLE"),   // 256
        (0x0200, "ST_NOATIME"),     // 512
        (0x0400, "ST_NODIRATIME"),  // 1024
        (0x0800, "ST_RELATIME"),    // 2048
        (0x1000, "ST_NOSYMFOLLOW"), // 4096
    ];

    let mut parts = Vec::new();
    for (bit, name) in flag_defs.iter() {
        if (flags as u64 & *bit as u64) != 0 {
            parts.push(*name);
        }
    }

    if parts.is_empty() {
        format!("0x{:x}", flags)
    } else {
        format!("0x{:x} ({})", flags, parts.join(" | "))
    }
}

/// Format statfs struct for display
pub fn old_format_statfs(statfs: &pinchy_common::kernel_types::Statfs) -> String {
    format!(
        "{{ type: {}, block_size: {}, blocks: {}, blocks_free: {}, blocks_available: {}, files: {}, files_free: {}, fsid: [{}, {}], name_max: {}, fragment_size: {}, mount_flags: {} }}",
        format_fs_type(statfs.f_type),
        statfs.f_bsize,
        statfs.f_blocks,
        statfs.f_bfree,
        statfs.f_bavail,
        statfs.f_files,
        statfs.f_ffree,
        statfs.f_fsid[0], statfs.f_fsid[1],
        statfs.f_namelen,
        statfs.f_frsize,
        format_mount_flags(statfs.f_flags)
    )
}

pub async fn format_statfs(
    sf: &mut SyscallFormatter<'_>,
    statfs: &pinchy_common::kernel_types::Statfs,
) -> anyhow::Result<()> {
    argf!(sf, "type: {}", format_fs_type(statfs.f_type));
    argf!(sf, "block_size: {}", statfs.f_bsize);
    argf!(sf, "blocks: {}", statfs.f_blocks);
    argf!(sf, "blocks_free: {}", statfs.f_bfree);
    argf!(sf, "blocks_available: {}", statfs.f_bavail);
    argf!(sf, "files: {}", statfs.f_files);
    argf!(sf, "files_free: {}", statfs.f_ffree);
    argf!(sf, "fsid: [{}, {}]", statfs.f_fsid[0], statfs.f_fsid[1]);
    argf!(sf, "name_max: {}", statfs.f_namelen);
    argf!(sf, "fragment_size: {}", statfs.f_frsize);
    argf!(sf, "mount_flags: {}", format_mount_flags(statfs.f_flags));
    Ok(())
}
