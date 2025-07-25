// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::borrow::Cow;

use pinchy_common::kernel_types::{Stat, Timespec};

use crate::{arg, argf, formatting::SyscallFormatter, raw, with_array, with_struct};

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
        format!("{path_str:?} ... (truncated)")
    } else {
        format!("{path_str:?}")
    }
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
        format!("{s:?}")
    } else {
        bytes
            .iter()
            .map(|b| format!("{b:>2x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub fn format_dirfd(dfd: i32) -> String {
    if dfd == libc::AT_FDCWD {
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

pub fn format_dup3_flags(flags: i32) -> String {
    if flags == 0 {
        return "0".to_string();
    }

    let mut parts = vec![];
    if flags & libc::O_CLOEXEC != 0 {
        parts.push("O_CLOEXEC");
    }

    if parts.is_empty() {
        format!("0x{flags:x}")
    } else {
        format!("0x{:x} ({})", flags, parts.join("|"))
    }
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
        format!("0x{flags:x}")
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
        format!("0x{prot:x}")
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
        format!("0x{flags:x}")
    } else {
        format!("0x{:x} ({})", flags, parts.join("|"))
    }
}

// Constants for madvise advice not available in libc or with different values
const MADV_WIPEONFORK: i32 = 18;
const MADV_KEEPONFORK: i32 = 19;
const MADV_COLD: i32 = 20;
const MADV_PAGEOUT: i32 = 21;
const MADV_POPULATE_READ: i32 = 22;
const MADV_POPULATE_WRITE: i32 = 23;

pub fn format_madvise_advice(advice: i32) -> String {
    let name = match advice {
        libc::MADV_NORMAL => "MADV_NORMAL",
        libc::MADV_RANDOM => "MADV_RANDOM",
        libc::MADV_SEQUENTIAL => "MADV_SEQUENTIAL",
        libc::MADV_WILLNEED => "MADV_WILLNEED",
        libc::MADV_DONTNEED => "MADV_DONTNEED",
        libc::MADV_FREE => "MADV_FREE",
        libc::MADV_REMOVE => "MADV_REMOVE",
        libc::MADV_DONTFORK => "MADV_DONTFORK",
        libc::MADV_DOFORK => "MADV_DOFORK",
        libc::MADV_MERGEABLE => "MADV_MERGEABLE",
        libc::MADV_UNMERGEABLE => "MADV_UNMERGEABLE",
        libc::MADV_HUGEPAGE => "MADV_HUGEPAGE",
        libc::MADV_NOHUGEPAGE => "MADV_NOHUGEPAGE",
        libc::MADV_DONTDUMP => "MADV_DONTDUMP",
        libc::MADV_DODUMP => "MADV_DODUMP",
        MADV_WIPEONFORK => "MADV_WIPEONFORK",
        MADV_KEEPONFORK => "MADV_KEEPONFORK",
        MADV_COLD => "MADV_COLD",
        MADV_PAGEOUT => "MADV_PAGEOUT",
        MADV_POPULATE_READ => "MADV_POPULATE_READ",
        MADV_POPULATE_WRITE => "MADV_POPULATE_WRITE",
        _ => return format!("UNKNOWN ({advice})"),
    };
    format!("{name} ({advice})")
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
#[cfg(target_arch = "aarch64")]
const PR_PAC_SET_ENABLED_KEYS: i32 = 60;
#[cfg(target_arch = "aarch64")]
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
        _ => return format!("UNKNOWN (0x{op:x})"),
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
        _ => return format!("UNKNOWN (0x{fs_type:x})"),
    };
    format!("{type_name} (0x{fs_type:x})")
}

/// Format mount flags from f_flags
pub fn format_mount_flags(flags: u64) -> String {
    const ST_NOSYMFOLLOW: u64 = 8192;
    let flag_defs = [
        (libc::ST_RDONLY, "ST_RDONLY"),
        (libc::ST_NOSUID, "ST_NOSUID"),
        (libc::ST_NODEV, "ST_NODEV"),
        (libc::ST_NOEXEC, "ST_NOEXEC"),
        (libc::ST_SYNCHRONOUS, "ST_SYNCHRONOUS"),
        (libc::ST_MANDLOCK, "ST_MANDLOCK"),
        (libc::ST_WRITE, "ST_WRITE"),
        (libc::ST_APPEND, "ST_APPEND"),
        (libc::ST_IMMUTABLE, "ST_IMMUTABLE"),
        (libc::ST_NOATIME, "ST_NOATIME"),
        (libc::ST_NODIRATIME, "ST_NODIRATIME"),
        (libc::ST_RELATIME, "ST_RELATIME"),
        (ST_NOSYMFOLLOW, "ST_NOSYMFOLLOW"),
    ];

    let mut parts = Vec::new();
    for (bit, name) in flag_defs.iter() {
        if (flags & *bit) != 0 {
            parts.push(*name);
        }
    }

    if parts.is_empty() {
        format!("0x{flags:x}")
    } else {
        format!("0x{:x} ({})", flags, parts.join("|"))
    }
}

/// Format statfs struct for display
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
    argf!(
        sf,
        "mount_flags: {}",
        format_mount_flags(statfs.f_flags as u64)
    );
    Ok(())
}

pub fn format_access_mode(mode: i32) -> String {
    match mode {
        libc::F_OK => "F_OK".to_string(),
        _ => {
            let mut parts = Vec::new();

            if mode & libc::R_OK != 0 {
                parts.push("R_OK");
            }
            if mode & libc::W_OK != 0 {
                parts.push("W_OK");
            }
            if mode & libc::X_OK != 0 {
                parts.push("X_OK");
            }

            if parts.is_empty() {
                format!("0x{mode:x}")
            } else {
                parts.join("|")
            }
        }
    }
}

/// Format AT_* flags used by *at syscalls (faccessat, newfstatat, etc.)
pub fn format_at_flags(flags: i32) -> String {
    if flags == 0 {
        return "0".to_string();
    }

    let mut parts = Vec::new();

    // Special value used for current working directory
    if flags & libc::AT_FDCWD == libc::AT_FDCWD {
        parts.push("AT_FDCWD");
    }

    // Common flags
    if flags & libc::AT_EACCESS != 0 {
        parts.push("AT_EACCESS");
    }
    if flags & libc::AT_SYMLINK_NOFOLLOW != 0 {
        parts.push("AT_SYMLINK_NOFOLLOW");
    }
    if flags & libc::AT_REMOVEDIR != 0 {
        parts.push("AT_REMOVEDIR");
    }
    if flags & libc::AT_SYMLINK_FOLLOW != 0 {
        parts.push("AT_SYMLINK_FOLLOW");
    }
    if flags & libc::AT_EMPTY_PATH != 0 {
        parts.push("AT_EMPTY_PATH");
    }

    // Less common flags
    const AT_NO_AUTOMOUNT: i32 = 0x800;
    if flags & AT_NO_AUTOMOUNT != 0 {
        parts.push("AT_NO_AUTOMOUNT");
    }

    // STATX related flags
    const AT_STATX_SYNC_TYPE: i32 = 0x6000;
    const AT_STATX_SYNC_AS_STAT: i32 = 0x0000;
    const AT_STATX_FORCE_SYNC: i32 = 0x2000;
    const AT_STATX_DONT_SYNC: i32 = 0x4000;

    // Extract STATX sync type
    let sync_type = flags & AT_STATX_SYNC_TYPE;
    match sync_type {
        AT_STATX_FORCE_SYNC => parts.push("AT_STATX_FORCE_SYNC"),
        AT_STATX_DONT_SYNC => parts.push("AT_STATX_DONT_SYNC"),
        AT_STATX_SYNC_AS_STAT => {
            // Only include this if other STATX flags are present
            if flags & AT_STATX_SYNC_TYPE != 0 {
                parts.push("AT_STATX_SYNC_AS_STAT");
            }
        }
        _ => {}
    }

    // Recursive flag
    const AT_RECURSIVE: i32 = 0x8000;
    if flags & AT_RECURSIVE != 0 {
        parts.push("AT_RECURSIVE");
    }

    if parts.is_empty() {
        format!("0x{flags:x}")
    } else {
        format!("{} (0x{flags:x})", parts.join("|"))
    }
}

// Formats a resource value for prlimit64 syscall
pub fn format_resource_type(resource: i32) -> Cow<'static, str> {
    match resource as u32 {
        libc::RLIMIT_CPU => Cow::Borrowed("RLIMIT_CPU"),
        libc::RLIMIT_FSIZE => Cow::Borrowed("RLIMIT_FSIZE"),
        libc::RLIMIT_DATA => Cow::Borrowed("RLIMIT_DATA"),
        libc::RLIMIT_STACK => Cow::Borrowed("RLIMIT_STACK"),
        libc::RLIMIT_CORE => Cow::Borrowed("RLIMIT_CORE"),
        libc::RLIMIT_RSS => Cow::Borrowed("RLIMIT_RSS"),
        libc::RLIMIT_NPROC => Cow::Borrowed("RLIMIT_NPROC"),
        libc::RLIMIT_NOFILE => Cow::Borrowed("RLIMIT_NOFILE"),
        libc::RLIMIT_MEMLOCK => Cow::Borrowed("RLIMIT_MEMLOCK"),
        libc::RLIMIT_AS => Cow::Borrowed("RLIMIT_AS"),
        libc::RLIMIT_LOCKS => Cow::Borrowed("RLIMIT_LOCKS"),
        libc::RLIMIT_SIGPENDING => Cow::Borrowed("RLIMIT_SIGPENDING"),
        libc::RLIMIT_MSGQUEUE => Cow::Borrowed("RLIMIT_MSGQUEUE"),
        libc::RLIMIT_NICE => Cow::Borrowed("RLIMIT_NICE"),
        libc::RLIMIT_RTPRIO => Cow::Borrowed("RLIMIT_RTPRIO"),
        libc::RLIMIT_RTTIME => Cow::Borrowed("RLIMIT_RTTIME"),
        _ => Cow::Owned(format!("UNKNOWN({resource})")),
    }
}

// Formats an rlimit value, handling the special RLIM_INFINITY case
pub fn format_rlimit_value(value: u64) -> Cow<'static, str> {
    if value == u64::MAX {
        Cow::Borrowed("RLIM_INFINITY")
    } else {
        Cow::Owned(value.to_string())
    }
}

/// Format rlimit struct for display
pub async fn format_rlimit(
    sf: &mut SyscallFormatter<'_>,
    rlimit: &pinchy_common::kernel_types::Rlimit,
) -> anyhow::Result<()> {
    argf!(sf, "rlim_cur: {}", format_rlimit_value(rlimit.rlim_cur));
    argf!(sf, "rlim_max: {}", format_rlimit_value(rlimit.rlim_max));
    Ok(())
}

// Formats rseq flags
pub fn format_rseq_flags(flags: i32) -> String {
    if flags == 0 {
        return "0".to_string();
    }

    // Define the RSEQ_FLAG constants as they are in linux/rseq.h
    let rseq_flag_unregister = 0x1;

    let mut flags_str = Vec::new();

    if flags & rseq_flag_unregister != 0 {
        flags_str.push("RSEQ_FLAG_UNREGISTER".to_string());
    }

    let remainder = flags & !(rseq_flag_unregister);
    if remainder != 0 {
        flags_str.push(format!("0x{remainder:x}"));
    }

    flags_str.join("|")
}

// Format the rseq cs flags
pub fn format_rseq_cs_flags(flags: u32) -> String {
    if flags == 0 {
        return "0".to_string();
    }

    // Define the RSEQ_CS_FLAG constants as they are in linux/rseq.h
    let rseq_cs_flag_no_restart_on_preempt = 0x1;
    let rseq_cs_flag_no_restart_on_signal = 0x2;
    let rseq_cs_flag_no_restart_on_migrate = 0x4;

    let mut flags_str = Vec::new();

    if flags & rseq_cs_flag_no_restart_on_preempt != 0 {
        flags_str.push("RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT".to_string());
    }
    if flags & rseq_cs_flag_no_restart_on_signal != 0 {
        flags_str.push("RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL".to_string());
    }
    if flags & rseq_cs_flag_no_restart_on_migrate != 0 {
        flags_str.push("RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE".to_string());
    }

    let remainder = flags
        & !(rseq_cs_flag_no_restart_on_preempt
            | rseq_cs_flag_no_restart_on_signal
            | rseq_cs_flag_no_restart_on_migrate);
    if remainder != 0 {
        flags_str.push(format!("0x{remainder:x}"));
    }

    flags_str.join("|")
}

/// Format rseq struct for display
pub async fn format_rseq(
    sf: &mut SyscallFormatter<'_>,
    rseq: &pinchy_common::kernel_types::Rseq,
    rseq_cs: Option<&pinchy_common::kernel_types::RseqCs>,
) -> anyhow::Result<()> {
    argf!(sf, "cpu_id_start: {}", rseq.cpu_id_start);
    argf!(
        sf,
        "cpu_id: {}",
        if rseq.cpu_id == u32::MAX {
            "-1".to_string()
        } else {
            rseq.cpu_id.to_string()
        }
    );
    if let Some(rseq_cs) = rseq_cs {
        arg!(sf, "rseq_cs:");
        with_struct!(sf, {
            format_rseq_cs(sf, rseq_cs).await?;
        });
    } else {
        arg!(sf, "rseq_cs: 0x0");
    }
    argf!(sf, "flags: {}", format_rseq_cs_flags(rseq.flags));
    argf!(sf, "node_id: {}", rseq.node_id);
    argf!(sf, "mm_cid: {}", rseq.mm_cid);
    Ok(())
}

/// Format rseq_cs struct for display
pub async fn format_rseq_cs(
    sf: &mut SyscallFormatter<'_>,
    rseq_cs: &pinchy_common::kernel_types::RseqCs,
) -> anyhow::Result<()> {
    argf!(sf, "version: {}", rseq_cs.version);
    argf!(sf, "flags: {}", format_rseq_cs_flags(rseq_cs.flags));
    argf!(sf, "start_ip: 0x{:x}", rseq_cs.start_ip);
    argf!(sf, "post_commit_offset: 0x{:x}", rseq_cs.post_commit_offset);
    argf!(sf, "abort_ip: 0x{:x}", rseq_cs.abort_ip);
    Ok(())
}

/// Extract a null-terminated string from a byte array with truncation detection
///
/// This helper handles the common pattern of reading C-style strings from eBPF
/// where the data might be truncated due to stack limits or buffer size constraints.
///
/// # Arguments
/// * `bytes` - The byte array to extract the string from
///
/// # Returns
/// A String with "... (truncated)" appended if truncation is detected
pub fn extract_cstring_with_truncation(bytes: &[u8]) -> String {
    let null_pos = bytes.iter().position(|&b| b == 0);

    match null_pos {
        Some(pos) => {
            // Found null terminator, extract the string up to that point
            let trimmed = &bytes[..pos];
            String::from_utf8_lossy(trimmed).into_owned()
        }
        None => {
            // No null terminator found - this indicates truncation
            let mut result = String::from_utf8_lossy(bytes).into_owned();
            result.push_str(" ... (truncated)");
            result
        }
    }
}

/// Format utsname struct for display
pub async fn format_utsname(
    sf: &mut SyscallFormatter<'_>,
    utsname: &pinchy_common::kernel_types::Utsname,
) -> anyhow::Result<()> {
    argf!(
        sf,
        "sysname: {:?}",
        extract_cstring_with_truncation(&utsname.sysname)
    );
    argf!(
        sf,
        "nodename: {:?}",
        extract_cstring_with_truncation(&utsname.nodename)
    );
    argf!(
        sf,
        "release: {:?}",
        extract_cstring_with_truncation(&utsname.release)
    );
    argf!(
        sf,
        "version: {:?}",
        extract_cstring_with_truncation(&utsname.version)
    );
    argf!(
        sf,
        "machine: {:?}",
        extract_cstring_with_truncation(&utsname.machine)
    );
    argf!(
        sf,
        "domainname: {:?}",
        extract_cstring_with_truncation(&utsname.domainname)
    );
    Ok(())
}

pub fn format_sigprocmask_how(how: i32) -> &'static str {
    match how {
        libc::SIG_BLOCK => "SIG_BLOCK",
        libc::SIG_UNBLOCK => "SIG_UNBLOCK",
        libc::SIG_SETMASK => "SIG_SETMASK",
        _ => "UNKNOWN",
    }
}

pub fn format_signal_number(signum: i32) -> Cow<'static, str> {
    match signum {
        libc::SIGHUP => Cow::Borrowed("SIGHUP"),
        libc::SIGINT => Cow::Borrowed("SIGINT"),
        libc::SIGQUIT => Cow::Borrowed("SIGQUIT"),
        libc::SIGILL => Cow::Borrowed("SIGILL"),
        libc::SIGTRAP => Cow::Borrowed("SIGTRAP"),
        libc::SIGABRT => Cow::Borrowed("SIGABRT"),
        libc::SIGBUS => Cow::Borrowed("SIGBUS"),
        libc::SIGFPE => Cow::Borrowed("SIGFPE"),
        libc::SIGKILL => Cow::Borrowed("SIGKILL"),
        libc::SIGUSR1 => Cow::Borrowed("SIGUSR1"),
        libc::SIGSEGV => Cow::Borrowed("SIGSEGV"),
        libc::SIGUSR2 => Cow::Borrowed("SIGUSR2"),
        libc::SIGPIPE => Cow::Borrowed("SIGPIPE"),
        libc::SIGALRM => Cow::Borrowed("SIGALRM"),
        libc::SIGTERM => Cow::Borrowed("SIGTERM"),
        libc::SIGSTKFLT => Cow::Borrowed("SIGSTKFLT"),
        libc::SIGCHLD => Cow::Borrowed("SIGCHLD"),
        libc::SIGCONT => Cow::Borrowed("SIGCONT"),
        libc::SIGSTOP => Cow::Borrowed("SIGSTOP"),
        libc::SIGTSTP => Cow::Borrowed("SIGTSTP"),
        libc::SIGTTIN => Cow::Borrowed("SIGTTIN"),
        libc::SIGTTOU => Cow::Borrowed("SIGTTOU"),
        libc::SIGURG => Cow::Borrowed("SIGURG"),
        libc::SIGXCPU => Cow::Borrowed("SIGXCPU"),
        libc::SIGXFSZ => Cow::Borrowed("SIGXFSZ"),
        libc::SIGVTALRM => Cow::Borrowed("SIGVTALRM"),
        libc::SIGPROF => Cow::Borrowed("SIGPROF"),
        libc::SIGWINCH => Cow::Borrowed("SIGWINCH"),
        libc::SIGIO => Cow::Borrowed("SIGIO"),
        libc::SIGPWR => Cow::Borrowed("SIGPWR"),
        libc::SIGSYS => Cow::Borrowed("SIGSYS"),
        _ => {
            if (34..=64).contains(&signum) {
                Cow::Owned(format!("SIGRT{}", signum - 34))
            } else {
                Cow::Owned(format!("UNKNOWN({signum})"))
            }
        }
    }
}

/// Format fcntl operation command into human-readable string
pub fn format_fcntl_cmd(cmd: i32) -> String {
    match cmd {
        // File descriptor duplication
        libc::F_DUPFD => "F_DUPFD".to_string(),
        libc::F_DUPFD_CLOEXEC => "F_DUPFD_CLOEXEC".to_string(),

        // File descriptor flags
        libc::F_GETFD => "F_GETFD".to_string(),
        libc::F_SETFD => "F_SETFD".to_string(),

        // File status flags
        libc::F_GETFL => "F_GETFL".to_string(),
        libc::F_SETFL => "F_SETFL".to_string(),

        // Advisory record locking
        libc::F_SETLK => "F_SETLK".to_string(),
        libc::F_SETLKW => "F_SETLKW".to_string(),
        libc::F_GETLK => "F_GETLK".to_string(),

        // Signal management
        libc::F_GETOWN => "F_GETOWN".to_string(),
        libc::F_SETOWN => "F_SETOWN".to_string(),

        // Linux-specific operations
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::F_SETLEASE => "F_SETLEASE".to_string(),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::F_GETLEASE => "F_GETLEASE".to_string(),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::F_NOTIFY => "F_NOTIFY".to_string(),

        _ => {
            // Handle additional Linux-specific commands not available in libc
            match cmd {
                // Signal management (Linux)
                8 => "F_GETSIG".to_string(),
                7 => "F_SETSIG".to_string(),

                // Extended signal management (Linux 2.6.32+)
                9 => "F_SETOWN_EX".to_string(),
                10 => "F_GETOWN_EX".to_string(),

                // Open file description locks (Linux 3.15+)
                14 => "F_OFD_GETLK".to_string(),
                15 => "F_OFD_SETLK".to_string(),
                16 => "F_OFD_SETLKW".to_string(),

                // Pipe capacity (Linux 2.6.35+)
                1031 => "F_SETPIPE_SZ".to_string(),
                1032 => "F_GETPIPE_SZ".to_string(),

                // File sealing (Linux 3.17+)
                1033 => "F_ADD_SEALS".to_string(),
                1034 => "F_GET_SEALS".to_string(),

                // Read/write hints (Linux 4.13+)
                1036 => "F_GET_RW_HINT".to_string(),
                1037 => "F_SET_RW_HINT".to_string(),
                1038 => "F_GET_FILE_RW_HINT".to_string(),
                1039 => "F_SET_FILE_RW_HINT".to_string(),

                _ => format!("0x{cmd:x}"),
            }
        }
    }
}

pub fn format_sendmsg_flags(flags: i32) -> String {
    let flag_defs = [
        (libc::MSG_CONFIRM, "MSG_CONFIRM"),
        (libc::MSG_DONTROUTE, "MSG_DONTROUTE"),
        (libc::MSG_DONTWAIT, "MSG_DONTWAIT"),
        (libc::MSG_EOR, "MSG_EOR"),
        (libc::MSG_MORE, "MSG_MORE"),
        (libc::MSG_NOSIGNAL, "MSG_NOSIGNAL"),
        (libc::MSG_OOB, "MSG_OOB"),
    ];

    let mut parts = Vec::new();
    let mut remaining_flags = flags;

    for (flag, name) in flag_defs.iter() {
        if (flags & flag) != 0 {
            parts.push(name.to_string());
            remaining_flags &= !flag;
        }
    }

    if remaining_flags != 0 {
        parts.push(format!("0x{remaining_flags:x}"));
    }

    if parts.is_empty() {
        "0".to_string()
    } else {
        format!("0x{:x} ({})", flags, parts.join("|"))
    }
}

pub fn format_recvmsg_flags(flags: i32) -> String {
    let flag_defs = [
        (libc::MSG_PEEK, "MSG_PEEK"),
        (libc::MSG_WAITALL, "MSG_WAITALL"),
        (libc::MSG_TRUNC, "MSG_TRUNC"),
        (libc::MSG_CTRUNC, "MSG_CTRUNC"),
        (libc::MSG_OOB, "MSG_OOB"),
        (libc::MSG_ERRQUEUE, "MSG_ERRQUEUE"),
        (libc::MSG_DONTWAIT, "MSG_DONTWAIT"),
        #[cfg(target_os = "linux")]
        (libc::MSG_CMSG_CLOEXEC, "MSG_CMSG_CLOEXEC"),
    ];

    let mut parts = Vec::new();
    let mut remaining_flags = flags;

    for (flag, name) in flag_defs.iter() {
        if (flags & flag) != 0 {
            parts.push(name.to_string());
            remaining_flags &= !flag;
        }
    }

    if remaining_flags != 0 {
        parts.push(format!("0x{remaining_flags:x}"));
    }

    if parts.is_empty() {
        "0".to_string()
    } else {
        format!("0x{:x} ({})", flags, parts.join("|"))
    }
}

pub fn format_accept4_flags(flags: i32) -> String {
    if flags == 0 {
        return "0".to_string();
    }

    let flag_defs = [
        (libc::SOCK_CLOEXEC, "SOCK_CLOEXEC"),
        (libc::SOCK_NONBLOCK, "SOCK_NONBLOCK"),
    ];

    let mut parts = Vec::new();
    let mut remaining_flags = flags;

    for (flag, name) in flag_defs.iter() {
        if (flags & flag) != 0 {
            parts.push(name.to_string());
            remaining_flags &= !flag;
        }
    }

    if remaining_flags != 0 {
        parts.push(format!("0x{remaining_flags:x}"));
    }

    if parts.is_empty() {
        "0".to_string()
    } else {
        format!("0x{:x} ({})", flags, parts.join("|"))
    }
}

pub fn format_socket_domain(domain: i32) -> Cow<'static, str> {
    match domain {
        libc::AF_UNIX => Cow::Borrowed("AF_UNIX"),
        libc::AF_INET => Cow::Borrowed("AF_INET"),
        libc::AF_INET6 => Cow::Borrowed("AF_INET6"),
        libc::AF_NETLINK => Cow::Borrowed("AF_NETLINK"),
        libc::AF_PACKET => Cow::Borrowed("AF_PACKET"),
        libc::AF_APPLETALK => Cow::Borrowed("AF_APPLETALK"),
        libc::AF_X25 => Cow::Borrowed("AF_X25"),
        _ => Cow::Owned(format!("{domain}")),
    }
}

pub fn format_socket_type(socket_type: i32) -> String {
    let base_type = socket_type & 0xFF; // Lower 8 bits are the base type
    let flags = socket_type & !0xFF; // Upper bits are flags

    let base_str = match base_type {
        libc::SOCK_STREAM => "SOCK_STREAM",
        libc::SOCK_DGRAM => "SOCK_DGRAM",
        libc::SOCK_SEQPACKET => "SOCK_SEQPACKET",
        libc::SOCK_RAW => "SOCK_RAW",
        libc::SOCK_RDM => "SOCK_RDM",
        _ => return format!("{socket_type}"),
    };

    let mut parts = vec![base_str];

    if flags & libc::SOCK_NONBLOCK != 0 {
        parts.push("SOCK_NONBLOCK");
    }
    if flags & libc::SOCK_CLOEXEC != 0 {
        parts.push("SOCK_CLOEXEC");
    }

    parts.join("|")
}

pub fn format_shutdown_how(how: i32) -> Cow<'static, str> {
    match how {
        libc::SHUT_RD => Cow::Borrowed("SHUT_RD"),
        libc::SHUT_WR => Cow::Borrowed("SHUT_WR"),
        libc::SHUT_RDWR => Cow::Borrowed("SHUT_RDWR"),
        _ => Cow::Owned(format!("{how}")),
    }
}

pub fn format_sockaddr_family(family: u16) -> Cow<'static, str> {
    match family {
        x if x == (libc::AF_UNIX as u16) => Cow::Borrowed("AF_UNIX"),
        x if x == (libc::AF_INET as u16) => Cow::Borrowed("AF_INET"),
        x if x == (libc::AF_INET6 as u16) => Cow::Borrowed("AF_INET6"),
        x if x == (libc::AF_NETLINK as u16) => Cow::Borrowed("AF_NETLINK"),
        x if x == (libc::AF_PACKET as u16) => Cow::Borrowed("AF_PACKET"),
        _ => Cow::Owned(format!("{family}")),
    }
}

pub async fn format_sockaddr(
    sf: &mut SyscallFormatter<'_>,
    addr: &pinchy_common::kernel_types::Sockaddr,
) -> anyhow::Result<()> {
    argf!(sf, "family: {}", format_sockaddr_family(addr.sa_family));

    match addr.sa_family {
        x if x == (libc::AF_INET as u16) => {
            // sockaddr_in: port (2 bytes) + IPv4 address (4 bytes)
            if addr.sa_data.len() >= 6 {
                let port = u16::from_be_bytes([addr.sa_data[0], addr.sa_data[1]]);
                let ip_bytes = &addr.sa_data[2..6];
                argf!(
                    sf,
                    "addr: {}:{}",
                    format!(
                        "{}.{}.{}.{}",
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                    ),
                    port
                );
            } else {
                argf!(sf, "addr: <truncated>");
            }
        }
        x if x == (libc::AF_INET6 as u16) => {
            // sockaddr_in6: port (2 bytes) + flowinfo (4 bytes) + IPv6 address (16 bytes) + scope_id (4 bytes)
            if addr.sa_data.len() >= 6 {
                let port = u16::from_be_bytes([addr.sa_data[0], addr.sa_data[1]]);
                let flowinfo = u32::from_be_bytes([
                    addr.sa_data[2],
                    addr.sa_data[3],
                    addr.sa_data[4],
                    addr.sa_data[5],
                ]);

                if addr.sa_data.len() >= 22 {
                    // We have enough data for the IPv6 address
                    let ipv6_bytes = &addr.sa_data[6..22];
                    let mut ipv6_parts = Vec::new();
                    for chunk in ipv6_bytes.chunks(2) {
                        if chunk.len() == 2 {
                            let part = u16::from_be_bytes([chunk[0], chunk[1]]);
                            ipv6_parts.push(format!("{part:x}"));
                        }
                    }
                    argf!(sf, "addr: [{}]:{}", ipv6_parts.join(":"), port);
                    if flowinfo != 0 {
                        argf!(sf, "flowinfo: {}", flowinfo);
                    }
                } else {
                    argf!(sf, "addr: <truncated IPv6>:{}", port);
                }
            } else {
                argf!(sf, "addr: <truncated>");
            }
        }
        x if x == (libc::AF_UNIX as u16) => {
            // sockaddr_un: filesystem path (null-terminated string)
            let path_bytes = &addr.sa_data;
            let null_pos = path_bytes.iter().position(|&b| b == 0);
            let path_end = null_pos.unwrap_or(path_bytes.len());
            let path = String::from_utf8_lossy(&path_bytes[..path_end]);

            if path.is_empty() {
                argf!(sf, "path: <unnamed>");
            } else if null_pos.is_none() {
                argf!(sf, "path: {:?} ... (truncated)", path);
            } else {
                argf!(sf, "path: {:?}", path);
            }
        }
        x if x == (libc::AF_NETLINK as u16) => {
            // sockaddr_nl: nl_pid (4 bytes) + nl_groups (4 bytes)
            if addr.sa_data.len() >= 8 {
                let pid = u32::from_le_bytes([
                    addr.sa_data[0],
                    addr.sa_data[1],
                    addr.sa_data[2],
                    addr.sa_data[3],
                ]);
                let groups = u32::from_le_bytes([
                    addr.sa_data[4],
                    addr.sa_data[5],
                    addr.sa_data[6],
                    addr.sa_data[7],
                ]);
                argf!(sf, "pid: {}", pid);
                argf!(sf, "groups: 0x{:x}", groups);
            } else {
                argf!(sf, "data: <truncated>");
            }
        }
        x if x == (libc::AF_PACKET as u16) => {
            // sockaddr_ll: protocol, ifindex, hatype, pkttype, halen, addr
            if addr.sa_data.len() >= 8 {
                let protocol = u16::from_be_bytes([addr.sa_data[0], addr.sa_data[1]]);
                let ifindex = i32::from_le_bytes([
                    addr.sa_data[2],
                    addr.sa_data[3],
                    addr.sa_data[4],
                    addr.sa_data[5],
                ]);

                if addr.sa_data.len() >= 10 {
                    let hatype = u16::from_le_bytes([addr.sa_data[6], addr.sa_data[7]]);
                    let pkttype = addr.sa_data[8];
                    let halen = addr.sa_data[9];

                    argf!(sf, "protocol: 0x{:x}", protocol);
                    argf!(sf, "ifindex: {}", ifindex);
                    argf!(sf, "hatype: {}", hatype);
                    argf!(sf, "pkttype: {}", pkttype);

                    if halen > 0 && addr.sa_data.len() >= (10 + halen as usize) {
                        let hw_addr = &addr.sa_data[10..(10 + halen as usize)];
                        let hw_str = hw_addr
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(":");
                        argf!(sf, "addr: {}", hw_str);
                    }
                } else {
                    argf!(sf, "protocol: 0x{:x}", protocol);
                    argf!(sf, "ifindex: {}", ifindex);
                    argf!(sf, "data: <truncated>");
                }
            } else {
                argf!(sf, "data: <truncated>");
            }
        }
        _ => {
            // Unknown/unsupported address family - show raw data
            argf!(sf, "data: {}", format_bytes(&addr.sa_data));
        }
    }

    Ok(())
}

pub async fn format_msghdr(
    sf: &mut SyscallFormatter<'_>,
    msg: &pinchy_common::kernel_types::Msghdr,
) -> anyhow::Result<()> {
    // Format name/address
    if msg.has_name {
        argf!(
            sf,
            "name: {{family: {}, len: {}}}",
            format_sockaddr_family(msg.name.sa_family),
            msg.msg_namelen
        );
    } else if msg.msg_name != 0 {
        argf!(
            sf,
            "name: {{ptr: 0x{:x}, len: {}}}",
            msg.msg_name,
            msg.msg_namelen
        );
    } else {
        arg!(sf, "name: NULL");
    }

    // Format iovec array
    if msg.msg_iovlen > 0 {
        arg!(sf, "iov:");
        with_array!(sf, {
            let iov_count = std::cmp::min(
                msg.msg_iovlen as usize,
                pinchy_common::kernel_types::MSG_IOV_COUNT,
            );
            for i in 0..iov_count {
                let iov = &msg.msg_iov[i];
                if iov.iov_base != 0 || iov.iov_len != 0 {
                    with_struct!(sf, {
                        argf!(sf, "base: 0x{:x}", iov.iov_base);
                        argf!(sf, "len: {}", iov.iov_len);
                    });
                }
            }
            if msg.msg_iovlen as usize > pinchy_common::kernel_types::MSG_IOV_COUNT {
                arg!(sf, "...");
            }
        });
        argf!(sf, "iovlen: {}", msg.msg_iovlen);
    } else {
        arg!(sf, "iov: NULL");
        argf!(sf, "iovlen: {}", msg.msg_iovlen);
    }

    // Format control data
    if msg.msg_control != 0 && msg.msg_controllen > 0 {
        argf!(
            sf,
            "control: {{ptr: 0x{:x}, len: {}}}",
            msg.msg_control,
            msg.msg_controllen
        );
    } else {
        arg!(sf, "control: NULL");
    }

    // Format flags
    if msg.msg_flags != 0 {
        argf!(sf, "flags: {}", format_recvmsg_flags(msg.msg_flags));
    } else {
        arg!(sf, "flags: 0");
    }

    Ok(())
}

pub fn format_wait_options(options: i32) -> String {
    if options == 0 {
        return "0".to_string();
    }

    let mut flags = vec![];

    if options & libc::WNOHANG != 0 {
        flags.push("WNOHANG");
    }

    if options & libc::WUNTRACED != 0 {
        flags.push("WUNTRACED");
    }

    if options & libc::WCONTINUED != 0 {
        flags.push("WCONTINUED");
    }

    if flags.is_empty() {
        format!("{options}")
    } else {
        flags.join("|")
    }
}

pub fn format_wait_status(status: i32) -> String {
    if libc::WIFEXITED(status) {
        let exit_code = libc::WEXITSTATUS(status);
        format!("{{WIFEXITED(s) && WEXITSTATUS(s) == {exit_code}}}")
    } else if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        let signal_name = format_signal_number(signal);
        if libc::WCOREDUMP(status) {
            format!("{{WIFSIGNALED(s) && WTERMSIG(s) == {signal_name} && WCOREDUMP(s)}}")
        } else {
            format!("{{WIFSIGNALED(s) && WTERMSIG(s) == {signal_name}}}")
        }
    } else if libc::WIFSTOPPED(status) {
        let signal = libc::WSTOPSIG(status);
        let signal_name = format_signal_number(signal);
        format!("{{WIFSTOPPED(s) && WSTOPSIG(s) == {signal_name}}}")
    } else if libc::WIFCONTINUED(status) {
        "{WIFCONTINUED(s)}".to_string()
    } else {
        format!("{status}")
    }
}

pub async fn format_rusage(
    sf: &mut SyscallFormatter<'_>,
    rusage: &pinchy_common::kernel_types::Rusage,
) -> anyhow::Result<()> {
    arg!(sf, "ru_utime:");
    with_struct!(sf, {
        argf!(sf, "tv_sec: {}", rusage.ru_utime.tv_sec);
        argf!(sf, "tv_usec: {}", rusage.ru_utime.tv_usec);
    });

    arg!(sf, "ru_stime:");
    with_struct!(sf, {
        argf!(sf, "tv_sec: {}", rusage.ru_stime.tv_sec);
        argf!(sf, "tv_usec: {}", rusage.ru_stime.tv_usec);
    });

    argf!(sf, "ru_maxrss: {}", rusage.ru_maxrss);
    argf!(sf, "ru_ixrss: {}", rusage.ru_ixrss);
    argf!(sf, "ru_idrss: {}", rusage.ru_idrss);
    argf!(sf, "ru_isrss: {}", rusage.ru_isrss);
    argf!(sf, "ru_minflt: {}", rusage.ru_minflt);
    argf!(sf, "ru_majflt: {}", rusage.ru_majflt);
    argf!(sf, "ru_nswap: {}", rusage.ru_nswap);
    argf!(sf, "ru_inblock: {}", rusage.ru_inblock);
    argf!(sf, "ru_oublock: {}", rusage.ru_oublock);
    argf!(sf, "ru_msgsnd: {}", rusage.ru_msgsnd);
    argf!(sf, "ru_msgrcv: {}", rusage.ru_msgrcv);
    argf!(sf, "ru_nsignals: {}", rusage.ru_nsignals);
    argf!(sf, "ru_nvcsw: {}", rusage.ru_nvcsw);
    argf!(sf, "ru_nivcsw: {}", rusage.ru_nivcsw);

    Ok(())
}

pub fn format_rusage_who(who: i32) -> &'static str {
    match who {
        libc::RUSAGE_SELF => "RUSAGE_SELF",
        libc::RUSAGE_CHILDREN => "RUSAGE_CHILDREN",
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::RUSAGE_THREAD => "RUSAGE_THREAD",
        _ => "UNKNOWN",
    }
}

pub fn format_clone_flags(flags: u64) -> String {
    let flag_defs = [
        (libc::CLONE_VM as u64, "CLONE_VM"),
        (libc::CLONE_FS as u64, "CLONE_FS"),
        (libc::CLONE_FILES as u64, "CLONE_FILES"),
        (libc::CLONE_SIGHAND as u64, "CLONE_SIGHAND"),
        (libc::CLONE_PIDFD as u64, "CLONE_PIDFD"),
        (libc::CLONE_PTRACE as u64, "CLONE_PTRACE"),
        (libc::CLONE_VFORK as u64, "CLONE_VFORK"),
        (libc::CLONE_PARENT as u64, "CLONE_PARENT"),
        (libc::CLONE_THREAD as u64, "CLONE_THREAD"),
        (libc::CLONE_NEWNS as u64, "CLONE_NEWNS"),
        (libc::CLONE_SYSVSEM as u64, "CLONE_SYSVSEM"),
        (libc::CLONE_SETTLS as u64, "CLONE_SETTLS"),
        (libc::CLONE_PARENT_SETTID as u64, "CLONE_PARENT_SETTID"),
        (libc::CLONE_CHILD_CLEARTID as u64, "CLONE_CHILD_CLEARTID"),
        (libc::CLONE_DETACHED as u64, "CLONE_DETACHED"),
        (libc::CLONE_UNTRACED as u64, "CLONE_UNTRACED"),
        (libc::CLONE_CHILD_SETTID as u64, "CLONE_CHILD_SETTID"),
        (libc::CLONE_NEWCGROUP as u64, "CLONE_NEWCGROUP"),
        (libc::CLONE_NEWUTS as u64, "CLONE_NEWUTS"),
        (libc::CLONE_NEWIPC as u64, "CLONE_NEWIPC"),
        (libc::CLONE_NEWUSER as u64, "CLONE_NEWUSER"),
        (libc::CLONE_NEWPID as u64, "CLONE_NEWPID"),
        (libc::CLONE_NEWNET as u64, "CLONE_NEWNET"),
        (libc::CLONE_IO as u64, "CLONE_IO"),
        (libc::CLONE_CLEAR_SIGHAND as u64, "CLONE_CLEAR_SIGHAND"),
        (libc::CLONE_INTO_CGROUP as u64, "CLONE_INTO_CGROUP"),
    ];

    let mut parts = Vec::new();
    let mut remaining_flags = flags;

    for (flag, name) in flag_defs.iter() {
        if (flags & flag) != 0 {
            parts.push(name.to_string());
            remaining_flags &= !flag;
        }
    }

    // Extract the exit signal (lower 8 bits)
    let exit_signal = flags & 0xff;
    if exit_signal != 0 {
        match exit_signal {
            17 => parts.push("SIGCHLD".to_string()), // Most common case
            _ => parts.push(format!("exit_signal={exit_signal}")),
        }
        remaining_flags &= !0xff; // Remove exit signal bits from remaining
    }

    if remaining_flags != 0 {
        parts.push(format!("0x{remaining_flags:x}"));
    }

    if parts.is_empty() {
        "0".to_string()
    } else {
        format!("0x{:x} ({})", flags, parts.join("|"))
    }
}

pub async fn format_xattr_list(
    sf: &mut crate::formatting::SyscallFormatter<'_>,
    xattr_list: &pinchy_common::kernel_types::XattrList,
) -> anyhow::Result<()> {
    let mut start = 0;
    with_array!(sf, {
        for i in 0..xattr_list.size {
            if xattr_list.data[i] == 0 {
                if start < i {
                    argf!(
                        sf,
                        "{}",
                        String::from_utf8_lossy(&xattr_list.data[start..i])
                    );
                }
                start = i + 1;
            }
        }
    });
    Ok(())
}

/// Formats return values with meaningful interpretation based on syscall type and value
/// Format the `which` parameter for getpriority/setpriority syscalls
pub fn format_priority_which(which: u32) -> Cow<'static, str> {
    match which {
        libc::PRIO_PROCESS => Cow::Borrowed("PRIO_PROCESS"),
        libc::PRIO_PGRP => Cow::Borrowed("PRIO_PGRP"),
        libc::PRIO_USER => Cow::Borrowed("PRIO_USER"),
        _ => Cow::Owned(format!("UNKNOWN({which})")),
    }
}

/// Format timeval structure for display
pub async fn format_timeval(
    sf: &mut SyscallFormatter<'_>,
    tv: &pinchy_common::kernel_types::Timeval,
) -> anyhow::Result<()> {
    argf!(sf, "tv_sec: {}", tv.tv_sec);
    argf!(sf, "tv_usec: {}", tv.tv_usec);
    Ok(())
}

/// Format fd_set structure for display
pub async fn format_fdset(
    sf: &mut SyscallFormatter<'_>,
    fdset: &pinchy_common::kernel_types::FdSet,
) -> anyhow::Result<()> {
    if fdset.len == 0 {
        raw!(sf, " []");
    } else {
        // Decode the bitmap to extract set file descriptors
        let mut set_fds = Vec::new();

        for byte_idx in 0..(fdset.len as usize) {
            let byte = fdset.bytes[byte_idx];
            for bit_idx in 0..8 {
                if byte & (1 << bit_idx) != 0 {
                    let fd = byte_idx * 8 + bit_idx;
                    set_fds.push(fd as i32);
                }
            }
        }

        with_array!(sf, {
            for fd in set_fds {
                argf!(sf, "{}", fd);
            }
        });
    }
    Ok(())
}

/// Format timezone structure for display
pub async fn format_timezone(
    sf: &mut SyscallFormatter<'_>,
    tz: &pinchy_common::kernel_types::Timezone,
) -> anyhow::Result<()> {
    argf!(sf, "tz_minuteswest: {}", tz.tz_minuteswest);
    argf!(sf, "tz_dsttime: {}", tz.tz_dsttime);
    Ok(())
}

/// Format sysinfo structure for display
pub async fn format_sysinfo(
    sf: &mut SyscallFormatter<'_>,
    info: &pinchy_common::kernel_types::Sysinfo,
) -> anyhow::Result<()> {
    argf!(sf, "uptime: {} seconds", info.uptime);
    argf!(
        sf,
        "loads: [{}, {}, {}]",
        info.loads[0],
        info.loads[1],
        info.loads[2]
    );

    // Convert memory values to human-readable format
    let mem_unit = if info.mem_unit > 0 {
        info.mem_unit as u64
    } else {
        1
    };
    let total_ram_mb = (info.totalram * mem_unit) / (1024 * 1024);
    let free_ram_mb = (info.freeram * mem_unit) / (1024 * 1024);
    let shared_ram_mb = (info.sharedram * mem_unit) / (1024 * 1024);
    let buffer_ram_mb = (info.bufferram * mem_unit) / (1024 * 1024);
    let total_swap_mb = (info.totalswap * mem_unit) / (1024 * 1024);
    let free_swap_mb = (info.freeswap * mem_unit) / (1024 * 1024);

    argf!(sf, "totalram: {} MB", total_ram_mb);
    argf!(sf, "freeram: {} MB", free_ram_mb);
    argf!(sf, "sharedram: {} MB", shared_ram_mb);
    argf!(sf, "bufferram: {} MB", buffer_ram_mb);
    argf!(sf, "totalswap: {} MB", total_swap_mb);
    argf!(sf, "freeswap: {} MB", free_swap_mb);
    argf!(sf, "procs: {}", info.procs);
    argf!(sf, "mem_unit: {} bytes", info.mem_unit);
    Ok(())
}

/// Format tms structure for display
pub async fn format_tms(
    sf: &mut SyscallFormatter<'_>,
    tms: &pinchy_common::kernel_types::Tms,
) -> anyhow::Result<()> {
    argf!(sf, "tms_utime: {} ticks", tms.tms_utime);
    argf!(sf, "tms_stime: {} ticks", tms.tms_stime);
    argf!(sf, "tms_cutime: {} ticks", tms.tms_cutime);
    argf!(sf, "tms_cstime: {} ticks", tms.tms_cstime);
    Ok(())
}

pub fn format_sched_policy(policy: i32) -> Cow<'static, str> {
    match policy {
        libc::SCHED_OTHER => Cow::Borrowed("SCHED_OTHER"),
        libc::SCHED_FIFO => Cow::Borrowed("SCHED_FIFO"),
        libc::SCHED_RR => Cow::Borrowed("SCHED_RR"),
        #[cfg(target_os = "linux")]
        libc::SCHED_BATCH => Cow::Borrowed("SCHED_BATCH"),
        #[cfg(target_os = "linux")]
        libc::SCHED_IDLE => Cow::Borrowed("SCHED_IDLE"),
        #[cfg(target_os = "linux")]
        libc::SCHED_DEADLINE => Cow::Borrowed("SCHED_DEADLINE"),
        _ => Cow::Owned(policy.to_string()),
    }
}

pub fn format_return_value(syscall_nr: i64, return_value: i64) -> std::borrow::Cow<'static, str> {
    use pinchy_common::syscalls;

    // Handle the common error case first
    if return_value == -1 {
        return std::borrow::Cow::Borrowed("-1 (error)");
    }

    match syscall_nr {
        // File descriptor returning syscalls - show success with fd number
        syscalls::SYS_openat
        | syscalls::SYS_dup
        | syscalls::SYS_dup3
        | syscalls::SYS_socket
        | syscalls::SYS_accept
        | syscalls::SYS_accept4
        | syscalls::SYS_epoll_create1
        | syscalls::SYS_signalfd4
        | syscalls::SYS_eventfd2
        | syscalls::SYS_timerfd_create
        | syscalls::SYS_memfd_create
        | syscalls::SYS_userfaultfd => {
            if return_value >= 0 {
                std::borrow::Cow::Owned(format!("{return_value} (fd)"))
            } else {
                std::borrow::Cow::Owned(format!("{return_value} (error)"))
            }
        }

        // File descriptor returning syscalls - show success with fd number
        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_open
        | syscalls::SYS_creat
        | syscalls::SYS_dup2
        | syscalls::SYS_epoll_create
        | syscalls::SYS_signalfd
        | syscalls::SYS_eventfd => {
            if return_value >= 0 {
                std::borrow::Cow::Owned(format!("{} (fd)", return_value))
            } else {
                std::borrow::Cow::Owned(format!("{} (error)", return_value))
            }
        }

        // Byte count returning syscalls - show success with byte count
        syscalls::SYS_read
        | syscalls::SYS_write
        | syscalls::SYS_pread64
        | syscalls::SYS_pwrite64
        | syscalls::SYS_readv
        | syscalls::SYS_writev
        | syscalls::SYS_preadv
        | syscalls::SYS_pwritev
        | syscalls::SYS_splice
        | syscalls::SYS_tee
        | syscalls::SYS_vmsplice
        | syscalls::SYS_recvmsg
        | syscalls::SYS_sendmsg
        | syscalls::SYS_recvfrom
        | syscalls::SYS_sendto => {
            if return_value >= 0 {
                std::borrow::Cow::Owned(format!("{return_value} (bytes)"))
            } else {
                std::borrow::Cow::Owned(format!("{return_value} (error)"))
            }
        }

        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_sendfile => {
            if return_value >= 0 {
                std::borrow::Cow::Owned(format!("{} (bytes)", return_value))
            } else {
                std::borrow::Cow::Owned(format!("{} (error)", return_value))
            }
        }

        // Boolean-like syscalls - 0 for success, non-zero for error
        syscalls::SYS_faccessat
        | syscalls::SYS_fchmod
        | syscalls::SYS_fchmodat
        | syscalls::SYS_fchown
        | syscalls::SYS_fchownat
        | syscalls::SYS_close
        | syscalls::SYS_fsync
        | syscalls::SYS_fdatasync
        | syscalls::SYS_sync
        | syscalls::SYS_syncfs
        | syscalls::SYS_truncate
        | syscalls::SYS_ftruncate
        | syscalls::SYS_mkdirat
        | syscalls::SYS_unlinkat
        | syscalls::SYS_linkat
        | syscalls::SYS_symlinkat
        | syscalls::SYS_renameat
        | syscalls::SYS_renameat2
        | syscalls::SYS_fstat
        | syscalls::SYS_newfstatat
        | syscalls::SYS_setuid
        | syscalls::SYS_setgid
        | syscalls::SYS_close_range
        | syscalls::SYS_setpgid
        | syscalls::SYS_vhangup
        | syscalls::SYS_ioprio_set
        | syscalls::SYS_setregid
        | syscalls::SYS_setresgid
        | syscalls::SYS_setresuid
        | syscalls::SYS_setreuid
        | syscalls::SYS_personality
        | syscalls::SYS_sysinfo
        | syscalls::SYS_gettimeofday
        | syscalls::SYS_settimeofday
        | syscalls::SYS_setpriority
        | syscalls::SYS_sched_setscheduler
        | syscalls::SYS_bind
        | syscalls::SYS_listen
        | syscalls::SYS_connect
        | syscalls::SYS_shutdown => match return_value {
            0 => std::borrow::Cow::Borrowed("0 (success)"),
            _ => std::borrow::Cow::Owned(format!("{return_value} (error)")),
        },

        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_pause => match return_value {
            0 => std::borrow::Cow::Borrowed("0 (success)"),
            _ => std::borrow::Cow::Owned(format!("{return_value} (error)")),
        },

        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_access
        | syscalls::SYS_chmod
        | syscalls::SYS_chown
        | syscalls::SYS_lchown
        | syscalls::SYS_mkdir
        | syscalls::SYS_rmdir
        | syscalls::SYS_unlink
        | syscalls::SYS_link
        | syscalls::SYS_symlink
        | syscalls::SYS_rename
        | syscalls::SYS_stat
        | syscalls::SYS_lstat => match return_value {
            0 => std::borrow::Cow::Borrowed("0 (success)"),
            _ => std::borrow::Cow::Owned(format!("{} (error)", return_value)),
        },

        // Count returning syscalls - special handling for poll/select family
        syscalls::SYS_pselect6 => match return_value {
            0 => std::borrow::Cow::Borrowed("0 (timeout)"),
            n if n > 0 => std::borrow::Cow::Owned(format!("{n} (ready)")),
            _ => std::borrow::Cow::Owned(format!("{return_value} (error)")),
        },

        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_poll | syscalls::SYS_select => match return_value {
            0 => std::borrow::Cow::Borrowed("0 (timeout)"),
            n if n > 0 => std::borrow::Cow::Owned(format!("{} (ready)", n)),
            _ => std::borrow::Cow::Owned(format!("{} (error)", return_value)),
        },

        // ppoll gets special handling with detailed ready state - handled in events.rs
        syscalls::SYS_ppoll => {
            // This syscall needs custom formatting in events.rs, so return empty for now
            // The events.rs handler will override this with the extra parameter
            match return_value {
                0 => std::borrow::Cow::Borrowed("0 (timeout)"),
                -1 => std::borrow::Cow::Borrowed("-1 (error)"),
                _ => std::borrow::Cow::Owned(format!("{return_value} (ready)")),
            }
        }

        // PID returning syscalls
        syscalls::SYS_getpid
        | syscalls::SYS_getppid
        | syscalls::SYS_gettid
        | syscalls::SYS_clone
        | syscalls::SYS_clone3
        | syscalls::SYS_setsid
        | syscalls::SYS_getpgid
        | syscalls::SYS_getsid => {
            if return_value >= 0 {
                std::borrow::Cow::Owned(format!("{return_value} (pid)"))
            } else {
                std::borrow::Cow::Owned(format!("{return_value} (error)"))
            }
        }

        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_getpgrp => {
            if return_value >= 0 {
                std::borrow::Cow::Owned(format!("{return_value} (pid)"))
            } else {
                std::borrow::Cow::Owned(format!("{return_value} (error)"))
            }
        }

        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_fork | syscalls::SYS_vfork => {
            if return_value >= 0 {
                std::borrow::Cow::Owned(format!("{} (pid)", return_value))
            } else {
                std::borrow::Cow::Owned(format!("{} (error)", return_value))
            }
        }

        // UID/GID returning syscalls
        syscalls::SYS_getuid
        | syscalls::SYS_geteuid
        | syscalls::SYS_getgid
        | syscalls::SYS_getegid => {
            if return_value >= 0 {
                std::borrow::Cow::Owned(format!("{return_value} (id)"))
            } else {
                std::borrow::Cow::Owned(format!("{return_value} (error)"))
            }
        }

        // Memory address returning syscalls
        syscalls::SYS_mmap | syscalls::SYS_mremap => {
            if return_value == -1 {
                std::borrow::Cow::Borrowed("-1 (error)")
            } else {
                std::borrow::Cow::Owned(format!("0x{return_value:x} (addr)"))
            }
        }

        // brk returns the new program break address
        syscalls::SYS_brk => std::borrow::Cow::Owned(format!("0x{return_value:x}")),

        // Memory/protection syscalls that return 0 on success
        syscalls::SYS_munmap
        | syscalls::SYS_mprotect
        | syscalls::SYS_madvise
        | syscalls::SYS_nanosleep
        | syscalls::SYS_clock_nanosleep => match return_value {
            0 => std::borrow::Cow::Borrowed("0 (success)"),
            _ => std::borrow::Cow::Owned(format!("{return_value} (error)")),
        },

        // Syscalls that always succeed or have no meaningful return interpretation
        syscalls::SYS_rt_sigreturn
        | syscalls::SYS_sched_yield
        | syscalls::SYS_umask
        | syscalls::SYS_ioprio_get
        | syscalls::SYS_times
        | syscalls::SYS_getpriority => std::borrow::Cow::Owned(return_value.to_string()),

        #[cfg(target_arch = "x86_64")]
        syscalls::SYS_alarm => std::borrow::Cow::Owned(return_value.to_string()),

        // Process-related syscalls - show success or error
        syscalls::SYS_kill
        | syscalls::SYS_tkill
        | syscalls::SYS_tgkill
        | syscalls::SYS_exit
        | syscalls::SYS_exit_group => match return_value {
            0 => std::borrow::Cow::Borrowed("0 (success)"),
            _ => std::borrow::Cow::Owned(format!("{return_value} (error)")),
        },

        // Default case - just show the raw value with error indication if negative
        _ => {
            if return_value < 0 {
                std::borrow::Cow::Owned(format!("{return_value} (error)"))
            } else {
                std::borrow::Cow::Owned(return_value.to_string())
            }
        }
    }
}

pub fn format_clockid(clockid: i32) -> Cow<'static, str> {
    match clockid {
        libc::CLOCK_REALTIME => Cow::Borrowed("CLOCK_REALTIME"),
        libc::CLOCK_MONOTONIC => Cow::Borrowed("CLOCK_MONOTONIC"),
        libc::CLOCK_PROCESS_CPUTIME_ID => Cow::Borrowed("CLOCK_PROCESS_CPUTIME_ID"),
        libc::CLOCK_THREAD_CPUTIME_ID => Cow::Borrowed("CLOCK_THREAD_CPUTIME_ID"),
        #[cfg(target_os = "linux")]
        libc::CLOCK_MONOTONIC_RAW => Cow::Borrowed("CLOCK_MONOTONIC_RAW"),
        #[cfg(target_os = "linux")]
        libc::CLOCK_REALTIME_COARSE => Cow::Borrowed("CLOCK_REALTIME_COARSE"),
        #[cfg(target_os = "linux")]
        libc::CLOCK_MONOTONIC_COARSE => Cow::Borrowed("CLOCK_MONOTONIC_COARSE"),
        #[cfg(target_os = "linux")]
        libc::CLOCK_BOOTTIME => Cow::Borrowed("CLOCK_BOOTTIME"),
        #[cfg(target_os = "linux")]
        libc::CLOCK_REALTIME_ALARM => Cow::Borrowed("CLOCK_REALTIME_ALARM"),
        #[cfg(target_os = "linux")]
        libc::CLOCK_BOOTTIME_ALARM => Cow::Borrowed("CLOCK_BOOTTIME_ALARM"),
        _ => Cow::Owned(format!("{clockid}")),
    }
}

pub fn format_clock_nanosleep_flags(flags: i32) -> &'static str {
    match flags {
        0 => "0",
        libc::TIMER_ABSTIME => "TIMER_ABSTIME",
        _ => "UNKNOWN",
    }
}

pub fn format_renameat2_flags(flags: u32) -> String {
    let mut parts = Vec::new();

    if flags & libc::RENAME_NOREPLACE != 0 {
        parts.push("RENAME_NOREPLACE");
    }

    if flags & libc::RENAME_EXCHANGE != 0 {
        parts.push("RENAME_EXCHANGE");
    }

    if flags & libc::RENAME_WHITEOUT != 0 {
        parts.push("RENAME_WHITEOUT");
    }

    if parts.is_empty() {
        format!("0x{flags:x}")
    } else {
        format!("0x{:x} ({})", flags, parts.join(" | "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_sched_policy() {
        // Test known policies
        assert_eq!(format_sched_policy(libc::SCHED_OTHER), "SCHED_OTHER");
        assert_eq!(format_sched_policy(libc::SCHED_FIFO), "SCHED_FIFO");
        assert_eq!(format_sched_policy(libc::SCHED_RR), "SCHED_RR");

        // Test unknown policy
        assert_eq!(format_sched_policy(999), "999");
    }
}
