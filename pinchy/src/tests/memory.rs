// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    syscalls::{
        SYS_brk, SYS_madvise, SYS_membarrier, SYS_memfd_secret, SYS_mlock, SYS_mlock2,
        SYS_mlockall, SYS_mmap, SYS_mprotect, SYS_mremap, SYS_msync, SYS_munlock, SYS_munlockall, SYS_munmap,
        SYS_pkey_alloc, SYS_pkey_free, SYS_process_madvise, SYS_readahead, SYS_userfaultfd,
    },
    SyscallEvent,
};

use crate::syscall_test;

// PKEY constants not available in libc crate
const PKEY_DISABLE_ACCESS: u32 = 0x1;
const PKEY_DISABLE_WRITE: u32 = 0x2;

syscall_test!(
    parse_mmap_success,
    {
        use pinchy_common::MmapData;
        SyscallEvent {
            syscall_nr: SYS_mmap,
            pid: 66,
            tid: 66,
            return_value: 0x7f1234567000,
            data: pinchy_common::SyscallEventData {
                mmap: MmapData {
                    addr: 0,
                    length: 4096,
                    prot: libc::PROT_READ | libc::PROT_WRITE,
                    flags: libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    fd: -1,
                    offset: 0,
                },
            },
        }
    },
    "66 mmap(addr: 0x0, length: 4096, prot: 0x3 (PROT_READ|PROT_WRITE), flags: 0x22 (MAP_PRIVATE|MAP_ANONYMOUS), fd: -1, offset: 0x0) = 0x7f1234567000 (addr)\n"
);

syscall_test!(
    parse_mmap_error,
    {
        use pinchy_common::MmapData;
        SyscallEvent {
            syscall_nr: SYS_mmap,
            pid: 66,
            tid: 66,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                mmap: MmapData {
                    addr: 0x7f0000000000,
                    length: 8192,
                    prot: libc::PROT_EXEC,
                    flags: libc::MAP_SHARED,
                    fd: 5,
                    offset: 4096,
                },
            },
        }
    },
    "66 mmap(addr: 0x7f0000000000, length: 8192, prot: 0x4 (PROT_EXEC), flags: 0x1 (MAP_SHARED), fd: 5, offset: 0x1000) = -1 (error)\n"
);

syscall_test!(
    parse_munmap_success,
    {
        use pinchy_common::MunmapData;
        SyscallEvent {
            syscall_nr: SYS_munmap,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                munmap: MunmapData {
                    addr: 0xffff8a9c2000,
                    length: 57344,
                },
            },
        }
    },
    "123 munmap(addr: 0xffff8a9c2000, length: 57344) = 0 (success)\n"
);

syscall_test!(
    parse_munmap_error,
    {
        use pinchy_common::MunmapData;
        SyscallEvent {
            syscall_nr: SYS_munmap,
            pid: 123,
            tid: 123,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                munmap: MunmapData {
                    addr: 0xffff8a9c2000,
                    length: 57344,
                },
            },
        }
    },
    "123 munmap(addr: 0xffff8a9c2000, length: 57344) = -1 (error)\n"
);

syscall_test!(
    parse_mprotect_success,
    {
        use pinchy_common::MprotectData;
        SyscallEvent {
            syscall_nr: SYS_mprotect,
            pid: 77,
            tid: 77,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                mprotect: MprotectData {
                    addr: 0x7f5678901000,
                    length: 8192,
                    prot: libc::PROT_READ | libc::PROT_EXEC,
                },
            },
        }
    },
    "77 mprotect(addr: 0x7f5678901000, length: 8192, prot: 0x5 (PROT_READ|PROT_EXEC)) = 0 (success)\n"
);

syscall_test!(
    parse_mprotect_error,
    {
        use pinchy_common::MprotectData;
        SyscallEvent {
            syscall_nr: SYS_mprotect,
            pid: 77,
            tid: 77,
            return_value: -22,
            data: pinchy_common::SyscallEventData {
                mprotect: MprotectData {
                    addr: 0x1000,
                    length: 4096,
                    prot: libc::PROT_WRITE,
                },
            },
        }
    },
    "77 mprotect(addr: 0x1000, length: 4096, prot: 0x2 (PROT_WRITE)) = -22 (error)\n"
);

syscall_test!(
    parse_brk_new_addr,
    {
        use pinchy_common::BrkData;
        SyscallEvent {
            syscall_nr: SYS_brk,
            pid: 888,
            tid: 888,
            return_value: 0x7f1234570000,
            data: pinchy_common::SyscallEventData {
                brk: BrkData {
                    addr: 0x7f1234560000,
                },
            },
        }
    },
    "888 brk(addr: 0x7f1234560000) = 0x7f1234570000\n"
);

syscall_test!(
    parse_brk_null_addr,
    {
        use pinchy_common::BrkData;
        SyscallEvent {
            syscall_nr: SYS_brk,
            pid: 888,
            tid: 888,
            return_value: 0x7f1234500000,
            data: pinchy_common::SyscallEventData {
                brk: BrkData { addr: 0 },
            },
        }
    },
    "888 brk(addr: 0x0) = 0x7f1234500000\n"
);

syscall_test!(
    parse_madvise_success,
    {
        use pinchy_common::MadviseData;
        SyscallEvent {
            syscall_nr: SYS_madvise,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                madvise: MadviseData {
                    addr: 0x7f1234567000,
                    length: 4096,
                    advice: libc::MADV_DONTNEED,
                },
            },
        }
    },
    "123 madvise(addr: 0x7f1234567000, length: 4096, advice: MADV_DONTNEED (4)) = 0 (success)\n"
);

syscall_test!(
    parse_madvise_error,
    {
        use pinchy_common::MadviseData;
        SyscallEvent {
            syscall_nr: SYS_madvise,
            pid: 456,
            tid: 456,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                madvise: MadviseData {
                    addr: 0x0,
                    length: 4096,
                    advice: libc::MADV_WILLNEED,
                },
            },
        }
    },
    "456 madvise(addr: 0x0, length: 4096, advice: MADV_WILLNEED (3)) = -1 (error)\n"
);

syscall_test!(
    parse_madvise_unknown_advice,
    {
        use pinchy_common::MadviseData;
        SyscallEvent {
            syscall_nr: SYS_madvise,
            pid: 789,
            tid: 789,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                madvise: MadviseData {
                    addr: 0x7f1234567000,
                    length: 8192,
                    advice: 999,
                },
            },
        }
    },
    "789 madvise(addr: 0x7f1234567000, length: 8192, advice: UNKNOWN (999)) = 0 (success)\n"
);

syscall_test!(
    parse_process_madvise_success,
    {
        use pinchy_common::ProcessMadviseData;
        SyscallEvent {
            syscall_nr: SYS_process_madvise,
            pid: 123,
            tid: 123,
            return_value: 4096,
            data: pinchy_common::SyscallEventData {
                process_madvise: ProcessMadviseData {
                    pidfd: 5,
                    iovecs: [
                        pinchy_common::kernel_types::Iovec {
                            iov_base: 0x7f1234567000,
                            iov_len: 4096,
                        },
                        pinchy_common::kernel_types::Iovec::default(),
                    ],
                    iov_lens: [4096, 0],
                    iov_bufs: [[0; pinchy_common::MEDIUM_READ_SIZE]; pinchy_common::IOV_COUNT],
                    iovcnt: 1,
                    advice: libc::MADV_DONTNEED,
                    flags: 0,
                    read_count: 1,
                },
            },
        }
    },
    "123 process_madvise(pidfd: 5, iov: [ iovec { base: 0x7f1234567000, len: 4096 } ], iovcnt: 1, advice: MADV_DONTNEED (4), flags: 0) = 4096 (bytes)\n"
);

syscall_test!(
    parse_process_madvise_error,
    {
        use pinchy_common::ProcessMadviseData;
        SyscallEvent {
            syscall_nr: SYS_process_madvise,
            pid: 456,
            tid: 456,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                process_madvise: ProcessMadviseData {
                    pidfd: 9,
                    iovecs: [
                        pinchy_common::kernel_types::Iovec {
                            iov_base: 0x7f9876543000,
                            iov_len: 8192,
                        },
                        pinchy_common::kernel_types::Iovec::default(),
                    ],
                    iov_lens: [8192, 0],
                    iov_bufs: [[0; pinchy_common::MEDIUM_READ_SIZE]; pinchy_common::IOV_COUNT],
                    iovcnt: 1,
                    advice: libc::MADV_WILLNEED,
                    flags: 0,
                    read_count: 1,
                },
            },
        }
    },
    "456 process_madvise(pidfd: 9, iov: [ iovec { base: 0x7f9876543000, len: 8192 } ], iovcnt: 1, advice: MADV_WILLNEED (3), flags: 0) = -1 (error)\n"
);

syscall_test!(
    parse_mlock_success,
    {
        use pinchy_common::MlockData;
        SyscallEvent {
            syscall_nr: SYS_mlock,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                mlock: MlockData {
                    addr: 0x7f1234567000,
                    len: 4096,
                },
            },
        }
    },
    "123 mlock(addr: 0x7f1234567000, len: 4096) = 0 (success)\n"
);

syscall_test!(
    parse_mlock2_success,
    {
        use pinchy_common::Mlock2Data;
        SyscallEvent {
            syscall_nr: SYS_mlock2,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                mlock2: Mlock2Data {
                    addr: 0x7f1234567000,
                    len: 8192,
                    flags: libc::MLOCK_ONFAULT as i32,
                },
            },
        }
    },
    "123 mlock2(addr: 0x7f1234567000, len: 8192, flags: 0x1 (MLOCK_ONFAULT)) = 0 (success)\n"
);

syscall_test!(
    parse_mlockall_success,
    {
        use pinchy_common::MlockallData;
        SyscallEvent {
            syscall_nr: SYS_mlockall,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                mlockall: MlockallData {
                    flags: libc::MCL_CURRENT | libc::MCL_FUTURE,
                },
            },
        }
    },
    "123 mlockall(flags: 0x3 (MCL_CURRENT|MCL_FUTURE)) = 0 (success)\n"
);

syscall_test!(
    parse_munlock_success,
    {
        use pinchy_common::MunlockData;
        SyscallEvent {
            syscall_nr: SYS_munlock,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                munlock: MunlockData {
                    addr: 0x7f1234567000,
                    len: 4096,
                },
            },
        }
    },
    "123 munlock(addr: 0x7f1234567000, len: 4096) = 0 (success)\n"
);

syscall_test!(
    parse_munlockall_success,
    {
        use pinchy_common::MunlockallData;
        SyscallEvent {
            syscall_nr: SYS_munlockall,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                munlockall: MunlockallData,
            },
        }
    },
    "123 munlockall() = 0 (success)\n"
);

syscall_test!(
    parse_munlockall_error,
    {
        use pinchy_common::MunlockallData;
        SyscallEvent {
            syscall_nr: SYS_munlockall,
            pid: 456,
            tid: 456,
            return_value: -1,
            data: pinchy_common::SyscallEventData {
                munlockall: MunlockallData,
            },
        }
    },
    "456 munlockall() = -1 (error)\n"
);

syscall_test!(
    parse_mremap_success,
    {
        use pinchy_common::MremapData;
        SyscallEvent {
            syscall_nr: SYS_mremap,
            pid: 123,
            tid: 123,
            return_value: 0x7f9876543000,
            data: pinchy_common::SyscallEventData {
                mremap: MremapData {
                    old_address: 0x7f1234567000,
                    old_size: 4096,
                    new_size: 8192,
                    flags: libc::MREMAP_MAYMOVE,
                },
            },
        }
    },
    "123 mremap(old_address: 0x7f1234567000, old_size: 4096, new_size: 8192, flags: 0x1 (MREMAP_MAYMOVE)) = 0x7f9876543000 (addr)\n"
);

syscall_test!(
    parse_msync_success,
    {
        use pinchy_common::MsyncData;
        SyscallEvent {
            syscall_nr: SYS_msync,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                msync: MsyncData {
                    addr: 0x7f1234567000,
                    length: 4096,
                    flags: libc::MS_SYNC,
                },
            },
        }
    },
    "123 msync(addr: 0x7f1234567000, length: 4096, flags: 0x4 (MS_SYNC)) = 0 (success)\n"
);

syscall_test!(
    parse_membarrier_success,
    {
        use pinchy_common::MembarrierData;
        SyscallEvent {
            syscall_nr: SYS_membarrier,
            pid: 123,
            tid: 123,
            return_value: 127, // Supported commands bitmask
            data: pinchy_common::SyscallEventData {
                membarrier: MembarrierData {
                    cmd: libc::MEMBARRIER_CMD_QUERY,
                    flags: 0,
                },
            },
        }
    },
    "123 membarrier(cmd: MEMBARRIER_CMD_QUERY, flags: 0) = 127 (bitmask)\n"
);

syscall_test!(
    parse_readahead_success,
    {
        use pinchy_common::ReadaheadData;
        SyscallEvent {
            syscall_nr: SYS_readahead,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                readahead: ReadaheadData {
                    fd: 5,
                    offset: 1024,
                    count: 4096,
                },
            },
        }
    },
    "123 readahead(fd: 5, offset: 1024, count: 4096) = 0 (success)\n"
);

syscall_test!(
    parse_memfd_secret_success,
    {
        use pinchy_common::MemfdSecretData;
        SyscallEvent {
            syscall_nr: SYS_memfd_secret,
            pid: 123,
            tid: 123,
            return_value: 8,
            data: pinchy_common::SyscallEventData {
                memfd_secret: MemfdSecretData {
                    flags: libc::FD_CLOEXEC as u32,
                },
            },
        }
    },
    "123 memfd_secret(flags: 0x1 (FD_CLOEXEC)) = 8 (fd)\n"
);

syscall_test!(
    parse_userfaultfd_success,
    {
        use pinchy_common::UserfaultfdData;
        SyscallEvent {
            syscall_nr: SYS_userfaultfd,
            pid: 123,
            tid: 123,
            return_value: 9,
            data: pinchy_common::SyscallEventData {
                userfaultfd: UserfaultfdData {
                    flags: (libc::O_CLOEXEC | libc::O_NONBLOCK) as u32,
                },
            },
        }
    },
    "123 userfaultfd(flags: 0x80800 (O_CLOEXEC|O_NONBLOCK)) = 9 (fd)\n"
);

syscall_test!(
    parse_pkey_alloc_success,
    {
        use pinchy_common::PkeyAllocData;
        SyscallEvent {
            syscall_nr: SYS_pkey_alloc,
            pid: 123,
            tid: 123,
            return_value: 1,
            data: pinchy_common::SyscallEventData {
                pkey_alloc: PkeyAllocData {
                    flags: 0,
                    access_rights: PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE,
                },
            },
        }
    },
    "123 pkey_alloc(flags: 0, access_rights: 0x3 (PKEY_DISABLE_ACCESS|PKEY_DISABLE_WRITE)) = 1 (pkey)\n"
);

syscall_test!(
    parse_pkey_free_success,
    {
        use pinchy_common::PkeyFreeData;
        SyscallEvent {
            syscall_nr: SYS_pkey_free,
            pid: 123,
            tid: 123,
            return_value: 0,
            data: pinchy_common::SyscallEventData {
                pkey_free: PkeyFreeData { pkey: 1 },
            },
        }
    },
    "123 pkey_free(pkey: 1) = 0 (success)\n"
);
