// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    kernel_types::Iovec,
    syscalls::{
        SYS_brk, SYS_get_mempolicy, SYS_madvise, SYS_mbind, SYS_membarrier, SYS_memfd_create,
        SYS_memfd_secret, SYS_migrate_pages, SYS_mincore, SYS_mlock, SYS_mlock2, SYS_mlockall,
        SYS_mmap, SYS_move_pages, SYS_mprotect, SYS_mremap, SYS_mseal, SYS_msync, SYS_munlock,
        SYS_munlockall, SYS_munmap, SYS_pkey_alloc, SYS_pkey_free, SYS_pkey_mprotect,
        SYS_process_madvise, SYS_process_vm_readv, SYS_process_vm_writev, SYS_readahead,
        SYS_remap_file_pages, SYS_set_mempolicy, SYS_set_mempolicy_home_node, SYS_userfaultfd,
    },
    IOV_COUNT, LARGER_READ_SIZE,
};

use crate::syscall_test;

// PKEY constants not available in libc crate
const PKEY_DISABLE_ACCESS: u32 = 0x1;
const PKEY_DISABLE_WRITE: u32 = 0x2;

syscall_test!(
    parse_mmap_success,
    {

        use pinchy_common::MmapData;

        let data = MmapData {
                    addr: 0,
                    length: 4096,
                    prot: libc::PROT_READ | libc::PROT_WRITE,
                    flags: libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    fd: -1,
                    offset: 0,
                };

        crate::tests::make_compact_test_data(SYS_mmap, 66, 0x7f1234567000, &data)
    },
    "66 mmap(addr: 0x0, length: 4096, prot: 0x3 (PROT_READ|PROT_WRITE), flags: 0x22 (MAP_PRIVATE|MAP_ANONYMOUS), fd: -1, offset: 0x0) = 0x7f1234567000 (addr)\n"
);

syscall_test!(
    parse_mmap_error,
    {

        use pinchy_common::MmapData;

        let data = MmapData {
                    addr: 0x7f0000000000,
                    length: 8192,
                    prot: libc::PROT_EXEC,
                    flags: libc::MAP_SHARED,
                    fd: 5,
                    offset: 4096,
                };

        crate::tests::make_compact_test_data(SYS_mmap, 66, -1, &data)
    },
    "66 mmap(addr: 0x7f0000000000, length: 8192, prot: 0x4 (PROT_EXEC), flags: 0x1 (MAP_SHARED), fd: 5, offset: 0x1000) = -1 (error)\n"
);

syscall_test!(
    parse_munmap_success,
    {
        use pinchy_common::MunmapData;

        let data = MunmapData {
            addr: 0xffff8a9c2000,
            length: 57344,
        };

        crate::tests::make_compact_test_data(SYS_munmap, 123, 0, &data)
    },
    "123 munmap(addr: 0xffff8a9c2000, length: 57344) = 0 (success)\n"
);

syscall_test!(
    parse_munmap_error,
    {
        use pinchy_common::MunmapData;

        let data = MunmapData {
            addr: 0xffff8a9c2000,
            length: 57344,
        };

        crate::tests::make_compact_test_data(SYS_munmap, 123, -1, &data)
    },
    "123 munmap(addr: 0xffff8a9c2000, length: 57344) = -1 (error)\n"
);

syscall_test!(
    parse_mprotect_success,
    {

        use pinchy_common::MprotectData;

        let data = MprotectData {
                    addr: 0x7f5678901000,
                    length: 8192,
                    prot: libc::PROT_READ | libc::PROT_EXEC,
                };

        crate::tests::make_compact_test_data(SYS_mprotect, 77, 0, &data)
    },
    "77 mprotect(addr: 0x7f5678901000, length: 8192, prot: 0x5 (PROT_READ|PROT_EXEC)) = 0 (success)\n"
);

syscall_test!(
    parse_mprotect_error,
    {
        use pinchy_common::MprotectData;

        let data = MprotectData {
            addr: 0x1000,
            length: 4096,
            prot: libc::PROT_WRITE,
        };

        crate::tests::make_compact_test_data(SYS_mprotect, 77, -22, &data)
    },
    "77 mprotect(addr: 0x1000, length: 4096, prot: 0x2 (PROT_WRITE)) = -22 (error)\n"
);

syscall_test!(
    parse_brk_new_addr,
    {
        use pinchy_common::BrkData;

        let data = BrkData {
            addr: 0x7f1234560000,
        };

        crate::tests::make_compact_test_data(SYS_brk, 888, 0x7f1234570000, &data)
    },
    "888 brk(addr: 0x7f1234560000) = 0x7f1234570000\n"
);

syscall_test!(
    parse_brk_null_addr,
    {
        use pinchy_common::BrkData;

        let data = BrkData { addr: 0 };

        crate::tests::make_compact_test_data(SYS_brk, 888, 0x7f1234500000, &data)
    },
    "888 brk(addr: 0x0) = 0x7f1234500000\n"
);

syscall_test!(
    parse_madvise_success,
    {
        use pinchy_common::MadviseData;

        let data = MadviseData {
            addr: 0x7f1234567000,
            length: 4096,
            advice: libc::MADV_DONTNEED,
        };

        crate::tests::make_compact_test_data(SYS_madvise, 123, 0, &data)
    },
    "123 madvise(addr: 0x7f1234567000, length: 4096, advice: MADV_DONTNEED (4)) = 0 (success)\n"
);

syscall_test!(
    parse_madvise_error,
    {
        use pinchy_common::MadviseData;

        let data = MadviseData {
            addr: 0x0,
            length: 4096,
            advice: libc::MADV_WILLNEED,
        };

        crate::tests::make_compact_test_data(SYS_madvise, 456, -1, &data)
    },
    "456 madvise(addr: 0x0, length: 4096, advice: MADV_WILLNEED (3)) = -1 (error)\n"
);

syscall_test!(
    parse_madvise_unknown_advice,
    {
        use pinchy_common::MadviseData;

        let data = MadviseData {
            addr: 0x7f1234567000,
            length: 8192,
            advice: 999,
        };

        crate::tests::make_compact_test_data(SYS_madvise, 789, 0, &data)
    },
    "789 madvise(addr: 0x7f1234567000, length: 8192, advice: UNKNOWN (999)) = 0 (success)\n"
);

syscall_test!(
    parse_process_madvise_success,
    {

        use pinchy_common::ProcessMadviseData;

        let data = ProcessMadviseData {
                    pidfd: 5,
                    iovecs: [
                        Iovec {
                            iov_base: 0x7f1234567000,
                            iov_len: 4096,
                        },
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                    ],
                    iov_lens: [4096, 0, 0, 0, 0, 0, 0, 0],
                    iov_bufs: [[0; LARGER_READ_SIZE]; IOV_COUNT],
                    iovcnt: 1,
                    advice: libc::MADV_DONTNEED,
                    flags: 0,
                    read_count: 1,
                };

        crate::tests::make_compact_test_data(SYS_process_madvise, 123, 4096, &data)
    },
    "123 process_madvise(pidfd: 5, iov: [ iovec { base: 0x7f1234567000, len: 4096 } ], iovcnt: 1, advice: MADV_DONTNEED (4), flags: 0) = 4096 (bytes)\n"
);

syscall_test!(
    parse_process_madvise_error,
    {

        use pinchy_common::ProcessMadviseData;

        let data = ProcessMadviseData {
                    pidfd: 9,
                    iovecs: [
                        Iovec {
                            iov_base: 0x7f9876543000,
                            iov_len: 8192,
                        },
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                    ],
                    iov_lens: [8192, 0, 0, 0, 0, 0, 0, 0],
                    iov_bufs: [[0; LARGER_READ_SIZE]; IOV_COUNT],
                    iovcnt: 1,
                    advice: libc::MADV_WILLNEED,
                    flags: 0,
                    read_count: 1,
                };

        crate::tests::make_compact_test_data(SYS_process_madvise, 456, -1, &data)
    },
    "456 process_madvise(pidfd: 9, iov: [ iovec { base: 0x7f9876543000, len: 8192 } ], iovcnt: 1, advice: MADV_WILLNEED (3), flags: 0) = -1 (error)\n"
);

syscall_test!(
    parse_mlock_success,
    {
        use pinchy_common::MlockData;

        let data = MlockData {
            addr: 0x7f1234567000,
            len: 4096,
        };

        crate::tests::make_compact_test_data(SYS_mlock, 123, 0, &data)
    },
    "123 mlock(addr: 0x7f1234567000, len: 4096) = 0 (success)\n"
);

syscall_test!(
    parse_mlock2_success,
    {
        use pinchy_common::Mlock2Data;

        let data = Mlock2Data {
            addr: 0x7f1234567000,
            len: 8192,
            flags: libc::MLOCK_ONFAULT as i32,
        };

        crate::tests::make_compact_test_data(SYS_mlock2, 123, 0, &data)
    },
    "123 mlock2(addr: 0x7f1234567000, len: 8192, flags: 0x1 (MLOCK_ONFAULT)) = 0 (success)\n"
);

syscall_test!(
    parse_mlockall_success,
    {
        use pinchy_common::MlockallData;

        let data = MlockallData {
            flags: libc::MCL_CURRENT | libc::MCL_FUTURE,
        };

        crate::tests::make_compact_test_data(SYS_mlockall, 123, 0, &data)
    },
    "123 mlockall(flags: 0x3 (MCL_CURRENT|MCL_FUTURE)) = 0 (success)\n"
);

syscall_test!(
    parse_munlock_success,
    {
        use pinchy_common::MunlockData;

        let data = MunlockData {
            addr: 0x7f1234567000,
            len: 4096,
        };

        crate::tests::make_compact_test_data(SYS_munlock, 123, 0, &data)
    },
    "123 munlock(addr: 0x7f1234567000, len: 4096) = 0 (success)\n"
);

syscall_test!(
    parse_munlockall_success,
    {
        use pinchy_common::MunlockallData;

        let data = MunlockallData;

        crate::tests::make_compact_test_data(SYS_munlockall, 123, 0, &data)
    },
    "123 munlockall() = 0 (success)\n"
);

syscall_test!(
    parse_munlockall_error,
    {
        use pinchy_common::MunlockallData;

        let data = MunlockallData;

        crate::tests::make_compact_test_data(SYS_munlockall, 456, -1, &data)
    },
    "456 munlockall() = -1 (error)\n"
);

syscall_test!(
    parse_mremap_success,
    {

        use pinchy_common::MremapData;

        let data = MremapData {
                    old_address: 0x7f1234567000,
                    old_size: 4096,
                    new_size: 8192,
                    flags: libc::MREMAP_MAYMOVE,
                };

        crate::tests::make_compact_test_data(SYS_mremap, 123, 0x7f9876543000, &data)
    },
    "123 mremap(old_address: 0x7f1234567000, old_size: 4096, new_size: 8192, flags: 0x1 (MREMAP_MAYMOVE)) = 0x7f9876543000 (addr)\n"
);

syscall_test!(
    parse_msync_success,
    {
        use pinchy_common::MsyncData;

        let data = MsyncData {
            addr: 0x7f1234567000,
            length: 4096,
            flags: libc::MS_SYNC,
        };

        crate::tests::make_compact_test_data(SYS_msync, 123, 0, &data)
    },
    "123 msync(addr: 0x7f1234567000, length: 4096, flags: 0x4 (MS_SYNC)) = 0 (success)\n"
);

syscall_test!(
    parse_membarrier_success,
    {
        use pinchy_common::MembarrierData;

        let data = MembarrierData {
            cmd: libc::MEMBARRIER_CMD_QUERY,
            flags: 0,
        };

        crate::tests::make_compact_test_data(SYS_membarrier, 123, 127, &data)
    },
    "123 membarrier(cmd: MEMBARRIER_CMD_QUERY, flags: 0) = 127 (bitmask)\n"
);

syscall_test!(
    parse_readahead_success,
    {
        use pinchy_common::ReadaheadData;

        let data = ReadaheadData {
            fd: 5,
            offset: 1024,
            count: 4096,
        };

        crate::tests::make_compact_test_data(SYS_readahead, 123, 0, &data)
    },
    "123 readahead(fd: 5, offset: 1024, count: 4096) = 0 (success)\n"
);

syscall_test!(
    parse_memfd_secret_success,
    {
        use pinchy_common::MemfdSecretData;

        let data = MemfdSecretData {
            flags: libc::FD_CLOEXEC as u32,
        };

        crate::tests::make_compact_test_data(SYS_memfd_secret, 123, 8, &data)
    },
    "123 memfd_secret(flags: 0x1 (FD_CLOEXEC)) = 8 (fd)\n"
);

syscall_test!(
    parse_userfaultfd_success,
    {
        use pinchy_common::UserfaultfdData;

        let data = UserfaultfdData {
            flags: (libc::O_CLOEXEC | libc::O_NONBLOCK) as u32,
        };

        crate::tests::make_compact_test_data(SYS_userfaultfd, 123, 9, &data)
    },
    "123 userfaultfd(flags: 0x80800 (O_CLOEXEC|O_NONBLOCK)) = 9 (fd)\n"
);

syscall_test!(
    parse_pkey_alloc_success,
    {

        use pinchy_common::PkeyAllocData;

        let data = PkeyAllocData {
                    flags: 0,
                    access_rights: PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE,
                };

        crate::tests::make_compact_test_data(SYS_pkey_alloc, 123, 1, &data)
    },
    "123 pkey_alloc(flags: 0, access_rights: 0x3 (PKEY_DISABLE_ACCESS|PKEY_DISABLE_WRITE)) = 1 (pkey)\n"
);

syscall_test!(
    parse_pkey_free_success,
    {
        use pinchy_common::PkeyFreeData;

        let data = PkeyFreeData { pkey: 1 };

        crate::tests::make_compact_test_data(SYS_pkey_free, 123, 0, &data)
    },
    "123 pkey_free(pkey: 1) = 0 (success)\n"
);

syscall_test!(
    parse_process_vm_readv_success,
    {

        use pinchy_common::ProcessVmData;

        let data = ProcessVmData {
                    pid: 456,
                    local_iovecs: [
                        Iovec {
                            iov_base: 0x7f1234567000,
                            iov_len: 32,
                        },
                        Iovec {
                            iov_base: 0x7f1234568000,
                            iov_len: 32,
                        },
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                    ],
                    local_iov_lens: [32, 32, 0, 0, 0, 0, 0, 0],
                    local_iovcnt: 2,
                    remote_iovecs: [
                        Iovec {
                            iov_base: 0x7f9876543000,
                            iov_len: 64,
                        },
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                    ],
                    remote_iov_lens: [64, 0, 0, 0, 0, 0, 0, 0],
                    remote_iovcnt: 1,
                    flags: 0,
                    local_read_count: 2,
                    remote_read_count: 1,
                    local_iov_bufs: [[0; LARGER_READ_SIZE]; IOV_COUNT],
                };

        crate::tests::make_compact_test_data(SYS_process_vm_readv, 123, 64, &data)
    },
    "123 process_vm_readv(pid: 456, local_iov: [ iovec { base: 0x7f1234567000, len: 32, buf: \"\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\" }, iovec { base: 0x7f1234568000, len: 32, buf: \"\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\" } ], liovcnt: 2, remote_iov: [ iovec { base: 0x7f9876543000, len: 64 } ], riovcnt: 1, flags: 0) = 64 (bytes)\n"
);

syscall_test!(
    parse_process_vm_readv_with_content,
    {

        use pinchy_common::ProcessVmData;
        let mut data = ProcessVmData {
            pid: 789,
            local_iovecs: [
                Iovec {
                    iov_base: 0x7f1234567000,
                    iov_len: 16,
                },
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
            ],
            local_iov_lens: [16, 0, 0, 0, 0, 0, 0, 0],
            local_iovcnt: 1,
            remote_iovecs: [
                Iovec {
                    iov_base: 0x7f9876543000,
                    iov_len: 16,
                },
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
            ],
            remote_iov_lens: [16, 0, 0, 0, 0, 0, 0, 0],
            remote_iovcnt: 1,
            flags: 0,
            local_read_count: 1,
            remote_read_count: 1,
            local_iov_bufs: [[0; LARGER_READ_SIZE]; IOV_COUNT],
        };

        // Add some readable content to the first buffer
        data.local_iov_bufs[0][..12].copy_from_slice(b"Hello World!");

        let data = data;

        crate::tests::make_compact_test_data(SYS_process_vm_readv, 789, 16, &data)
    },
    "789 process_vm_readv(pid: 789, local_iov: [ iovec { base: 0x7f1234567000, len: 16, buf: \"Hello World!\\0\\0\\0\\0\" } ], liovcnt: 1, remote_iov: [ iovec { base: 0x7f9876543000, len: 16 } ], riovcnt: 1, flags: 0) = 16 (bytes)\n"
);

syscall_test!(
    parse_process_vm_writev_success,
    {

        use pinchy_common::ProcessVmData;

        let data = ProcessVmData {
                    pid: 654,
                    local_iovecs: [
                        Iovec {
                            iov_base: 0x7f1111111000,
                            iov_len: 32,
                        },
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                    ],
                    local_iov_lens: [32, 0, 0, 0, 0, 0, 0, 0],
                    local_iovcnt: 1,
                    remote_iovecs: [
                        Iovec {
                            iov_base: 0x7f2222222000,
                            iov_len: 32,
                        },
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                    ],
                    remote_iov_lens: [32, 0, 0, 0, 0, 0, 0, 0],
                    remote_iovcnt: 1,
                    flags: 0,
                    local_read_count: 1,
                    remote_read_count: 1,
                    local_iov_bufs: [[0; LARGER_READ_SIZE]; IOV_COUNT],
                };

        crate::tests::make_compact_test_data(SYS_process_vm_writev, 321, 32, &data)
    },
    "321 process_vm_writev(pid: 654, local_iov: [ iovec { base: 0x7f1111111000, len: 32, buf: \"\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\" } ], liovcnt: 1, remote_iov: [ iovec { base: 0x7f2222222000, len: 32 } ], riovcnt: 1, flags: 0) = 32 (bytes)\n"
);

syscall_test!(
    parse_process_vm_writev_with_content,
    {

        use pinchy_common::ProcessVmData;
        let mut data = ProcessVmData {
            pid: 987,
            local_iovecs: [
                Iovec {
                    iov_base: 0x7f3333333000,
                    iov_len: 8,
                },
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
            ],
            local_iov_lens: [8, 0, 0, 0, 0, 0, 0, 0],
            local_iovcnt: 1,
            remote_iovecs: [
                Iovec {
                    iov_base: 0x7f4444444000,
                    iov_len: 8,
                },
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
                Iovec::default(),
            ],
            remote_iov_lens: [8, 0, 0, 0, 0, 0, 0, 0],
            remote_iovcnt: 1,
            flags: 0,
            local_read_count: 1,
            remote_read_count: 1,
            local_iov_bufs: [[0; LARGER_READ_SIZE]; IOV_COUNT],
        };

        // Add some content to be written
        data.local_iov_bufs[0][..8].copy_from_slice(b"TestData");

        let data = data;

        crate::tests::make_compact_test_data(SYS_process_vm_writev, 987, 8, &data)
    },
    "987 process_vm_writev(pid: 987, local_iov: [ iovec { base: 0x7f3333333000, len: 8, buf: \"TestData\" } ], liovcnt: 1, remote_iov: [ iovec { base: 0x7f4444444000, len: 8 } ], riovcnt: 1, flags: 0) = 8 (bytes)\n"
);

syscall_test!(
    parse_process_vm_readv_error,
    {

        use pinchy_common::ProcessVmData;

        let data = ProcessVmData {
                    pid: 123,
                    local_iovecs: [
                        Iovec {
                            iov_base: 0x7f1234567000,
                            iov_len: 32,
                        },
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                    ],
                    local_iov_lens: [32, 0, 0, 0, 0, 0, 0, 0],
                    local_iovcnt: 1,
                    remote_iovecs: [
                        Iovec {
                            iov_base: 0x0,
                            iov_len: 32,
                        },
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                        Iovec::default(),
                    ],
                    remote_iov_lens: [32, 0, 0, 0, 0, 0, 0, 0],
                    remote_iovcnt: 1,
                    flags: 0,
                    local_read_count: 1,
                    remote_read_count: 1,
                    local_iov_bufs: [[0; LARGER_READ_SIZE]; IOV_COUNT],
                };

        crate::tests::make_compact_test_data(SYS_process_vm_readv, 999, -1, &data)
    },
    "999 process_vm_readv(pid: 123, local_iov: [ iovec { base: 0x7f1234567000, len: 32, buf: \"\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\" } ], liovcnt: 1, remote_iov: [ iovec { base: 0x0, len: 32 } ], riovcnt: 1, flags: 0) = -1 (error)\n"
);

syscall_test!(
    parse_mbind_success,
    {

        use pinchy_common::MbindData;

        let data = MbindData {
                    addr: 0x7f1234567000,
                    len: 4096,
                    mode: pinchy_common::MPOL_BIND,
                    maxnode: 64,
                    flags: pinchy_common::MPOL_MF_STRICT | pinchy_common::MPOL_MF_MOVE,
                    nodemask: [0b00000101, 0],
                    nodemask_read_count: 1,
                };

        crate::tests::make_compact_test_data(SYS_mbind, 123, 0, &data)
    },
    "123 mbind(addr: 0x7f1234567000, len: 4096, mode: MPOL_BIND, nodemask: [0, 2], maxnode: 64, flags: 0x3 (MPOL_MF_STRICT|MPOL_MF_MOVE)) = 0 (success)\n"
);

syscall_test!(
    parse_mbind_null_nodemask,
    {

        use pinchy_common::MbindData;

        let data = MbindData {
                    addr: 0x7f1234567000,
                    len: 8192,
                    mode: pinchy_common::MPOL_DEFAULT,
                    maxnode: 0,
                    flags: 0,
                    nodemask: [0, 0],
                    nodemask_read_count: 0,
                };

        crate::tests::make_compact_test_data(SYS_mbind, 123, 0, &data)
    },
    "123 mbind(addr: 0x7f1234567000, len: 8192, mode: MPOL_DEFAULT, nodemask: NULL, maxnode: 0, flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_get_mempolicy_success,
    {

        use pinchy_common::GetMempolicyData;

        let data = GetMempolicyData {
                    maxnode: 64,
                    addr: 0x7f1234567000,
                    flags: pinchy_common::MPOL_F_ADDR,
                    mode_out: pinchy_common::MPOL_INTERLEAVE,
                    mode_valid: true,
                    nodemask_out: [0b00001001, 0],
                    nodemask_read_count: 1,
                };

        crate::tests::make_compact_test_data(SYS_get_mempolicy, 123, 0, &data)
    },
    "123 get_mempolicy(mode: MPOL_INTERLEAVE, nodemask: [0, 3], maxnode: 64, addr: 0x7f1234567000, flags: 0x2 (MPOL_F_ADDR)) = 0 (success)\n"
);

syscall_test!(
    parse_get_mempolicy_null_output,
    {

        use pinchy_common::GetMempolicyData;

        let data = GetMempolicyData {
                    maxnode: 64,
                    addr: 0,
                    flags: pinchy_common::MPOL_F_MEMS_ALLOWED,
                    mode_out: 0,
                    mode_valid: false,
                    nodemask_out: [0, 0],
                    nodemask_read_count: 0,
                };

        crate::tests::make_compact_test_data(SYS_get_mempolicy, 123, 0, &data)
    },
    "123 get_mempolicy(mode: NULL, nodemask: NULL, maxnode: 64, addr: 0x0, flags: 0x4 (MPOL_F_MEMS_ALLOWED)) = 0 (success)\n"
);

syscall_test!(
    parse_set_mempolicy_success,
    {

        use pinchy_common::SetMempolicyData;

        let data = SetMempolicyData {
                    mode: pinchy_common::MPOL_PREFERRED_MANY | pinchy_common::MPOL_F_STATIC_NODES,
                    maxnode: 64,
                    nodemask: [0b00000011, 0],
                    nodemask_read_count: 1,
                };

        crate::tests::make_compact_test_data(SYS_set_mempolicy, 123, 0, &data)
    },
    "123 set_mempolicy(mode: MPOL_PREFERRED_MANY|MPOL_F_STATIC_NODES, nodemask: [0, 1], maxnode: 64) = 0 (success)\n"
);

syscall_test!(
    parse_set_mempolicy_home_node_success,
    {

        use pinchy_common::SetMempolicyHomeNodeData;

        let data = SetMempolicyHomeNodeData {
                    start: 0x7f1234567000,
                    len: 4096,
                    home_node: 2,
                    flags: 0,
                };

        crate::tests::make_compact_test_data(SYS_set_mempolicy_home_node, 123, 0, &data)
    },
    "123 set_mempolicy_home_node(start: 0x7f1234567000, len: 4096, home_node: 2, flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_migrate_pages_success,
    {

        use pinchy_common::MigratePagesData;

        let data = MigratePagesData {
                    pid: 456,
                    maxnode: 64,
                    old_nodes: [0b00000001, 0],
                    new_nodes: [0b00000010, 0],
                    old_nodes_read_count: 1,
                    new_nodes_read_count: 1,
                };

        crate::tests::make_compact_test_data(SYS_migrate_pages, 123, 0, &data)
    },
    "123 migrate_pages(pid: 456, maxnode: 64, old_nodes: [0], new_nodes: [1]) = 0 (pages not migrated)\n"
);

syscall_test!(
    parse_move_pages_success,
    {

        use pinchy_common::MovePagesData;

        let data = MovePagesData {
                    pid: 456,
                    count: 3,
                    flags: pinchy_common::MPOL_MF_MOVE as i32,
                    pages: [0x7f1234567000, 0x7f1234568000, 0x7f1234569000, 0, 0, 0, 0, 0],
                    nodes: [0, 1, 0, 0, 0, 0, 0, 0],
                    status: [0, 0, -14, 0, 0, 0, 0, 0],
                    pages_read_count: 3,
                    nodes_read_count: 3,
                    status_read_count: 3,
                };

        crate::tests::make_compact_test_data(SYS_move_pages, 123, 0, &data)
    },
    "123 move_pages(pid: 456, count: 3, pages: [0x7f1234567000, 0x7f1234568000, 0x7f1234569000], nodes: [0, 1, 0], status: [0, 0, -14], flags: 0x2 (MPOL_MF_MOVE)) = 0 (success)\n"
);

syscall_test!(
    parse_move_pages_truncated,
    {

        use pinchy_common::MovePagesData;

        let data = MovePagesData {
                    pid: 456,
                    count: 100,
                    flags: 0,
                    pages: [
                        0x7f1234567000,
                        0x7f1234568000,
                        0x7f1234569000,
                        0x7f123456a000,
                        0x7f123456b000,
                        0x7f123456c000,
                        0x7f123456d000,
                        0x7f123456e000,
                    ],
                    nodes: [0, 1, 0, 1, 0, 1, 0, 1],
                    status: [0, 0, -14, 0, -12, 0, -22, 0],
                    pages_read_count: 8,
                    nodes_read_count: 8,
                    status_read_count: 8,
                };

        crate::tests::make_compact_test_data(SYS_move_pages, 123, 2, &data)
    },
    "123 move_pages(pid: 456, count: 100, pages: [0x7f1234567000, 0x7f1234568000, 0x7f1234569000, 0x7f123456a000, 0x7f123456b000, 0x7f123456c000, 0x7f123456d000, 0x7f123456e000... (showing 8 of 100)], nodes: [0, 1, 0, 1, 0, 1, 0, 1... (showing 8 of 100)], status: [0, 0, -14, 0, -12, 0, -22, 0... (showing 8 of 100)], flags: 0) = 2 (pages not migrated)\n"
);

syscall_test!(
    parse_mincore_success,
    {
        use pinchy_common::MincoreData;

        let data = MincoreData {
            addr: 0x7f1234567000,
            length: 16384,
            vec: [
                1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            vec_read_count: 4,
        };

        crate::tests::make_compact_test_data(SYS_mincore, 123, 0, &data)
    },
    "123 mincore(addr: 0x7f1234567000, length: 16384, vec: [1,1,0,1]) = 0 (success)\n"
);

syscall_test!(
    parse_mincore_truncated,
    {

        use pinchy_common::MincoreData;

        let data = MincoreData {
                    addr: 0x7f1234567000,
                    length: 200 * 4096,
                    vec: [
                        1, 1, 0, 1, 0, 0, 0, 0,
                        1, 1, 1, 1, 0, 0, 0, 0,
                        1, 0, 1, 0, 1, 0, 1, 0,
                        0, 1, 0, 1, 0, 1, 0, 1,
                    ],
                    vec_read_count: 32,
                };

        crate::tests::make_compact_test_data(SYS_mincore, 123, 0, &data)
    },
    "123 mincore(addr: 0x7f1234567000, length: 819200, vec: [1,1,0,1,0,0,0,0,1,1,1,1,0,0,0,0,1,0,1,0,1,0,1,0,0,1,0,1,0,1,0,1... (showing 32 of 200 pages)]) = 0 (success)\n"
);

syscall_test!(
    parse_memfd_create_basic,
    {
        use pinchy_common::MemfdCreateData;

        let data = MemfdCreateData {
            name: *b"myfile\0\0",
            flags: crate::format_helpers::memfd_constants::MFD_CLOEXEC,
        };

        crate::tests::make_compact_test_data(SYS_memfd_create, 123, 3, &data)
    },
    "123 memfd_create(name: \"myfile\", flags: 0x1 (MFD_CLOEXEC)) = 3 (fd)\n"
);

syscall_test!(
    parse_memfd_create_hugetlb,
    {
        use pinchy_common::MemfdCreateData;

        let data = MemfdCreateData {
            name: *b"huge\0\0\0\0",
            flags: crate::format_helpers::memfd_constants::MFD_HUGETLB
                | crate::format_helpers::memfd_constants::MFD_HUGE_2MB,
        };

        crate::tests::make_compact_test_data(SYS_memfd_create, 123, 4, &data)
    },
    "123 memfd_create(name: \"huge\", flags: 0x54000004 (MFD_HUGETLB|MFD_HUGE_2MB)) = 4 (fd)\n"
);

syscall_test!(
    parse_pkey_mprotect_success,
    {

        use pinchy_common::PkeyMprotectData;

        let data = PkeyMprotectData {
                    addr: 0x7f1234567000,
                    len: 4096,
                    prot: libc::PROT_READ | libc::PROT_WRITE,
                    pkey: 1,
                };

        crate::tests::make_compact_test_data(SYS_pkey_mprotect, 123, 0, &data)
    },
    "123 pkey_mprotect(addr: 0x7f1234567000, len: 4096, prot: 0x3 (PROT_READ|PROT_WRITE), pkey: 1) = 0 (success)\n"
);

syscall_test!(
    parse_mseal_success,
    {
        use pinchy_common::MsealData;

        let data = MsealData {
            addr: 0x7f1234567000,
            len: 8192,
            flags: 0,
        };

        crate::tests::make_compact_test_data(SYS_mseal, 123, 0, &data)
    },
    "123 mseal(addr: 0x7f1234567000, len: 8192, flags: 0) = 0 (success)\n"
);

syscall_test!(
    parse_remap_file_pages_success,
    {

        use pinchy_common::RemapFilePagesData;

        let data = RemapFilePagesData {
                    addr: 0x7f1234567000,
                    size: 4096,
                    prot: libc::PROT_READ,
                    pgoff: 0,
                    flags: libc::MAP_SHARED,
                };

        crate::tests::make_compact_test_data(SYS_remap_file_pages, 123, 0, &data)
    },
    "123 remap_file_pages(addr: 0x7f1234567000, size: 4096, prot: 0x1 (PROT_READ), pgoff: 0, flags: 0x1 (MAP_SHARED)) = 0 (success)\n"
);
