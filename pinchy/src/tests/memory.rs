// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    syscalls::{SYS_brk, SYS_madvise, SYS_mmap, SYS_mprotect, SYS_munmap},
    SyscallEvent,
};

use crate::syscall_test;

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
                    advice: 4,
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
                    advice: 3,
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
