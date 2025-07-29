use pinchy_common::{SyscallEvent, SyscallEventData};

use crate::syscall_test;

syscall_test!(
    parse_shmat_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_shmat,
            pid: 1111,
            tid: 1111,
            return_value: 0x7fabc000,
            data: SyscallEventData {
                shmat: pinchy_common::ShmatData {
                    shmid: 123,
                    shmaddr: 0,
                    shmflg: libc::SHM_RDONLY,
                },
            },
        }
    },
    "1111 shmat(shmid: 123, shmaddr: 0x0, shmflg: SHM_NORESERVE|SHM_RDONLY) = 0x7fabc000\n"
);

syscall_test!(
    parse_shmat_error,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_shmat,
            pid: 2222,
            tid: 2222,
            return_value: -1,
            data: SyscallEventData {
                shmat: pinchy_common::ShmatData {
                    shmid: 456,
                    shmaddr: 0x1000,
                    shmflg: 0,
                },
            },
        }
    },
    "2222 shmat(shmid: 456, shmaddr: 0x1000, shmflg: 0x0) = -1 (error)\n"
);

syscall_test!(
    parse_shmdt_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_shmdt,
            pid: 3333,
            tid: 3333,
            return_value: 0,
            data: SyscallEventData {
                shmdt: pinchy_common::ShmdtData {
                    shmaddr: 0x7fabc000,
                },
            },
        }
    },
    "3333 shmdt(shmaddr: 0x7fabc000) = 0 (success)\n"
);

syscall_test!(
    parse_shmdt_error,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_shmdt,
            pid: 4444,
            tid: 4444,
            return_value: -1,
            data: SyscallEventData {
                shmdt: pinchy_common::ShmdtData {
                    shmaddr: 0xdeadbeef,
                },
            },
        }
    },
    "4444 shmdt(shmaddr: 0xdeadbeef) = -1 (error)\n"
);

syscall_test!(
    parse_shmget_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_shmget,
            pid: 5555,
            tid: 5555,
            return_value: 77,
            data: SyscallEventData {
                shmget: pinchy_common::ShmgetData {
                    key: 0x1234,
                    size: 4096,
                    shmflg: libc::IPC_CREAT | libc::IPC_EXCL,
                },
            },
        }
    },
    "5555 shmget(key: 0x1234, size: 4096, shmflg: IPC_CREAT|IPC_EXCL) = 77 (shmid)\n"
);

syscall_test!(
    parse_shmget_error,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_shmget,
            pid: 6666,
            tid: 6666,
            return_value: -1,
            data: SyscallEventData {
                shmget: pinchy_common::ShmgetData {
                    key: 0xbeef,
                    size: 8192,
                    shmflg: 0,
                },
            },
        }
    },
    "6666 shmget(key: 0xbeef, size: 8192, shmflg: 0x0) = -1 (error)\n"
);

syscall_test!(
    parse_shmctl_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_shmctl,
            pid: 7777,
            tid: 7777,
            return_value: 0,
            data: SyscallEventData {
                shmctl: pinchy_common::ShmctlData {
                    shmid: 55,
                    cmd: libc::IPC_STAT,
                    buf: pinchy_common::kernel_types::ShmidDs {
                        shm_perm: pinchy_common::kernel_types::IpcPerm {
                            key: 0x12345678,
                            uid: 1000,
                            gid: 1000,
                            cuid: 1000,
                            cgid: 1000,
                            mode: 0o666,
                            __pad1: 0,
                            seq: 42,
                        },
                        shm_segsz: 4096,
                        shm_atime: 1620000000,
                        shm_dtime: 1620001000,
                        shm_ctime: 1620002000,
                        shm_cpid: 1234,
                        shm_lpid: 5678,
                        shm_nattch: 2,
                    },
                    has_buf: true,
                },
            },
        }
    },
    "7777 shmctl(shmid: 55, cmd: IPC_STAT, buf: { ipc_perm { key: 0x12345678, uid: 1000, gid: 1000, cuid: 1000, cgid: 1000, mode: 0o666 (rw-rw-rw-), seq: 42 }, segsz: 4096, atime: 1620000000, dtime: 1620001000, ctime: 1620002000, cpid: 1234, lpid: 5678, nattch: 2 }) = 0\n"
);

syscall_test!(
    parse_shmctl_error,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_shmctl,
            pid: 8888,
            tid: 8888,
            return_value: -1,
            data: SyscallEventData {
                shmctl: pinchy_common::ShmctlData {
                    shmid: 99,
                    cmd: libc::IPC_RMID,
                    buf: pinchy_common::kernel_types::ShmidDs::default(),
                    has_buf: false,
                },
            },
        }
    },
    "8888 shmctl(shmid: 99, cmd: IPC_RMID, buf: NULL) = -1 (error)\n"
);
