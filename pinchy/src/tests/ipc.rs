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
    "7777 shmctl(shmid: 55, cmd: IPC_STAT, buf: { ipc_perm { key: 0x12345678, uid: 1000, gid: 1000, cuid: 1000, cgid: 1000, mode: 0o666 (rw-rw-rw-), seq: 42 }, segsz: 4096, atime: 1620000000, dtime: 1620001000, ctime: 1620002000, cpid: 1234, lpid: 5678, nattch: 2 }) = 0 (success)\n"
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

syscall_test!(
    parse_msgget_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_msgget,
            pid: 10101,
            tid: 10101,
            return_value: 42,
            data: SyscallEventData {
                msgget: pinchy_common::MsggetData {
                    key: 0xbeef,
                    msgflg: libc::IPC_CREAT | libc::IPC_EXCL,
                },
            },
        }
    },
    "10101 msgget(key: 0xbeef, msgflg: IPC_CREAT|IPC_EXCL) = 42 (msqid)\n"
);

syscall_test!(
    parse_msgsnd_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_msgsnd,
            pid: 10202,
            tid: 10202,
            return_value: 0,
            data: SyscallEventData {
                msgsnd: pinchy_common::MsgsndData {
                    msqid: 123,
                    msgp: 0x7fff0000,
                    msgsz: 128,
                    msgflg: libc::IPC_NOWAIT | libc::MSG_NOERROR,
                },
            },
        }
    },
    "10202 msgsnd(msqid: 123, msgp: 0x7fff0000, msgsz: 128, msgflg: IPC_NOWAIT|MSG_NOERROR) = 0 (success)\n"
);

syscall_test!(
    parse_msgrcv_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_msgrcv,
            pid: 10303,
            tid: 10303,
            return_value: 64,
            data: SyscallEventData {
                msgrcv: pinchy_common::MsgrcvData {
                    msqid: 321,
                    msgp: 0x7fff1000,
                    msgsz: 64,
                    msgtyp: 2,
                    msgflg: libc::MSG_NOERROR,
                },
            },
        }
    },
    "10303 msgrcv(msqid: 321, msgp: 0x7fff1000, msgsz: 64, msgtyp: 2, msgflg: MSG_NOERROR) = 64\n"
);

syscall_test!(
    parse_msgctl_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_msgctl,
            pid: 10404,
            tid: 10404,
            return_value: 0,
            data: SyscallEventData {
                msgctl: pinchy_common::MsgctlData {
                    msqid: 555,
                    op: libc::IPC_STAT,
                    buf: pinchy_common::kernel_types::MsqidDs {
                        msg_perm: pinchy_common::kernel_types::IpcPerm {
                            key: 0x123456,
                            uid: 1001,
                            gid: 1002,
                            cuid: 1003,
                            cgid: 1004,
                            mode: 0o600,
                            __pad1: 0,
                            seq: 99,
                        },
                        msg_stime: 1620000000,
                        msg_rtime: 1620001000,
                        msg_ctime: 1620002000,
                        msg_cbytes: 256,
                        msg_qnum: 3,
                        msg_qbytes: 8192,
                        msg_lspid: 4321,
                        msg_lrpid: 8765,
                    },
                    has_buf: true,
                },
            },
        }
    },
    "10404 msgctl(msqid: 555, cmd: IPC_STAT, buf: { ipc_perm { key: 0x123456, uid: 1001, gid: 1002, cuid: 1003, cgid: 1004, mode: 0o600 (rw-------), seq: 99 }, stime: 1620000000, rtime: 1620001000, ctime: 1620002000, cbytes: 256, qnum: 3, qbytes: 8192, lspid: 4321, lrpid: 8765 }) = 0 (success)\n"
);

syscall_test!(
    parse_msgctl_error,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_msgctl,
            pid: 10505,
            tid: 10505,
            return_value: -1,
            data: SyscallEventData {
                msgctl: pinchy_common::MsgctlData {
                    msqid: 666,
                    op: libc::IPC_RMID,
                    buf: pinchy_common::kernel_types::MsqidDs::default(),
                    has_buf: false,
                },
            },
        }
    },
    "10505 msgctl(msqid: 666, cmd: IPC_RMID, buf: NULL) = -1 (error)\n"
);

syscall_test!(
    parse_semget_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_semget,
            pid: 20001,
            tid: 20001,
            return_value: 123,
            data: SyscallEventData {
                semget: pinchy_common::SemgetData {
                    key: 0xfeed,
                    nsems: 4,
                    semflg: libc::IPC_CREAT | libc::IPC_EXCL,
                },
            },
        }
    },
    "20001 semget(key: 0xfeed, nsems: 4, semflg: IPC_CREAT|IPC_EXCL) = 123\n"
);

syscall_test!(
    parse_semget_error,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_semget,
            pid: 20002,
            tid: 20002,
            return_value: -1,
            data: SyscallEventData {
                semget: pinchy_common::SemgetData {
                    key: 0xbeef,
                    nsems: 2,
                    semflg: 0,
                },
            },
        }
    },
    "20002 semget(key: 0xbeef, nsems: 2, semflg: 0x0) = -1 (error)\n"
);

syscall_test!(
    parse_semop_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_semop,
            pid: 20003,
            tid: 20003,
            return_value: 0,
            data: SyscallEventData {
                semop: pinchy_common::SemopData {
                    semid: 321,
                    sops: 0x7fff2000,
                    nsops: 2,
                },
            },
        }
    },
    "20003 semop(semid: 321, sops: 0x7fff2000, nsops: 2) = 0 (success)\n"
);

syscall_test!(
    parse_semop_error,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_semop,
            pid: 20004,
            tid: 20004,
            return_value: -1,
            data: SyscallEventData {
                semop: pinchy_common::SemopData {
                    semid: 654,
                    sops: 0x7fff3000,
                    nsops: 1,
                },
            },
        }
    },
    "20004 semop(semid: 654, sops: 0x7fff3000, nsops: 1) = -1 (error)\n"
);

syscall_test!(
    parse_semctl_setval,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_semctl,
            pid: 20005,
            tid: 20005,
            return_value: 0,
            data: SyscallEventData {
                semctl: pinchy_common::SemctlData {
                    semid: 42,
                    semnum: 1,
                    op: libc::SETVAL,
                    has_arg: true,
                    arg: pinchy_common::kernel_types::Semun { val: 123 },
                    array: [0u16; 16],
                },
            },
        }
    },
    "20005 semctl(semid: 42, semnum: 1, op: SETVAL, val: 123) = 0 (success)\n"
);

syscall_test!(
    parse_semctl_setall,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_semctl,
            pid: 20006,
            tid: 20006,
            return_value: 0,
            data: SyscallEventData {
                semctl: pinchy_common::SemctlData {
                    semid: 99,
                    semnum: 0,
                    op: libc::SETALL,
                    has_arg: true,
                    arg: pinchy_common::kernel_types::Semun { array: 0x7fff4000 },
                    array: [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                },
            },
        }
    },
    "20006 semctl(semid: 99, semnum: 0, op: SETALL, array: 0x7fff4000) = 0 (success)\n"
);

syscall_test!(
    parse_semctl_stat,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_semctl,
            pid: 20007,
            tid: 20007,
            return_value: 0,
            data: SyscallEventData {
                semctl: pinchy_common::SemctlData {
                    semid: 77,
                    semnum: 0,
                    op: libc::IPC_STAT,
                    has_arg: true,
                    arg: pinchy_common::kernel_types::Semun {
                        buf: pinchy_common::kernel_types::SemidDs {
                            sem_perm: pinchy_common::kernel_types::IpcPerm {
                                key: 0xabcdef,
                                uid: 1000,
                                gid: 1000,
                                cuid: 1000,
                                cgid: 1000,
                                mode: 0o600,
                                __pad1: 0,
                                seq: 7,
                            },
                            sem_otime: 1620000000,
                            sem_ctime: 1620001000,
                            sem_nsems: 4,
                        },
                    },
                    array: [0u16; 16],
                },
            },
        }
    },
    "20007 semctl(semid: 77, semnum: 0, op: IPC_STAT, buf: { ipc_perm { key: 0xabcdef, uid: 1000, gid: 1000, cuid: 1000, cgid: 1000, mode: 0o600 (rw-------), seq: 7 }, otime: 1620000000, ctime: 1620001000, nsems: 4 }) = 0 (success)\n"
);

syscall_test!(
    parse_semctl_error,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_semctl,
            pid: 20008,
            tid: 20008,
            return_value: -1,
            data: SyscallEventData {
                semctl: pinchy_common::SemctlData {
                    semid: 88,
                    semnum: 2,
                    op: libc::SETVAL,
                    has_arg: false,
                    arg: pinchy_common::kernel_types::Semun { val: 0 },
                    array: [0u16; 16],
                },
            },
        }
    },
    "20008 semctl(semid: 88, semnum: 2, op: SETVAL, val: 0) = -1 (error)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_eventfd_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_eventfd,
            pid: 5555,
            tid: 5555,
            return_value: 7,
            data: SyscallEventData {
                eventfd: pinchy_common::EventfdData {
                    initval: 0,
                    flags: 0,
                },
            },
        }
    },
    "5555 eventfd(initval: 0, flags: 0) = 7 (fd)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_eventfd_with_flags,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_eventfd,
            pid: 6666,
            tid: 6666,
            return_value: 8,
            data: SyscallEventData {
                eventfd: pinchy_common::EventfdData {
                    initval: 5,
                    flags: libc::O_CLOEXEC, // EFD_CLOEXEC
                },
            },
        }
    },
    "6666 eventfd(initval: 5, flags: 0x80000 (EFD_CLOEXEC)) = 8 (fd)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_eventfd_error,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_eventfd,
            pid: 7777,
            tid: 7777,
            return_value: -1,
            data: SyscallEventData {
                eventfd: pinchy_common::EventfdData {
                    initval: 100,
                    flags: -1, // invalid flags
                },
            },
        }
    },
    "7777 eventfd(initval: 100, flags: 0xffffffff (EFD_CLOEXEC|EFD_NONBLOCK|UNKNOWN)) = -1 (error)\n"
);

syscall_test!(
    parse_eventfd2_success,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_eventfd2,
            pid: 8888,
            tid: 8888,
            return_value: 9,
            data: SyscallEventData {
                eventfd2: pinchy_common::Eventfd2Data {
                    initval: 0,
                    flags: libc::O_NONBLOCK, // EFD_NONBLOCK
                },
            },
        }
    },
    "8888 eventfd2(initval: 0, flags: 0x800 (EFD_NONBLOCK)) = 9 (fd)\n"
);

syscall_test!(
    parse_eventfd2_error,
    {
        SyscallEvent {
            syscall_nr: pinchy_common::syscalls::SYS_eventfd2,
            pid: 9999,
            tid: 9999,
            return_value: -1,
            data: SyscallEventData {
                eventfd2: pinchy_common::Eventfd2Data {
                    initval: 42,
                    flags: 999999, // invalid flags
                },
            },
        }
    },
    "9999 eventfd2(initval: 42, flags: 0xf423f (EFD_CLOEXEC|UNKNOWN)) = -1 (error)\n"
);
