use crate::syscall_test;

syscall_test!(
    parse_shmat_success,
    {
        let data = pinchy_common::ShmatData {
            shmid: 123,
            shmaddr: 0,
            shmflg: libc::SHM_RDONLY,
        };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_shmat,
            1111,
            0x7fabc000,
            &data,
        )
    },
    "1111 shmat(shmid: 123, shmaddr: 0x0, shmflg: SHM_NORESERVE|SHM_RDONLY) = 0x7fabc000\n"
);

syscall_test!(
    parse_shmat_error,
    {
        let data = pinchy_common::ShmatData {
            shmid: 456,
            shmaddr: 0x1000,
            shmflg: 0,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_shmat, 2222, -1, &data)
    },
    "2222 shmat(shmid: 456, shmaddr: 0x1000, shmflg: 0x0) = -1 (error)\n"
);

syscall_test!(
    parse_shmdt_success,
    {
        let data = pinchy_common::ShmdtData {
            shmaddr: 0x7fabc000,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_shmdt, 3333, 0, &data)
    },
    "3333 shmdt(shmaddr: 0x7fabc000) = 0 (success)\n"
);

syscall_test!(
    parse_shmdt_error,
    {
        let data = pinchy_common::ShmdtData {
            shmaddr: 0xdeadbeef,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_shmdt, 4444, -1, &data)
    },
    "4444 shmdt(shmaddr: 0xdeadbeef) = -1 (error)\n"
);

syscall_test!(
    parse_shmget_success,
    {
        let data = pinchy_common::ShmgetData {
            key: 0x1234,
            size: 4096,
            shmflg: libc::IPC_CREAT | libc::IPC_EXCL,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_shmget, 5555, 77, &data)
    },
    "5555 shmget(key: 0x1234, size: 4096, shmflg: IPC_CREAT|IPC_EXCL) = 77 (shmid)\n"
);

syscall_test!(
    parse_shmget_error,
    {
        let data = pinchy_common::ShmgetData {
            key: 0xbeef,
            size: 8192,
            shmflg: 0,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_shmget, 6666, -1, &data)
    },
    "6666 shmget(key: 0xbeef, size: 8192, shmflg: 0x0) = -1 (error)\n"
);

syscall_test!(
    parse_shmctl_success,
    {
        let data = pinchy_common::ShmctlData {
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
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_shmctl, 7777, 0, &data)
    },
    "7777 shmctl(shmid: 55, cmd: IPC_STAT, buf: { ipc_perm { key: 0x12345678, uid: 1000, gid: 1000, cuid: 1000, cgid: 1000, mode: 0o666 (rw-rw-rw-), seq: 42 }, segsz: 4096, atime: 1620000000, dtime: 1620001000, ctime: 1620002000, cpid: 1234, lpid: 5678, nattch: 2 }) = 0 (success)\n"
);

syscall_test!(
    parse_shmctl_error,
    {
        let data = pinchy_common::ShmctlData {
            shmid: 99,
            cmd: libc::IPC_RMID,
            buf: pinchy_common::kernel_types::ShmidDs::default(),
            has_buf: false,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_shmctl, 8888, -1, &data)
    },
    "8888 shmctl(shmid: 99, cmd: IPC_RMID, buf: NULL) = -1 (error)\n"
);

syscall_test!(
    parse_msgget_success,
    {
        let data = pinchy_common::MsggetData {
            key: 0xbeef,
            msgflg: libc::IPC_CREAT | libc::IPC_EXCL,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_msgget, 10101, 42, &data)
    },
    "10101 msgget(key: 0xbeef, msgflg: IPC_CREAT|IPC_EXCL) = 42 (msqid)\n"
);

syscall_test!(
    parse_msgsnd_success,
    {
        let data = pinchy_common::MsgsndData {
                    msqid: 123,
                    msgp: 0x7fff0000,
                    msgsz: 128,
                    msgflg: libc::IPC_NOWAIT | libc::MSG_NOERROR,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_msgsnd, 10202, 0, &data)
    },
    "10202 msgsnd(msqid: 123, msgp: 0x7fff0000, msgsz: 128, msgflg: IPC_NOWAIT|MSG_NOERROR) = 0 (success)\n"
);

syscall_test!(
    parse_msgrcv_success,
    {
        let data = pinchy_common::MsgrcvData {
            msqid: 321,
            msgp: 0x7fff1000,
            msgsz: 64,
            msgtyp: 2,
            msgflg: libc::MSG_NOERROR,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_msgrcv, 10303, 64, &data)
    },
    "10303 msgrcv(msqid: 321, msgp: 0x7fff1000, msgsz: 64, msgtyp: 2, msgflg: MSG_NOERROR) = 64\n"
);

syscall_test!(
    parse_msgctl_success,
    {
        let data = pinchy_common::MsgctlData {
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
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_msgctl, 10404, 0, &data)
    },
    "10404 msgctl(msqid: 555, cmd: IPC_STAT, buf: { ipc_perm { key: 0x123456, uid: 1001, gid: 1002, cuid: 1003, cgid: 1004, mode: 0o600 (rw-------), seq: 99 }, stime: 1620000000, rtime: 1620001000, ctime: 1620002000, cbytes: 256, qnum: 3, qbytes: 8192, lspid: 4321, lrpid: 8765 }) = 0 (success)\n"
);

syscall_test!(
    parse_msgctl_error,
    {
        let data = pinchy_common::MsgctlData {
            msqid: 666,
            op: libc::IPC_RMID,
            buf: pinchy_common::kernel_types::MsqidDs::default(),
            has_buf: false,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_msgctl, 10505, -1, &data)
    },
    "10505 msgctl(msqid: 666, cmd: IPC_RMID, buf: NULL) = -1 (error)\n"
);

syscall_test!(
    parse_semget_success,
    {
        let data = pinchy_common::SemgetData {
            key: 0xfeed,
            nsems: 4,
            semflg: libc::IPC_CREAT | libc::IPC_EXCL,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_semget, 20001, 123, &data)
    },
    "20001 semget(key: 0xfeed, nsems: 4, semflg: IPC_CREAT|IPC_EXCL) = 123 (semid)\n"
);

syscall_test!(
    parse_semget_error,
    {
        let data = pinchy_common::SemgetData {
            key: 0xbeef,
            nsems: 2,
            semflg: 0,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_semget, 20002, -1, &data)
    },
    "20002 semget(key: 0xbeef, nsems: 2, semflg: 0x0) = -1 (error)\n"
);

syscall_test!(
    parse_semop_success,
    {
        let data = pinchy_common::SemopData {
            semid: 321,
            sops: 0x7fff2000,
            nsops: 2,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_semop, 20003, 0, &data)
    },
    "20003 semop(semid: 321, sops: 0x7fff2000, nsops: 2) = 0 (success)\n"
);

syscall_test!(
    parse_semop_error,
    {
        let data = pinchy_common::SemopData {
            semid: 654,
            sops: 0x7fff3000,
            nsops: 1,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_semop, 20004, -1, &data)
    },
    "20004 semop(semid: 654, sops: 0x7fff3000, nsops: 1) = -1 (error)\n"
);

syscall_test!(
    parse_semctl_setval,
    {
        let data = pinchy_common::SemctlData {
            semid: 42,
            semnum: 1,
            op: libc::SETVAL,
            has_arg: true,
            arg: pinchy_common::kernel_types::Semun { val: 123 },
            array: [0u16; 16],
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_semctl, 20005, 0, &data)
    },
    "20005 semctl(semid: 42, semnum: 1, op: SETVAL, val: 123) = 0 (success)\n"
);

syscall_test!(
    parse_semctl_setall,
    {
        let data = pinchy_common::SemctlData {
            semid: 99,
            semnum: 0,
            op: libc::SETALL,
            has_arg: true,
            arg: pinchy_common::kernel_types::Semun { array: 0x7fff4000 },
            array: [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_semctl, 20006, 0, &data)
    },
    "20006 semctl(semid: 99, semnum: 0, op: SETALL, array: 0x7fff4000) = 0 (success)\n"
);

syscall_test!(
    parse_semctl_stat,
    {
        let data = pinchy_common::SemctlData {
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
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_semctl, 20007, 0, &data)
    },
    "20007 semctl(semid: 77, semnum: 0, op: IPC_STAT, buf: { ipc_perm { key: 0xabcdef, uid: 1000, gid: 1000, cuid: 1000, cgid: 1000, mode: 0o600 (rw-------), seq: 7 }, otime: 1620000000, ctime: 1620001000, nsems: 4 }) = 0 (success)\n"
);

syscall_test!(
    parse_semctl_error,
    {
        let data = pinchy_common::SemctlData {
            semid: 88,
            semnum: 2,
            op: libc::SETVAL,
            has_arg: false,
            arg: pinchy_common::kernel_types::Semun { val: 0 },
            array: [0u16; 16],
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_semctl, 20008, -1, &data)
    },
    "20008 semctl(semid: 88, semnum: 2, op: SETVAL, val: 0) = -1 (error)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_eventfd_success,
    {
        let data = pinchy_common::EventfdData {
            initval: 0,
            flags: 0,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_eventfd, 5555, 7, &data)
    },
    "5555 eventfd(initval: 0, flags: 0) = 7 (fd)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_eventfd_with_flags,
    {
        let data = pinchy_common::EventfdData {
            initval: 5,
            flags: libc::O_CLOEXEC, // EFD_CLOEXEC
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_eventfd, 6666, 8, &data)
    },
    "6666 eventfd(initval: 5, flags: 0x80000 (EFD_CLOEXEC)) = 8 (fd)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_eventfd_error,
    {
        let data = pinchy_common::EventfdData {
                    initval: 100,
                    flags: -1, // invalid flags
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_eventfd, 7777, -1, &data)
    },
    "7777 eventfd(initval: 100, flags: 0xffffffff (EFD_CLOEXEC|EFD_NONBLOCK|UNKNOWN)) = -1 (error)\n"
);

syscall_test!(
    parse_eventfd2_success,
    {
        let data = pinchy_common::Eventfd2Data {
            initval: 0,
            flags: libc::O_NONBLOCK, // EFD_NONBLOCK
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_eventfd2, 8888, 9, &data)
    },
    "8888 eventfd2(initval: 0, flags: 0x800 (EFD_NONBLOCK)) = 9 (fd)\n"
);

syscall_test!(
    parse_eventfd2_error,
    {
        let data = pinchy_common::Eventfd2Data {
            initval: 42,
            flags: 999999, // invalid flags
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_eventfd2, 9999, -1, &data)
    },
    "9999 eventfd2(initval: 42, flags: 0xf423f (EFD_CLOEXEC|UNKNOWN)) = -1 (error)\n"
);

syscall_test!(
    parse_mq_open_success_no_attr,
    {
        let data = pinchy_common::MqOpenData {
            name: 0x7fff1234,
            flags: libc::O_RDONLY,
            mode: 0,
            attr: pinchy_common::kernel_types::MqAttr::default(),
            has_attr: false,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mq_open, 1234, 3, &data)
    },
    "1234 mq_open(name: 0x7fff1234, flags: 0x0 (O_RDONLY), mode: 0, attr: NULL) = 3\n"
);

syscall_test!(
    parse_mq_open_success_with_attr,
    {
        let data = pinchy_common::MqOpenData {
                    name: 0x7fff5678,
                    flags: libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                    mode: 0o644,
                    attr: pinchy_common::kernel_types::MqAttr {
                        mq_flags: 0,
                        mq_maxmsg: 10,
                        mq_msgsize: 8192,
                        mq_curmsgs: 0,
                    },
                    has_attr: true,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mq_open, 1234, 4, &data)
    },
    "1234 mq_open(name: 0x7fff5678, flags: 0xc2 (O_RDWR|O_CREAT|O_EXCL), mode: 0o644 (rw-r--r--), attr: { mq_flags: 0, mq_maxmsg: 10, mq_msgsize: 8192, mq_curmsgs: 0 }) = 4\n"
);

syscall_test!(
    parse_mq_open_error,
    {
        let data = pinchy_common::MqOpenData {
                    name: 0x7fff9abc,
                    flags: libc::O_WRONLY | libc::O_NONBLOCK,
                    mode: 0o600,
                    attr: pinchy_common::kernel_types::MqAttr::default(),
                    has_attr: false,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mq_open, 5678, -1, &data)
    },
    "5678 mq_open(name: 0x7fff9abc, flags: 0x801 (O_WRONLY|O_NONBLOCK), mode: 0o600 (rw-------), attr: NULL) = -1 (error)\n"
);

syscall_test!(
    parse_mq_unlink_success,
    {
        let data = pinchy_common::MqUnlinkData { name: 0x7fff2345 };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mq_unlink, 2345, 0, &data)
    },
    "2345 mq_unlink(name: 0x7fff2345) = 0 (success)\n"
);

syscall_test!(
    parse_mq_unlink_error,
    {
        let data = pinchy_common::MqUnlinkData { name: 0x7fff3456 };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_mq_unlink,
            3456,
            -1,
            &data,
        )
    },
    "3456 mq_unlink(name: 0x7fff3456) = -1 (error)\n"
);

syscall_test!(
    parse_mq_timedsend_success,
    {
        let data = pinchy_common::MqTimedsendData {
                    mqdes: 3,
                    msg_ptr: 0x7fff4567,
                    msg_len: 1024,
                    msg_prio: 5,
                    abs_timeout: 0x7fff5678,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mq_timedsend, 4567, 0, &data)
    },
    "4567 mq_timedsend(mqdes: 3, msg_ptr: 0x7fff4567, msg_len: 1024, msg_prio: 5, abs_timeout: 0x7fff5678) = 0 (success)\n"
);

syscall_test!(
    parse_mq_timedsend_error,
    {
        let data = pinchy_common::MqTimedsendData {
                    mqdes: 4,
                    msg_ptr: 0x7fff6789,
                    msg_len: 2048,
                    msg_prio: 10,
                    abs_timeout: 0,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mq_timedsend, 5678, -1, &data)
    },
    "5678 mq_timedsend(mqdes: 4, msg_ptr: 0x7fff6789, msg_len: 2048, msg_prio: 10, abs_timeout: 0x0) = -1 (error)\n"
);

syscall_test!(
    parse_mq_timedreceive_success,
    {
        let data = pinchy_common::MqTimedreceiveData {
                    mqdes: 3,
                    msg_ptr: 0x7fff789a,
                    msg_len: 8192,
                    msg_prio: 0,
                    abs_timeout: 0x7fff89ab,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mq_timedreceive, 6789, 512, &data)
    },
    "6789 mq_timedreceive(mqdes: 3, msg_ptr: 0x7fff789a, msg_len: 8192, msg_prio: 0, abs_timeout: 0x7fff89ab) = 512\n"
);

syscall_test!(
    parse_mq_timedreceive_error,
    {
        let data = pinchy_common::MqTimedreceiveData {
                    mqdes: 5,
                    msg_ptr: 0x7fff9abc,
                    msg_len: 4096,
                    msg_prio: 1,
                    abs_timeout: 0,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mq_timedreceive, 7890, -1, &data)
    },
    "7890 mq_timedreceive(mqdes: 5, msg_ptr: 0x7fff9abc, msg_len: 4096, msg_prio: 1, abs_timeout: 0x0) = -1 (error)\n"
);

syscall_test!(
    parse_mq_notify_success,
    {
        let data = pinchy_common::MqNotifyData {
            mqdes: 3,
            sevp: 0x7fffabcd,
        };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mq_notify, 8901, 0, &data)
    },
    "8901 mq_notify(mqdes: 3, sevp: 0x7fffabcd) = 0 (success)\n"
);

syscall_test!(
    parse_mq_notify_error,
    {
        let data = pinchy_common::MqNotifyData { mqdes: 4, sevp: 0 };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_mq_notify,
            9012,
            -1,
            &data,
        )
    },
    "9012 mq_notify(mqdes: 4, sevp: 0x0) = -1 (error)\n"
);

syscall_test!(
    parse_mq_getsetattr_success,
    {
        let data = pinchy_common::MqGetsetattrData {
                    mqdes: 3,
                    newattr: pinchy_common::kernel_types::MqAttr {
                        mq_flags: libc::O_NONBLOCK as i64,
                        mq_maxmsg: 0,
                        mq_msgsize: 0,
                        mq_curmsgs: 0,
                    },
                    oldattr: pinchy_common::kernel_types::MqAttr {
                        mq_flags: 0,
                        mq_maxmsg: 10,
                        mq_msgsize: 8192,
                        mq_curmsgs: 2,
                    },
                    has_newattr: true,
                    has_oldattr: true,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_mq_getsetattr, 1357, 0, &data)
    },
    "1357 mq_getsetattr(mqdes: 3, newattr: { mq_flags: 2048, mq_maxmsg: 0, mq_msgsize: 0, mq_curmsgs: 0 }, oldattr: { mq_flags: 0, mq_maxmsg: 10, mq_msgsize: 8192, mq_curmsgs: 2 }) = 0 (success)\n"
);

syscall_test!(
    parse_mq_getsetattr_error,
    {
        let data = pinchy_common::MqGetsetattrData {
            mqdes: 99,
            newattr: pinchy_common::kernel_types::MqAttr::default(),
            oldattr: pinchy_common::kernel_types::MqAttr::default(),
            has_newattr: false,
            has_oldattr: false,
        };

        crate::tests::make_compact_test_data(
            pinchy_common::syscalls::SYS_mq_getsetattr,
            2468,
            -1,
            &data,
        )
    },
    "2468 mq_getsetattr(mqdes: 99, newattr: NULL, oldattr: NULL) = -1 (error)\n"
);

syscall_test!(
    parse_semtimedop_success,
    {

        use pinchy_common::kernel_types::{Sembuf, Timespec};

        let data = pinchy_common::SemtimedopData {
                    semid: 123,
                    sops: [
                        Sembuf {
                            sem_num: 0,
                            sem_op: -1,
                            sem_flg: 0,
                        },
                        Sembuf {
                            sem_num: 1,
                            sem_op: 1,
                            sem_flg: libc::IPC_NOWAIT as i16,
                        },
                        Sembuf::default(),
                        Sembuf::default(),
                    ],
                    nsops: 2,
                    timeout: Timespec {
                        seconds: 5,
                        nanos: 500000000,
                    },
                    timeout_is_null: 0,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_semtimedop, 300, 0, &data)
    },
    "300 semtimedop(semid: 123, sops: [ sembuf { sem_num: 0, sem_op: -1, sem_flg: 0x0 }, sembuf { sem_num: 1, sem_op: 1, sem_flg: 0x800 } ], nsops: 2, timeout: {tv_sec: 5, tv_nsec: 500000000}) = 0 (success)\n"
);

syscall_test!(
    parse_semtimedop_null_timeout,
    {

        use pinchy_common::kernel_types::{Sembuf, Timespec};

        let data = pinchy_common::SemtimedopData {
                    semid: 456,
                    sops: [
                        Sembuf {
                            sem_num: 0,
                            sem_op: 1,
                            sem_flg: 0,
                        },
                        Sembuf::default(),
                        Sembuf::default(),
                        Sembuf::default(),
                    ],
                    nsops: 1,
                    timeout: Timespec::default(),
                    timeout_is_null: 1,
                };

        crate::tests::make_compact_test_data(pinchy_common::syscalls::SYS_semtimedop, 301, 0, &data)
    },
    "301 semtimedop(semid: 456, sops: [ sembuf { sem_num: 0, sem_op: 1, sem_flg: 0x0 } ], nsops: 1, timeout: NULL) = 0 (success)\n"
);
