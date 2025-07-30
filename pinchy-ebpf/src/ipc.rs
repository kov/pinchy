// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::helpers::bpf_probe_read_user;
use pinchy_common::kernel_types;

use crate::syscall_handler;

syscall_handler!(shmget, args, data, {
    data.key = args[0] as i32;
    data.size = args[1] as usize;
    data.shmflg = args[2] as i32;
});

syscall_handler!(shmat, args, data, {
    data.shmid = args[0] as i32;
    data.shmaddr = args[1];
    data.shmflg = args[2] as i32;
});

syscall_handler!(shmdt, args, data, {
    data.shmaddr = args[0];
});

syscall_handler!(shmctl, args, data, {
    data.shmid = args[0] as i32;
    data.cmd = args[1] as i32;

    let buf_ptr = args[2] as *const kernel_types::ShmidDs;
    if !buf_ptr.is_null() {
        data.has_buf = true;
        data.buf = unsafe {
            bpf_probe_read_user::<kernel_types::ShmidDs>(buf_ptr)
                .unwrap_or(kernel_types::ShmidDs::default())
        };
    } else {
        data.has_buf = false;
    }
});

// System V message queue handlers
syscall_handler!(msgget, args, data, {
    data.key = args[0] as i32;
    data.msgflg = args[1] as i32;
});

syscall_handler!(msgsnd, args, data, {
    data.msqid = args[0] as i32;
    data.msgp = args[1];
    data.msgsz = args[2] as usize;
    data.msgflg = args[3] as i32;
});

syscall_handler!(msgrcv, args, data, {
    data.msqid = args[0] as i32;
    data.msgp = args[1];
    data.msgsz = args[2] as usize;
    data.msgtyp = args[3] as i64;
    data.msgflg = args[4] as i32;
});

syscall_handler!(msgctl, args, data, {
    data.msqid = args[0] as i32;
    data.op = args[1] as i32;

    let buf_ptr = args[2] as *const kernel_types::MsqidDs;
    if !buf_ptr.is_null() {
        data.has_buf = true;
        data.buf = unsafe {
            bpf_probe_read_user::<kernel_types::MsqidDs>(buf_ptr)
                .unwrap_or(kernel_types::MsqidDs::default())
        };
    } else {
        data.has_buf = false;
    }
});

// System V semaphore handlers
syscall_handler!(semget, args, data, {
    data.key = args[0] as i32;
    data.nsems = args[1] as i32;
    data.semflg = args[2] as i32;
});

syscall_handler!(semop, args, data, {
    data.semid = args[0] as i32;
    data.sops = args[1];
    data.nsops = args[2] as usize;
});

syscall_handler!(semctl, args, data, {
    data.semid = args[0] as i32;
    data.semnum = args[1] as i32;
    data.op = args[2] as i32;

    // We cannot use libc:: here, so we define our own constants - we could read the size of the union,
    // but the eBPF verifier doesn't like that, it wants us to read the specific members.
    const IPC_STAT: i32 = 2;
    const IPC_SET: i32 = 1;
    const IPC_RMID: i32 = 0;
    const IPC_INFO: i32 = 3;
    const SEM_STAT: i32 = 18;
    const SEM_INFO: i32 = 19;
    const GETPID: i32 = 11;
    const GETVAL: i32 = 12;
    const GETALL: i32 = 13;
    const GETNCNT: i32 = 14;
    const GETZCNT: i32 = 15;
    const SETVAL: i32 = 16;
    const SETALL: i32 = 17;

    let arg_ptr = args[3] as *const kernel_types::Semun;
    data.has_arg = !arg_ptr.is_null();
    if data.has_arg {
        match data.op {
            SETVAL => {
                let val_ptr = arg_ptr as *const i32;

                data.arg.val = unsafe { bpf_probe_read_user::<i32>(val_ptr).unwrap_or(0) };
            }
            SETALL | GETALL => {
                let array_ptr = arg_ptr as *const u16;

                data.arg.array = arg_ptr as usize;

                for (i, item) in data.array.iter_mut().enumerate() {
                    unsafe {
                        *item = bpf_probe_read_user::<u16>(array_ptr.add(i)).unwrap_or(0);
                    }
                }
            }
            IPC_STAT | IPC_SET => {
                let buf_ptr = arg_ptr as *const kernel_types::SemidDs;

                data.arg.buf = unsafe {
                    bpf_probe_read_user::<kernel_types::SemidDs>(buf_ptr).unwrap_or_default()
                };
            }
            IPC_INFO | SEM_INFO => {
                let info_ptr = arg_ptr as *const kernel_types::Seminfo;

                data.arg.info = unsafe {
                    bpf_probe_read_user::<kernel_types::Seminfo>(info_ptr).unwrap_or_default()
                };
            }
            IPC_RMID | SEM_STAT | GETPID | GETVAL | GETNCNT | GETZCNT => {}
            _ => {
                // For other ops, just store the pointer value
                data.arg.array = arg_ptr as usize;
            }
        }
    }
});
