// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{helpers::bpf_probe_read_user, macros::tracepoint, programs::TracePointContext};
use pinchy_common::{kernel_types, syscalls};

use crate::{
    data_mut,
    util::{get_args, get_return_value, get_syscall_nr, Entry},
};

#[tracepoint]
pub fn syscall_exit_ipc(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = get_syscall_nr(&ctx)?;
        let args = get_args(&ctx, syscall_nr)?;
        let _return_value = get_return_value(&ctx)?;

        let mut entry = Entry::new(&ctx, syscall_nr)?;

        match syscall_nr {
            syscalls::SYS_shmget => {
                let data = data_mut!(entry, shmget);
                data.key = args[0] as i32;
                data.size = args[1] as usize;
                data.shmflg = args[2] as i32;
            }
            syscalls::SYS_shmat => {
                let data = data_mut!(entry, shmat);
                data.shmid = args[0] as i32;
                data.shmaddr = args[1];
                data.shmflg = args[2] as i32;
            }
            syscalls::SYS_shmdt => {
                let data = data_mut!(entry, shmdt);
                data.shmaddr = args[0];
            }
            syscalls::SYS_shmctl => {
                let data = data_mut!(entry, shmctl);
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
            }
            syscalls::SYS_msgget => {
                let data = data_mut!(entry, msgget);
                data.key = args[0] as i32;
                data.msgflg = args[1] as i32;
            }
            syscalls::SYS_msgsnd => {
                let data = data_mut!(entry, msgsnd);
                data.msqid = args[0] as i32;
                data.msgp = args[1];
                data.msgsz = args[2] as usize;
                data.msgflg = args[3] as i32;
            }
            syscalls::SYS_msgrcv => {
                let data = data_mut!(entry, msgrcv);
                data.msqid = args[0] as i32;
                data.msgp = args[1];
                data.msgsz = args[2] as usize;
                data.msgtyp = args[3] as i64;
                data.msgflg = args[4] as i32;
            }
            syscalls::SYS_msgctl => {
                let data = data_mut!(entry, msgctl);
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
            }
            syscalls::SYS_semget => {
                let data = data_mut!(entry, semget);
                data.key = args[0] as i32;
                data.nsems = args[1] as i32;
                data.semflg = args[2] as i32;
            }
            syscalls::SYS_semop => {
                let data = data_mut!(entry, semop);
                data.semid = args[0] as i32;
                data.sops = args[1];
                data.nsops = args[2] as usize;
            }
            syscalls::SYS_semctl => {
                let data = data_mut!(entry, semctl);
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

                            data.arg.val =
                                unsafe { bpf_probe_read_user::<i32>(val_ptr).unwrap_or(0) };
                        }
                        SETALL | GETALL => {
                            let array_ptr = arg_ptr as *const u16;

                            data.arg.array = arg_ptr as usize;

                            for (i, item) in data.array.iter_mut().enumerate() {
                                unsafe {
                                    *item =
                                        bpf_probe_read_user::<u16>(array_ptr.add(i)).unwrap_or(0);
                                }
                            }
                        }
                        IPC_STAT | IPC_SET => {
                            let buf_ptr = arg_ptr as *const kernel_types::SemidDs;

                            data.arg.buf = unsafe {
                                bpf_probe_read_user::<kernel_types::SemidDs>(buf_ptr)
                                    .unwrap_or_default()
                            };
                        }
                        IPC_INFO | SEM_INFO => {
                            let info_ptr = arg_ptr as *const kernel_types::Seminfo;

                            data.arg.info = unsafe {
                                bpf_probe_read_user::<kernel_types::Seminfo>(info_ptr)
                                    .unwrap_or_default()
                            };
                        }
                        IPC_RMID | SEM_STAT | GETPID | GETVAL | GETNCNT | GETZCNT => {}
                        _ => {
                            // For other ops, just store the pointer value
                            data.arg.array = arg_ptr as usize;
                        }
                    }
                }
            }
            syscalls::SYS_mq_open => {
                let data = data_mut!(entry, mq_open);
                data.name = args[0];
                data.flags = args[1] as i32;
                data.mode = args[2] as u32;

                let attr_ptr = args[3] as *const kernel_types::MqAttr;
                if !attr_ptr.is_null() {
                    data.has_attr = true;
                    data.attr = unsafe {
                        bpf_probe_read_user::<kernel_types::MqAttr>(attr_ptr)
                            .unwrap_or(kernel_types::MqAttr::default())
                    };
                } else {
                    data.has_attr = false;
                }
            }
            syscalls::SYS_mq_unlink => {
                let data = data_mut!(entry, mq_unlink);
                data.name = args[0];
            }
            syscalls::SYS_mq_timedsend => {
                let data = data_mut!(entry, mq_timedsend);
                data.mqdes = args[0] as i32;
                data.msg_ptr = args[1];
                data.msg_len = args[2] as usize;
                data.msg_prio = args[3] as u32;
                data.abs_timeout = args[4];
            }
            syscalls::SYS_mq_timedreceive => {
                let data = data_mut!(entry, mq_timedreceive);
                data.mqdes = args[0] as i32;
                data.msg_ptr = args[1];
                data.msg_len = args[2] as usize;

                // msg_prio is an output parameter (pointer to unsigned int)
                // Read the actual priority value that was written by the kernel
                let msg_prio_ptr = args[3] as *const u32;
                if !msg_prio_ptr.is_null() {
                    data.msg_prio =
                        unsafe { bpf_probe_read_user::<u32>(msg_prio_ptr).unwrap_or(0) };
                } else {
                    data.msg_prio = 0;
                }

                data.abs_timeout = args[4];
            }
            syscalls::SYS_mq_notify => {
                let data = data_mut!(entry, mq_notify);
                data.mqdes = args[0] as i32;
                data.sevp = args[1];
            }
            syscalls::SYS_mq_getsetattr => {
                let data = data_mut!(entry, mq_getsetattr);
                data.mqdes = args[0] as i32;

                let newattr_ptr = args[1] as *const kernel_types::MqAttr;
                if !newattr_ptr.is_null() {
                    data.has_newattr = true;
                    data.newattr = unsafe {
                        bpf_probe_read_user::<kernel_types::MqAttr>(newattr_ptr)
                            .unwrap_or(kernel_types::MqAttr::default())
                    };
                } else {
                    data.has_newattr = false;
                }

                let oldattr_ptr = args[2] as *const kernel_types::MqAttr;
                if !oldattr_ptr.is_null() {
                    data.has_oldattr = true;
                    data.oldattr = unsafe {
                        bpf_probe_read_user::<kernel_types::MqAttr>(oldattr_ptr)
                            .unwrap_or(kernel_types::MqAttr::default())
                    };
                } else {
                    data.has_oldattr = false;
                }
            }
            _ => {
                entry.discard();
                return Ok(());
            }
        }

        entry.submit();
        Ok(())
    }

    match inner(ctx) {
        Ok(()) => 0,
        Err(e) => e,
    }
}
