// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{helpers::bpf_probe_read_user, macros::tracepoint, programs::TracePointContext};
use pinchy_common::{kernel_types, syscalls};

use crate::util::{get_args, get_return_value, get_syscall_nr};

#[tracepoint]
pub fn syscall_exit_ipc(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = get_syscall_nr(&ctx)?;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_shmget => {
                crate::util::submit_compact_payload::<pinchy_common::ShmgetData, _>(
                    &ctx,
                    syscalls::SYS_shmget,
                    return_value,
                    |payload| {
                        payload.key = args[0] as i32;
                        payload.size = args[1] as usize;
                        payload.shmflg = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_shmat => {
                crate::util::submit_compact_payload::<pinchy_common::ShmatData, _>(
                    &ctx,
                    syscalls::SYS_shmat,
                    return_value,
                    |payload| {
                        payload.shmid = args[0] as i32;
                        payload.shmaddr = args[1];
                        payload.shmflg = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_shmdt => {
                crate::util::submit_compact_payload::<pinchy_common::ShmdtData, _>(
                    &ctx,
                    syscalls::SYS_shmdt,
                    return_value,
                    |payload| {
                        payload.shmaddr = args[0];
                    },
                )?;
            }
            syscalls::SYS_shmctl => {
                crate::util::submit_compact_payload::<pinchy_common::ShmctlData, _>(
                    &ctx,
                    syscalls::SYS_shmctl,
                    return_value,
                    |payload| {
                        payload.shmid = args[0] as i32;
                        payload.cmd = args[1] as i32;

                        let buf_ptr = args[2] as *const kernel_types::ShmidDs;
                        if !buf_ptr.is_null() {
                            payload.has_buf = true;
                            payload.buf = unsafe {
                                bpf_probe_read_user::<kernel_types::ShmidDs>(buf_ptr)
                                    .unwrap_or(kernel_types::ShmidDs::default())
                            };
                        } else {
                            payload.has_buf = false;
                        }
                    },
                )?;
            }
            syscalls::SYS_msgget => {
                crate::util::submit_compact_payload::<pinchy_common::MsggetData, _>(
                    &ctx,
                    syscalls::SYS_msgget,
                    return_value,
                    |payload| {
                        payload.key = args[0] as i32;
                        payload.msgflg = args[1] as i32;
                    },
                )?;
            }
            syscalls::SYS_msgsnd => {
                crate::util::submit_compact_payload::<pinchy_common::MsgsndData, _>(
                    &ctx,
                    syscalls::SYS_msgsnd,
                    return_value,
                    |payload| {
                        payload.msqid = args[0] as i32;
                        payload.msgp = args[1];
                        payload.msgsz = args[2] as usize;
                        payload.msgflg = args[3] as i32;
                    },
                )?;
            }
            syscalls::SYS_msgrcv => {
                crate::util::submit_compact_payload::<pinchy_common::MsgrcvData, _>(
                    &ctx,
                    syscalls::SYS_msgrcv,
                    return_value,
                    |payload| {
                        payload.msqid = args[0] as i32;
                        payload.msgp = args[1];
                        payload.msgsz = args[2] as usize;
                        payload.msgtyp = args[3] as i64;
                        payload.msgflg = args[4] as i32;
                    },
                )?;
            }
            syscalls::SYS_msgctl => {
                crate::util::submit_compact_payload::<pinchy_common::MsgctlData, _>(
                    &ctx,
                    syscalls::SYS_msgctl,
                    return_value,
                    |payload| {
                        payload.msqid = args[0] as i32;
                        payload.op = args[1] as i32;

                        let buf_ptr = args[2] as *const kernel_types::MsqidDs;
                        if !buf_ptr.is_null() {
                            payload.has_buf = true;
                            payload.buf = unsafe {
                                bpf_probe_read_user::<kernel_types::MsqidDs>(buf_ptr)
                                    .unwrap_or(kernel_types::MsqidDs::default())
                            };
                        } else {
                            payload.has_buf = false;
                        }
                    },
                )?;
            }
            syscalls::SYS_semget => {
                crate::util::submit_compact_payload::<pinchy_common::SemgetData, _>(
                    &ctx,
                    syscalls::SYS_semget,
                    return_value,
                    |payload| {
                        payload.key = args[0] as i32;
                        payload.nsems = args[1] as i32;
                        payload.semflg = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_semop => {
                crate::util::submit_compact_payload::<pinchy_common::SemopData, _>(
                    &ctx,
                    syscalls::SYS_semop,
                    return_value,
                    |payload| {
                        payload.semid = args[0] as i32;
                        payload.sops = args[1];
                        payload.nsops = args[2] as usize;
                    },
                )?;
            }
            syscalls::SYS_semtimedop => {
                crate::util::submit_compact_payload::<pinchy_common::SemtimedopData, _>(
                    &ctx,
                    syscalls::SYS_semtimedop,
                    return_value,
                    |payload| {
                        payload.semid = args[0] as i32;
                        payload.nsops = args[2] as usize;

                        let sops_ptr = args[1] as *const kernel_types::Sembuf;

                        for (i, sop) in payload.sops.iter_mut().enumerate() {
                            if i < payload.nsops && i < 4 {
                                unsafe {
                                    if let Ok(val) =
                                        bpf_probe_read_user::<kernel_types::Sembuf>(sops_ptr.add(i))
                                    {
                                        *sop = val;
                                    }
                                }
                            }
                        }

                        let timeout_ptr = args[3] as *const kernel_types::Timespec;

                        if timeout_ptr.is_null() {
                            payload.timeout_is_null = 1;
                        } else {
                            payload.timeout_is_null = 0;
                            payload.timeout = unsafe {
                                bpf_probe_read_user::<kernel_types::Timespec>(timeout_ptr)
                                    .unwrap_or(kernel_types::Timespec::default())
                            };
                        }
                    },
                )?;
            }
            syscalls::SYS_semctl => {
                crate::util::submit_compact_payload::<pinchy_common::SemctlData, _>(
                    &ctx,
                    syscalls::SYS_semctl,
                    return_value,
                    |payload| {
                        payload.semid = args[0] as i32;
                        payload.semnum = args[1] as i32;
                        payload.op = args[2] as i32;

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
                        payload.has_arg = !arg_ptr.is_null();
                        if payload.has_arg {
                            match payload.op {
                                SETVAL => {
                                    let val_ptr = arg_ptr as *const i32;

                                    payload.arg.val =
                                        unsafe { bpf_probe_read_user::<i32>(val_ptr).unwrap_or(0) };
                                }
                                SETALL | GETALL => {
                                    let array_ptr = arg_ptr as *const u16;

                                    payload.arg.array = arg_ptr as usize;

                                    for (i, item) in payload.array.iter_mut().enumerate() {
                                        unsafe {
                                            *item = bpf_probe_read_user::<u16>(array_ptr.add(i))
                                                .unwrap_or(0);
                                        }
                                    }
                                }
                                IPC_STAT | IPC_SET => {
                                    let buf_ptr = arg_ptr as *const kernel_types::SemidDs;

                                    payload.arg.buf = unsafe {
                                        bpf_probe_read_user::<kernel_types::SemidDs>(buf_ptr)
                                            .unwrap_or_default()
                                    };
                                }
                                IPC_INFO | SEM_INFO => {
                                    let info_ptr = arg_ptr as *const kernel_types::Seminfo;

                                    payload.arg.info = unsafe {
                                        bpf_probe_read_user::<kernel_types::Seminfo>(info_ptr)
                                            .unwrap_or_default()
                                    };
                                }
                                IPC_RMID | SEM_STAT | GETPID | GETVAL | GETNCNT | GETZCNT => {}
                                _ => {
                                    // For other ops, just store the pointer value
                                    payload.arg.array = arg_ptr as usize;
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_mq_open => {
                crate::util::submit_compact_payload::<pinchy_common::MqOpenData, _>(
                    &ctx,
                    syscalls::SYS_mq_open,
                    return_value,
                    |payload| {
                        payload.name = args[0];
                        payload.flags = args[1] as i32;
                        payload.mode = args[2] as u32;

                        let attr_ptr = args[3] as *const kernel_types::MqAttr;
                        if !attr_ptr.is_null() {
                            payload.has_attr = true;
                            payload.attr = unsafe {
                                bpf_probe_read_user::<kernel_types::MqAttr>(attr_ptr)
                                    .unwrap_or(kernel_types::MqAttr::default())
                            };
                        } else {
                            payload.has_attr = false;
                        }
                    },
                )?;
            }
            syscalls::SYS_mq_unlink => {
                crate::util::submit_compact_payload::<pinchy_common::MqUnlinkData, _>(
                    &ctx,
                    syscalls::SYS_mq_unlink,
                    return_value,
                    |payload| {
                        payload.name = args[0];
                    },
                )?;
            }
            syscalls::SYS_mq_timedsend => {
                crate::util::submit_compact_payload::<pinchy_common::MqTimedsendData, _>(
                    &ctx,
                    syscalls::SYS_mq_timedsend,
                    return_value,
                    |payload| {
                        payload.mqdes = args[0] as i32;
                        payload.msg_ptr = args[1];
                        payload.msg_len = args[2] as usize;
                        payload.msg_prio = args[3] as u32;
                        payload.abs_timeout = args[4];
                    },
                )?;
            }
            syscalls::SYS_mq_timedreceive => {
                crate::util::submit_compact_payload::<pinchy_common::MqTimedreceiveData, _>(
                    &ctx,
                    syscalls::SYS_mq_timedreceive,
                    return_value,
                    |payload| {
                        payload.mqdes = args[0] as i32;
                        payload.msg_ptr = args[1];
                        payload.msg_len = args[2] as usize;

                        // msg_prio is an output parameter (pointer to unsigned int)
                        // Read the actual priority value that was written by the kernel
                        let msg_prio_ptr = args[3] as *const u32;
                        if !msg_prio_ptr.is_null() {
                            payload.msg_prio =
                                unsafe { bpf_probe_read_user::<u32>(msg_prio_ptr).unwrap_or(0) };
                        } else {
                            payload.msg_prio = 0;
                        }

                        payload.abs_timeout = args[4];
                    },
                )?;
            }
            syscalls::SYS_mq_notify => {
                crate::util::submit_compact_payload::<pinchy_common::MqNotifyData, _>(
                    &ctx,
                    syscalls::SYS_mq_notify,
                    return_value,
                    |payload| {
                        payload.mqdes = args[0] as i32;
                        payload.sevp = args[1];
                    },
                )?;
            }
            syscalls::SYS_mq_getsetattr => {
                crate::util::submit_compact_payload::<pinchy_common::MqGetsetattrData, _>(
                    &ctx,
                    syscalls::SYS_mq_getsetattr,
                    return_value,
                    |payload| {
                        payload.mqdes = args[0] as i32;

                        let newattr_ptr = args[1] as *const kernel_types::MqAttr;
                        if !newattr_ptr.is_null() {
                            payload.has_newattr = true;
                            payload.newattr = unsafe {
                                bpf_probe_read_user::<kernel_types::MqAttr>(newattr_ptr)
                                    .unwrap_or(kernel_types::MqAttr::default())
                            };
                        } else {
                            payload.has_newattr = false;
                        }

                        let oldattr_ptr = args[2] as *const kernel_types::MqAttr;
                        if !oldattr_ptr.is_null() {
                            payload.has_oldattr = true;
                            payload.oldattr = unsafe {
                                bpf_probe_read_user::<kernel_types::MqAttr>(oldattr_ptr)
                                    .unwrap_or(kernel_types::MqAttr::default())
                            };
                        } else {
                            payload.has_oldattr = false;
                        }
                    },
                )?;
            }
            _ => {}
        }

        Ok(())
    }

    match inner(ctx) {
        Ok(()) => 0,
        Err(e) => e,
    }
}
