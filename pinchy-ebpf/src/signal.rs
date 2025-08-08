// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::helpers::{bpf_probe_read_buf, bpf_probe_read_user};
use pinchy_common::kernel_types::{self, StackT};

use crate::{syscall_handler, util::read_sigset};

syscall_handler!(rt_sigprocmask, args, data, {
    data.how = args[0] as i32;
    data.set = args[1];
    data.oldset = args[2];
    data.sigsetsize = args[3];

    if let Some(set_data) = read_sigset(args[1] as *const _) {
        data.set_data = set_data;
        data.has_set_data = true;
    }

    if let Some(oldset_data) = read_sigset(args[2] as *const _) {
        data.oldset_data = oldset_data;
        data.has_oldset_data = true;
    }
});

syscall_handler!(rt_sigpending, args, data, {
    data.set = args[0];
    data.sigsetsize = args[1];

    if let Some(set_data) = read_sigset(args[0] as *const _) {
        data.set_data = set_data;
        data.has_set_data = true;
    }
});

syscall_handler!(rt_sigsuspend, args, data, {
    data.mask = args[0];
    data.sigsetsize = args[1];

    if let Some(mask_data) = read_sigset(args[0] as *const _) {
        data.mask_data = mask_data;
        data.has_mask_data = true;
    }
});

syscall_handler!(rt_sigtimedwait, args, data, {
    data.set = args[0];
    data.info = args[1];
    data.timeout = args[2];
    data.sigsetsize = args[3];

    if let Some(set_data) = read_sigset(args[0] as *const _) {
        data.set_data = set_data;
        data.has_set_data = true;
    }
});

syscall_handler!(sigaltstack, args, data, {
    data.ss_ptr = args[0];
    data.old_ss_ptr = args[1];

    let ss_ptr = args[0] as *const u8;
    if !ss_ptr.is_null() {
        let buf = unsafe {
            core::slice::from_raw_parts_mut(
                &mut data.ss as *mut StackT as *mut u8,
                core::mem::size_of::<StackT>(),
            )
        };

        let _ = unsafe { bpf_probe_read_buf(ss_ptr, buf) };
        data.has_ss = true;
    }

    let old_ss_ptr = args[1] as *const u8;

    if !old_ss_ptr.is_null() {
        let buf = unsafe {
            core::slice::from_raw_parts_mut(
                &mut data.old_ss as *mut StackT as *mut u8,
                core::mem::size_of::<StackT>(),
            )
        };

        let _ = unsafe { bpf_probe_read_buf(old_ss_ptr, buf) };
        data.has_old_ss = true;
    }
});

#[cfg(x86_64)]
syscall_handler!(signalfd, args, data, {
    data.fd = args[0] as i32;
    data.flags = args[2] as i32;

    let mask_ptr = args[1] as *const kernel_types::Sigset;
    if !mask_ptr.is_null() {
        unsafe {
            data.mask = bpf_probe_read_user::<kernel_types::Sigset>(mask_ptr).unwrap_or_default();
        }
        data.has_mask = true;
    }
});

syscall_handler!(signalfd4, args, data, {
    data.fd = args[0] as i32;
    data.flags = args[2] as i32;

    let mask_ptr = args[1] as *const kernel_types::Sigset;
    if !mask_ptr.is_null() {
        unsafe {
            data.mask = bpf_probe_read_user::<kernel_types::Sigset>(mask_ptr).unwrap_or_default();
        }
        data.has_mask = true;
    }
});
