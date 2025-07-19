// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{helpers::bpf_probe_read_buf, macros::tracepoint, programs::TracePointContext};
use pinchy_common::{
    kernel_types::Utsname,
    syscalls::{SYS_ioctl, SYS_uname},
};

use crate::util::{get_args, get_return_value, output_event};

#[tracepoint]
pub fn syscall_exit_uname(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_uname;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let buf_ptr = args[0] as *const u8;
        let mut utsname = Utsname::default();

        // Each field in the Linux kernel utsname struct is 65 bytes
        // We read fewer bytes of most fields to fit within eBPF stack limits
        const FIELD_SIZE: usize = 65; // Linux kernel field size

        // Read sysname (offset 0)
        unsafe {
            let _ = bpf_probe_read_buf(
                buf_ptr,
                core::slice::from_raw_parts_mut(
                    utsname.sysname.as_mut_ptr(),
                    pinchy_common::kernel_types::SYSNAME_READ_SIZE,
                ),
            );
        }

        // Read nodename (offset FIELD_SIZE)
        unsafe {
            let _ = bpf_probe_read_buf(
                buf_ptr.add(FIELD_SIZE),
                core::slice::from_raw_parts_mut(
                    utsname.nodename.as_mut_ptr(),
                    pinchy_common::kernel_types::NODENAME_READ_SIZE,
                ),
            );
        }

        // Read release (offset 2 * FIELD_SIZE)
        unsafe {
            let _ = bpf_probe_read_buf(
                buf_ptr.add(2 * FIELD_SIZE),
                core::slice::from_raw_parts_mut(
                    utsname.release.as_mut_ptr(),
                    pinchy_common::kernel_types::RELEASE_READ_SIZE,
                ),
            );
        }

        // Read version (offset 3 * FIELD_SIZE)
        unsafe {
            let _ = bpf_probe_read_buf(
                buf_ptr.add(3 * FIELD_SIZE),
                core::slice::from_raw_parts_mut(
                    utsname.version.as_mut_ptr(),
                    pinchy_common::kernel_types::VERSION_READ_SIZE,
                ),
            );
        }

        // Read machine (offset 4 * FIELD_SIZE)
        unsafe {
            let _ = bpf_probe_read_buf(
                buf_ptr.add(4 * FIELD_SIZE),
                core::slice::from_raw_parts_mut(
                    utsname.machine.as_mut_ptr(),
                    pinchy_common::kernel_types::MACHINE_READ_SIZE,
                ),
            );
        }

        // Read domainname (offset 5 * FIELD_SIZE)
        unsafe {
            let _ = bpf_probe_read_buf(
                buf_ptr.add(5 * FIELD_SIZE),
                core::slice::from_raw_parts_mut(
                    utsname.domainname.as_mut_ptr(),
                    pinchy_common::kernel_types::DOMAIN_READ_SIZE,
                ),
            );
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                uname: pinchy_common::UnameData { utsname },
            },
        )
    }

    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_ioctl(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_ioctl;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let fd = args[0] as i32;
        let request = args[1] as u32;
        let arg = args[2];

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                ioctl: pinchy_common::IoctlData { fd, request, arg },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}
