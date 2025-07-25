// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_buf, bpf_probe_read_user},
    macros::tracepoint,
    programs::TracePointContext,
};
use pinchy_common::{
    kernel_types::{Sysinfo, Timespec, Timeval, Timezone, Tms, Utsname},
    syscalls::{
        SYS_clock_nanosleep, SYS_gettimeofday, SYS_ioctl, SYS_nanosleep, SYS_settimeofday,
        SYS_sysinfo, SYS_times, SYS_uname,
    },
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

#[tracepoint]
pub fn syscall_exit_gettimeofday(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_gettimeofday;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let tv_ptr = args[0] as *const Timeval;
        let tz_ptr = args[1] as *const Timezone;

        let mut tv = Timeval::default();
        let mut tz = Timezone::default();
        let mut has_tv = false;
        let mut has_tz = false;

        // Read timeval struct if pointer is valid and syscall succeeded
        if !tv_ptr.is_null() && return_value == 0 {
            if let Ok(data) = unsafe { bpf_probe_read_user::<Timeval>(tv_ptr) } {
                tv = data;
                has_tv = true;
            }
        }

        // Read timezone struct if pointer is valid and syscall succeeded
        if !tz_ptr.is_null() && return_value == 0 {
            if let Ok(data) = unsafe { bpf_probe_read_user::<Timezone>(tz_ptr) } {
                tz = data;
                has_tz = true;
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                gettimeofday: pinchy_common::GettimeofdayData {
                    tv,
                    tz,
                    has_tv,
                    has_tz,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_settimeofday(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_settimeofday;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let tv_ptr = args[0] as *const Timeval;
        let tz_ptr = args[1] as *const Timezone;

        let mut tv = Timeval::default();
        let mut tz = Timezone::default();
        let mut has_tv = false;
        let mut has_tz = false;

        // Read timeval struct if pointer is valid (we read it even if syscall failed)
        if !tv_ptr.is_null() {
            if let Ok(data) = unsafe { bpf_probe_read_user::<Timeval>(tv_ptr) } {
                tv = data;
                has_tv = true;
            }
        }

        // Read timezone struct if pointer is valid (we read it even if syscall failed)
        if !tz_ptr.is_null() {
            if let Ok(data) = unsafe { bpf_probe_read_user::<Timezone>(tz_ptr) } {
                tz = data;
                has_tz = true;
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                settimeofday: pinchy_common::SettimeofdayData {
                    tv,
                    tz,
                    has_tv,
                    has_tz,
                },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_sysinfo(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_sysinfo;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let info_ptr = args[0] as *const Sysinfo;

        let mut info = Sysinfo::default();
        let mut has_info = false;

        // Read sysinfo struct if pointer is valid and syscall succeeded
        if !info_ptr.is_null() && return_value == 0 {
            if let Ok(data) = unsafe { bpf_probe_read_user::<Sysinfo>(info_ptr) } {
                info = data;
                has_info = true;
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                sysinfo: pinchy_common::SysinfoData { info, has_info },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_times(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_times;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let buf_ptr = args[0] as *const Tms;

        let mut buf = Tms::default();
        let mut has_buf = false;

        // Read tms struct if pointer is valid and syscall succeeded
        if !buf_ptr.is_null() && return_value >= 0 {
            if let Ok(data) = unsafe { bpf_probe_read_user::<Tms>(buf_ptr) } {
                buf = data;
                has_buf = true;
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                times: pinchy_common::TimesData { buf, has_buf },
            },
        )
    }
    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_nanosleep(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_nanosleep;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let req_ptr = args[0] as *const Timespec;
        let rem_ptr = args[1] as *const Timespec;

        let mut req = Timespec::default();
        let mut rem = Timespec::default();
        let mut has_rem = false;

        // Read the request timespec if pointer is valid
        if !req_ptr.is_null() {
            if let Ok(data) = unsafe { bpf_probe_read_user::<Timespec>(req_ptr) } {
                req = data;
            }
        }

        // Read the remaining timespec if pointer is valid and syscall was interrupted (EINTR)
        if !rem_ptr.is_null() && return_value == -4 {
            // -4 is EINTR (interrupted system call)
            if let Ok(data) = unsafe { bpf_probe_read_user::<Timespec>(rem_ptr) } {
                rem = data;
                has_rem = true;
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                nanosleep: pinchy_common::NanosleepData { req, rem, has_rem },
            },
        )
    }

    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_exit_clock_nanosleep(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = SYS_clock_nanosleep;
        let args = get_args(&ctx, syscall_nr)?;
        let return_value = get_return_value(&ctx)?;

        let clockid = args[0] as i32;
        let flags = args[1] as i32;
        let req_ptr = args[2] as *const Timespec;
        let rem_ptr = args[3] as *const Timespec;

        let mut req = Timespec::default();
        let mut rem = Timespec::default();
        let mut has_rem = false;

        // Read the request timespec if pointer is valid
        if !req_ptr.is_null() {
            if let Ok(data) = unsafe { bpf_probe_read_user::<Timespec>(req_ptr) } {
                req = data;
            }
        }

        // Read the remaining timespec if pointer is valid, syscall was interrupted (EINTR),
        // and it's a relative sleep (flags == 0)
        if !rem_ptr.is_null() && return_value == -4 && flags == 0 {
            // -4 is EINTR (interrupted system call)
            // Only relative sleeps (flags == 0) set the remaining time
            if let Ok(data) = unsafe { bpf_probe_read_user::<Timespec>(rem_ptr) } {
                rem = data;
                has_rem = true;
            }
        }

        output_event(
            &ctx,
            syscall_nr,
            return_value,
            pinchy_common::SyscallEventData {
                clock_nanosleep: pinchy_common::ClockNanosleepData {
                    clockid,
                    flags,
                    req,
                    rem,
                    has_rem,
                },
            },
        )
    }

    match inner(ctx) {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}
