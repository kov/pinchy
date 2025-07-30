// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::helpers::{bpf_probe_read_buf, bpf_probe_read_user};
use pinchy_common::kernel_types::{Sysinfo, Timespec, Timeval, Timezone, Tms, Utsname};

use crate::syscall_handler;

syscall_handler!(uname, uname, args, data, {
    let buf_ptr = args[0] as *const u8;
    data.utsname = Utsname::default();
    const FIELD_SIZE: usize = 65;
    unsafe {
        let _ = bpf_probe_read_buf(
            buf_ptr,
            core::slice::from_raw_parts_mut(
                data.utsname.sysname.as_mut_ptr(),
                pinchy_common::kernel_types::SYSNAME_READ_SIZE,
            ),
        );
        let _ = bpf_probe_read_buf(
            buf_ptr.add(FIELD_SIZE),
            core::slice::from_raw_parts_mut(
                data.utsname.nodename.as_mut_ptr(),
                pinchy_common::kernel_types::NODENAME_READ_SIZE,
            ),
        );
        let _ = bpf_probe_read_buf(
            buf_ptr.add(2 * FIELD_SIZE),
            core::slice::from_raw_parts_mut(
                data.utsname.release.as_mut_ptr(),
                pinchy_common::kernel_types::RELEASE_READ_SIZE,
            ),
        );
        let _ = bpf_probe_read_buf(
            buf_ptr.add(3 * FIELD_SIZE),
            core::slice::from_raw_parts_mut(
                data.utsname.version.as_mut_ptr(),
                pinchy_common::kernel_types::VERSION_READ_SIZE,
            ),
        );
        let _ = bpf_probe_read_buf(
            buf_ptr.add(4 * FIELD_SIZE),
            core::slice::from_raw_parts_mut(
                data.utsname.machine.as_mut_ptr(),
                pinchy_common::kernel_types::MACHINE_READ_SIZE,
            ),
        );
        let _ = bpf_probe_read_buf(
            buf_ptr.add(5 * FIELD_SIZE),
            core::slice::from_raw_parts_mut(
                data.utsname.domainname.as_mut_ptr(),
                pinchy_common::kernel_types::DOMAIN_READ_SIZE,
            ),
        );
    }
});

syscall_handler!(ioctl, ioctl, args, data, {
    data.fd = args[0] as i32;
    data.request = args[1] as u32;
    data.arg = args[2];
});

syscall_handler!(gettimeofday, args, data, {
    data.has_tv = false;
    data.has_tz = false;

    let tv_ptr = args[0] as *const Timeval;
    if let Ok(val) = unsafe { bpf_probe_read_user::<Timeval>(tv_ptr) } {
        data.tv = val;
        data.has_tv = true;
    }

    let tz_ptr = args[1] as *const Timezone;
    if let Ok(val) = unsafe { bpf_probe_read_user::<Timezone>(tz_ptr) } {
        data.tz = val;
        data.has_tz = true;
    }
});

syscall_handler!(settimeofday, settimeofday, args, data, {
    data.has_tv = false;
    data.has_tz = false;

    let tv_ptr = args[0] as *const Timeval;
    if let Ok(val) = unsafe { bpf_probe_read_user::<Timeval>(tv_ptr) } {
        data.tv = val;
        data.has_tv = true;
    }

    let tz_ptr = args[1] as *const Timezone;
    if let Ok(val) = unsafe { bpf_probe_read_user::<Timezone>(tz_ptr) } {
        data.tz = val;
        data.has_tz = true;
    }
});

syscall_handler!(sysinfo, args, data, {
    let info_ptr = args[0] as *const Sysinfo;
    data.has_info = false;
    if let Ok(val) = unsafe { bpf_probe_read_user::<Sysinfo>(info_ptr) } {
        data.info = val;
        data.has_info = true;
    }
});

syscall_handler!(times, args, data, {
    let buf_ptr = args[0] as *const Tms;
    data.buf = Tms::default();
    data.has_buf = false;
    if let Ok(val) = unsafe { bpf_probe_read_user::<Tms>(buf_ptr) } {
        data.buf = val;
        data.has_buf = true;
    }
});

syscall_handler!(nanosleep, args, data, {
    data.has_rem = false;

    let req_ptr = args[0] as *const Timespec;
    if let Ok(val) = unsafe { bpf_probe_read_user::<Timespec>(req_ptr) } {
        data.req = val;
    }

    let rem_ptr = args[1] as *const Timespec;
    if let Ok(val) = unsafe { bpf_probe_read_user::<Timespec>(rem_ptr) } {
        data.rem = val;
        data.has_rem = true;
    }
});

syscall_handler!(clock_nanosleep, args, data, {
    data.clockid = args[0] as i32;
    data.flags = args[1] as i32;
    data.has_rem = false;

    let req_ptr = args[2] as *const Timespec;
    if let Ok(val) = unsafe { bpf_probe_read_user::<Timespec>(req_ptr) } {
        data.req = val;
    }

    let rem_ptr = args[3] as *const Timespec;
    if let Ok(val) = unsafe { bpf_probe_read_user::<Timespec>(rem_ptr) } {
        data.rem = val;
        data.has_rem = true;
    }
});

syscall_handler!(getcpu, args, data, {
    let cpu_ptr = args[0] as *const u32;
    let node_ptr = args[1] as *const u32;
    data.tcache = args[2];

    if !cpu_ptr.is_null() {
        if let Ok(val) = unsafe { bpf_probe_read_user::<u32>(cpu_ptr) } {
            data.cpu = val;
            data.has_cpu = true;
        }
    }

    if !node_ptr.is_null() {
        if let Ok(val) = unsafe { bpf_probe_read_user::<u32>(node_ptr) } {
            data.node = val;
            data.has_node = true;
        }
    }
});
