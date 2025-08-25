// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_buf, bpf_probe_read_user},
    macros::tracepoint,
    programs::TracePointContext,
};
use pinchy_common::{
    kernel_types::{
        self, CapUserData, CapUserHeader, Rlimit, Sysinfo, Timespec, Timeval, Timezone, Tms,
        Utsname,
    },
    syscalls,
};

use crate::{data_mut, util};

#[tracepoint]
pub fn syscall_exit_system(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;

        let mut entry = util::Entry::new(&ctx, syscall_nr)?;

        match syscall_nr {
            syscalls::SYS_reboot => {
                let data = data_mut!(entry, reboot);
                data.magic1 = args[0] as i32;
                data.magic2 = args[1] as i32;
                data.cmd = args[2] as i32;
                data.arg = args[3] as u64;

                data.has_restart2 = false;

                let arg_ptr = args[3] as *const u8;

                if !arg_ptr.is_null() {
                    // Best-effort read; mark present only on successful copy
                    if let Ok(()) = unsafe { bpf_probe_read_buf(arg_ptr, &mut data.restart2) } {
                        data.has_restart2 = true;
                    }
                }
            }
            syscalls::SYS_uname => {
                let data = data_mut!(entry, uname);
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
            }
            syscalls::SYS_ioctl => {
                let data = data_mut!(entry, ioctl);
                data.fd = args[0] as i32;
                data.request = args[1] as u32;
                data.arg = args[2];
            }
            syscalls::SYS_gettimeofday => {
                let data = data_mut!(entry, gettimeofday);
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
            }
            syscalls::SYS_settimeofday => {
                let data = data_mut!(entry, settimeofday);
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
            }
            syscalls::SYS_sysinfo => {
                let data = data_mut!(entry, sysinfo);
                let info_ptr = args[0] as *const Sysinfo;
                data.has_info = false;
                if let Ok(val) = unsafe { bpf_probe_read_user::<Sysinfo>(info_ptr) } {
                    data.info = val;
                    data.has_info = true;
                }
            }
            syscalls::SYS_times => {
                let data = data_mut!(entry, times);
                let buf_ptr = args[0] as *const Tms;
                data.buf = Tms::default();
                data.has_buf = false;
                if let Ok(val) = unsafe { bpf_probe_read_user::<Tms>(buf_ptr) } {
                    data.buf = val;
                    data.has_buf = true;
                }
            }
            syscalls::SYS_nanosleep => {
                let data = data_mut!(entry, nanosleep);
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
            }
            syscalls::SYS_clock_nanosleep => {
                let data = data_mut!(entry, clock_nanosleep);
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
            }
            syscalls::SYS_getcpu => {
                let data = data_mut!(entry, getcpu);
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
            }
            syscalls::SYS_capget => {
                let data = data_mut!(entry, capsetget);
                read_cap_header_and_data(&args, data);
            }
            syscalls::SYS_capset => {
                let data = data_mut!(entry, capsetget);
                read_cap_header_and_data(&args, data);
            }
            syscalls::SYS_setrlimit => {
                let data = data_mut!(entry, rlimit);
                data.resource = args[0] as i32;

                let rlim_ptr = args[1] as *const Rlimit;
                data.has_limit = false;
                if !rlim_ptr.is_null() {
                    if let Ok(val) = unsafe { bpf_probe_read_user::<Rlimit>(rlim_ptr) } {
                        data.limit = val;
                        data.has_limit = true;
                    }
                }
            }
            syscalls::SYS_getrlimit => {
                let data = data_mut!(entry, rlimit);
                data.resource = args[0] as i32;

                let rlim_ptr = args[1] as *const Rlimit;
                data.has_limit = false;
                if !rlim_ptr.is_null() {
                    if let Ok(val) = unsafe { bpf_probe_read_user::<Rlimit>(rlim_ptr) } {
                        data.limit = val;
                        data.has_limit = true;
                    }
                }
            }
            syscalls::SYS_init_module => {
                let data = data_mut!(entry, init_module);
                data.module_image = args[0];
                data.len = args[1];

                let param_ptr = args[2] as *const u8;
                if !param_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_buf(param_ptr, &mut data.param_values) };
                }
            }
            syscalls::SYS_finit_module => {
                let data = data_mut!(entry, finit_module);
                data.fd = args[0] as i32;
                data.flags = args[2] as u32;

                let param_ptr = args[1] as *const u8;
                if !param_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_buf(param_ptr, &mut data.param_values) };
                }
            }
            syscalls::SYS_delete_module => {
                let data = data_mut!(entry, delete_module);
                data.flags = args[1] as i32;

                let name_ptr = args[0] as *const u8;
                if !name_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_buf(name_ptr, &mut data.name) };
                }
            }
            syscalls::SYS_sethostname => {
                let data = data_mut!(entry, sethostname);
                data.len = args[1];

                let name_ptr = args[0] as *const u8;
                if !name_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_buf(name_ptr, &mut data.name) };
                }
            }
            syscalls::SYS_setdomainname => {
                let data = data_mut!(entry, setdomainname);
                data.len = args[1];

                let name_ptr = args[0] as *const u8;
                if !name_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_buf(name_ptr, &mut data.name) };
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
        Err(code) => code,
    }
}

fn read_cap_header_and_data(args: &[usize; 6], data: &mut pinchy_common::CapsetgetData) {
    let header_ptr = args[0] as *const CapUserHeader;
    let data_ptr = args[1] as *const CapUserData;

    data.header = CapUserHeader::default();
    data.data_count = 0;
    data.data = [CapUserData::default(); 3];

    if let Ok(header) = unsafe { bpf_probe_read_user::<CapUserHeader>(header_ptr) } {
        data.header = header;

        let count = match header.version {
            kernel_types::LINUX_CAPABILITY_VERSION_1 => 1,
            kernel_types::LINUX_CAPABILITY_VERSION_2 => 2,
            kernel_types::LINUX_CAPABILITY_VERSION_3 => 3,
            _ => 0,
        };

        data.data_count = count;

        let mut i = 0;

        while i < count {
            let ptr = unsafe { data_ptr.add(i as usize) };

            if let Ok(val) = unsafe { bpf_probe_read_user::<CapUserData>(ptr) } {
                data.data[i as usize] = val;
            }

            i += 1;
        }
    }
}
