// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use aya_ebpf::{
    helpers::{bpf_probe_read_user, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes},
    macros::tracepoint,
    programs::TracePointContext,
};
use pinchy_common::{
    kernel_types::{
        self, CapUserData, CapUserHeader, LandlockNetPortAttr, LandlockPathBeneathAttr, Rlimit,
        Sysinfo, Timespec, Timeval, Timezone, Tms, Utsname,
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
                    if let Ok(()) = unsafe { bpf_probe_read_user_buf(arg_ptr, &mut data.restart2) }
                    {
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
                    let _ = bpf_probe_read_user_buf(
                        buf_ptr,
                        core::slice::from_raw_parts_mut(
                            data.utsname.sysname.as_mut_ptr(),
                            pinchy_common::kernel_types::SYSNAME_READ_SIZE,
                        ),
                    );
                    let _ = bpf_probe_read_user_buf(
                        buf_ptr.add(FIELD_SIZE),
                        core::slice::from_raw_parts_mut(
                            data.utsname.nodename.as_mut_ptr(),
                            pinchy_common::kernel_types::NODENAME_READ_SIZE,
                        ),
                    );
                    let _ = bpf_probe_read_user_buf(
                        buf_ptr.add(2 * FIELD_SIZE),
                        core::slice::from_raw_parts_mut(
                            data.utsname.release.as_mut_ptr(),
                            pinchy_common::kernel_types::RELEASE_READ_SIZE,
                        ),
                    );
                    let _ = bpf_probe_read_user_buf(
                        buf_ptr.add(3 * FIELD_SIZE),
                        core::slice::from_raw_parts_mut(
                            data.utsname.version.as_mut_ptr(),
                            pinchy_common::kernel_types::VERSION_READ_SIZE,
                        ),
                    );
                    let _ = bpf_probe_read_user_buf(
                        buf_ptr.add(4 * FIELD_SIZE),
                        core::slice::from_raw_parts_mut(
                            data.utsname.machine.as_mut_ptr(),
                            pinchy_common::kernel_types::MACHINE_READ_SIZE,
                        ),
                    );
                    let _ = bpf_probe_read_user_buf(
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
                    let _ = unsafe { bpf_probe_read_user_buf(param_ptr, &mut data.param_values) };
                }
            }
            syscalls::SYS_finit_module => {
                let data = data_mut!(entry, finit_module);
                data.fd = args[0] as i32;
                data.flags = args[2] as u32;

                let param_ptr = args[1] as *const u8;
                if !param_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_user_buf(param_ptr, &mut data.param_values) };
                }
            }
            syscalls::SYS_delete_module => {
                let data = data_mut!(entry, delete_module);
                data.flags = args[1] as i32;

                let name_ptr = args[0] as *const u8;
                if !name_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_user_buf(name_ptr, &mut data.name) };
                }
            }
            syscalls::SYS_sethostname => {
                let data = data_mut!(entry, sethostname);
                data.len = args[1];

                let name_ptr = args[0] as *const u8;
                if !name_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_user_buf(name_ptr, &mut data.name) };
                }
            }
            syscalls::SYS_setdomainname => {
                let data = data_mut!(entry, setdomainname);
                data.len = args[1];

                let name_ptr = args[0] as *const u8;
                if !name_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_user_buf(name_ptr, &mut data.name) };
                }
            }
            syscalls::SYS_prctl => {
                let data = data_mut!(entry, generic);
                data.args = args;
            }
            syscalls::SYS_landlock_create_ruleset => {
                let data = data_mut!(entry, landlock_create_ruleset);
                data.attr = args[0] as u64;
                data.size = args[1];
                data.flags = args[2] as u32;
            }
            syscalls::SYS_landlock_add_rule => {
                let data = data_mut!(entry, landlock_add_rule);
                data.ruleset_fd = args[0] as i32;
                data.rule_type = args[1] as u32;
                data.rule_attr = args[2] as u64;
                data.flags = args[3] as u32;

                let rule_attr_ptr = args[2] as *const u8;

                match data.rule_type {
                    pinchy_common::LANDLOCK_RULE_PATH_BENEATH => {
                        if let Ok(attr) = unsafe {
                            bpf_probe_read_user::<LandlockPathBeneathAttr>(
                                rule_attr_ptr as *const LandlockPathBeneathAttr,
                            )
                        } {
                            data.rule_attr_data.path_beneath = attr;
                        }
                    }
                    pinchy_common::LANDLOCK_RULE_NET_PORT => {
                        if let Ok(attr) = unsafe {
                            bpf_probe_read_user::<LandlockNetPortAttr>(
                                rule_attr_ptr as *const LandlockNetPortAttr,
                            )
                        } {
                            data.rule_attr_data.net_port = attr;
                        }
                    }
                    _ => {}
                }
            }
            syscalls::SYS_landlock_restrict_self => {
                let data = data_mut!(entry, landlock_restrict_self);
                data.ruleset_fd = args[0] as i32;
                data.flags = args[1] as u32;
            }
            syscalls::SYS_add_key => {
                let data = data_mut!(entry, add_key);
                data.keyring = args[4] as i32;

                let type_ptr = args[0] as *const u8;
                let desc_ptr = args[1] as *const u8;
                let payload_ptr = args[2] as *const u8;
                let payload_len = args[3];

                if !type_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_user_buf(type_ptr, &mut data.key_type) };
                }

                if !desc_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_user_buf(desc_ptr, &mut data.description) };
                }

                if !payload_ptr.is_null() && payload_len > 0 {
                    data.payload_len = if payload_len > pinchy_common::MEDIUM_READ_SIZE {
                        pinchy_common::MEDIUM_READ_SIZE
                    } else {
                        payload_len
                    };
                    let _ = unsafe {
                        bpf_probe_read_user_buf(
                            payload_ptr,
                            core::slice::from_raw_parts_mut(
                                data.payload.as_mut_ptr(),
                                data.payload_len,
                            ),
                        )
                    };
                } else {
                    data.payload_len = 0;
                }
            }
            syscalls::SYS_request_key => {
                let data = data_mut!(entry, request_key);
                data.dest_keyring = args[3] as i32;

                let type_ptr = args[0] as *const u8;
                let desc_ptr = args[1] as *const u8;
                let info_ptr = args[2] as *const u8;

                if !type_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_user_buf(type_ptr, &mut data.key_type) };
                }

                if !desc_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_user_buf(desc_ptr, &mut data.description) };
                }

                if !info_ptr.is_null() {
                    let _ = unsafe { bpf_probe_read_user_buf(info_ptr, &mut data.callout_info) };
                    data.callout_info_len = pinchy_common::MEDIUM_READ_SIZE;
                } else {
                    data.callout_info_len = 0;
                }
            }
            syscalls::SYS_keyctl => {
                let data = data_mut!(entry, keyctl);
                data.operation = args[0] as i32;
                data.arg1 = args[1] as u64;
                data.arg2 = args[2] as u64;
                data.arg3 = args[3] as u64;
                data.arg4 = args[4] as u64;
            }
            syscalls::SYS_perf_event_open => {
                let data = data_mut!(entry, perf_event_open);

                let attr_ptr = args[0] as *const pinchy_common::kernel_types::PerfEventAttr;
                if !attr_ptr.is_null() {
                    data.attr = unsafe {
                        bpf_probe_read_user::<pinchy_common::kernel_types::PerfEventAttr>(attr_ptr)
                    }
                    .unwrap_or_default();
                }

                data.pid = args[1] as i32;
                data.cpu = args[2] as i32;
                data.group_fd = args[3] as i32;
                data.flags = args[4] as u64;
            }
            syscalls::SYS_bpf => {
                let data = data_mut!(entry, bpf);
                let cmd = args[0] as i32;
                data.cmd = cmd;
                data.size = args[2] as u32;

                let attr_ptr = args[1] as usize;
                if attr_ptr != 0 {
                    // BPF_MAP_CREATE = 0
                    if cmd == pinchy_common::kernel_types::bpf_cmd::MAP_CREATE {
                        let map_attr_ptr =
                            attr_ptr as *const pinchy_common::kernel_types::BpfMapCreateAttr;
                        if let Ok(attr) = unsafe {
                            bpf_probe_read_user::<pinchy_common::kernel_types::BpfMapCreateAttr>(
                                map_attr_ptr,
                            )
                        } {
                            data.map_create_attr = attr;
                            data.which_attr = 1;
                        }
                    }
                    // BPF_PROG_LOAD = 5
                    else if cmd == pinchy_common::kernel_types::bpf_cmd::PROG_LOAD {
                        let prog_attr_ptr =
                            attr_ptr as *const pinchy_common::kernel_types::BpfProgLoadAttr;
                        if let Ok(attr) = unsafe {
                            bpf_probe_read_user::<pinchy_common::kernel_types::BpfProgLoadAttr>(
                                prog_attr_ptr,
                            )
                        } {
                            data.prog_load_attr = attr;
                            data.which_attr = 2;

                            // Read the license string from the pointer
                            let license_ptr = attr.license as *const u8;
                            if !license_ptr.is_null() {
                                unsafe {
                                    let _ = bpf_probe_read_user_str_bytes(
                                        license_ptr,
                                        &mut data.license_str,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            syscalls::SYS_syslog => {
                let data = data_mut!(entry, syslog);
                data.type_ = args[0] as i32;
                data.bufp = args[1] as u64;
                data.size = args[2] as i32;
            }
            syscalls::SYS_restart_syscall => {
                let _data = data_mut!(entry, restart_syscall);
                // No arguments to capture
            }
            syscalls::SYS_kexec_load => {
                let data = data_mut!(entry, kexec_load);
                data.entry = args[0] as u64;
                data.nr_segments = args[1] as u64;
                data.segments = args[2] as u64;
                data.flags = args[3] as u64;

                let segments_ptr = args[2] as *const kernel_types::KexecSegment;

                if !segments_ptr.is_null() && data.nr_segments > 0 {
                    let max_to_read = core::cmp::min(
                        kernel_types::KEXEC_SEGMENT_ARRAY_CAP,
                        data.nr_segments as usize,
                    );

                    for i in 0..max_to_read {
                        unsafe {
                            let ptr = segments_ptr.add(i);

                            if let Ok(segment) = bpf_probe_read_user(ptr) {
                                data.parsed_segments[i] = segment;
                                data.segments_read += 1;
                            } else {
                                break;
                            }
                        }
                    }
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
