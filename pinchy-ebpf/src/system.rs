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

use crate::util;

#[tracepoint]
pub fn syscall_exit_system(ctx: TracePointContext) -> u32 {
    fn inner(ctx: TracePointContext) -> Result<(), u32> {
        let syscall_nr = util::get_syscall_nr(&ctx)?;
        let args = util::get_args(&ctx, syscall_nr)?;
        let return_value = util::get_return_value(&ctx)?;

        match syscall_nr {
            syscalls::SYS_reboot => {
                crate::util::submit_compact_payload::<pinchy_common::RebootData, _>(
                    &ctx,
                    syscalls::SYS_reboot,
                    return_value,
                    |payload| {
                        payload.magic1 = args[0] as i32;
                        payload.magic2 = args[1] as i32;
                        payload.cmd = args[2] as i32;
                        payload.arg = args[3] as u64;

                        payload.has_restart2 = false;

                        let arg_ptr = args[3] as *const u8;

                        if !arg_ptr.is_null() {
                            // Best-effort read; mark present only on successful copy
                            if let Ok(()) =
                                unsafe { bpf_probe_read_user_buf(arg_ptr, &mut payload.restart2) }
                            {
                                payload.has_restart2 = true;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_uname => {
                crate::util::submit_compact_payload::<pinchy_common::UnameData, _>(
                    &ctx,
                    syscalls::SYS_uname,
                    return_value,
                    |payload| {
                        let buf_ptr = args[0] as *const u8;
                        payload.utsname = Utsname::default();
                        const FIELD_SIZE: usize = 65;
                        unsafe {
                            let _ = bpf_probe_read_user_buf(
                                buf_ptr,
                                core::slice::from_raw_parts_mut(
                                    payload.utsname.sysname.as_mut_ptr(),
                                    pinchy_common::kernel_types::SYSNAME_READ_SIZE,
                                ),
                            );
                            let _ = bpf_probe_read_user_buf(
                                buf_ptr.add(FIELD_SIZE),
                                core::slice::from_raw_parts_mut(
                                    payload.utsname.nodename.as_mut_ptr(),
                                    pinchy_common::kernel_types::NODENAME_READ_SIZE,
                                ),
                            );
                            let _ = bpf_probe_read_user_buf(
                                buf_ptr.add(2 * FIELD_SIZE),
                                core::slice::from_raw_parts_mut(
                                    payload.utsname.release.as_mut_ptr(),
                                    pinchy_common::kernel_types::RELEASE_READ_SIZE,
                                ),
                            );
                            let _ = bpf_probe_read_user_buf(
                                buf_ptr.add(3 * FIELD_SIZE),
                                core::slice::from_raw_parts_mut(
                                    payload.utsname.version.as_mut_ptr(),
                                    pinchy_common::kernel_types::VERSION_READ_SIZE,
                                ),
                            );
                            let _ = bpf_probe_read_user_buf(
                                buf_ptr.add(4 * FIELD_SIZE),
                                core::slice::from_raw_parts_mut(
                                    payload.utsname.machine.as_mut_ptr(),
                                    pinchy_common::kernel_types::MACHINE_READ_SIZE,
                                ),
                            );
                            let _ = bpf_probe_read_user_buf(
                                buf_ptr.add(5 * FIELD_SIZE),
                                core::slice::from_raw_parts_mut(
                                    payload.utsname.domainname.as_mut_ptr(),
                                    pinchy_common::kernel_types::DOMAIN_READ_SIZE,
                                ),
                            );
                        }
                    },
                )?;
            }
            syscalls::SYS_ioctl => {
                crate::util::submit_compact_payload::<pinchy_common::IoctlData, _>(
                    &ctx,
                    syscalls::SYS_ioctl,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.request = args[1] as u32;
                        payload.arg = args[2];
                    },
                )?;
            }
            syscalls::SYS_gettimeofday => {
                crate::util::submit_compact_payload::<pinchy_common::GettimeofdayData, _>(
                    &ctx,
                    syscalls::SYS_gettimeofday,
                    return_value,
                    |payload| {
                        payload.has_tv = false;
                        payload.has_tz = false;

                        let tv_ptr = args[0] as *const Timeval;
                        if let Ok(val) = unsafe { bpf_probe_read_user::<Timeval>(tv_ptr) } {
                            payload.tv = val;
                            payload.has_tv = true;
                        }

                        let tz_ptr = args[1] as *const Timezone;
                        if let Ok(val) = unsafe { bpf_probe_read_user::<Timezone>(tz_ptr) } {
                            payload.tz = val;
                            payload.has_tz = true;
                        }
                    },
                )?;
            }
            syscalls::SYS_settimeofday => {
                crate::util::submit_compact_payload::<pinchy_common::SettimeofdayData, _>(
                    &ctx,
                    syscalls::SYS_settimeofday,
                    return_value,
                    |payload| {
                        payload.has_tv = false;
                        payload.has_tz = false;

                        let tv_ptr = args[0] as *const Timeval;
                        if let Ok(val) = unsafe { bpf_probe_read_user::<Timeval>(tv_ptr) } {
                            payload.tv = val;
                            payload.has_tv = true;
                        }

                        let tz_ptr = args[1] as *const Timezone;
                        if let Ok(val) = unsafe { bpf_probe_read_user::<Timezone>(tz_ptr) } {
                            payload.tz = val;
                            payload.has_tz = true;
                        }
                    },
                )?;
            }
            syscalls::SYS_sysinfo => {
                crate::util::submit_compact_payload::<pinchy_common::SysinfoData, _>(
                    &ctx,
                    syscalls::SYS_sysinfo,
                    return_value,
                    |payload| {
                        let info_ptr = args[0] as *const Sysinfo;
                        payload.has_info = false;
                        if let Ok(val) = unsafe { bpf_probe_read_user::<Sysinfo>(info_ptr) } {
                            payload.info = val;
                            payload.has_info = true;
                        }
                    },
                )?;
            }
            syscalls::SYS_times => {
                crate::util::submit_compact_payload::<pinchy_common::TimesData, _>(
                    &ctx,
                    syscalls::SYS_times,
                    return_value,
                    |payload| {
                        let buf_ptr = args[0] as *const Tms;
                        payload.buf = Tms::default();
                        payload.has_buf = false;
                        if let Ok(val) = unsafe { bpf_probe_read_user::<Tms>(buf_ptr) } {
                            payload.buf = val;
                            payload.has_buf = true;
                        }
                    },
                )?;
            }
            syscalls::SYS_nanosleep => {
                crate::util::submit_compact_payload::<pinchy_common::NanosleepData, _>(
                    &ctx,
                    syscalls::SYS_nanosleep,
                    return_value,
                    |payload| {
                        payload.has_rem = false;

                        let req_ptr = args[0] as *const Timespec;
                        if let Ok(val) = unsafe { bpf_probe_read_user::<Timespec>(req_ptr) } {
                            payload.req = val;
                        }

                        let rem_ptr = args[1] as *const Timespec;
                        if let Ok(val) = unsafe { bpf_probe_read_user::<Timespec>(rem_ptr) } {
                            payload.rem = val;
                            payload.has_rem = true;
                        }
                    },
                )?;
            }
            syscalls::SYS_clock_nanosleep => {
                crate::util::submit_compact_payload::<pinchy_common::ClockNanosleepData, _>(
                    &ctx,
                    syscalls::SYS_clock_nanosleep,
                    return_value,
                    |payload| {
                        payload.clockid = args[0] as i32;
                        payload.flags = args[1] as i32;
                        payload.has_rem = false;

                        let req_ptr = args[2] as *const Timespec;
                        if let Ok(val) = unsafe { bpf_probe_read_user::<Timespec>(req_ptr) } {
                            payload.req = val;
                        }

                        let rem_ptr = args[3] as *const Timespec;
                        if let Ok(val) = unsafe { bpf_probe_read_user::<Timespec>(rem_ptr) } {
                            payload.rem = val;
                            payload.has_rem = true;
                        }
                    },
                )?;
            }
            syscalls::SYS_getcpu => {
                crate::util::submit_compact_payload::<pinchy_common::GetcpuData, _>(
                    &ctx,
                    syscalls::SYS_getcpu,
                    return_value,
                    |payload| {
                        let cpu_ptr = args[0] as *const u32;
                        let node_ptr = args[1] as *const u32;
                        payload.tcache = args[2];

                        if !cpu_ptr.is_null() {
                            if let Ok(val) = unsafe { bpf_probe_read_user::<u32>(cpu_ptr) } {
                                payload.cpu = val;
                                payload.has_cpu = true;
                            }
                        }

                        if !node_ptr.is_null() {
                            if let Ok(val) = unsafe { bpf_probe_read_user::<u32>(node_ptr) } {
                                payload.node = val;
                                payload.has_node = true;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_capget => {
                crate::util::submit_compact_payload::<pinchy_common::CapsetgetData, _>(
                    &ctx,
                    syscalls::SYS_capget,
                    return_value,
                    |payload| {
                        read_cap_header_and_data(&args, payload);
                    },
                )?;
            }
            syscalls::SYS_capset => {
                crate::util::submit_compact_payload::<pinchy_common::CapsetgetData, _>(
                    &ctx,
                    syscalls::SYS_capset,
                    return_value,
                    |payload| {
                        read_cap_header_and_data(&args, payload);
                    },
                )?;
            }
            syscalls::SYS_setrlimit => {
                crate::util::submit_compact_payload::<pinchy_common::RlimitData, _>(
                    &ctx,
                    syscalls::SYS_setrlimit,
                    return_value,
                    |payload| {
                        payload.resource = args[0] as i32;

                        let rlim_ptr = args[1] as *const Rlimit;
                        payload.has_limit = false;
                        if !rlim_ptr.is_null() {
                            if let Ok(val) = unsafe { bpf_probe_read_user::<Rlimit>(rlim_ptr) } {
                                payload.limit = val;
                                payload.has_limit = true;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_getrlimit => {
                crate::util::submit_compact_payload::<pinchy_common::RlimitData, _>(
                    &ctx,
                    syscalls::SYS_getrlimit,
                    return_value,
                    |payload| {
                        payload.resource = args[0] as i32;

                        let rlim_ptr = args[1] as *const Rlimit;
                        payload.has_limit = false;
                        if !rlim_ptr.is_null() {
                            if let Ok(val) = unsafe { bpf_probe_read_user::<Rlimit>(rlim_ptr) } {
                                payload.limit = val;
                                payload.has_limit = true;
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_init_module => {
                crate::util::submit_compact_payload::<pinchy_common::InitModuleData, _>(
                    &ctx,
                    syscalls::SYS_init_module,
                    return_value,
                    |payload| {
                        payload.module_image = args[0];
                        payload.len = args[1];

                        let param_ptr = args[2] as *const u8;
                        if !param_ptr.is_null() {
                            let _ = unsafe {
                                bpf_probe_read_user_buf(param_ptr, &mut payload.param_values)
                            };
                        }
                    },
                )?;
            }
            syscalls::SYS_finit_module => {
                crate::util::submit_compact_payload::<pinchy_common::FinitModuleData, _>(
                    &ctx,
                    syscalls::SYS_finit_module,
                    return_value,
                    |payload| {
                        payload.fd = args[0] as i32;
                        payload.flags = args[2] as u32;

                        let param_ptr = args[1] as *const u8;
                        if !param_ptr.is_null() {
                            let _ = unsafe {
                                bpf_probe_read_user_buf(param_ptr, &mut payload.param_values)
                            };
                        }
                    },
                )?;
            }
            syscalls::SYS_delete_module => {
                crate::util::submit_compact_payload::<pinchy_common::DeleteModuleData, _>(
                    &ctx,
                    syscalls::SYS_delete_module,
                    return_value,
                    |payload| {
                        payload.flags = args[1] as i32;

                        let name_ptr = args[0] as *const u8;
                        if !name_ptr.is_null() {
                            let _ = unsafe { bpf_probe_read_user_buf(name_ptr, &mut payload.name) };
                        }
                    },
                )?;
            }
            syscalls::SYS_sethostname => {
                crate::util::submit_compact_payload::<pinchy_common::SethostnameData, _>(
                    &ctx,
                    syscalls::SYS_sethostname,
                    return_value,
                    |payload| {
                        payload.len = args[1];

                        let name_ptr = args[0] as *const u8;
                        if !name_ptr.is_null() {
                            let _ = unsafe { bpf_probe_read_user_buf(name_ptr, &mut payload.name) };
                        }
                    },
                )?;
            }
            syscalls::SYS_setdomainname => {
                crate::util::submit_compact_payload::<pinchy_common::SetdomainnameData, _>(
                    &ctx,
                    syscalls::SYS_setdomainname,
                    return_value,
                    |payload| {
                        payload.len = args[1];

                        let name_ptr = args[0] as *const u8;
                        if !name_ptr.is_null() {
                            let _ = unsafe { bpf_probe_read_user_buf(name_ptr, &mut payload.name) };
                        }
                    },
                )?;
            }
            syscalls::SYS_prctl => {
                crate::util::submit_compact_payload::<pinchy_common::GenericSyscallData, _>(
                    &ctx,
                    syscalls::SYS_prctl,
                    return_value,
                    |payload| {
                        payload.args = args;
                    },
                )?;
            }
            syscalls::SYS_landlock_create_ruleset => {
                crate::util::submit_compact_payload::<pinchy_common::LandlockCreateRulesetData, _>(
                    &ctx,
                    syscalls::SYS_landlock_create_ruleset,
                    return_value,
                    |payload| {
                        payload.attr = args[0] as u64;
                        payload.size = args[1];
                        payload.flags = args[2] as u32;
                    },
                )?;
            }
            syscalls::SYS_landlock_add_rule => {
                crate::util::submit_compact_payload::<pinchy_common::LandlockAddRuleData, _>(
                    &ctx,
                    syscalls::SYS_landlock_add_rule,
                    return_value,
                    |payload| {
                        payload.ruleset_fd = args[0] as i32;
                        payload.rule_type = args[1] as u32;
                        payload.rule_attr = args[2] as u64;
                        payload.flags = args[3] as u32;

                        let rule_attr_ptr = args[2] as *const u8;

                        match payload.rule_type {
                            pinchy_common::LANDLOCK_RULE_PATH_BENEATH => {
                                if let Ok(attr) = unsafe {
                                    bpf_probe_read_user::<LandlockPathBeneathAttr>(
                                        rule_attr_ptr as *const LandlockPathBeneathAttr,
                                    )
                                } {
                                    payload.rule_attr_data.path_beneath = attr;
                                }
                            }
                            pinchy_common::LANDLOCK_RULE_NET_PORT => {
                                if let Ok(attr) = unsafe {
                                    bpf_probe_read_user::<LandlockNetPortAttr>(
                                        rule_attr_ptr as *const LandlockNetPortAttr,
                                    )
                                } {
                                    payload.rule_attr_data.net_port = attr;
                                }
                            }
                            _ => {}
                        }
                    },
                )?;
            }
            syscalls::SYS_landlock_restrict_self => {
                crate::util::submit_compact_payload::<pinchy_common::LandlockRestrictSelfData, _>(
                    &ctx,
                    syscalls::SYS_landlock_restrict_self,
                    return_value,
                    |payload| {
                        payload.ruleset_fd = args[0] as i32;
                        payload.flags = args[1] as u32;
                    },
                )?;
            }
            syscalls::SYS_add_key => {
                crate::util::submit_compact_payload::<pinchy_common::AddKeyData, _>(
                    &ctx,
                    syscalls::SYS_add_key,
                    return_value,
                    |payload| {
                        payload.keyring = args[4] as i32;

                        let type_ptr = args[0] as *const u8;
                        let desc_ptr = args[1] as *const u8;
                        let payload_ptr = args[2] as *const u8;
                        let payload_len = args[3];

                        if !type_ptr.is_null() {
                            let _ =
                                unsafe { bpf_probe_read_user_buf(type_ptr, &mut payload.key_type) };
                        }

                        if !desc_ptr.is_null() {
                            let _ = unsafe {
                                bpf_probe_read_user_buf(desc_ptr, &mut payload.description)
                            };
                        }

                        if !payload_ptr.is_null() && payload_len > 0 {
                            payload.payload_len = if payload_len > pinchy_common::MEDIUM_READ_SIZE {
                                pinchy_common::MEDIUM_READ_SIZE
                            } else {
                                payload_len
                            };
                            let _ = unsafe {
                                bpf_probe_read_user_buf(
                                    payload_ptr,
                                    core::slice::from_raw_parts_mut(
                                        payload.payload.as_mut_ptr(),
                                        payload.payload_len,
                                    ),
                                )
                            };
                        } else {
                            payload.payload_len = 0;
                        }
                    },
                )?;
            }
            syscalls::SYS_request_key => {
                crate::util::submit_compact_payload::<pinchy_common::RequestKeyData, _>(
                    &ctx,
                    syscalls::SYS_request_key,
                    return_value,
                    |payload| {
                        payload.dest_keyring = args[3] as i32;

                        let type_ptr = args[0] as *const u8;
                        let desc_ptr = args[1] as *const u8;
                        let info_ptr = args[2] as *const u8;

                        if !type_ptr.is_null() {
                            let _ =
                                unsafe { bpf_probe_read_user_buf(type_ptr, &mut payload.key_type) };
                        }

                        if !desc_ptr.is_null() {
                            let _ = unsafe {
                                bpf_probe_read_user_buf(desc_ptr, &mut payload.description)
                            };
                        }

                        if !info_ptr.is_null() {
                            let _ = unsafe {
                                bpf_probe_read_user_buf(info_ptr, &mut payload.callout_info)
                            };
                            payload.callout_info_len = pinchy_common::MEDIUM_READ_SIZE;
                        } else {
                            payload.callout_info_len = 0;
                        }
                    },
                )?;
            }
            syscalls::SYS_keyctl => {
                crate::util::submit_compact_payload::<pinchy_common::KeyctlData, _>(
                    &ctx,
                    syscalls::SYS_keyctl,
                    return_value,
                    |payload| {
                        payload.operation = args[0] as i32;
                        payload.arg1 = args[1] as u64;
                        payload.arg2 = args[2] as u64;
                        payload.arg3 = args[3] as u64;
                        payload.arg4 = args[4] as u64;
                    },
                )?;
            }
            syscalls::SYS_perf_event_open => {
                crate::util::submit_compact_payload::<pinchy_common::PerfEventOpenData, _>(
                    &ctx,
                    syscalls::SYS_perf_event_open,
                    return_value,
                    |payload| {
                        let attr_ptr = args[0] as *const pinchy_common::kernel_types::PerfEventAttr;
                        if !attr_ptr.is_null() {
                            payload.attr = unsafe {
                                bpf_probe_read_user::<pinchy_common::kernel_types::PerfEventAttr>(
                                    attr_ptr,
                                )
                            }
                            .unwrap_or_default();
                        }

                        payload.pid = args[1] as i32;
                        payload.cpu = args[2] as i32;
                        payload.group_fd = args[3] as i32;
                        payload.flags = args[4] as u64;
                    },
                )?;
            }
            syscalls::SYS_bpf => {
                crate::util::submit_compact_payload::<pinchy_common::BpfData, _>(
                    &ctx,
                    syscalls::SYS_bpf,
                    return_value,
                    |payload| {
                        let cmd = args[0] as i32;
                        payload.cmd = cmd;
                        payload.size = args[2] as u32;

                        let attr_ptr = args[1] as usize;
                        if attr_ptr != 0 {
                            // BPF_MAP_CREATE = 0
                            if cmd == pinchy_common::kernel_types::bpf_cmd::MAP_CREATE {
                                let map_attr_ptr = attr_ptr
                                    as *const pinchy_common::kernel_types::BpfMapCreateAttr;
                                if let Ok(attr) = unsafe {
                                    bpf_probe_read_user::<
                                        pinchy_common::kernel_types::BpfMapCreateAttr,
                                    >(map_attr_ptr)
                                } {
                                    payload.map_create_attr = attr;
                                    payload.which_attr = 1;
                                }
                            }
                            // BPF_PROG_LOAD = 5
                            else if cmd == pinchy_common::kernel_types::bpf_cmd::PROG_LOAD {
                                let prog_attr_ptr =
                                    attr_ptr as *const pinchy_common::kernel_types::BpfProgLoadAttr;
                                if let Ok(attr) = unsafe {
                                    bpf_probe_read_user::<
                                        pinchy_common::kernel_types::BpfProgLoadAttr,
                                    >(prog_attr_ptr)
                                } {
                                    payload.prog_load_attr = attr;
                                    payload.which_attr = 2;

                                    // Read the license string from the pointer
                                    let license_ptr = attr.license as *const u8;
                                    if !license_ptr.is_null() {
                                        unsafe {
                                            let _ = bpf_probe_read_user_str_bytes(
                                                license_ptr,
                                                &mut payload.license_str,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    },
                )?;
            }
            syscalls::SYS_syslog => {
                crate::util::submit_compact_payload::<pinchy_common::SyslogData, _>(
                    &ctx,
                    syscalls::SYS_syslog,
                    return_value,
                    |payload| {
                        payload.type_ = args[0] as i32;
                        payload.bufp = args[1] as u64;
                        payload.size = args[2] as i32;
                    },
                )?;
            }
            syscalls::SYS_restart_syscall => {
                crate::util::submit_compact_payload::<pinchy_common::RestartSyscallData, _>(
                    &ctx,
                    syscalls::SYS_restart_syscall,
                    return_value,
                    |_payload| {
                        // No arguments to capture
                    },
                )?;
            }
            syscalls::SYS_kexec_load => {
                crate::util::submit_compact_payload::<pinchy_common::KexecLoadData, _>(
                    &ctx,
                    syscalls::SYS_kexec_load,
                    return_value,
                    |payload| {
                        payload.entry = args[0] as u64;
                        payload.nr_segments = args[1] as u64;
                        payload.segments = args[2] as u64;
                        payload.flags = args[3] as u64;

                        let segments_ptr = args[2] as *const kernel_types::KexecSegment;

                        if !segments_ptr.is_null() && payload.nr_segments > 0 {
                            let max_to_read = core::cmp::min(
                                kernel_types::KEXEC_SEGMENT_ARRAY_CAP,
                                payload.nr_segments as usize,
                            );

                            for i in 0..max_to_read {
                                unsafe {
                                    let ptr = segments_ptr.add(i);

                                    if let Ok(segment) = bpf_probe_read_user(ptr) {
                                        payload.parsed_segments[i] = segment;
                                        payload.segments_read += 1;
                                    } else {
                                        break;
                                    }
                                }
                            }
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
