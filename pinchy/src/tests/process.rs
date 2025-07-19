use std::pin::Pin;

use pinchy_common::{
    syscalls::{SYS_execve, SYS_fchdir, SYS_getpid, SYS_getrusage, SYS_set_tid_address, SYS_wait4},
    ExecveData, GetpidData, GetrusageData, SetTidAddressData, SyscallEvent, Wait4Data,
    SMALL_READ_SIZE,
};

use crate::{
    events::handle_event,
    formatting::{Formatter, FormattingStyle},
};

#[tokio::test]
async fn parse_execve() {
    let mut event = SyscallEvent {
        syscall_nr: SYS_execve,
        pid: 22,
        tid: 22,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            execve: ExecveData {
                filename: [0u8; SMALL_READ_SIZE * 4],
                filename_truncated: false,
                argv: [[0u8; SMALL_READ_SIZE]; 4],
                argv_len: [0u16; 4],
                argc: 0,
                envp: [[0u8; SMALL_READ_SIZE]; 2],
                envp_len: [0u16; 2],
                envc: 0,
            },
        },
    };

    let execve_data = unsafe { &mut event.data.execve };
    let filename = c"/bin/find".to_bytes_with_nul();
    execve_data.filename[..filename.len()].copy_from_slice(filename);

    let argv = [
        c"/etc".to_bytes_with_nul(),
        c"-name".to_bytes_with_nul(),
        c"org.pinc".to_bytes(),
    ];
    execve_data.argv[0][..argv[0].len()].copy_from_slice(argv[0]);
    execve_data.argv_len[0] = argv[0].len() as u16;

    execve_data.argv[1][..argv[1].len()].copy_from_slice(argv[1]);
    execve_data.argv_len[1] = argv[1].len() as u16;

    execve_data.argv[2][..argv[2].len()].copy_from_slice(argv[2]);
    execve_data.argv_len[2] = argv[2].len() as u16;

    execve_data.argc = 3;

    let envp = [c"HOME=/ro".to_bytes(), c"WAYLAND=".to_bytes()];
    execve_data.envp[0][..SMALL_READ_SIZE].copy_from_slice(&envp[0][..SMALL_READ_SIZE]);
    execve_data.envp_len[0] = envp[0].len() as u16;

    execve_data.envp[1][..SMALL_READ_SIZE].copy_from_slice(&envp[1][..SMALL_READ_SIZE]);
    execve_data.envp_len[1] = envp[1].len() as u16;

    execve_data.envc = 30;

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "22 execve(filename: \"/bin/find\", argv: [/etc\0, -name\0, org.pinc], envp: [HOME=/ro, WAYLAND=, ... (28 more)]) = 0\n"
        )
    );
}

#[tokio::test]
async fn parse_prctl() {
    use pinchy_common::{syscalls::SYS_prctl, GenericSyscallData, SyscallEvent, SyscallEventData};

    // Test standard prctl operation - PR_SET_NAME
    let event = SyscallEvent {
        syscall_nr: SYS_prctl,
        pid: 999,
        tid: 999,
        return_value: 0, // Success
        data: SyscallEventData {
            generic: GenericSyscallData {
                args: [
                    libc::PR_SET_NAME as usize,
                    0x7fffffff0000, // Pointer to name string
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("999 prctl(PR_SET_NAME, 0x7fffffff0000) = 0\n")
    );

    // Test prctl with error return value - PR_CAPBSET_DROP
    let event = SyscallEvent {
        syscall_nr: SYS_prctl,
        pid: 999,
        tid: 999,
        return_value: -1, // Error
        data: SyscallEventData {
            generic: GenericSyscallData {
                args: [
                    libc::PR_CAPBSET_DROP as usize,
                    10, // CAP_NET_BIND_SERVICE capability
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("999 prctl(PR_CAPBSET_DROP, 0xa) = -1\n")
    );

    // Test PR_CAP_AMBIENT with PR_CAP_AMBIENT_CLEAR_ALL sub-operation
    let event = SyscallEvent {
        syscall_nr: SYS_prctl,
        pid: 999,
        tid: 999,
        return_value: 0, // Success
        data: SyscallEventData {
            generic: GenericSyscallData {
                args: [
                    libc::PR_CAP_AMBIENT as usize,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL as usize,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("999 prctl(PR_CAP_AMBIENT, 0x4, 0x0) = 0\n")
    );
}

#[tokio::test]
async fn parse_set_tid_address() {
    // Test with a non-NULL address
    let event = SyscallEvent {
        syscall_nr: SYS_set_tid_address,
        pid: 5678,
        tid: 5678,
        return_value: 5678, // Returns the thread ID
        data: pinchy_common::SyscallEventData {
            set_tid_address: SetTidAddressData {
                tidptr: 0x7f1234560000, // Address to store the thread ID
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("5678 set_tid_address(tidptr: 0x7f1234560000) = 5678\n")
    );

    // Test with NULL address
    let event = SyscallEvent {
        syscall_nr: SYS_set_tid_address,
        pid: 5678,
        tid: 5678,
        return_value: 5678, // Returns the thread ID
        data: pinchy_common::SyscallEventData {
            set_tid_address: SetTidAddressData {
                tidptr: 0, // NULL address
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("5678 set_tid_address(tidptr: 0x0) = 5678\n")
    );
}

#[tokio::test]
async fn test_getpid() {
    let event = SyscallEvent {
        syscall_nr: SYS_getpid,
        pid: 1234,
        tid: 1234,
        return_value: 1234, // getpid returns the process ID
        data: pinchy_common::SyscallEventData { getpid: GetpidData },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("1234 getpid() = 1234\n")
    );
}

#[tokio::test]
async fn parse_prlimit64() {
    use pinchy_common::{
        kernel_types::Rlimit, syscalls::SYS_prlimit64, PrlimitData, SyscallEvent, SyscallEventData,
    };

    // Test with new_limit and old_limit both provided
    let event = SyscallEvent {
        syscall_nr: SYS_prlimit64,
        pid: 9876,
        tid: 9876,
        return_value: 0, // Success
        data: SyscallEventData {
            prlimit: PrlimitData {
                pid: 1234,
                resource: 7, // RLIMIT_NOFILE
                has_old: true,
                has_new: true,
                old_limit: Rlimit {
                    rlim_cur: 1024,
                    rlim_max: 4096,
                },
                new_limit: Rlimit {
                    rlim_cur: 2048,
                    rlim_max: 4096,
                },
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "9876 prlimit64(pid: 1234, resource: RLIMIT_NOFILE, new_limit: {{ rlim_cur: 2048, rlim_max: 4096 }}, old_limit: {{ rlim_cur: 1024, rlim_max: 4096 }}) = 0\n"
        )
    );

    // Test with only old_limit (query case)
    let event = SyscallEvent {
        syscall_nr: SYS_prlimit64,
        pid: 9876,
        tid: 9876,
        return_value: 0, // Success
        data: SyscallEventData {
            prlimit: PrlimitData {
                pid: 0,      // Current process
                resource: 3, // RLIMIT_STACK
                has_old: true,
                has_new: false,
                old_limit: Rlimit {
                    rlim_cur: 8 * 1024 * 1024, // 8MB
                    rlim_max: u64::MAX,        // RLIM_INFINITY
                },
                new_limit: Rlimit::default(),
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "9876 prlimit64(pid: 0, resource: RLIMIT_STACK, new_limit: NULL, old_limit: {{ rlim_cur: 8388608, rlim_max: RLIM_INFINITY }}) = 0\n"
        )
    );

    // Test with only new_limit (set case) and error
    let event = SyscallEvent {
        syscall_nr: SYS_prlimit64,
        pid: 9876,
        tid: 9876,
        return_value: -1, // Error
        data: SyscallEventData {
            prlimit: PrlimitData {
                pid: 5678,
                resource: 9, // RLIMIT_AS
                has_old: false,
                has_new: true,
                old_limit: Rlimit::default(),
                new_limit: Rlimit {
                    rlim_cur: 4 * 1024 * 1024 * 1024, // 4GB
                    rlim_max: 8 * 1024 * 1024 * 1024, // 8GB
                },
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!(
            "9876 prlimit64(pid: 5678, resource: RLIMIT_AS, new_limit: {{ rlim_cur: 4294967296, rlim_max: 8589934592 }}, old_limit: NULL) = -1\n"
        )
    );
}

#[tokio::test]
async fn parse_fchdir() {
    let event = SyscallEvent {
        syscall_nr: SYS_fchdir,
        pid: 42,
        tid: 42,
        return_value: 0,
        data: pinchy_common::SyscallEventData {
            fchdir: pinchy_common::FchdirData { fd: 5 },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(String::from_utf8_lossy(&output), "42 fchdir(fd: 5) = 0\n");
}

#[tokio::test]
async fn test_wait4_successful() {
    let event = SyscallEvent {
        syscall_nr: SYS_wait4,
        pid: 1000,
        tid: 1001,
        return_value: 1234, // child PID that was waited on
        data: pinchy_common::SyscallEventData {
            wait4: Wait4Data {
                pid: -1,    // wait for any child
                wstatus: 0, // child exited with status 0 (WIFEXITED)
                options: libc::WNOHANG | libc::WUNTRACED,
                has_rusage: true,
                rusage: pinchy_common::kernel_types::Rusage {
                    ru_utime: pinchy_common::kernel_types::Timeval {
                        tv_sec: 0,
                        tv_usec: 123456,
                    },
                    ru_stime: pinchy_common::kernel_types::Timeval {
                        tv_sec: 0,
                        tv_usec: 78910,
                    },
                    ru_maxrss: 1024,
                    ru_minflt: 100,
                    ru_majflt: 5,
                    ..Default::default()
                },
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "1001 wait4(pid: -1, wstatus: {WIFEXITED(s) && WEXITSTATUS(s) == 0}, options: WNOHANG|WUNTRACED, rusage: { ru_utime: { tv_sec: 0, tv_usec: 123456 }, ru_stime: { tv_sec: 0, tv_usec: 78910 }, ru_maxrss: 1024, ru_ixrss: 0, ru_idrss: 0, ru_isrss: 0, ru_minflt: 100, ru_majflt: 5, ru_nswap: 0, ru_inblock: 0, ru_oublock: 0, ru_msgsnd: 0, ru_msgrcv: 0, ru_nsignals: 0, ru_nvcsw: 0, ru_nivcsw: 0 }) = 1234\n"
    );
}

#[tokio::test]
async fn test_wait4_no_rusage() {
    let event = SyscallEvent {
        syscall_nr: SYS_wait4,
        pid: 2000,
        tid: 2001,
        return_value: 5678,
        data: pinchy_common::SyscallEventData {
            wait4: Wait4Data {
                pid: 1234,       // wait for specific child
                wstatus: 9 << 8, // child exited with status 9
                options: 0,
                has_rusage: false,          // no rusage requested
                rusage: Default::default(), // should be ignored
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "2001 wait4(pid: 1234, wstatus: {WIFEXITED(s) && WEXITSTATUS(s) == 9}, options: 0, rusage: NULL) = 5678\n"
    );
}

#[tokio::test]
async fn test_getrusage_self() {
    let event = SyscallEvent {
        syscall_nr: SYS_getrusage,
        pid: 3000,
        tid: 3001,
        return_value: 0, // success
        data: pinchy_common::SyscallEventData {
            getrusage: GetrusageData {
                who: libc::RUSAGE_SELF,
                rusage: pinchy_common::kernel_types::Rusage {
                    ru_utime: pinchy_common::kernel_types::Timeval {
                        tv_sec: 1,
                        tv_usec: 250000,
                    },
                    ru_stime: pinchy_common::kernel_types::Timeval {
                        tv_sec: 0,
                        tv_usec: 150000,
                    },
                    ru_maxrss: 2048,
                    ru_minflt: 200,
                    ru_majflt: 10,
                    ru_nvcsw: 50,
                    ru_nivcsw: 5,
                    ..Default::default()
                },
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    let result = String::from_utf8_lossy(&output);
    assert_eq!(
        result,
        "3001 getrusage(who: RUSAGE_SELF, rusage: { ru_utime: { tv_sec: 1, tv_usec: 250000 }, ru_stime: { tv_sec: 0, tv_usec: 150000 }, ru_maxrss: 2048, ru_ixrss: 0, ru_idrss: 0, ru_isrss: 0, ru_minflt: 200, ru_majflt: 10, ru_nswap: 0, ru_inblock: 0, ru_oublock: 0, ru_msgsnd: 0, ru_msgrcv: 0, ru_nsignals: 0, ru_nvcsw: 50, ru_nivcsw: 5 }) = 0\n"
    );
}

#[tokio::test]
async fn test_getrusage_children() {
    let event = SyscallEvent {
        syscall_nr: SYS_getrusage,
        pid: 4000,
        tid: 4001,
        return_value: 0, // success
        data: pinchy_common::SyscallEventData {
            getrusage: GetrusageData {
                who: libc::RUSAGE_CHILDREN,
                rusage: pinchy_common::kernel_types::Rusage {
                    ru_utime: pinchy_common::kernel_types::Timeval {
                        tv_sec: 5,
                        tv_usec: 750000,
                    },
                    ru_stime: pinchy_common::kernel_types::Timeval {
                        tv_sec: 2,
                        tv_usec: 500000,
                    },
                    ru_maxrss: 4096,
                    ru_inblock: 100,
                    ru_oublock: 50,
                    ..Default::default()
                },
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    let result = String::from_utf8_lossy(&output);
    assert_eq!(
        result,
        "4001 getrusage(who: RUSAGE_CHILDREN, rusage: { ru_utime: { tv_sec: 5, tv_usec: 750000 }, ru_stime: { tv_sec: 2, tv_usec: 500000 }, ru_maxrss: 4096, ru_ixrss: 0, ru_idrss: 0, ru_isrss: 0, ru_minflt: 0, ru_majflt: 0, ru_nswap: 0, ru_inblock: 100, ru_oublock: 50, ru_msgsnd: 0, ru_msgrcv: 0, ru_nsignals: 0, ru_nvcsw: 0, ru_nivcsw: 0 }) = 0\n"
    );
}

#[tokio::test]
async fn test_getrusage_error() {
    let event = SyscallEvent {
        syscall_nr: SYS_getrusage,
        pid: 5000,
        tid: 5001,
        return_value: -22, // -EINVAL
        data: pinchy_common::SyscallEventData {
            getrusage: GetrusageData {
                who: 999,                   // invalid who parameter
                rusage: Default::default(), // should be ignored for failed calls
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    let result = String::from_utf8_lossy(&output);
    assert_eq!(result, "5001 getrusage(who: UNKNOWN, rusage: NULL) = -22\n");
}
