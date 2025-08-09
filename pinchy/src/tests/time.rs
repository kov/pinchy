// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    kernel_types::{Itimerspec, Sigevent, SigeventUn, Sigval, Timespec, Timeval, Timex},
    syscalls::{
        SYS_adjtimex, SYS_clock_adjtime, SYS_clock_getres, SYS_clock_gettime, SYS_clock_settime,
        SYS_timer_create, SYS_timer_delete, SYS_timer_getoverrun, SYS_timer_gettime,
        SYS_timer_settime,
    },
    AdjtimexData, ClockAdjtimeData, ClockTimeData, SyscallEvent, SyscallEventData, TimerCreateData,
    TimerDeleteData, TimerGetoverrunData, TimerGettimeData, TimerSettimeData,
};

use crate::syscall_test;

syscall_test!(
    test_adjtimex_basic,
    {
        SyscallEvent {
            syscall_nr: SYS_adjtimex,
            pid: 1234,
            tid: 1234,
            return_value: 0, // TIME_OK
            data: SyscallEventData {
                adjtimex: AdjtimexData {
                    timex: Timex {
                        modes: libc::ADJ_OFFSET, // ADJ_OFFSET
                        offset: 1000,  // 1ms offset
                        freq: 32768000, // 500 ppm frequency adjustment
                        maxerror: 16000, // 16ms max error
                        esterror: 4000,  // 4ms estimated error
                        status: libc::STA_PLL,
                        constant: 10,
                        precision: 1000,
                        tolerance: 32768000,
                        time: Timeval {
                            tv_sec: 1672531200, // 2023-01-01 00:00:00 UTC
                            tv_usec: 123456,
                        },
                        tick: 10000, // 10ms tick
                        ..Default::default()
                    },
                },
            },
        }
    },
    "1234 adjtimex(timex: { modes: 0x1 (ADJ_OFFSET), offset: 1000, freq: 32768000, maxerror: 16000, esterror: 4000, status: 0x1 (STA_PLL), constant: 10, precision: 1000, tolerance: 32768000, time: { tv_sec: 1672531200, tv_usec: 123456 }, tick: 10000 }) = 0 (TIME_OK)\n"
);

// FIXME: we should map 22 to EINVAL in the pretty printing
syscall_test!(
    test_adjtimex_error,
    {
        SyscallEvent {
            syscall_nr: SYS_adjtimex,
            pid: 5678,
            tid: 5678,
            return_value: libc::EINVAL as i64,
            data: SyscallEventData {
                adjtimex: AdjtimexData {
                    timex: Timex {
                        modes: 0xffff, // Invalid modes
                        ..Default::default()
                    },
                },
            },
        }
    },
    "5678 adjtimex(timex: { modes: 0xffff (ADJ_OFFSET|ADJ_FREQUENCY|ADJ_MAXERROR|ADJ_ESTERROR|ADJ_STATUS|ADJ_TIMECONST|ADJ_TAI|ADJ_SETOFFSET|ADJ_MICRO|ADJ_NANO|ADJ_TICK), offset: 0, freq: 0, maxerror: 0, esterror: 0, status: 0x0, constant: 0, precision: 0, tolerance: 0, time: { tv_sec: 0, tv_usec: 0 }, tick: 0 }) = 22 (22)\n"
);

syscall_test!(
    test_clock_adjtime_realtime,
    {
        SyscallEvent {
            syscall_nr: SYS_clock_adjtime,
            pid: 2468,
            tid: 2468,
            return_value: libc::TIME_INS as i64,
            data: SyscallEventData {
                clock_adjtime: ClockAdjtimeData {
                    clockid: libc::CLOCK_REALTIME,
                    timex: Timex {
                        modes: libc::ADJ_FREQUENCY,
                        freq: -65536000, // -1000 ppm frequency adjustment
                        status: libc::STA_PPSFREQ | libc::STA_INS,
                        time: Timeval {
                            tv_sec: 1672531200,
                            tv_usec: 654321,
                        },
                        ..Default::default()
                    },
                },
            },
        }
    },
    "2468 clock_adjtime(clockid: CLOCK_REALTIME, timex: { modes: 0x2 (ADJ_FREQUENCY), offset: 0, freq: -65536000, maxerror: 0, esterror: 0, status: 0x12 (STA_PPSFREQ|STA_INS), constant: 0, precision: 0, tolerance: 0, time: { tv_sec: 1672531200, tv_usec: 654321 }, tick: 0 }) = 1 (TIME_INS)\n"
);

// FIXME: we should map 95 to EOPNOSUPP in the pretty printing
syscall_test!(
    test_clock_adjtime_monotonic_error,
    {
        SyscallEvent {
            syscall_nr: SYS_clock_adjtime,
            pid: 9999,
            tid: 9999,
            return_value: libc::EOPNOTSUPP as i64,
            data: SyscallEventData {
                clock_adjtime: ClockAdjtimeData {
                    clockid: libc::CLOCK_MONOTONIC,
                    timex: Timex {
                        modes: libc::ADJ_OFFSET,
                        offset: 500,
                        ..Default::default()
                    },
                },
            },
        }
    },
    "9999 clock_adjtime(clockid: CLOCK_MONOTONIC, timex: { modes: 0x1 (ADJ_OFFSET), offset: 500, freq: 0, maxerror: 0, esterror: 0, status: 0x0, constant: 0, precision: 0, tolerance: 0, time: { tv_sec: 0, tv_usec: 0 }, tick: 0 }) = 95 (95)\n"
);

syscall_test!(
    test_clock_getres,
    {
        SyscallEvent {
            syscall_nr: SYS_clock_getres,
            pid: 42,
            tid: 42,
            return_value: 0,
            data: SyscallEventData {
                clock_time: ClockTimeData {
                    clockid: libc::CLOCK_REALTIME,
                    tp: Timespec {
                        seconds: 1,
                        nanos: 234_567_890,
                    },
                    has_tp: true,
                },
            },
        }
    },
    "42 clock_getres(clockid: CLOCK_REALTIME, res: { secs: 1, nanos: 234567890 }) = 0 (success)\n"
);

syscall_test!(
    test_clock_gettime,
    {
        SyscallEvent {
            syscall_nr: SYS_clock_gettime,
            pid: 43,
            tid: 43,
            return_value: 0,
            data: SyscallEventData {
                clock_time: ClockTimeData {
                    clockid: libc::CLOCK_MONOTONIC,
                    tp: Timespec {
                        seconds: 123,
                        nanos: 456_789,
                    },
                    has_tp: true,
                },
            },
        }
    },
    "43 clock_gettime(clockid: CLOCK_MONOTONIC, tp: { secs: 123, nanos: 456789 }) = 0 (success)\n"
);

syscall_test!(
    test_clock_settime,
    {
        SyscallEvent {
            syscall_nr: SYS_clock_settime,
            pid: 44,
            tid: 44,
            return_value: 0,
            data: SyscallEventData {
                clock_time: ClockTimeData {
                    clockid: libc::CLOCK_REALTIME,
                    tp: Timespec {
                        seconds: 5,
                        nanos: 0,
                    },
                    has_tp: true,
                },
            },
        }
    },
    "44 clock_settime(clockid: CLOCK_REALTIME, tp: { secs: 5, nanos: 0 }) = 0 (success)\n"
);

syscall_test!(
    test_timer_create_with_sigevent,
    {
        SyscallEvent {
            syscall_nr: SYS_timer_create,
            pid: 1000,
            tid: 1000,
            return_value: 0,
            data: SyscallEventData {
                timer_create: TimerCreateData {
                    clockid: libc::CLOCK_REALTIME,
                    has_sevp: true,
                    sevp: Sigevent {
                        sigev_value: Sigval { sival_int: 0x12345678 },
                        sigev_signo: libc::SIGUSR1,
                        sigev_notify: libc::SIGEV_SIGNAL,
                        sigev_un: SigeventUn::default(),
                    },
                },
            },
        }
    },
    "1000 timer_create(clockid: CLOCK_REALTIME, sevp: { sigev_notify: SIGEV_SIGNAL, sigev_signo: 10, sigev_value.sival_int: 305419896 }, timerid: <output>) = 0 (success)\n"
);

syscall_test!(
    test_timer_create_no_sigevent,
    {
        SyscallEvent {
            syscall_nr: SYS_timer_create,
            pid: 1001,
            tid: 1001,
            return_value: 0,
            data: SyscallEventData {
                timer_create: TimerCreateData {
                    clockid: libc::CLOCK_MONOTONIC,
                    has_sevp: false,
                    sevp: Sigevent::default(),
                },
            },
        }
    },
    "1001 timer_create(clockid: CLOCK_MONOTONIC, sevp: NULL, timerid: <output>) = 0 (success)\n"
);

syscall_test!(
    test_timer_delete_success,
    {
        SyscallEvent {
            syscall_nr: SYS_timer_delete,
            pid: 1002,
            tid: 1002,
            return_value: 0,
            data: SyscallEventData {
                timer_delete: TimerDeleteData {
                    timerid: 0x12345678,
                },
            },
        }
    },
    "1002 timer_delete(timerid: 0x12345678) = 0 (success)\n"
);

syscall_test!(
    test_timer_getoverrun,
    {
        SyscallEvent {
            syscall_nr: SYS_timer_getoverrun,
            pid: 1003,
            tid: 1003,
            return_value: 5,
            data: SyscallEventData {
                timer_getoverrun: TimerGetoverrunData {
                    timerid: 0x87654321,
                },
            },
        }
    },
    "1003 timer_getoverrun(timerid: 0x87654321) = 5 (overruns)\n"
);

syscall_test!(
    test_timer_gettime,
    {
        SyscallEvent {
            syscall_nr: SYS_timer_gettime,
            pid: 1004,
            tid: 1004,
            return_value: 0,
            data: SyscallEventData {
                timer_gettime: TimerGettimeData {
                    timerid: 0xabcdef00,
                    curr_value: Itimerspec {
                        it_interval: Timespec { seconds: 1, nanos: 500_000_000 },
                        it_value: Timespec { seconds: 0, nanos: 750_000_000 },
                    },
                },
            },
        }
    },
    "1004 timer_gettime(timerid: 0xabcdef00, curr_value: { it_interval: { secs: 1, nanos: 500000000 }, it_value: { secs: 0, nanos: 750000000 } }) = 0 (success)\n"
);

syscall_test!(
    test_timer_settime_absolute,
    {
        SyscallEvent {
            syscall_nr: SYS_timer_settime,
            pid: 1005,
            tid: 1005,
            return_value: 0,
            data: SyscallEventData {
                timer_settime: TimerSettimeData {
                    timerid: 0xfedcba09,
                    flags: 1, // TIMER_ABSTIME
                    has_new_value: true,
                    new_value: Itimerspec {
                        it_interval: Timespec { seconds: 2, nanos: 0 },
                        it_value: Timespec { seconds: 1675209600, nanos: 0 }, // Absolute time
                    },
                    has_old_value: true,
                    old_value: Itimerspec {
                        it_interval: Timespec { seconds: 1, nanos: 0 },
                        it_value: Timespec { seconds: 0, nanos: 250_000_000 },
                    },
                },
            },
        }
    },
    "1005 timer_settime(timerid: 0xfedcba09, flags: TIMER_ABSTIME, new_value: { it_interval: { secs: 2, nanos: 0 }, it_value: { secs: 1675209600, nanos: 0 } }, old_value: { it_interval: { secs: 1, nanos: 0 }, it_value: { secs: 0, nanos: 250000000 } }) = 0 (success)\n"
);

syscall_test!(
    test_timer_settime_no_old_value,
    {
        SyscallEvent {
            syscall_nr: SYS_timer_settime,
            pid: 1006,
            tid: 1006,
            return_value: 0,
            data: SyscallEventData {
                timer_settime: TimerSettimeData {
                    timerid: 0x13579bdf,
                    flags: 0, // Relative time
                    has_new_value: true,
                    new_value: Itimerspec {
                        it_interval: Timespec { seconds: 0, nanos: 100_000_000 },
                        it_value: Timespec { seconds: 0, nanos: 50_000_000 },
                    },
                    has_old_value: false,
                    old_value: Itimerspec::default(),
                },
            },
        }
    },
    "1006 timer_settime(timerid: 0x13579bdf, flags: 0, new_value: { it_interval: { secs: 0, nanos: 100000000 }, it_value: { secs: 0, nanos: 50000000 } }, old_value: NULL) = 0 (success)\n"
);
