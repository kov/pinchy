// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use pinchy_common::{
    kernel_types::{Itimerspec, Itimerval, Sigevent, SigeventUn, Sigval, Timespec, Timeval, Timex},
    syscalls::{
        SYS_adjtimex, SYS_clock_adjtime, SYS_clock_getres, SYS_clock_gettime, SYS_clock_settime,
        SYS_getitimer, SYS_setitimer, SYS_timer_create, SYS_timer_delete, SYS_timer_getoverrun,
        SYS_timer_gettime, SYS_timer_settime, SYS_timerfd_create, SYS_timerfd_gettime,
        SYS_timerfd_settime,
    },
    AdjtimexData, ClockAdjtimeData, ClockTimeData, GetItimerData, SetItimerData, TimerCreateData,
    TimerDeleteData, TimerGetoverrunData, TimerGettimeData, TimerSettimeData, TimerfdCreateData,
    TimerfdGettimeData, TimerfdSettimeData,
};

use crate::syscall_test;

syscall_test!(
    test_adjtimex_basic,
    {
        let data = AdjtimexData {
                    timex: Timex {
                        modes: libc::ADJ_OFFSET,
                        offset: 1000,
                        freq: 32768000,
                        maxerror: 16000,
                        esterror: 4000,
                        status: libc::STA_PLL,
                        constant: 10,
                        precision: 1000,
                        tolerance: 32768000,
                        time: Timeval {
                            tv_sec: 1672531200,
                            tv_usec: 123456,
                        },
                        tick: 10000,
                        ..Default::default()
                    },
                };

        crate::tests::make_compact_test_data(SYS_adjtimex, 1234, 0, &data)
    },
    "1234 adjtimex(timex: { modes: 0x1 (ADJ_OFFSET), offset: 1000, freq: 32768000, maxerror: 16000, esterror: 4000, status: 0x1 (STA_PLL), constant: 10, precision: 1000, tolerance: 32768000, time: { tv_sec: 1672531200, tv_usec: 123456 }, tick: 10000 }) = 0 (TIME_OK)\n"
);

// FIXME: we should map 22 to EINVAL in the pretty printing
syscall_test!(
    test_adjtimex_error,
    {
        let data = AdjtimexData {
                    timex: Timex {
                        modes: 0xffff,
                        ..Default::default()
                    },
                };

        crate::tests::make_compact_test_data(SYS_adjtimex, 5678, libc::EINVAL as i64, &data)
    },
    "5678 adjtimex(timex: { modes: 0xffff (ADJ_OFFSET|ADJ_FREQUENCY|ADJ_MAXERROR|ADJ_ESTERROR|ADJ_STATUS|ADJ_TIMECONST|ADJ_TAI|ADJ_SETOFFSET|ADJ_MICRO|ADJ_NANO|ADJ_TICK), offset: 0, freq: 0, maxerror: 0, esterror: 0, status: 0x0, constant: 0, precision: 0, tolerance: 0, time: { tv_sec: 0, tv_usec: 0 }, tick: 0 }) = 22 (22)\n"
);

syscall_test!(
    test_clock_adjtime_realtime,
    {
        let data = ClockAdjtimeData {
                    clockid: libc::CLOCK_REALTIME,
                    timex: Timex {
                        modes: libc::ADJ_FREQUENCY,
                        freq: -65536000,
                        status: libc::STA_PPSFREQ | libc::STA_INS,
                        time: Timeval {
                            tv_sec: 1672531200,
                            tv_usec: 654321,
                        },
                        ..Default::default()
                    },
                };

        crate::tests::make_compact_test_data(SYS_clock_adjtime, 2468, libc::TIME_INS as i64, &data)
    },
    "2468 clock_adjtime(clockid: CLOCK_REALTIME, timex: { modes: 0x2 (ADJ_FREQUENCY), offset: 0, freq: -65536000, maxerror: 0, esterror: 0, status: 0x12 (STA_PPSFREQ|STA_INS), constant: 0, precision: 0, tolerance: 0, time: { tv_sec: 1672531200, tv_usec: 654321 }, tick: 0 }) = 1 (TIME_INS)\n"
);

// FIXME: we should map 95 to EOPNOSUPP in the pretty printing
syscall_test!(
    test_clock_adjtime_monotonic_error,
    {
        let data = ClockAdjtimeData {
                    clockid: libc::CLOCK_MONOTONIC,
                    timex: Timex {
                        modes: libc::ADJ_OFFSET,
                        offset: 500,
                        ..Default::default()
                    },
                };

        crate::tests::make_compact_test_data(SYS_clock_adjtime, 9999, libc::EOPNOTSUPP as i64, &data)
    },
    "9999 clock_adjtime(clockid: CLOCK_MONOTONIC, timex: { modes: 0x1 (ADJ_OFFSET), offset: 500, freq: 0, maxerror: 0, esterror: 0, status: 0x0, constant: 0, precision: 0, tolerance: 0, time: { tv_sec: 0, tv_usec: 0 }, tick: 0 }) = 95 (95)\n"
);

syscall_test!(
    test_clock_getres,
    {
        let data = ClockTimeData {
            clockid: libc::CLOCK_REALTIME,
            tp: Timespec {
                seconds: 1,
                nanos: 234_567_890,
            },
            has_tp: true,
        };

        crate::tests::make_compact_test_data(SYS_clock_getres, 42, 0, &data)
    },
    "42 clock_getres(clockid: CLOCK_REALTIME, res: { secs: 1, nanos: 234567890 }) = 0 (success)\n"
);

syscall_test!(
    test_clock_gettime,
    {
        let data = ClockTimeData {
            clockid: libc::CLOCK_MONOTONIC,
            tp: Timespec {
                seconds: 123,
                nanos: 456_789,
            },
            has_tp: true,
        };

        crate::tests::make_compact_test_data(SYS_clock_gettime, 43, 0, &data)
    },
    "43 clock_gettime(clockid: CLOCK_MONOTONIC, tp: { secs: 123, nanos: 456789 }) = 0 (success)\n"
);

syscall_test!(
    test_clock_settime,
    {
        let data = ClockTimeData {
            clockid: libc::CLOCK_REALTIME,
            tp: Timespec {
                seconds: 5,
                nanos: 0,
            },
            has_tp: true,
        };

        crate::tests::make_compact_test_data(SYS_clock_settime, 44, 0, &data)
    },
    "44 clock_settime(clockid: CLOCK_REALTIME, tp: { secs: 5, nanos: 0 }) = 0 (success)\n"
);

syscall_test!(
    test_timer_create_with_sigevent,
    {
        let data = TimerCreateData {
                    clockid: libc::CLOCK_REALTIME,
                    has_sevp: true,
                    sevp: Sigevent {
                        sigev_value: Sigval { sival_int: 0x12345678 },
                        sigev_signo: libc::SIGUSR1,
                        sigev_notify: libc::SIGEV_SIGNAL,
                        sigev_un: SigeventUn::default(),
                    },
                };

        crate::tests::make_compact_test_data(SYS_timer_create, 1000, 0, &data)
    },
    "1000 timer_create(clockid: CLOCK_REALTIME, sevp: { sigev_notify: SIGEV_SIGNAL, sigev_signo: 10, sigev_value.sival_int: 305419896 }, timerid: <output>) = 0 (success)\n"
);

syscall_test!(
    test_timer_create_no_sigevent,
    {
        let data = TimerCreateData {
            clockid: libc::CLOCK_MONOTONIC,
            has_sevp: false,
            sevp: Sigevent::default(),
        };

        crate::tests::make_compact_test_data(SYS_timer_create, 1001, 0, &data)
    },
    "1001 timer_create(clockid: CLOCK_MONOTONIC, sevp: NULL, timerid: <output>) = 0 (success)\n"
);

syscall_test!(
    test_timer_delete_success,
    {
        let data = TimerDeleteData {
            timerid: 0x12345678,
        };

        crate::tests::make_compact_test_data(SYS_timer_delete, 1002, 0, &data)
    },
    "1002 timer_delete(timerid: 0x12345678) = 0 (success)\n"
);

syscall_test!(
    test_timer_getoverrun,
    {
        let data = TimerGetoverrunData {
            timerid: 0x87654321,
        };

        crate::tests::make_compact_test_data(SYS_timer_getoverrun, 1003, 5, &data)
    },
    "1003 timer_getoverrun(timerid: 0x87654321) = 5 (overruns)\n"
);

syscall_test!(
    test_timer_gettime,
    {
        let data = TimerGettimeData {
                    timerid: 0xabcdef00,
                    curr_value: Itimerspec {
                        it_interval: Timespec { seconds: 1, nanos: 500_000_000 },
                        it_value: Timespec { seconds: 0, nanos: 750_000_000 },
                    },
                };

        crate::tests::make_compact_test_data(SYS_timer_gettime, 1004, 0, &data)
    },
    "1004 timer_gettime(timerid: 0xabcdef00, curr_value: { it_interval: { secs: 1, nanos: 500000000 }, it_value: { secs: 0, nanos: 750000000 } }) = 0 (success)\n"
);

syscall_test!(
    test_timer_settime_absolute,
    {
        let data = TimerSettimeData {
                    timerid: 0xfedcba09,
                    flags: 1,
                    has_new_value: true,
                    new_value: Itimerspec {
                        it_interval: Timespec { seconds: 2, nanos: 0 },
                        it_value: Timespec { seconds: 1675209600, nanos: 0 },
                    },
                    has_old_value: true,
                    old_value: Itimerspec {
                        it_interval: Timespec { seconds: 1, nanos: 0 },
                        it_value: Timespec { seconds: 0, nanos: 250_000_000 },
                    },
                };

        crate::tests::make_compact_test_data(SYS_timer_settime, 1005, 0, &data)
    },
    "1005 timer_settime(timerid: 0xfedcba09, flags: TIMER_ABSTIME, new_value: { it_interval: { secs: 2, nanos: 0 }, it_value: { secs: 1675209600, nanos: 0 } }, old_value: { it_interval: { secs: 1, nanos: 0 }, it_value: { secs: 0, nanos: 250000000 } }) = 0 (success)\n"
);

syscall_test!(
    test_timer_settime_no_old_value,
    {
        let data = TimerSettimeData {
                    timerid: 0x13579bdf,
                    flags: 0,
                    has_new_value: true,
                    new_value: Itimerspec {
                        it_interval: Timespec { seconds: 0, nanos: 100_000_000 },
                        it_value: Timespec { seconds: 0, nanos: 50_000_000 },
                    },
                    has_old_value: false,
                    old_value: Itimerspec::default(),
                };

        crate::tests::make_compact_test_data(SYS_timer_settime, 1006, 0, &data)
    },
    "1006 timer_settime(timerid: 0x13579bdf, flags: 0, new_value: { it_interval: { secs: 0, nanos: 100000000 }, it_value: { secs: 0, nanos: 50000000 } }, old_value: NULL) = 0 (success)\n"
);

syscall_test!(
    test_timerfd_create_basic,
    {
        let data = TimerfdCreateData {
            clockid: libc::CLOCK_MONOTONIC,
            flags: 0,
        };

        crate::tests::make_compact_test_data(SYS_timerfd_create, 2001, 5, &data)
    },
    "2001 timerfd_create(clockid: CLOCK_MONOTONIC, flags: 0) = 5 (fd)\n"
);

syscall_test!(
    test_timerfd_create_with_flags,
    {
        let data = TimerfdCreateData {
            clockid: libc::CLOCK_REALTIME,
            flags: libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
        };

        crate::tests::make_compact_test_data(SYS_timerfd_create, 2002, 6, &data)
    },
    "2002 timerfd_create(clockid: CLOCK_REALTIME, flags: TFD_CLOEXEC|TFD_NONBLOCK) = 6 (fd)\n"
);

syscall_test!(
    test_timerfd_gettime,
    {
        let data = TimerfdGettimeData {
                    fd: 5,
                    curr_value: Itimerspec {
                        it_interval: Timespec { seconds: 1, nanos: 500_000_000 },
                        it_value: Timespec { seconds: 0, nanos: 750_000_000 },
                    },
                };

        crate::tests::make_compact_test_data(SYS_timerfd_gettime, 2003, 0, &data)
    },
    "2003 timerfd_gettime(fd: 5, curr_value: { it_interval: { secs: 1, nanos: 500000000 }, it_value: { secs: 0, nanos: 750000000 } }) = 0 (success)\n"
);

syscall_test!(
    test_timerfd_settime_relative,
    {
        let data = TimerfdSettimeData {
                    fd: 6,
                    flags: 0,
                    has_new_value: true,
                    new_value: Itimerspec {
                        it_interval: Timespec { seconds: 2, nanos: 0 },
                        it_value: Timespec { seconds: 1, nanos: 500_000_000 },
                    },
                    has_old_value: true,
                    old_value: Itimerspec {
                        it_interval: Timespec { seconds: 0, nanos: 0 },
                        it_value: Timespec { seconds: 0, nanos: 0 },
                    },
                };

        crate::tests::make_compact_test_data(SYS_timerfd_settime, 2004, 0, &data)
    },
    "2004 timerfd_settime(fd: 6, flags: 0, new_value: { it_interval: { secs: 2, nanos: 0 }, it_value: { secs: 1, nanos: 500000000 } }, old_value: { it_interval: { secs: 0, nanos: 0 }, it_value: { secs: 0, nanos: 0 } }) = 0 (success)\n"
);

syscall_test!(
    test_timerfd_settime_absolute,
    {
        let data = TimerfdSettimeData {
                    fd: 7,
                    flags: 1,
                    has_new_value: true,
                    new_value: Itimerspec {
                        it_interval: Timespec { seconds: 0, nanos: 0 },
                        it_value: Timespec { seconds: 1675209700, nanos: 0 },
                    },
                    has_old_value: false,
                    old_value: Itimerspec::default(),
                };

        crate::tests::make_compact_test_data(SYS_timerfd_settime, 2005, 0, &data)
    },
    "2005 timerfd_settime(fd: 7, flags: TIMER_ABSTIME, new_value: { it_interval: { secs: 0, nanos: 0 }, it_value: { secs: 1675209700, nanos: 0 } }, old_value: NULL) = 0 (success)\n"
);

syscall_test!(
    parse_getitimer_real,
    {
        let data = GetItimerData {
                    which: libc::ITIMER_REAL,
                    curr_value: Itimerval {
                        it_interval: Timeval {
                            tv_sec: 1,
                            tv_usec: 500000,
                        },
                        it_value: Timeval {
                            tv_sec: 0,
                            tv_usec: 100000,
                        },
                    },
                };

        crate::tests::make_compact_test_data(SYS_getitimer, 1234, 0, &data)
    },
    "1234 getitimer(which: ITIMER_REAL, curr_value: { it_interval: { tv_sec: 1, tv_usec: 500000 }, it_value: { tv_sec: 0, tv_usec: 100000 } }) = 0 (success)\n"
);

syscall_test!(
    parse_getitimer_virtual,
    {
        let data = GetItimerData {
                    which: libc::ITIMER_VIRTUAL,
                    curr_value: Itimerval {
                        it_interval: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        it_value: Timeval {
                            tv_sec: 2,
                            tv_usec: 750000,
                        },
                    },
                };

        crate::tests::make_compact_test_data(SYS_getitimer, 1234, 0, &data)
    },
    "1234 getitimer(which: ITIMER_VIRTUAL, curr_value: { it_interval: { tv_sec: 0, tv_usec: 0 }, it_value: { tv_sec: 2, tv_usec: 750000 } }) = 0 (success)\n"
);

syscall_test!(
    parse_getitimer_error,
    {
        let data = GetItimerData {
                    which: 999,
                    curr_value: Itimerval {
                        it_interval: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        it_value: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                    },
                };

        crate::tests::make_compact_test_data(SYS_getitimer, 1234, -1, &data)
    },
    "1234 getitimer(which: 999, curr_value: { it_interval: { tv_sec: 0, tv_usec: 0 }, it_value: { tv_sec: 0, tv_usec: 0 } }) = -1 (error)\n"
);

syscall_test!(
    parse_setitimer_prof,
    {
        let data = SetItimerData {
                    which: libc::ITIMER_PROF,
                    new_value: Itimerval {
                        it_interval: Timeval {
                            tv_sec: 0,
                            tv_usec: 100000,
                        },
                        it_value: Timeval {
                            tv_sec: 0,
                            tv_usec: 100000,
                        },
                    },
                    has_old_value: true,
                    old_value: Itimerval {
                        it_interval: Timeval {
                            tv_sec: 1,
                            tv_usec: 0,
                        },
                        it_value: Timeval {
                            tv_sec: 0,
                            tv_usec: 250000,
                        },
                    },
                };

        crate::tests::make_compact_test_data(SYS_setitimer, 1234, 0, &data)
    },
    "1234 setitimer(which: ITIMER_PROF, new_value: { it_interval: { tv_sec: 0, tv_usec: 100000 }, it_value: { tv_sec: 0, tv_usec: 100000 } }, old_value: { it_interval: { tv_sec: 1, tv_usec: 0 }, it_value: { tv_sec: 0, tv_usec: 250000 } }) = 0 (success)\n"
);

syscall_test!(
    parse_setitimer_real,
    {
        let data = SetItimerData {
                    which: libc::ITIMER_REAL,
                    new_value: Itimerval {
                        it_interval: Timeval {
                            tv_sec: 5,
                            tv_usec: 0,
                        },
                        it_value: Timeval {
                            tv_sec: 5,
                            tv_usec: 0,
                        },
                    },
                    has_old_value: true,
                    old_value: Itimerval {
                        it_interval: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        it_value: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                    },
                };

        crate::tests::make_compact_test_data(SYS_setitimer, 1234, 0, &data)
    },
    "1234 setitimer(which: ITIMER_REAL, new_value: { it_interval: { tv_sec: 5, tv_usec: 0 }, it_value: { tv_sec: 5, tv_usec: 0 } }, old_value: { it_interval: { tv_sec: 0, tv_usec: 0 }, it_value: { tv_sec: 0, tv_usec: 0 } }) = 0 (success)\n"
);

syscall_test!(
    parse_setitimer_error,
    {
        let data = SetItimerData {
                    which: -1,
                    new_value: Itimerval {
                        it_interval: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        it_value: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                    },
                    has_old_value: true,
                    old_value: Itimerval {
                        it_interval: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        it_value: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                    },
                };

        crate::tests::make_compact_test_data(SYS_setitimer, 1234, -1, &data)
    },
    "1234 setitimer(which: -1, new_value: { it_interval: { tv_sec: 0, tv_usec: 0 }, it_value: { tv_sec: 0, tv_usec: 0 } }, old_value: { it_interval: { tv_sec: 0, tv_usec: 0 }, it_value: { tv_sec: 0, tv_usec: 0 } }) = -1 (error)\n"
);

syscall_test!(
    parse_setitimer_null_old_value,
    {
        let data = SetItimerData {
                    which: libc::ITIMER_REAL,
                    new_value: Itimerval {
                        it_interval: Timeval {
                            tv_sec: 0,
                            tv_usec: 100000,
                        },
                        it_value: Timeval {
                            tv_sec: 0,
                            tv_usec: 100000,
                        },
                    },
                    has_old_value: false,
                    old_value: Itimerval {
                        it_interval: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        it_value: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                    },
                };

        crate::tests::make_compact_test_data(SYS_setitimer, 1234, 0, &data)
    },
    "1234 setitimer(which: ITIMER_REAL, new_value: { it_interval: { tv_sec: 0, tv_usec: 100000 }, it_value: { tv_sec: 0, tv_usec: 100000 } }, old_value: NULL) = 0 (success)\n"
);
