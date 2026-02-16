// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

mod basic_io;
mod client;
mod filesystem;
mod ipc;
mod memory;
mod network;
mod process;
mod return_values;
mod scheduling;
mod security;
mod signal;
mod sync;
mod system;
mod time;

pub(crate) fn make_compact_test_data<T: Copy>(
    syscall_nr: i64,
    pid: u32,
    return_value: i64,
    data: &T,
) -> (pinchy_common::WireEventHeader, Vec<u8>) {
    let header = pinchy_common::WireEventHeader {
        version: pinchy_common::WIRE_VERSION,
        kind: pinchy_common::WIRE_KIND_COMPACT_SYSCALL_EVENT,
        payload_len: core::mem::size_of::<T>() as u32,
        syscall_nr,
        pid,
        tid: pid,
        return_value,
    };

    let payload = unsafe {
        std::slice::from_raw_parts((data as *const T).cast::<u8>(), core::mem::size_of::<T>())
            .to_vec()
    };

    (header, payload)
}

#[macro_export]
macro_rules! syscall_test {
    ($name:ident, $init:block, $expected:expr) => {
        #[::tokio::test]
        async fn $name() {
            let event = $init;

            let mut output: Vec<u8> = vec![];
            let pin_output = unsafe { std::pin::Pin::new_unchecked(&mut output) };
            let formatter = $crate::formatting::Formatter::new(
                pin_output,
                $crate::formatting::FormattingStyle::OneLine,
            );

            $crate::events::handle_event(&event, formatter)
                .await
                .unwrap();

            assert_eq!(
                String::from_utf8_lossy(&output).to_string().as_str(),
                $expected
            );
        }
    };
}

#[macro_export]
macro_rules! syscall_compact_test {
    ($name:ident, $init:block, $expected:expr) => {
        #[::tokio::test]
        async fn $name() {
            let (header, payload) = $init;

            let mut output: Vec<u8> = vec![];
            let pin_output = unsafe { std::pin::Pin::new_unchecked(&mut output) };
            let formatter = $crate::formatting::Formatter::new(
                pin_output,
                $crate::formatting::FormattingStyle::OneLine,
            );

            let handled = $crate::events::handle_compact_event(&header, &payload, formatter)
                .await
                .unwrap();

            assert!(handled);
            assert_eq!(
                String::from_utf8_lossy(&output).to_string().as_str(),
                $expected
            );
        }
    };
}

syscall_test!(
    parse_generic_syscall,
    {
        use pinchy_common::{
            syscalls::SYS_generic_parse_test, GenericSyscallData, SyscallEvent, SyscallEventData,
        };

        SyscallEvent {
            syscall_nr: SYS_generic_parse_test,
            pid: 1234,
            tid: 1234,
            return_value: 42,
            data: SyscallEventData {
                generic: GenericSyscallData {
                    args: [0, 1, 2, 3, 4, 5],
                },
            },
        }
    },
    "1234 generic_parse_test(0, 1, 2, 3, 4, 5) = 42 <STUB>\n"
);
