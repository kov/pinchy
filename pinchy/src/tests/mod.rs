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
