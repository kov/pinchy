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
            let (header, payload) = $init;

            let mut output: Vec<u8> = vec![];
            let pin_output = unsafe { std::pin::Pin::new_unchecked(&mut output) };
            let formatter = $crate::formatting::Formatter::new(
                pin_output,
                $crate::formatting::FormattingStyle::OneLine,
            );

            $crate::events::handle_event(&header, &payload, formatter)
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
        use pinchy_common::{syscalls::SYS_generic_parse_test, GenericSyscallData};

        let data = GenericSyscallData {
            args: [0, 1, 2, 3, 4, 5],
        };

        crate::tests::make_compact_test_data(SYS_generic_parse_test, 1234, 42, &data)
    },
    "1234 generic_parse_test(0, 1, 2, 3, 4, 5) = 42 <STUB>\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_arch_prctl_set_fs,
    {
        use pinchy_common::{syscalls::SYS_arch_prctl, ArchPrctlData};

        let data = ArchPrctlData {
            code: pinchy_common::kernel_types::ARCH_SET_FS as i32,
            addr: 0x7f8a1b2c3d4e,
            has_val: false,
            val: 0,
        };

        crate::tests::make_compact_test_data(SYS_arch_prctl, 5678, 0, &data)
    },
    "5678 arch_prctl(ARCH_SET_FS, 0x7f8a1b2c3d4e, val: (unavailable)) = 0 (success)\n"
);

#[cfg(target_arch = "x86_64")]
syscall_test!(
    parse_arch_prctl_get_fs,
    {
        use pinchy_common::{syscalls::SYS_arch_prctl, ArchPrctlData};

        let data = ArchPrctlData {
            code: pinchy_common::kernel_types::ARCH_GET_FS as i32,
            addr: 0x7f8a1b2c3d4e,
            has_val: true,
            val: 0xffffffffff600000,
        };

        crate::tests::make_compact_test_data(SYS_arch_prctl, 9012, 0, &data)
    },
    "9012 arch_prctl(ARCH_GET_FS, 0x7f8a1b2c3d4e, val: 0xffffffffff600000) = 0 (success)\n"
);
