mod basic_io;
mod filesystem;
mod memory;
mod process;
mod scheduling;
mod signal;
mod sync;
mod system;

use std::pin::Pin;

use crate::{
    events::handle_event,
    formatting::{Formatter, FormattingStyle},
};

#[tokio::test]
async fn parse_generic_syscall() {
    use pinchy_common::{
        syscalls::SYS_generic_parse_test, GenericSyscallData, SyscallEvent, SyscallEventData,
    };

    // Test the generic syscall handler using a fake syscall
    let event = SyscallEvent {
        syscall_nr: SYS_generic_parse_test,
        pid: 1234,
        tid: 1234,
        return_value: 42,
        data: SyscallEventData {
            generic: GenericSyscallData {
                args: [0, 1, 2, 3, 4, 5],
            },
        },
    };

    let mut output: Vec<u8> = vec![];
    let pin_output = unsafe { Pin::new_unchecked(&mut output) };
    let formatter = Formatter::new(pin_output, FormattingStyle::OneLine);

    handle_event(&event, formatter).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&output),
        format!("1234 generic_parse_test(0, 1, 2, 3, 4, 5) = 42 <STUB>\n")
    );
}
