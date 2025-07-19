use core::ops::DerefMut as _;

use aya_ebpf::{
    bindings::BPF_RB_FORCE_WAKEUP, helpers::bpf_probe_read_user, programs::TracePointContext,
    EbpfContext as _,
};
use aya_log_ebpf::error;
use pinchy_common::{kernel_types::Timespec, SyscallEvent};

use crate::{ENTER_MAP, EVENTS, SYSCALL_RETURN_OFFSET};

#[inline(always)]
pub fn read_timespec(ptr: *const Timespec) -> Timespec {
    unsafe { bpf_probe_read_user::<Timespec>(ptr) }.unwrap_or_default()
}

#[inline(always)]
pub fn get_syscall_nr(ctx: &TracePointContext) -> Result<i64, u32> {
    unsafe { ENTER_MAP.get(&ctx.pid()) }
        .map(|data| data.syscall_nr)
        .ok_or(1)
}

#[inline(always)]
pub fn get_args(ctx: &TracePointContext, expected_syscall_nr: i64) -> Result<[usize; 6], u32> {
    let tgid = ctx.tgid();
    let tid = ctx.pid();

    let Some(enter_data) = (unsafe { ENTER_MAP.get(&tid) }) else {
        error!(
            ctx,
            "Could not find matching enter data for syscall {} exit (tid {}, tgid {})",
            expected_syscall_nr,
            tid,
            tgid
        );
        return Err(1);
    };

    if enter_data.syscall_nr != expected_syscall_nr {
        error!(
            ctx,
            "Expected syscall {} found syscall {} on enter data (tid {}, tgid {})",
            expected_syscall_nr,
            enter_data.syscall_nr,
            tid,
            tgid
        );
        return Err(1);
    }

    // Copy the part of the enter data we care about...
    let args = enter_data.args;

    // Then remove the item from the map.
    let _ = unsafe { ENTER_MAP.remove(&tid) };

    Ok(args)
}

#[inline(always)]
pub fn get_return_value(ctx: &TracePointContext) -> Result<i64, u32> {
    Ok(unsafe {
        ctx.read_at::<i64>(SYSCALL_RETURN_OFFSET)
            .map_err(|_| 1u32)?
    })
}

#[inline(always)]
pub fn output_event(
    ctx: &TracePointContext,
    syscall_nr: i64,
    return_value: i64,
    data: pinchy_common::SyscallEventData,
) -> Result<(), u32> {
    let tgid = ctx.tgid();
    let tid = ctx.pid();

    unsafe {
        let mut buf: Option<aya_ebpf::maps::ring_buf::RingBufEntry<SyscallEvent>> = None;

        // Retry a few times if the buffer is full, give time for userspace to catch up
        for _ in 0..1_024 {
            buf = EVENTS.reserve(0);
            if buf.is_some() {
                break;
            }
        }

        match buf {
            Some(mut entry) => {
                let event = entry.deref_mut();
                event.write(SyscallEvent {
                    syscall_nr,
                    pid: tgid,
                    tid,
                    return_value,
                    data,
                });
                entry.submit(BPF_RB_FORCE_WAKEUP.into());
            }
            None => {
                error!(
                    ctx,
                    "Failed to reserve space for event - ring buffer was full."
                );
            }
        }
    }

    Ok(())
}
