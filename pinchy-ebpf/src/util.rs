use core::{mem::size_of, ops::DerefMut as _};

use aya_ebpf::{
    bindings::BPF_RB_FORCE_WAKEUP,
    helpers::{bpf_probe_read_user, bpf_probe_read_user_buf},
    programs::TracePointContext,
    EbpfContext as _,
};
use aya_log_ebpf::error;
use pinchy_common::{
    kernel_types::{EpollEvent, Timespec},
    WireEventHeader, WIRE_VERSION,
};

use crate::{ENTER_MAP, EVENTS, SYSCALL_RETURN_OFFSET};

mod efficiency {
    #[cfg(feature = "efficiency-metrics")]
    mod enabled {
        use pinchy_common::{
            EFF_STAT_BYTES_SUBMITTED, EFF_STAT_EVENTS_COMPACT, EFF_STAT_EVENTS_SUBMITTED,
            EFF_STAT_RESERVE_FAIL,
        };

        use crate::EFFICIENCY_STATS;

        #[inline(always)]
        fn counter_add(counter: u32, value: u64) {
            let Some(ptr) = (unsafe { EFFICIENCY_STATS.get_ptr_mut(counter) }) else {
                return;
            };

            unsafe {
                let current = core::ptr::read_volatile(ptr);
                core::ptr::write_volatile(ptr, current.wrapping_add(value));
            }
        }

        #[inline(always)]
        pub(crate) fn record_reserve_fail() {
            counter_add(EFF_STAT_RESERVE_FAIL, 1);
        }

        #[inline(always)]
        pub(crate) fn record_compact_submit_size(bytes: u64) {
            counter_add(EFF_STAT_EVENTS_SUBMITTED, 1);
            counter_add(EFF_STAT_EVENTS_COMPACT, 1);
            counter_add(EFF_STAT_BYTES_SUBMITTED, bytes);
        }
    }

    #[cfg(not(feature = "efficiency-metrics"))]
    mod disabled {
        #[inline(always)]
        pub(crate) fn record_reserve_fail() {}

        #[inline(always)]
        pub(crate) fn record_compact_submit_size(_bytes: u64) {}
    }

    #[cfg(not(feature = "efficiency-metrics"))]
    pub(crate) use disabled::*;
    #[cfg(feature = "efficiency-metrics")]
    pub(crate) use enabled::*;
}

pub(crate) use efficiency::{record_compact_submit_size, record_reserve_fail};

#[inline(always)]
pub fn read_timespec(ptr: *const Timespec) -> Timespec {
    unsafe { bpf_probe_read_user::<Timespec>(ptr) }.unwrap_or_default()
}

#[inline(always)]
pub fn read_sigset(
    ptr: *const pinchy_common::kernel_types::Sigset,
) -> Option<pinchy_common::kernel_types::Sigset> {
    if ptr.is_null() {
        return None;
    }
    unsafe { bpf_probe_read_user::<pinchy_common::kernel_types::Sigset>(ptr) }.ok()
}

// Helper function to read timeval from userspace
#[cfg(x86_64)]
use pinchy_common::kernel_types::Timeval;

#[cfg(x86_64)]
#[inline(always)]
pub fn read_timeval(timeval_ptr: *const Timeval) -> Timeval {
    unsafe { bpf_probe_read_user::<Timeval>(timeval_ptr) }.unwrap_or_default()
}

#[inline(always)]
pub fn read_epoll_events(events_ptr: *const EpollEvent, nevents: usize, events: &mut [EpollEvent]) {
    if events_ptr.is_null() || nevents == 0 {
        return;
    }

    let base_ptr = events_ptr;
    for (i, event) in events.iter_mut().enumerate() {
        if i < nevents {
            unsafe {
                let ptr = base_ptr.add(i);
                if let Ok(evt) = bpf_probe_read_user::<EpollEvent>(ptr) {
                    *event = evt;
                }
            }
        }
    }
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

#[repr(C, packed)]
struct WireCompactPayload<T> {
    header: WireEventHeader,
    payload: T,
}

pub fn submit_compact_payload<T, F>(
    ctx: &TracePointContext,
    syscall_nr: i64,
    return_value: i64,
    initialize_payload: F,
) -> Result<(), u32>
where
    T: 'static,
    F: FnOnce(&mut T),
{
    let Some(mut entry) = (unsafe { EVENTS.reserve::<WireCompactPayload<T>>(0) }) else {
        record_reserve_fail();

        error!(
            ctx,
            "Failed to reserve ringbuf entry for syscall {}", syscall_nr
        );

        return Err(1);
    };

    let event = entry.deref_mut();
    event.write(unsafe { core::mem::zeroed::<WireCompactPayload<T>>() });

    let event = unsafe { event.assume_init_mut() as *mut WireCompactPayload<T> as *mut u8 };
    let header_ptr = event as *mut WireEventHeader;

    unsafe {
        header_ptr.write(WireEventHeader {
            version: WIRE_VERSION,
            payload_len: core::mem::size_of::<T>() as u32,
            syscall_nr,
            pid: ctx.tgid(),
            tid: ctx.pid(),
            return_value,
        });
    }

    let payload_ptr = unsafe { event.add(core::mem::size_of::<WireEventHeader>()) as *mut T };

    initialize_payload(unsafe { &mut *payload_ptr });

    record_compact_submit_size(core::mem::size_of::<WireCompactPayload<T>>() as u64);

    entry.submit(BPF_RB_FORCE_WAKEUP.into());

    Ok(())
}

use pinchy_common::{kernel_types::Iovec, IOV_COUNT, LARGER_READ_SIZE};

#[derive(Clone, Copy)]
pub enum IovecOp {
    Read,
    Write,
    AddressOnly, // Only read iovec structs, no buffer contents
}

/// Reads an array of iovec structs and their pointed-to buffers from user memory.
/// Returns the filled arrays for iovecs, lens, and bufs, and the count.
#[inline(always)]
pub fn read_iovec_array(
    iov_addr: u64,
    iovcnt: usize,
    op: IovecOp,
    iovecs: &mut [Iovec; IOV_COUNT],
    iov_lens: &mut [usize; IOV_COUNT],
    mut iov_bufs: Option<&mut [[u8; LARGER_READ_SIZE]; IOV_COUNT]>,
    read_count: &mut usize,
    return_value: i64,
) {
    *read_count = core::cmp::min(iovcnt, IOV_COUNT);

    let mut bytes_left = match op {
        IovecOp::Read => {
            if return_value < 0 {
                0
            } else {
                return_value as usize
            }
        }
        IovecOp::Write => usize::MAX,
        IovecOp::AddressOnly => 0, // Don't read buffer contents
    };

    for i in 0..*read_count {
        let iov_ptr = (iov_addr as *const u8).wrapping_add(i * size_of::<Iovec>());
        let iov_base = unsafe {
            bpf_probe_read_user::<*const u8>(iov_ptr as *const _).unwrap_or(core::ptr::null())
        };

        // Bail out early if we're dealing with a null pointer, the array item is zeroed already.
        if iov_base.is_null() {
            continue;
        }

        let iov_len =
            unsafe { bpf_probe_read_user::<u64>((iov_ptr as *const u64).add(1)).unwrap_or(0) };

        iovecs[i] = Iovec {
            iov_base: iov_base as u64,
            iov_len,
        };
        iov_lens[i] = iov_len as usize;

        // Only read buffer contents if not AddressOnly and we have a buffer to write to
        if !matches!(op, IovecOp::AddressOnly) && iov_bufs.is_some() {
            // Only read up to a specific number of bytes per iovec, and only up to bytes_left for read
            let to_read = core::cmp::min(
                LARGER_READ_SIZE,
                match op {
                    IovecOp::Read => core::cmp::min(iov_len as usize, bytes_left),
                    IovecOp::Write => iov_len as usize,
                    IovecOp::AddressOnly => 0, // Already handled above, but keep for completeness
                },
            );

            if to_read > 0 {
                if let Some(ref mut bufs) = iov_bufs {
                    unsafe {
                        let _ =
                            bpf_probe_read_user_buf(iov_base as *const u8, &mut bufs[i][..to_read]);
                    }
                }
            }

            if let IovecOp::Read = op {
                bytes_left = bytes_left.saturating_sub(to_read);
                if bytes_left == 0 {
                    break;
                }
            }
        }
    }
}
