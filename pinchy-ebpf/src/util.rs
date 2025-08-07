use core::ops::DerefMut as _;

use aya_ebpf::{
    bindings::BPF_RB_FORCE_WAKEUP,
    helpers::{bpf_probe_read_buf, bpf_probe_read_user},
    maps::ring_buf::RingBufEntry,
    programs::TracePointContext,
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

#[macro_export]
macro_rules! syscall_handler {
    // Pattern with default data field (same as syscall name)
    ($name:ident, $args:ident, $data:ident, $body:block) => {
        syscall_handler!($name, $name, $args, $data, $body);
    };

    ($name:ident, $data_field:ident, $args:ident, $data:ident, $body:block) => {
        syscall_handler!($name, $data_field, $args, $data, _return_value, $body);
    };

    ($name:ident, $data_field:ident, $args:ident, $data:ident, $return_value:ident, $body:block) => {
        syscall_handler!($name, $data_field, $args, $data, $return_value, _ctx, $body);
    };

    ($name:ident, $data_field:ident, $args:ident, $data:ident, $return_value:ident, $ctx:ident, $body:block) => {
        #[::aya_ebpf::macros::tracepoint]
        pub fn ${concat(syscall_exit_, $name)}(ctx: ::aya_ebpf::programs::TracePointContext) -> u32 {
            let syscall_nr = pinchy_common::syscalls::${concat(SYS_, $name)};
            let Ok(mut entry) = $crate::util::Entry::new(&ctx, syscall_nr) else {
                return 1;
            };

            fn inner(ctx: &::aya_ebpf::programs::TracePointContext, entry: &mut $crate::util::Entry) -> Result<(), u32> {
                let $args = $crate::util::get_args(ctx, entry.syscall_nr)?;
                let $data = unsafe { &mut entry.data.$data_field };
                let $return_value = $crate::util::get_return_value(&ctx)?;
                let $ctx = ctx;

                $body;

                Ok(())
            }

            match inner(&ctx, &mut entry) {
                Ok(_) => entry.submit(),
                Err(ret) => {
                    entry.discard();
                    ret
                }
            }
        }
    };
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

pub struct Entry {
    inner: RingBufEntry<SyscallEvent>,
}

impl Entry {
    pub fn new(ctx: &TracePointContext, syscall_nr: i64) -> Result<Self, u32> {
        let Some(mut entry) = (unsafe { EVENTS.reserve::<SyscallEvent>(0) }) else {
            error!(
                ctx,
                "Failed to reserve ringbuf entry for syscall {}", syscall_nr
            );
            return Err(1);
        };

        let event = entry.deref_mut();
        event.write(unsafe { core::mem::zeroed::<SyscallEvent>() });

        let event = unsafe { event.assume_init_mut() };

        event.pid = ctx.pid();
        event.tid = ctx.tgid();
        event.syscall_nr = syscall_nr;
        event.return_value = match get_return_value(&ctx) {
            Ok(return_value) => return_value,
            Err(e) => {
                entry.discard(0);
                return Err(e);
            }
        };

        Ok(Entry { inner: entry })
    }

    fn event_mut(&mut self) -> &mut SyscallEvent {
        unsafe { self.inner.deref_mut().assume_init_mut() }
    }

    pub fn submit(self) -> u32 {
        self.inner.submit(BPF_RB_FORCE_WAKEUP.into());
        0
    }

    pub fn discard(self) {
        self.inner.discard(0);
    }
}

impl core::ops::Deref for Entry {
    type Target = SyscallEvent;

    fn deref(&self) -> &Self::Target {
        unsafe { self.inner.assume_init_ref() }
    }
}

impl core::ops::DerefMut for Entry {
    fn deref_mut(&mut self) -> &mut SyscallEvent {
        self.event_mut()
    }
}

use pinchy_common::{kernel_types::Iovec, IOV_COUNT, MEDIUM_READ_SIZE};

pub enum IovecOp {
    Read,
    Write,
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
    iov_bufs: &mut [[u8; MEDIUM_READ_SIZE]; IOV_COUNT],
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

        // Only read up to MEDIUM_READ_SIZE bytes per iovec, and only up to bytes_left for read
        let to_read = core::cmp::min(
            MEDIUM_READ_SIZE,
            match op {
                IovecOp::Read => core::cmp::min(iov_len as usize, bytes_left),
                IovecOp::Write => iov_len as usize,
            },
        );

        if to_read > 0 {
            unsafe {
                let _ = bpf_probe_read_buf(iov_base as *const u8, &mut iov_bufs[i][..to_read]);
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
