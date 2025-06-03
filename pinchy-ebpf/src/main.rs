#![no_std]
#![no_main]
#![allow(non_snake_case, non_upper_case_globals, static_mut_refs)]
use aya_ebpf::{
    helpers::bpf_probe_read_user,
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    EbpfContext as _,
};
use aya_log_ebpf::{error, trace};
use pinchy_common::{
    kernel_types::{EpollEvent, Pollfd, Timespec},
    syscalls::{SYS_epoll_pwait, SYS_ppoll},
    SyscallEvent,
};

#[map]
static mut PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static mut EVENTS: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);

#[map]
static mut ENTER_MAP: HashMap<u32, SyscallEnterData> = HashMap::with_max_entries(10240, 0);

#[repr(C)]
pub struct SyscallEnterData {
    pub tgid: u32,
    pub syscall_nr: i64,
    pub args: [usize; SYSCALL_ARGS_COUNT],
}

#[tracepoint]
pub fn pinchy(ctx: TracePointContext) -> u32 {
    match try_pinchy(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/format
//
// name: sys_enter
// ID: 25
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;
//
// 	field:long id;	offset:8;	size:8;	signed:1;
// 	field:unsigned long args[6];	offset:16;	size:48;	signed:0;
//
// print fmt: "NR %ld (%lx, %lx, %lx, %lx, %lx, %lx)", REC->id, REC->args[0], REC->args[1], REC->args[2], REC->args[3], REC->args[4], REC->args[5]
const SYSCALL_OFFSET: usize = 8;
const SYSCALL_ARGS_OFFSET: usize = 16;
const SYSCALL_ARGS_COUNT: usize = 6;
fn try_pinchy(ctx: TracePointContext) -> Result<u32, u32> {
    let tgid = ctx.tgid();
    let tid = ctx.pid();

    if unsafe { PID_FILTER.get(&tgid).is_none() } {
        return Ok(0);
    }

    let syscall_nr = unsafe { ctx.read_at::<i64>(SYSCALL_OFFSET).map_err(|e| e as u32)? };

    let args = unsafe {
        ctx.read_at::<[usize; SYSCALL_ARGS_COUNT]>(SYSCALL_ARGS_OFFSET)
            .map_err(|e| e as u32)?
    };

    let data = SyscallEnterData {
        tgid,
        syscall_nr,
        args,
    };

    if let Err(err) = unsafe { ENTER_MAP.insert(&tid, &data, 0) } {
        error!(
            &ctx,
            "Failed to insert data for syscall {} (tid {}, tgid {}). Error code: {}",
            syscall_nr,
            tid,
            tgid,
            err
        );
        return Err(err as u32);
    }

    Ok(0)
}

#[tracepoint]
pub fn pinchy_exit(ctx: TracePointContext) -> u32 {
    match try_pinchy_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/format
//
// name: sys_exit
// ID: 24
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;
//
// 	field:long id;	offset:8;	size:8;	signed:1;
// 	field:long ret;	offset:16;	size:8;	signed:1;
//
// print fmt: "NR %ld = %ld", REC->id, REC->ret
const SYSCALL_RETURN_OFFSET: usize = 16;
fn try_pinchy_exit(ctx: TracePointContext) -> Result<u32, u32> {
    let tgid = ctx.tgid();
    let tid = ctx.pid();

    if unsafe { PID_FILTER.get(&tgid).is_none() } {
        return Ok(0);
    }

    let syscall_nr = unsafe { ctx.read_at::<i64>(SYSCALL_OFFSET).map_err(|e| e as u32)? };

    let Some(enter_data) = (unsafe { ENTER_MAP.get(&tid) }) else {
        error!(
            &ctx,
            "Could not find matching enter data for syscall {} exit (tid {}, tgid {})",
            syscall_nr,
            tid,
            tgid
        );
        return Err(1);
    };

    // Copy the part of the enter data we care about...
    let args = enter_data.args;

    // Then remove the item from the map.
    let _ = unsafe { ENTER_MAP.remove(&tid) };

    if enter_data.syscall_nr != syscall_nr {
        error!(
            &ctx,
            "Expected syscall {} found syscall {} on enter data (tid {}, tgid {})",
            syscall_nr,
            enter_data.syscall_nr,
            tid,
            tgid
        );
        return Err(1);
    }

    let return_value = unsafe {
        ctx.read_at::<i64>(SYSCALL_RETURN_OFFSET)
            .map_err(|e| e as u32)?
    };

    let data = match syscall_nr {
        SYS_epoll_pwait => {
            let epfd = args[0] as i32;
            let events_ptr = args[1] as *const EpollEvent;
            let max_events = args[2] as i32;
            let timeout = args[3] as i32;

            let mut events = [EpollEvent::default(); 8];
            for i in 0..events.len() {
                // The events pointer is an out parameter, the return value tells us how many were
                // populated by the syscall.
                if i < return_value as usize {
                    unsafe {
                        let events_ptr = events_ptr.add(i as usize);
                        if let Ok(evt) = bpf_probe_read_user::<EpollEvent>(events_ptr as *const _) {
                            events[i] = evt;
                        }
                    }
                }
            }

            pinchy_common::SyscallEventData {
                epoll_pwait: pinchy_common::EpollPWaitData {
                    epfd,
                    events,
                    max_events,
                    timeout,
                },
            }
        }
        SYS_ppoll => {
            let nfds = args[1];

            let fds_ptr = args[0] as *const Pollfd;

            let mut fds = [0i32; 16];
            let mut events = [0i16; 16];
            let mut revents = [0i16; 16];
            for i in 0..fds.len() {
                if i < nfds {
                    unsafe {
                        let entry_ptr = fds_ptr.add(i as usize);
                        if let Ok(pollfd) = bpf_probe_read_user::<Pollfd>(entry_ptr as *const _) {
                            fds[i] = pollfd.fd;
                            events[i] = pollfd.events;
                            revents[i] = pollfd.revents;
                        }
                    }
                }
            }

            let timeout = read_timespec(args[2] as *const _);

            pinchy_common::SyscallEventData {
                ppoll: pinchy_common::PpollData {
                    fds,
                    events,
                    revents,
                    nfds: nfds as u32,
                    timeout,
                },
            }
        }
        _ => {
            trace!(&ctx, "unknown syscall {}", syscall_nr);
            return Ok(0);
        }
    };

    let event = SyscallEvent {
        syscall_nr,
        pid: tgid,
        tid,
        return_value,
        data,
    };
    unsafe { EVENTS.output(&ctx, &event, 0) };

    Ok(0)
}

fn read_timespec(ptr: *const Timespec) -> Timespec {
    unsafe { bpf_probe_read_user::<Timespec>(ptr) }.unwrap_or_default()
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
