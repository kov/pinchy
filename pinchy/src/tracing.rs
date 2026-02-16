#![allow(non_snake_case, non_upper_case_globals)]
use std::{
    collections::HashMap,
    os::fd::{AsRawFd as _, OwnedFd},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

use aya::{
    maps::{ring_buf::RingBuf, Array},
    Ebpf,
};
use pinchy_common::{
    compact_payload_size, syscalls, wire_validation_enabled, SyscallEvent, WireEventHeader,
    WIRE_KIND_COMPACT_SYSCALL_EVENT, WIRE_KIND_LEGACY_SYSCALL_EVENT, WIRE_VERSION,
};
use tokio::{
    io::{unix::AsyncFd, AsyncWriteExt},
    sync::{mpsc::error::TrySendError, RwLock},
    time::{sleep, Duration},
};

pub type SharedEventDispatch = Arc<RwLock<EventDispatch>>;

// Constants for timeout behavior
const PID_TIMEOUT_MS: u64 = 50; // Initial timeout after process exit
const MAX_TIMEOUT_RESETS: u32 = 10; // Maximum number of times we'll reset the timeout
const TIMEOUT_EXTENSION_MS: u64 = 10; // How much to extend on each event

mod efficiency {
    #[cfg(feature = "efficiency-metrics")]
    mod enabled {
        use std::sync::atomic::{AtomicU64, Ordering};

        use aya::{maps::Array, Ebpf};
        use pinchy_common::{
            EFF_STAT_BYTES_SUBMITTED, EFF_STAT_COUNT, EFF_STAT_EVENTS_LEGACY,
            EFF_STAT_EVENTS_SUBMITTED, EFF_STAT_RESERVE_FAIL,
        };

        pub(crate) type EbpfCounters = [u64; EFF_STAT_COUNT as usize];

        #[derive(Default)]
        pub(crate) struct DispatchStats {
            ring_items_read: AtomicU64,
            ring_bytes_read: AtomicU64,
            ring_items_unexpected: AtomicU64,
            framed_events: AtomicU64,
            framed_bytes: AtomicU64,
            dispatch_events_matched: AtomicU64,
            dispatch_send_ok: AtomicU64,
            dispatch_send_fail: AtomicU64,
            dispatch_send_queue_full: AtomicU64,
            dispatch_send_closed: AtomicU64,
            drop_legacy_events: AtomicU64,
            queue_depth_current: AtomicU64,
            queue_depth_peak: AtomicU64,
            writer_events_written: AtomicU64,
            writer_bytes_written: AtomicU64,
            writer_write_errors: AtomicU64,
            writer_flush_errors: AtomicU64,
        }

        #[derive(Clone, Copy, Default)]
        pub(crate) struct DispatchStatsSnapshot {
            ring_items_read: u64,
            ring_bytes_read: u64,
            ring_items_unexpected: u64,
            framed_events: u64,
            framed_bytes: u64,
            dispatch_events_matched: u64,
            dispatch_send_ok: u64,
            dispatch_send_fail: u64,
            dispatch_send_queue_full: u64,
            dispatch_send_closed: u64,
            drop_legacy_events: u64,
            queue_depth_current: u64,
            queue_depth_peak: u64,
            writer_events_written: u64,
            writer_bytes_written: u64,
            writer_write_errors: u64,
            writer_flush_errors: u64,
        }

        impl DispatchStats {
            pub(crate) fn new() -> Self {
                Self::default()
            }

            pub(crate) fn writer_write_error(&self) {
                self.writer_write_errors.fetch_add(1, Ordering::Relaxed);
            }

            pub(crate) fn writer_flush_error(&self) {
                self.writer_flush_errors.fetch_add(1, Ordering::Relaxed);
            }

            pub(crate) fn writer_event_written(&self, bytes: usize) {
                self.writer_events_written.fetch_add(1, Ordering::Relaxed);
                self.writer_bytes_written
                    .fetch_add(bytes as u64, Ordering::Relaxed);
            }

            pub(crate) fn ring_item_read(&self, bytes: usize) {
                self.ring_items_read.fetch_add(1, Ordering::Relaxed);
                self.ring_bytes_read
                    .fetch_add(bytes as u64, Ordering::Relaxed);
            }

            pub(crate) fn ring_item_unexpected(&self) {
                self.ring_items_unexpected.fetch_add(1, Ordering::Relaxed);
            }

            pub(crate) fn framed_event(&self, bytes: usize) {
                self.framed_events.fetch_add(1, Ordering::Relaxed);
                self.framed_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
            }

            pub(crate) fn dispatch_event_matched(&self) {
                self.dispatch_events_matched.fetch_add(1, Ordering::Relaxed);
            }

            pub(crate) fn dispatch_send(&self, ok: bool) {
                if ok {
                    self.dispatch_send_ok.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.dispatch_send_fail.fetch_add(1, Ordering::Relaxed);
                }
            }

            pub(crate) fn dispatch_send_drop(&self, is_full: bool) {
                if is_full {
                    self.dispatch_send_queue_full
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.dispatch_send_closed.fetch_add(1, Ordering::Relaxed);
                }

                self.drop_legacy_events.fetch_add(1, Ordering::Relaxed);
            }

            pub(crate) fn queue_depth_increment(&self) {
                let current = self.queue_depth_current.fetch_add(1, Ordering::Relaxed) + 1;

                let _ = self.queue_depth_peak.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |peak| if current > peak { Some(current) } else { None },
                );
            }

            pub(crate) fn queue_depth_decrement(&self) {
                let _ = self.queue_depth_current.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |value: u64| Some(value.saturating_sub(1)),
                );
            }

            pub(crate) fn snapshot(&self) -> DispatchStatsSnapshot {
                DispatchStatsSnapshot {
                    ring_items_read: self.ring_items_read.load(Ordering::Relaxed),
                    ring_bytes_read: self.ring_bytes_read.load(Ordering::Relaxed),
                    ring_items_unexpected: self.ring_items_unexpected.load(Ordering::Relaxed),
                    framed_events: self.framed_events.load(Ordering::Relaxed),
                    framed_bytes: self.framed_bytes.load(Ordering::Relaxed),
                    dispatch_events_matched: self.dispatch_events_matched.load(Ordering::Relaxed),
                    dispatch_send_ok: self.dispatch_send_ok.load(Ordering::Relaxed),
                    dispatch_send_fail: self.dispatch_send_fail.load(Ordering::Relaxed),
                    dispatch_send_queue_full: self.dispatch_send_queue_full.load(Ordering::Relaxed),
                    dispatch_send_closed: self.dispatch_send_closed.load(Ordering::Relaxed),
                    drop_legacy_events: self.drop_legacy_events.load(Ordering::Relaxed),
                    queue_depth_current: self.queue_depth_current.load(Ordering::Relaxed),
                    queue_depth_peak: self.queue_depth_peak.load(Ordering::Relaxed),
                    writer_events_written: self.writer_events_written.load(Ordering::Relaxed),
                    writer_bytes_written: self.writer_bytes_written.load(Ordering::Relaxed),
                    writer_write_errors: self.writer_write_errors.load(Ordering::Relaxed),
                    writer_flush_errors: self.writer_flush_errors.load(Ordering::Relaxed),
                }
            }
        }

        pub(crate) fn stats_enabled_from_env() -> bool {
            match std::env::var("PINCHY_EFF_STATS") {
                Ok(value) => value == "1" || value.eq_ignore_ascii_case("true"),
                Err(_) => false,
            }
        }

        pub(crate) fn read_ebpf_counters(ebpf: &mut Ebpf) -> Option<EbpfCounters> {
            let map = ebpf.map("EFFICIENCY_STATS")?;
            let map: Array<_, u64> = Array::try_from(map).ok()?;

            let mut counters = [0u64; EFF_STAT_COUNT as usize];

            for i in 0..EFF_STAT_COUNT {
                counters[i as usize] = map.get(&i, 0).ok()?;
            }

            Some(counters)
        }

        pub(crate) fn print_efficiency_snapshot(
            userspace: DispatchStatsSnapshot,
            ebpf: Option<EbpfCounters>,
            queue_snapshot: &str,
        ) {
            let mut line = format!(
                "EFF userspace ring_items={} ring_bytes={} unexpected={} framed_events={} framed_bytes={} matched={} send_ok={} send_fail={} send_queue_full={} send_closed={} drop_legacy={} qdepth={} qpeak={} writer_events={} writer_bytes={} writer_write_err={} writer_flush_err={}",
                userspace.ring_items_read,
                userspace.ring_bytes_read,
                userspace.ring_items_unexpected,
                userspace.framed_events,
                userspace.framed_bytes,
                userspace.dispatch_events_matched,
                userspace.dispatch_send_ok,
                userspace.dispatch_send_fail,
                userspace.dispatch_send_queue_full,
                userspace.dispatch_send_closed,
                userspace.drop_legacy_events,
                userspace.queue_depth_current,
                userspace.queue_depth_peak,
                userspace.writer_events_written,
                userspace.writer_bytes_written,
                userspace.writer_write_errors,
                userspace.writer_flush_errors,
            );

            if let Some(ebpf) = ebpf {
                line.push_str(&format!(
                    " ebpf_submitted={} ebpf_bytes={} ebpf_reserve_fail={} ebpf_legacy_events={}",
                    ebpf[EFF_STAT_EVENTS_SUBMITTED as usize],
                    ebpf[EFF_STAT_BYTES_SUBMITTED as usize],
                    ebpf[EFF_STAT_RESERVE_FAIL as usize],
                    ebpf[EFF_STAT_EVENTS_LEGACY as usize],
                ));
            }

            if !queue_snapshot.is_empty() {
                line.push_str(" queue_clients=");
                line.push_str(queue_snapshot);
            }

            println!("{line}");
        }
    }

    #[cfg(not(feature = "efficiency-metrics"))]
    mod disabled {
        use aya::Ebpf;

        #[derive(Default)]
        pub(crate) struct DispatchStats;

        #[derive(Clone, Copy, Default)]
        pub(crate) struct DispatchStatsSnapshot;

        pub(crate) type EbpfCounters = ();

        impl DispatchStats {
            pub(crate) fn new() -> Self {
                Self
            }

            pub(crate) fn writer_write_error(&self) {}

            pub(crate) fn writer_flush_error(&self) {}

            pub(crate) fn writer_event_written(&self, _bytes: usize) {}

            pub(crate) fn ring_item_read(&self, _bytes: usize) {}

            pub(crate) fn ring_item_unexpected(&self) {}

            pub(crate) fn framed_event(&self, _bytes: usize) {}

            pub(crate) fn dispatch_event_matched(&self) {}

            pub(crate) fn dispatch_send(&self, _ok: bool) {}

            pub(crate) fn dispatch_send_drop(&self, _is_full: bool) {}

            pub(crate) fn queue_depth_increment(&self) {}

            pub(crate) fn queue_depth_decrement(&self) {}

            pub(crate) fn snapshot(&self) -> DispatchStatsSnapshot {
                DispatchStatsSnapshot
            }
        }

        pub(crate) fn stats_enabled_from_env() -> bool {
            false
        }

        pub(crate) fn read_ebpf_counters(_ebpf: &mut Ebpf) -> Option<EbpfCounters> {
            None
        }

        pub(crate) fn print_efficiency_snapshot(
            _userspace: DispatchStatsSnapshot,
            _ebpf: Option<EbpfCounters>,
            _queue_snapshot: &str,
        ) {
        }
    }

    #[cfg(not(feature = "efficiency-metrics"))]
    pub(crate) use disabled::*;
    #[cfg(feature = "efficiency-metrics")]
    pub(crate) use enabled::*;
}

use efficiency::{DispatchStats, EbpfCounters};

#[derive(Debug, Default)]
struct ClientQueueStats {
    depth: AtomicUsize,
    peak: AtomicUsize,
    drop_full: AtomicU64,
    drop_closed: AtomicU64,
}

impl ClientQueueStats {
    fn increment_depth(&self) {
        let current = self.depth.fetch_add(1, Ordering::Relaxed) + 1;

        let _ = self
            .peak
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |peak| {
                if current > peak {
                    Some(current)
                } else {
                    None
                }
            });
    }

    fn decrement_depth(&self) {
        let _ = self
            .depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_sub(1))
            });
    }

    fn record_full_drop(&self) {
        self.drop_full.fetch_add(1, Ordering::Relaxed);
    }

    fn record_closed_drop(&self) {
        self.drop_closed.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (usize, usize, u64, u64) {
        (
            self.depth.load(Ordering::Relaxed),
            self.peak.load(Ordering::Relaxed),
            self.drop_full.load(Ordering::Relaxed),
            self.drop_closed.load(Ordering::Relaxed),
        )
    }
}

struct WriterTask {
    client_id: u64,
    writer: tokio::io::BufWriter<tokio::fs::File>,
    event_rx: tokio::sync::mpsc::Receiver<Arc<[u8]>>,
    cleanup_tx: tokio::sync::mpsc::Sender<u64>,
    stats: Arc<DispatchStats>,
    queue_stats: Arc<ClientQueueStats>,
}

impl WriterTask {
    async fn run(mut self) {
        // Get the underlying file descriptor
        let fd = self.writer.get_ref().as_raw_fd();

        // Check if the pipe is still writable using poll
        let poll_fd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };

        loop {
            tokio::select! {
                event_bytes = self.event_rx.recv() => {
                    let Some(event_bytes) = event_bytes else {
                        log::trace!("Writer task ended: no more events to read");
                        break;
                    };

                    self.queue_stats.decrement_depth();
                    self.stats.queue_depth_decrement();

                    if self.writer.write_all(&event_bytes).await.is_err() {
                        self.stats.writer_write_error();

                        log::trace!("Writer task ended: write error");
                        break;
                    }

                    self.stats.writer_event_written(event_bytes.len());

                    log::trace!("Writer task wrote: {} bytes", event_bytes.len());
                },
                _ = sleep(Duration::from_millis(10)) => {
                    if self.writer.flush().await.is_err() {
                        self.stats.writer_flush_error();

                        log::trace!("Writer task ended: flush error");
                        break;
                    }

                    // FIXME: there must be a better, more high level way of identifying the other end
                    // of the pipe got closed? I tried a 0-sized write followed by a flush, I suppose the
                    // BufWriter absorbs it.
                    let poll_result = unsafe { libc::poll(&poll_fd as *const _ as *mut _, 1, 0) };
                    if poll_result < 0
                        || (poll_fd.revents & libc::POLLHUP) != 0
                        || (poll_fd.revents & libc::POLLERR) != 0
                    {
                        log::trace!("Writer task ended: pipe closed");
                        break;
                    }
                }
            }
        }

        let _ = self.writer.flush().await;
        let _ = self.cleanup_tx.send(self.client_id).await;
    }
}

#[derive(Debug)]
struct Client {
    client_id: u64,
    #[allow(unused)]
    pid: u32,
    sender: tokio::sync::mpsc::Sender<Arc<[u8]>>,
    syscalls: Vec<i64>,
    queue_stats: Arc<ClientQueueStats>,
}

#[derive(Debug)]
struct PidTimeout {
    #[allow(unused)]
    pid: u32,
    expire_at: RwLock<Instant>,
    reset_count: RwLock<u32>,
}

pub struct EventDispatch {
    // Maps PID to list of clients interested in that PID
    clients_map: HashMap<u32, Vec<Client>>,
    next_client_id: u64,
    cleanup_tx: tokio::sync::mpsc::Sender<u64>,
    ebpf: Ebpf,
    // Timeout tracking for PIDs
    pid_timeouts: HashMap<u32, PidTimeout>,
    timeout_tx: tokio::sync::mpsc::Sender<u32>,
    client_queue_capacity: usize,
    stats: Arc<DispatchStats>,
}

fn parse_event_metadata(event: &[u8]) -> Option<WireEventHeader> {
    let header_size = std::mem::size_of::<WireEventHeader>();

    if event.len() >= header_size {
        let header = unsafe { std::ptr::read_unaligned(event.as_ptr() as *const WireEventHeader) };

        if header.version == WIRE_VERSION {
            let payload_len = header.payload_len as usize;
            let total_size = header_size.checked_add(payload_len)?;

            if total_size == event.len() {
                let payload = &event[header_size..];

                match header.kind {
                    WIRE_KIND_LEGACY_SYSCALL_EVENT => {
                        if payload.len() != std::mem::size_of::<SyscallEvent>() {
                            return None;
                        }

                        return Some(header);
                    }

                    WIRE_KIND_COMPACT_SYSCALL_EVENT => {
                        let expected_payload_size = compact_payload_size(header.syscall_nr)?;

                        if payload.len() != expected_payload_size {
                            return None;
                        }

                        return Some(header);
                    }

                    _ => {
                        return None;
                    }
                }
            }
        }
    }

    None
}

fn parse_trusted_wire_metadata(event: &[u8]) -> Option<WireEventHeader> {
    let header_size = std::mem::size_of::<WireEventHeader>();

    if event.len() < header_size {
        return None;
    }

    let header = unsafe { std::ptr::read_unaligned(event.as_ptr() as *const WireEventHeader) };

    assert_eq!(header.version, WIRE_VERSION);

    Some(header)
}

fn parse_client_queue_capacity() -> usize {
    std::env::var("PINCHY_CLIENT_QUEUE_CAPACITY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(128)
}

// Core event processing and client management
//
// This block handles the main event loop, spawning background tasks, dispatching events
impl EventDispatch {
    pub async fn spawn(
        mut ebpf: Ebpf,
        idle_since: Arc<RwLock<Instant>>,
    ) -> anyhow::Result<SharedEventDispatch> {
        let stats = Arc::new(DispatchStats::new());

        let stats_enabled = efficiency::stats_enabled_from_env();
        let client_queue_capacity = parse_client_queue_capacity();
        let validate_wire = wire_validation_enabled();

        // Create channels for internal communication
        let (cleanup_tx, mut cleanup_rx) = tokio::sync::mpsc::channel(128);
        let (timeout_tx, mut timeout_rx) = tokio::sync::mpsc::channel(128);

        // Set up the ring buffer for reading events from eBPF
        let ring = RingBuf::try_from(
            ebpf.take_map("EVENTS")
                .ok_or_else(|| anyhow::anyhow!("EVENTS map not found"))?,
        )?;
        let mut async_ring = AsyncFd::new(ring)?;

        let dispatch = Self {
            clients_map: HashMap::new(),
            next_client_id: 1,
            cleanup_tx,
            ebpf,
            pid_timeouts: HashMap::new(),
            timeout_tx,
            client_queue_capacity,
            stats: stats.clone(),
        };

        let shared_dispatch = Arc::new(RwLock::new(dispatch));

        // Spawn the periodic timeout cleanup task
        let cleanup_dispatch = shared_dispatch.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(50));
            loop {
                interval.tick().await;

                // Get list of PIDs that have timeouts
                let pids_to_check: Vec<u32> = {
                    let dispatch = cleanup_dispatch.read().await;
                    dispatch.pid_timeouts.keys().copied().collect()
                };

                if pids_to_check.is_empty() {
                    continue;
                }

                // Check each PID's timeout
                let mut dispatch = cleanup_dispatch.write().await;
                for pid in pids_to_check {
                    if let Err(e) = dispatch.handle_pid_timeout(pid).await {
                        eprintln!("Error handling timeout for PID {pid}: {e}");
                    }
                }
            }
        });

        if stats_enabled {
            let reporter_dispatch = shared_dispatch.clone();
            let reporter_stats = stats.clone();

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));

                loop {
                    interval.tick().await;

                    let userspace = reporter_stats.snapshot();

                    let (ebpf_counters, queue_snapshot) = {
                        let mut dispatch = reporter_dispatch.write().await;
                        let ebpf = dispatch.read_efficiency_counters();
                        let queue_snapshot = dispatch.client_queue_snapshot();
                        (ebpf, queue_snapshot)
                    };

                    efficiency::print_efficiency_snapshot(
                        userspace,
                        ebpf_counters,
                        &queue_snapshot,
                    );
                }
            });
        }

        // Spawn the main event loop that reads from ring buffer and handles events
        let event_dispatch = shared_dispatch.clone();
        let event_stats = stats.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Read events from eBPF ring buffer
                    ring_result = async_ring.readable_mut() => {
                        match ring_result {
                            Ok(mut guard) => {
                                *idle_since.write().await = Instant::now();

                                log::trace!("RingBuf had something to read...");

                                let ring = guard.get_inner_mut();
                                while let Some(item) = ring.next() {
                                    let event = &*item;

                                    event_stats.ring_item_read(event.len());

                                    let parsed = if validate_wire {
                                        parse_event_metadata(event)
                                    } else {
                                        parse_trusted_wire_metadata(event)
                                    };

                                    let Some(header) = parsed else {
                                        event_stats.ring_item_unexpected();
                                        log::trace!("RingBuf item had unexpected size, discarded...");
                                        continue;
                                    };

                                    let framed_event = Arc::<[u8]>::from(event.to_vec());

                                    event_stats.framed_event(framed_event.len());

                                    log::trace!("Read {} bytes from ringbuf...", event.len());
                                    event_dispatch.read().await.dispatch_event(header, framed_event);
                                }
                                guard.clear_ready();
                            }
                            Err(e) => {
                                eprintln!("RingBuf read error: {e}");
                                return;
                            }
                        }
                    },
                    Some(client_id) = cleanup_rx.recv() => {
                        let _ = event_dispatch.write().await.remove_client(client_id).await;
                    },
                    Some(pid) = timeout_rx.recv() => {
                        let _ = event_dispatch.write().await.start_pid_timeout(pid).await;
                    },
                }
            }
        });

        Ok(shared_dispatch)
    }

    fn dispatch_event(&self, header: WireEventHeader, event_bytes: Arc<[u8]>) {
        if let Some(clients) = self.clients_map.get(&header.pid) {
            let interested_clients: Vec<_> = clients
                .iter()
                .filter(|client| client.syscalls.contains(&header.syscall_nr))
                .collect();

            if !interested_clients.is_empty() {
                self.stats.dispatch_event_matched();

                for client in interested_clients {
                    match client.sender.try_send(event_bytes.clone()) {
                        Ok(()) => {
                            client.queue_stats.increment_depth();
                            self.stats.queue_depth_increment();
                            self.stats.dispatch_send(true);
                        }
                        Err(TrySendError::Full(_)) => {
                            client.queue_stats.record_full_drop();
                            self.stats.dispatch_send(false);
                            self.stats.dispatch_send_drop(true);
                        }
                        Err(TrySendError::Closed(_)) => {
                            client.queue_stats.record_closed_drop();
                            self.stats.dispatch_send(false);
                            self.stats.dispatch_send_drop(false);
                        }
                    }
                }

                // Reset timeout for this PID if it has one
                self.reset_pid_timeout(header.pid);
            }
        }
    }

    fn read_efficiency_counters(&mut self) -> Option<EbpfCounters> {
        efficiency::read_ebpf_counters(&mut self.ebpf)
    }

    fn client_queue_snapshot(&self) -> String {
        let mut entries = Vec::new();

        for clients in self.clients_map.values() {
            for client in clients {
                let (depth, peak, drop_full, drop_closed) = client.queue_stats.snapshot();

                if depth == 0 && peak == 0 && drop_full == 0 && drop_closed == 0 {
                    continue;
                }

                entries.push(format!(
                    "{}:{}:{}/{}/{}",
                    client.client_id,
                    client.pid,
                    depth,
                    peak,
                    drop_full + drop_closed
                ));
            }
        }

        if entries.is_empty() {
            return String::new();
        }

        entries.join(",")
    }
}

// Client book keeping
//
// This block has the methods that keeps track of the clients we have and which PIDs and
// syscalls they are interested in. It includes the eBPF integration and syscall filtering.
impl EventDispatch {
    pub async fn register_client(
        &mut self,
        pid: u32,
        writer: tokio::io::BufWriter<tokio::fs::File>,
        mut syscalls: Vec<i64>,
        pidfd: Option<OwnedFd>, // Pass pidfd from server for monitoring
    ) -> anyhow::Result<u64> {
        let client_id = self.next_client_id;
        self.next_client_id += 1;

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(self.client_queue_capacity);
        let cleanup_tx = self.cleanup_tx.clone();
        let queue_stats = Arc::new(ClientQueueStats::default());

        // Both execve and execveat rely on the execve exit tracepoint.
        if syscalls.contains(&syscalls::SYS_execveat) && !syscalls.contains(&syscalls::SYS_execve) {
            syscalls.push(syscalls::SYS_execve);
        }

        let client_info = Client {
            client_id,
            pid,
            sender: event_tx,
            syscalls,
            queue_stats: queue_stats.clone(),
        };

        let is_new_pid = !self.clients_map.contains_key(&pid);
        self.clients_map.entry(pid).or_default().push(client_info);

        // Add PID to eBPF filter if this is the first client for this PID
        if is_new_pid {
            let mut pid_filter: aya::maps::HashMap<_, u32, u8> = self
                .ebpf
                .map_mut("PID_FILTER")
                .ok_or_else(|| anyhow::anyhow!("PID_FILTER map not found"))?
                .try_into()
                .map_err(|e| anyhow::anyhow!("Map conversion failed: {e}"))?;
            pid_filter
                .insert(pid, 0, 0)
                .map_err(|e| anyhow::anyhow!("Failed to insert PID: {e}"))?; // Start monitoring this PID if we got a pidfd
            if let Some(pidfd) = pidfd {
                // Set up async monitoring
                self.start_pidfd_monitoring(pid, pidfd).await?;
            }
        }

        // Update syscall filtering
        self.resubscribe_syscalls().await;

        let task = WriterTask {
            client_id,
            writer,
            event_rx,
            cleanup_tx,
            stats: self.stats.clone(),
            queue_stats,
        };

        tokio::spawn(task.run());

        Ok(client_id)
    }

    pub async fn remove_client(&mut self, client_id: u64) -> anyhow::Result<()> {
        let mut removed_pid = None;

        self.clients_map.retain(|&pid, clients| {
            clients.retain(|client| client.client_id != client_id);
            if clients.is_empty() {
                removed_pid = Some(pid);
                false
            } else {
                true
            }
        });

        // Remove PID from eBPF filter if this was the last client for this PID
        if let Some(pid) = removed_pid {
            // Clean up any timeout tracking for this PID
            self.pid_timeouts.remove(&pid);

            // Remove PID from eBPF filter and resubscribe
            self.remove_pid_from_filter(pid).await?;
        }

        Ok(())
    }

    pub async fn remove_all_clients_for_pid(&mut self, pid: u32) -> anyhow::Result<()> {
        // Remove all clients for this PID
        if self.clients_map.remove(&pid).is_some() {
            // Clean up any timeout tracking for this PID
            self.pid_timeouts.remove(&pid);

            // Remove PID from eBPF filter and resubscribe
            self.remove_pid_from_filter(pid).await?;
        }

        Ok(())
    }

    pub fn active_pid_count(&self) -> usize {
        self.clients_map.len()
    }

    // Helper method for syscall filtering - iterates over all syscalls for all clients of all PIDs
    pub fn for_each_syscall<F>(&self, mut f: F)
    where
        F: FnMut(i64),
    {
        for clients in self.clients_map.values() {
            for client in clients {
                for &syscall_nr in &client.syscalls {
                    f(syscall_nr);
                }
            }
        }
    }

    pub async fn resubscribe_syscalls(&mut self) {
        let mut bitmap = [0u8; 64];

        self.for_each_syscall(|syscall_nr| {
            bitmap[(syscall_nr / 8) as usize] |= 1 << (syscall_nr % 8);
        });

        let mut map: aya::maps::Array<_, u8> =
            Array::try_from(self.ebpf.map_mut("SYSCALL_FILTER").unwrap()).unwrap();

        for (i, byte) in bitmap.iter().enumerate() {
            map.set(i as u32, byte, 0).unwrap();
        }
    }

    async fn remove_pid_from_filter(&mut self, pid: u32) -> anyhow::Result<()> {
        // Remove PID from eBPF filter
        let mut pid_filter: aya::maps::HashMap<_, u32, u8> = self
            .ebpf
            .map_mut("PID_FILTER")
            .ok_or_else(|| anyhow::anyhow!("PID_FILTER map not found"))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("Map conversion failed: {e}"))?;

        // Aya considers trying to remove an item that is not in the map an error. This should not
        // happen, but if it does we log it, so it can be debugged.
        if pid_filter.get(&pid, 0).is_ok() {
            match pid_filter.remove(&pid) {
                Ok(_) => {}
                Err(e) => {
                    use aya::maps::MapError;
                    match &e {
                        MapError::KeyNotFound | MapError::ElementNotFound => {}
                        _ => return Err(anyhow::anyhow!("Failed to remove PID from filter: {e}")),
                    }
                }
            }
        }

        // Update syscall filtering
        self.resubscribe_syscalls().await;
        Ok(())
    }
}

// Process file descriptor monitoring and PID timeout management
//
// This block handles monitoring processes using pidfd to detect when they exit.
// When a process exits, it triggers the timeout mechanism to give a grace period
// for any remaining events before cleaning up the clients.
//
// It also manages timeouts for processes that have exited. When a process exits,
// we start a timeout to allow any remaining events to be processed before cleaning
// up the clients. The timeout can be reset a limited number of times if events
// are still being received.
impl EventDispatch {
    async fn start_pidfd_monitoring(&mut self, pid: u32, pidfd: OwnedFd) -> anyhow::Result<()> {
        let async_pidfd = AsyncFd::new(pidfd)
            .map_err(|e| anyhow::anyhow!("Failed to wrap pidfd in AsyncFd: {e}"))?;

        // Start the monitoring task
        let timeout_tx = self.timeout_tx.clone();
        tokio::spawn(async move {
            let _ = async_pidfd.readable().await;

            // Process has exited, notify so we can start timeout immediately
            let _ = timeout_tx.send(pid).await;
        });
        Ok(())
    }

    fn reset_pid_timeout(&self, pid: u32) {
        if let Some(timeout) = self.pid_timeouts.get(&pid) {
            if let Ok(current_reset_count) = timeout.reset_count.try_read() {
                if *current_reset_count < MAX_TIMEOUT_RESETS {
                    if let Ok(mut reset_count) = timeout.reset_count.try_write() {
                        *reset_count += 1;
                    }
                    if let Ok(mut expire_at) = timeout.expire_at.try_write() {
                        *expire_at = Instant::now() + Duration::from_millis(TIMEOUT_EXTENSION_MS);
                    }
                }
                // If we've hit the reset limit, let the existing timeout expire
            }
        }
    }

    pub async fn start_pid_timeout(&mut self, pid: u32) {
        let timeout = PidTimeout {
            pid,
            expire_at: RwLock::new(Instant::now() + Duration::from_millis(PID_TIMEOUT_MS)),
            reset_count: RwLock::new(0),
        };

        self.pid_timeouts.insert(pid, timeout);
    }

    pub async fn handle_pid_timeout(&mut self, pid: u32) -> anyhow::Result<()> {
        if let Some(timeout) = self.pid_timeouts.get(&pid) {
            // Check if this timeout has expired
            let expire_at = *timeout.expire_at.read().await;
            if Instant::now() >= expire_at {
                // Timeout has expired, remove all clients for this PID
                log::trace!("Timeout for {pid} elapsed");
                self.pid_timeouts.remove(&pid);
                self.remove_all_clients_for_pid(pid).await?;
            }
        }
        Ok(())
    }
}
