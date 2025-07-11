#![allow(non_snake_case, non_upper_case_globals)]
use std::{
    collections::HashMap,
    convert::TryFrom,
    os::fd::{AsRawFd as _, OwnedFd},
    sync::Arc,
    time::Instant,
};

use aya::{
    maps::{ring_buf::RingBuf, Array},
    Ebpf,
};
use pinchy_common::SyscallEvent;
use tokio::{
    io::{unix::AsyncFd, AsyncWriteExt},
    sync::RwLock,
    time::{sleep, Duration},
};

pub type SharedEventDispatch = Arc<RwLock<EventDispatch>>;

// Constants for timeout behavior
const PID_TIMEOUT_MS: u64 = 50; // Initial timeout after process exit
const MAX_TIMEOUT_RESETS: u32 = 10; // Maximum number of times we'll reset the timeout
const TIMEOUT_EXTENSION_MS: u64 = 10; // How much to extend on each event

struct WriterTask {
    client_id: u64,
    writer: tokio::io::BufWriter<tokio::fs::File>,
    event_rx: tokio::sync::mpsc::Receiver<Arc<Vec<u8>>>,
    cleanup_tx: tokio::sync::mpsc::Sender<u64>,
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

                    if self.writer.write_all(&event_bytes).await.is_err() {
                        log::trace!("Writer task ended: write error");
                        break;
                    }
                },
                _ = sleep(Duration::from_millis(10)) => {
                    if self.writer.flush().await.is_err() {
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
    sender: tokio::sync::mpsc::Sender<Arc<Vec<u8>>>,
    syscalls: Vec<i64>,
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
}

// Core event processing and client management
//
// This block handles the main event loop, spawning background tasks, dispatching events
impl EventDispatch {
    pub async fn spawn(
        mut ebpf: Ebpf,
        idle_since: Arc<RwLock<Instant>>,
    ) -> anyhow::Result<SharedEventDispatch> {
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

        // Spawn the main event loop that reads from ring buffer and handles events
        let event_dispatch = shared_dispatch.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Read events from eBPF ring buffer
                    ring_result = async_ring.readable_mut() => {
                        match ring_result {
                            Ok(mut guard) => {
                                *idle_since.write().await = Instant::now();

                                let ring = guard.get_inner_mut();
                                while let Some(item) = ring.next() {
                                    let event = &*item;
                                    if event.len() == std::mem::size_of::<SyscallEvent>() {
                                        let event_bytes = Arc::new(event.to_vec());
                                        event_dispatch.read().await.dispatch_event(event_bytes);
                                    }
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

    pub fn dispatch_event(&self, event_bytes: Arc<Vec<u8>>) {
        if event_bytes.len() != std::mem::size_of::<SyscallEvent>() {
            return;
        }

        let event: &SyscallEvent = unsafe { &*(event_bytes.as_ptr() as *const SyscallEvent) };

        let pid = event.pid;
        let syscall_nr = event.syscall_nr;

        if let Some(clients) = self.clients_map.get(&pid) {
            let interested_clients: Vec<_> = clients
                .iter()
                .filter(|client| client.syscalls.contains(&syscall_nr))
                .collect();

            if !interested_clients.is_empty() {
                for client in interested_clients {
                    let _ = client.sender.try_send(event_bytes.clone());
                }

                // Reset timeout for this PID if it has one
                self.reset_pid_timeout(pid);
            }
        }
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
        syscalls: Vec<i64>,
        pidfd: Option<OwnedFd>, // Pass pidfd from server for monitoring
    ) -> anyhow::Result<u64> {
        let client_id = self.next_client_id;
        self.next_client_id += 1;

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(128);
        let cleanup_tx = self.cleanup_tx.clone();

        let client_info = Client {
            client_id,
            pid,
            sender: event_tx,
            syscalls: syscalls.clone(),
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
