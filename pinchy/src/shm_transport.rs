// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
};

pub const SHM_RING_MAGIC: u32 = 0x50494E43; // "PINC"
pub const SHM_RING_VERSION: u32 = 1;
const DEFAULT_CLIENT_RING_SIZE: u32 = 512 * 1024;

#[repr(C)]
struct ControlBlock {
    magic: u32,
    version: u32,
    capacity: u32,
    _pad0: u32,
    head: AtomicU32,
    _cacheline_pad1: [u8; 56],
    tail: AtomicU32,
    _cacheline_pad2: [u8; 56],
    dropped_events: AtomicU64,
}

struct MmapRegion {
    ptr: *mut u8,
    len: usize,
}

unsafe impl Send for MmapRegion {}
unsafe impl Sync for MmapRegion {}

impl Drop for MmapRegion {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

pub struct RingWriter {
    region: Arc<MmapRegion>,
    capacity: u32,
    mask: u32,
    cached_tail: u32,
}

unsafe impl Send for RingWriter {}

impl std::fmt::Debug for RingWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingWriter")
            .field("capacity", &self.capacity)
            .finish()
    }
}

pub struct RingReader {
    region: Arc<MmapRegion>,
    capacity: u32,
    mask: u32,
}

unsafe impl Send for RingReader {}

impl std::fmt::Debug for RingReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingReader")
            .field("capacity", &self.capacity)
            .finish()
    }
}

fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

fn data_offset() -> usize {
    page_size()
}

impl RingWriter {
    fn control_block(&self) -> &ControlBlock {
        unsafe { &*(self.region.ptr as *const ControlBlock) }
    }

    fn data_ptr(&self) -> *mut u8 {
        unsafe { self.region.ptr.add(data_offset()) }
    }

    fn free_space(&mut self) -> u32 {
        let head = self.control_block().head.load(Ordering::Relaxed);
        let used = head.wrapping_sub(self.cached_tail);

        if used > self.capacity {
            self.cached_tail = self.control_block().tail.load(Ordering::Acquire);
            let used = head.wrapping_sub(self.cached_tail);
            self.capacity - used
        } else {
            self.capacity - used
        }
    }

    pub fn push(&mut self, frame: &[u8]) -> bool {
        let entry_size = 4 + frame.len() as u32;

        if entry_size > self.capacity {
            self.control_block()
                .dropped_events
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        if self.free_space() < entry_size {
            self.cached_tail = self.control_block().tail.load(Ordering::Acquire);

            let head = self.control_block().head.load(Ordering::Relaxed);
            let used = head.wrapping_sub(self.cached_tail);

            if self.capacity - used < entry_size {
                self.control_block()
                    .dropped_events
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }

        let head = self.control_block().head.load(Ordering::Relaxed);
        let pos = head & self.mask;
        let frame_len = frame.len() as u32;

        self.write_bytes(pos, &frame_len.to_ne_bytes());
        self.write_bytes((pos + 4) & self.mask, frame);

        self.control_block()
            .head
            .store(head.wrapping_add(entry_size), Ordering::Release);

        true
    }

    fn write_bytes(&self, start_pos: u32, data: &[u8]) {
        let start = start_pos as usize;
        let cap = self.capacity as usize;
        let first_chunk = cap - start;

        if first_chunk >= data.len() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    self.data_ptr().add(start),
                    data.len(),
                );
            }
        } else {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    self.data_ptr().add(start),
                    first_chunk,
                );

                std::ptr::copy_nonoverlapping(
                    data.as_ptr().add(first_chunk),
                    self.data_ptr(),
                    data.len() - first_chunk,
                );
            }
        }
    }
}

impl RingReader {
    fn control_block(&self) -> &ControlBlock {
        unsafe { &*(self.region.ptr as *const ControlBlock) }
    }

    fn data_ptr(&self) -> *const u8 {
        unsafe { self.region.ptr.add(data_offset()) as *const u8 }
    }

    pub fn pop(&mut self, buf: &mut Vec<u8>) -> bool {
        let head = self.control_block().head.load(Ordering::Acquire);
        let tail = self.control_block().tail.load(Ordering::Relaxed);

        if head == tail {
            return false;
        }

        let pos = tail & self.mask;
        let mut len_bytes = [0u8; 4];
        self.read_bytes(pos, &mut len_bytes);
        let frame_len = u32::from_ne_bytes(len_bytes);

        if frame_len == 0 || frame_len > self.capacity {
            self.control_block().tail.store(head, Ordering::Release);
            return false;
        }

        let entry_size = 4 + frame_len;
        let available = head.wrapping_sub(tail);

        if entry_size > available {
            self.control_block().tail.store(head, Ordering::Release);
            return false;
        }

        buf.resize(frame_len as usize, 0);
        self.read_bytes((pos + 4) & self.mask, buf);

        self.control_block()
            .tail
            .store(tail.wrapping_add(entry_size), Ordering::Release);

        true
    }

    pub fn dropped_events(&self) -> u64 {
        self.control_block().dropped_events.load(Ordering::Relaxed)
    }

    fn read_bytes(&self, start_pos: u32, data: &mut [u8]) {
        let start = start_pos as usize;
        let cap = self.capacity as usize;
        let first_chunk = cap - start;

        if first_chunk >= data.len() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.data_ptr().add(start),
                    data.as_mut_ptr(),
                    data.len(),
                );
            }
        } else {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.data_ptr().add(start),
                    data.as_mut_ptr(),
                    first_chunk,
                );

                std::ptr::copy_nonoverlapping(
                    self.data_ptr(),
                    data.as_mut_ptr().add(first_chunk),
                    data.len() - first_chunk,
                );
            }
        }
    }
}

pub fn create_ring(capacity: u32) -> io::Result<(OwnedFd, RingWriter)> {
    if !capacity.is_power_of_two() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capacity must be a power of two",
        ));
    }

    let page = page_size();
    let total_size = page + capacity as usize;

    let name = c"pinchy-ring";
    let memfd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };

    if memfd < 0 {
        return Err(io::Error::last_os_error());
    }

    let memfd = unsafe { OwnedFd::from_raw_fd(memfd) };

    let ret = unsafe { libc::ftruncate(memfd.as_raw_fd(), total_size as libc::off_t) };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
    let ret = unsafe { libc::fcntl(memfd.as_raw_fd(), libc::F_ADD_SEALS, seals) };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            total_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            memfd.as_raw_fd(),
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }

    let region = Arc::new(MmapRegion {
        ptr: ptr as *mut u8,
        len: total_size,
    });

    let cb = unsafe { &mut *(region.ptr as *mut ControlBlock) };
    cb.magic = SHM_RING_MAGIC;
    cb.version = SHM_RING_VERSION;
    cb.capacity = capacity;
    cb._pad0 = 0;
    *cb.head.get_mut() = 0;
    cb._cacheline_pad1 = [0; 56];
    *cb.tail.get_mut() = 0;
    cb._cacheline_pad2 = [0; 56];
    *cb.dropped_events.get_mut() = 0;

    let writer = RingWriter {
        region,
        capacity,
        mask: capacity - 1,
        cached_tail: 0,
    };

    Ok((memfd, writer))
}

pub fn open_ring(memfd: &OwnedFd, expected_capacity: u32) -> io::Result<RingReader> {
    let page = page_size();
    let total_size = page + expected_capacity as usize;

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            total_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            memfd.as_raw_fd(),
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }

    let region = Arc::new(MmapRegion {
        ptr: ptr as *mut u8,
        len: total_size,
    });

    let cb = unsafe { &*(region.ptr as *const ControlBlock) };

    if cb.magic != SHM_RING_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid magic: expected {SHM_RING_MAGIC:#x}, got {:#x}",
                cb.magic
            ),
        ));
    }

    if cb.version != SHM_RING_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "version mismatch: expected {SHM_RING_VERSION}, got {}",
                cb.version
            ),
        ));
    }

    if cb.capacity != expected_capacity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "capacity mismatch: expected {expected_capacity}, got {}",
                cb.capacity
            ),
        ));
    }

    Ok(RingReader {
        region,
        capacity: expected_capacity,
        mask: expected_capacity - 1,
    })
}

pub fn create_eventfd() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn dup_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let new_fd = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };

    if new_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

pub fn create_sentinel() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    Ok((read_end, write_end))
}

pub fn eventfd_signal(fd: RawFd) {
    let value: u64 = 1;
    unsafe {
        libc::write(
            fd,
            &value as *const u64 as *const libc::c_void,
            std::mem::size_of::<u64>(),
        );
    }
}

pub fn eventfd_drain(fd: RawFd) {
    let mut buf = [0u8; 8];
    unsafe {
        libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 8);
    }
}

pub fn parse_ring_capacity() -> u32 {
    let capacity = std::env::var("PINCHY_CLIENT_RING_SIZE")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_CLIENT_RING_SIZE);

    if capacity.is_power_of_two() && capacity >= 4096 {
        capacity
    } else {
        DEFAULT_CLIENT_RING_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ring(capacity: u32) -> (RingWriter, RingReader) {
        let (memfd, writer) = create_ring(capacity).unwrap();
        let reader = open_ring(&memfd, capacity).unwrap();
        (writer, reader)
    }

    #[test]
    fn push_pop_single_entry() {
        let (mut writer, mut reader) = make_ring(4096);
        let data = b"hello world";

        assert!(writer.push(data));

        let mut buf = Vec::new();
        assert!(reader.pop(&mut buf));
        assert_eq!(&buf, data);
    }

    #[test]
    fn push_pop_multiple_entries() {
        let (mut writer, mut reader) = make_ring(4096);

        for i in 0u32..10 {
            let data = format!("entry-{i}");
            assert!(writer.push(data.as_bytes()));
        }

        let mut buf = Vec::new();

        for i in 0u32..10 {
            assert!(reader.pop(&mut buf));
            assert_eq!(buf, format!("entry-{i}").as_bytes());
        }

        assert!(!reader.pop(&mut buf));
    }

    #[test]
    fn ring_full_drops_and_increments_counter() {
        let (mut writer, reader) = make_ring(4096);

        let data = [0u8; 1024];
        let mut pushed = 0;

        while writer.push(&data) {
            pushed += 1;
        }

        assert!(pushed > 0);
        assert!(reader.dropped_events() >= 1);

        let prev = reader.dropped_events();
        assert!(!writer.push(&data));
        assert_eq!(reader.dropped_events(), prev + 1);
    }

    #[test]
    fn wrap_around_boundary() {
        let (mut writer, mut reader) = make_ring(4096);

        let data = [0xAA; 1000];

        for _ in 0..3 {
            assert!(writer.push(&data));
        }

        let mut buf = Vec::new();

        for _ in 0..3 {
            assert!(reader.pop(&mut buf));
            assert_eq!(buf, &data[..]);
        }

        for _ in 0..3 {
            assert!(writer.push(&data));
        }

        for _ in 0..3 {
            assert!(reader.pop(&mut buf));
            assert_eq!(buf, &data[..]);
        }

        assert!(!reader.pop(&mut buf));
    }

    #[test]
    fn concurrent_producer_consumer() {
        let (memfd, mut writer) = create_ring(65536).unwrap();
        let mut reader = open_ring(&memfd, 65536).unwrap();

        let n = 1000;

        let producer = std::thread::spawn(move || {
            for i in 0u32..n {
                let data = i.to_ne_bytes();

                while !writer.push(&data) {
                    std::thread::yield_now();
                }
            }
        });

        let consumer = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut received = 0u32;

            while received < n {
                if reader.pop(&mut buf) {
                    let val = u32::from_ne_bytes(buf[..4].try_into().unwrap());
                    assert_eq!(val, received);
                    received += 1;
                } else {
                    std::thread::yield_now();
                }
            }
        });

        producer.join().unwrap();
        consumer.join().unwrap();
    }

    #[test]
    fn magic_validation_failure() {
        let (memfd, _writer) = create_ring(4096).unwrap();

        let page = page_size();
        let total_size = page + 4096;

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                memfd.as_raw_fd(),
                0,
            )
        };

        assert_ne!(ptr, libc::MAP_FAILED);

        unsafe {
            *(ptr as *mut u32) = 0xDEADBEEF;
        }

        let result = open_ring(&memfd, 4096);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid magic"));

        unsafe {
            libc::munmap(ptr, total_size);
        }
    }

    #[test]
    fn non_power_of_two_rejected() {
        let result = create_ring(5000);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("power of two"));
    }

    #[test]
    fn pop_empty_returns_false() {
        let (_writer, mut reader) = make_ring(4096);
        let mut buf = Vec::new();
        assert!(!reader.pop(&mut buf));
    }

    #[test]
    fn eventfd_create_and_signal() {
        let efd = create_eventfd().unwrap();
        eventfd_signal(efd.as_raw_fd());
        eventfd_drain(efd.as_raw_fd());
    }

    #[test]
    fn sentinel_pipe_works() {
        let (read_end, write_end) = create_sentinel().unwrap();

        let mut poll_fd = libc::pollfd {
            fd: write_end.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };

        let ret = unsafe { libc::poll(&mut poll_fd, 1, 0) };
        assert!(ret >= 0);

        drop(read_end);

        poll_fd.revents = 0;
        let ret = unsafe { libc::poll(&mut poll_fd, 1, 100) };
        assert!(ret > 0);

        let disconnected =
            (poll_fd.revents & libc::POLLHUP) != 0 || (poll_fd.revents & libc::POLLERR) != 0;
        assert!(
            disconnected,
            "expected POLLHUP or POLLERR, got revents={:#x}",
            poll_fd.revents
        );
    }

    #[test]
    fn dup_fd_works() {
        let efd = create_eventfd().unwrap();
        let duped = dup_fd(&efd).unwrap();
        assert_ne!(efd.as_raw_fd(), duped.as_raw_fd());

        eventfd_signal(efd.as_raw_fd());
        eventfd_drain(duped.as_raw_fd());
    }
}
