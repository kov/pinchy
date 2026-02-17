use std::{
    collections::HashMap,
    ffi::OsStr,
    fs,
    io::{self, ErrorKind, Read as _},
    os::unix::ffi::OsStrExt as _,
    path::PathBuf,
    sync::{Arc, RwLock, mpsc::Sender},
    time::{Duration, Instant},
};

use pinchy_common::{
    CloseData, OpenAtData, ReadData, WIRE_VERSION, WireEventHeader, WriteData, syscalls,
};

#[derive(Debug)]
pub enum TrackerNotification {
    #[allow(unused)]
    Finished,
    Error(io::Error),
}

#[derive(Debug)]
pub struct OpenFiles {
    pub pid: u32,
    pub fd_map: HashMap<u32, FdMeta>,
}

impl OpenFiles {
    pub fn new(pid: u32) -> anyhow::Result<Self> {
        let mut fd_map = HashMap::new();
        let fd_dir = PathBuf::from(format!("/proc/{}/fd", pid));

        for entry in fs::read_dir(&fd_dir)? {
            let entry = entry?;
            if let Ok(target) = fs::read_link(entry.path()) {
                if let Ok(fd_num) = entry.file_name().to_string_lossy().parse::<u32>() {
                    let mut meta = FdMeta::default();

                    meta.fd = fd_num;
                    meta.path = target;

                    fd_map.insert(fd_num, meta);
                }
            }
        }

        Ok(Self { pid, fd_map })
    }

    fn fd_meta(&self, fd: u32) -> Option<&FdMeta> {
        self.fd_map.get(&fd)
    }

    fn add_fd(&mut self, fd: u32, os_str: &OsStr, integrity: &StringIntegrity) -> &FdMeta {
        let path = match integrity {
            StringIntegrity::Full => PathBuf::from(os_str),
            StringIntegrity::Truncated => self.proc_path_for_fd(fd),
        };

        let mut meta = FdMeta::default();

        meta.fd = fd;
        meta.path = path;

        self.fd_map.insert(fd, meta);

        self.fd_meta(fd).unwrap()
    }

    fn rm_fd(&mut self, fd: u32) -> Option<FdMeta> {
        self.fd_map.remove(&fd)
    }

    fn mut_fd(&mut self, fd: u32) -> Option<&mut FdMeta> {
        self.fd_map.get_mut(&fd)
    }

    pub fn proc_path_for_fd(&self, fd: u32) -> PathBuf {
        let pid = self.pid;
        let fd_path = PathBuf::from(format!("/proc/{pid}/fd/{fd}"));

        fs::read_link(fd_path).unwrap_or_else(|_| PathBuf::from("<unknown>"))
    }
}

const CURRENT_IO_THRESHOLD: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Default)]
pub struct FdMeta {
    pub fd: u32,
    pub path: PathBuf,
    pub bytes_read: usize,
    pub bytes_written: usize,
    pub cur_reads: Vec<IoOp>,
    pub cur_writes: Vec<IoOp>,
}

impl FdMeta {
    pub fn bytes_read_per_sec(&self) -> f64 {
        self.bytes_per_sec(&self.cur_reads)
    }

    pub fn bytes_written_per_sec(&self) -> f64 {
        self.bytes_per_sec(&self.cur_writes)
    }

    fn bytes_per_sec(&self, ops: &[IoOp]) -> f64 {
        if ops.is_empty() {
            return 0.;
        }

        (ops.iter()
            .filter(|op| op.instant.elapsed() < CURRENT_IO_THRESHOLD)
            .fold(0, |acc, op| acc + op.bytes)
            / CURRENT_IO_THRESHOLD.as_secs() as usize) as f64
    }
}

#[derive(Clone, Debug)]
pub struct IoOp {
    bytes: usize,
    instant: Instant,
}

pub fn run(
    open_files: Arc<RwLock<OpenFiles>>,
    mut reader: std::io::BufReader<std::fs::File>,
    notify_tx: Sender<TrackerNotification>,
) {
    let mut header_buf = [0u8; std::mem::size_of::<WireEventHeader>()];

    loop {
        match reader.read_exact(&mut header_buf) {
            Ok(_) => {
                let header: WireEventHeader = unsafe {
                    std::ptr::read_unaligned(header_buf.as_ptr() as *const WireEventHeader)
                };

                if header.version != WIRE_VERSION {
                    notify_tx
                        .send(TrackerNotification::Error(io::Error::new(
                            ErrorKind::InvalidData,
                            "invalid wire header",
                        )))
                        .expect("Trying to send error notification");
                    break;
                }

                let mut payload = vec![0u8; header.payload_len as usize];

                if let Err(e) = reader.read_exact(&mut payload) {
                    if e.kind() == ErrorKind::UnexpectedEof {
                        break;
                    }

                    notify_tx
                        .send(TrackerNotification::Error(e))
                        .expect("Trying to send error notification");
                    break;
                }

                match header.syscall_nr {
                    syscalls::SYS_openat => {
                        if payload.len() != std::mem::size_of::<OpenAtData>() {
                            continue;
                        }

                        let data = unsafe {
                            std::ptr::read_unaligned(payload.as_ptr() as *const OpenAtData)
                        };
                        let (path, integrity) = get_path(&data.pathname);

                        if header.return_value >= 0 {
                            let _meta = open_files.write().unwrap().add_fd(
                                header.return_value as u32,
                                path,
                                &integrity,
                            );
                        }
                    }
                    syscalls::SYS_close => {
                        if payload.len() != std::mem::size_of::<CloseData>() {
                            continue;
                        }

                        let data = unsafe {
                            std::ptr::read_unaligned(payload.as_ptr() as *const CloseData)
                        };
                        let _ = open_files.write().unwrap().rm_fd(data.fd as u32);
                    }
                    syscalls::SYS_read => {
                        if header.return_value < 0 {
                            continue;
                        }

                        if payload.len() != std::mem::size_of::<ReadData>() {
                            continue;
                        }

                        let data = unsafe {
                            std::ptr::read_unaligned(payload.as_ptr() as *const ReadData)
                        };
                        if let Some(meta) = open_files.write().unwrap().mut_fd(data.fd as u32) {
                            let bytes = header.return_value as usize;
                            meta.bytes_read += bytes;

                            meta.cur_reads
                                .retain(|r| r.instant.elapsed() < CURRENT_IO_THRESHOLD);

                            meta.cur_reads.push(IoOp {
                                bytes,
                                instant: Instant::now(),
                            })
                        }
                    }
                    syscalls::SYS_write => {
                        if header.return_value < 0 {
                            continue;
                        }

                        if payload.len() != std::mem::size_of::<WriteData>() {
                            continue;
                        }

                        let data = unsafe {
                            std::ptr::read_unaligned(payload.as_ptr() as *const WriteData)
                        };
                        if let Some(meta) = open_files.write().unwrap().mut_fd(data.fd as u32) {
                            let bytes = header.return_value as usize;
                            meta.bytes_written += bytes;

                            meta.cur_writes
                                .retain(|r| r.instant.elapsed() < CURRENT_IO_THRESHOLD);

                            meta.cur_writes.push(IoOp {
                                bytes,
                                instant: Instant::now(),
                            })
                        }
                    }
                    syscall_nr => unreachable!(
                        "Got unexpected syscall: {syscall_nr} ({:?})",
                        pinchy_common::syscalls::syscall_name_from_nr(syscall_nr)
                    ),
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                notify_tx
                    .send(TrackerNotification::Error(e))
                    .expect("Trying to send error notification");
                break;
            }
        }
    }
}

enum StringIntegrity {
    Full,
    Truncated,
}

/// Note that the returned OsStr may be invalid UTF-8, the eBPF side makes no guarantees.
fn get_path<const N: usize>(bytes: &[u8; N]) -> (&OsStr, StringIntegrity) {
    // Find the nul byte
    let end = bytes
        .iter()
        .position(|&b| b == b'\0')
        .unwrap_or_else(|| bytes.len());

    let integrity = if end == bytes.len() {
        StringIntegrity::Truncated
    } else {
        StringIntegrity::Full
    };

    (OsStr::from_bytes(&bytes[..end]), integrity)
}
