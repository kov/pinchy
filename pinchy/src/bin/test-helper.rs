use std::{
    env::{current_dir, set_current_dir},
    ffi::{c_void, CString},
    fs,
    path::PathBuf,
};

use anyhow::bail;
use pinchy_common::DATA_READ_SIZE;

/// Returns the workspace root by walking up from the crate root.
fn find_workspace_root(mut dir: PathBuf) -> PathBuf {
    loop {
        let candidate = dir.join("Cargo.toml");
        if candidate.exists() {
            // Check if this Cargo.toml is a workspace root
            if fs::read_to_string(&candidate)
                .map(|s| s.contains("[workspace]"))
                .unwrap_or(false)
            {
                return dir;
            }
        }
        if !dir.pop() {
            panic!("Workspace root not found!");
        }
    }
}

fn main() -> anyhow::Result<()> {
    // Start from the crate's root
    let workspace_root = find_workspace_root(current_dir()?);

    // Change to workspace root if not already there
    let cwd = current_dir()?;
    if cwd != workspace_root {
        set_current_dir(&workspace_root)?;
    }

    fs::exists("pinchy/tests/GPLv2").expect("probably not on the correct cwd");

    let mut args = std::env::args();

    // Ignore the binary name
    let _ = args.next();

    // Call the workload for the test provided as argument
    if let Some(name) = args.next() {
        match name.as_str() {
            "pinchy_reads" => pinchy_reads(),
            "rt_sig" => rt_sig(),
            "rt_sigaction_realtime" => rt_sigaction_realtime(),
            "rt_sigaction_standard" => rt_sigaction_standard(),
            "fcntl_test" => fcntl_test(),
            "fchdir_test" => fchdir_test(),
            "network_test" => network_test(),
            "accept_test" => accept_test(),
            "socket_lifecycle_test" => socket_lifecycle_test(),
            "recvfrom_test" => recvfrom_test(),
            "identity_syscalls" => identity_syscalls(),
            "madvise_test" => madvise_test(),
            "mlock_test" => mlock_test(),
            "file_descriptor_test" => file_descriptor_test(),
            "session_process_test" => session_process_test(),
            "uid_gid_test" => uid_gid_test(),
            "system_operations_test" => system_operations_test(),
            "ioprio_test" => ioprio_test(),
            "scheduler_test" => scheduler_test(),
            "pread_pwrite_test" => pread_pwrite_test(),
            "readv_writev_test" => readv_writev_test(),
            "pselect6_test" => pselect6_test(),
            "filesystem_sync_test" => filesystem_sync_test(),
            "filesystem_syscalls_test" => filesystem_syscalls_test(),
            "epoll_test" => epoll_test(),
            "eventfd_test" => eventfd_test(),
            "timer_test" => timer_test(),
            "execveat_test" => execveat_test(),
            "pipe_operations_test" => pipe_operations_test(),
            "io_multiplexing_test" => io_multiplexing_test(),
            "xattr_test" => xattr_test(),
            "sysv_ipc_test" => sysv_ipc_test(),
            "socketpair_sendmmsg_test" => socketpair_sendmmsg_test(),
            "system_info_test" => system_info_test(),
            name => bail!("Unknown test name: {name}"),
        }
    } else {
        bail!("Need a test name as the first argument, nothing provided.")
    }
}

fn filesystem_syscalls_test() -> anyhow::Result<()> {
    use std::{
        fs::{self, File},
        os::unix::io::AsRawFd,
        path::Path,
    };

    // Use the GPLv2 file and its directory as test targets
    let gpl_path = Path::new("pinchy/tests/GPLv2");
    let gpl_cpath =
        CString::new(gpl_path.as_os_str().as_encoded_bytes()).expect("Converting path to CString");
    let dir_path = gpl_path.parent().expect("should have parent directory");

    // --- getdents64 ---
    let dir = fs::File::open(dir_path)?;
    let dir_fd = dir.as_raw_fd();
    let mut buf = vec![0u8; 4096];
    let nread = unsafe { libc::syscall(libc::SYS_getdents64, dir_fd, buf.as_mut_ptr(), buf.len()) };
    assert!(nread > 0, "getdents64 should return > 0");

    // --- fstat ---
    let file = File::open(gpl_path)?;
    let fd = file.as_raw_fd();
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::fstat(fd, &mut stat) };
    assert_eq!(res, 0, "fstat should succeed");
    assert!(stat.st_size > 0, "GPLv2 file should not be empty");

    // --- newfstatat ---
    let mut stat2: pinchy_common::kernel_types::Stat = unsafe { std::mem::zeroed() };
    let res = unsafe {
        libc::syscall(
            libc::SYS_newfstatat,
            libc::AT_FDCWD,
            gpl_cpath.as_ptr(),
            &mut stat2,
            0,
        )
    };
    assert_eq!(res, 0, "newfstatat should succeed");
    assert_eq!(stat2.st_size, stat.st_size, "sizes should match");

    // --- faccessat ---
    let res = unsafe {
        libc::syscall(
            libc::SYS_faccessat,
            libc::AT_FDCWD,
            gpl_cpath.as_ptr(),
            libc::R_OK,
            0,
        )
    };
    assert_eq!(res, 0, "faccessat should succeed for readable file");

    Ok(())
}

fn pinchy_reads() -> anyhow::Result<()> {
    unsafe {
        let fd = libc::openat(
            libc::AT_FDCWD,
            c"pinchy/tests/GPLv2".as_ptr(),
            libc::O_RDONLY,
        );

        let mut buf: Vec<u8> = Vec::with_capacity(1024);

        // This read should not have any elipsing in the output.
        let count = libc::read(fd, buf.as_mut_ptr() as *mut c_void, DATA_READ_SIZE);
        assert_eq!(count, DATA_READ_SIZE as isize);

        // This read should elipsize.
        let count = libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.capacity());
        assert_eq!(count, buf.capacity() as isize);

        libc::lseek(fd, 0, libc::SEEK_END);

        // This read should produce EOF.
        let count = libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.capacity());
        assert_eq!(count, 0);
    }
    Ok(())
}

fn rt_sig() -> anyhow::Result<()> {
    unsafe {
        let mut old_set: libc::sigset_t = std::mem::zeroed();
        let mut new_set: libc::sigset_t = std::mem::zeroed();

        // Initialize the new signal set and add SIGUSR1 to it
        libc::sigemptyset(&mut new_set);
        libc::sigaddset(&mut new_set, libc::SIGUSR1);

        // Block SIGUSR1 using SIG_BLOCK
        let result = libc::sigprocmask(libc::SIG_BLOCK, &new_set, &mut old_set);
        assert_eq!(result, 0, "Failed to block SIGUSR1");

        // Get current signal mask using SIG_SETMASK with NULL set
        let mut current_set: libc::sigset_t = std::mem::zeroed();
        let result = libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut current_set);
        assert_eq!(result, 0, "Failed to get current signal mask");

        // Verify SIGUSR1 is in the current mask
        let is_blocked = libc::sigismember(&current_set, libc::SIGUSR1);
        assert_eq!(is_blocked, 1, "SIGUSR1 should be blocked");

        // Unblock SIGUSR1 using SIG_UNBLOCK
        let result = libc::sigprocmask(libc::SIG_UNBLOCK, &new_set, std::ptr::null_mut());
        assert_eq!(result, 0, "Failed to unblock SIGUSR1");

        // Restore the original signal mask
        let result = libc::sigprocmask(libc::SIG_SETMASK, &old_set, std::ptr::null_mut());
        assert_eq!(result, 0, "Failed to restore original signal mask");
    }
    Ok(())
}

fn rt_sigaction_realtime() -> anyhow::Result<()> {
    unsafe {
        // Test rt_sigaction with a real-time signal (SIGRT1 = SIGRTMIN + 1)
        let sigrt1 = libc::SIGRTMIN() + 1;

        let mut old_action: libc::sigaction = std::mem::zeroed();
        let mut new_action: libc::sigaction = std::mem::zeroed();

        // Set up a simple signal handler (we'll use SIG_IGN for simplicity)
        new_action.sa_sigaction = libc::SIG_IGN;
        new_action.sa_flags = 0;
        libc::sigemptyset(&mut new_action.sa_mask);

        // Install the signal handler for SIGRT1
        let result = libc::sigaction(sigrt1, &new_action, &mut old_action);
        assert_eq!(result, 0, "Failed to install signal handler for SIGRT1");

        // Get the current signal handler (this will trigger another rt_sigaction call)
        let mut current_action: libc::sigaction = std::mem::zeroed();
        let result = libc::sigaction(sigrt1, std::ptr::null(), &mut current_action);
        assert_eq!(result, 0, "Failed to get current signal handler for SIGRT1");

        // Verify the handler was set correctly
        assert_eq!(current_action.sa_sigaction, libc::SIG_IGN);

        // Restore the original signal handler
        let result = libc::sigaction(sigrt1, &old_action, std::ptr::null_mut());
        assert_eq!(
            result, 0,
            "Failed to restore original signal handler for SIGRT1"
        );
    }
    Ok(())
}

fn rt_sigaction_standard() -> anyhow::Result<()> {
    unsafe {
        // Test rt_sigaction with a standard signal (SIGUSR1)
        let sigusr1 = libc::SIGUSR1;

        let mut old_action: libc::sigaction = std::mem::zeroed();
        let mut new_action: libc::sigaction = std::mem::zeroed();

        // Set up a simple signal handler (we'll use SIG_IGN for simplicity)
        new_action.sa_sigaction = libc::SIG_IGN;
        new_action.sa_flags = 0;
        libc::sigemptyset(&mut new_action.sa_mask);

        // Install the signal handler for SIGUSR1
        let result = libc::sigaction(sigusr1, &new_action, &mut old_action);
        assert_eq!(result, 0, "Failed to install signal handler for SIGUSR1");

        // Get the current signal handler (this will trigger another rt_sigaction call)
        let mut current_action: libc::sigaction = std::mem::zeroed();
        let result = libc::sigaction(sigusr1, std::ptr::null(), &mut current_action);
        assert_eq!(
            result, 0,
            "Failed to get current signal handler for SIGUSR1"
        );

        // Verify the handler was set correctly
        assert_eq!(current_action.sa_sigaction, libc::SIG_IGN);

        // Restore the original signal handler
        let result = libc::sigaction(sigusr1, &old_action, std::ptr::null_mut());
        assert_eq!(
            result, 0,
            "Failed to restore original signal handler for SIGUSR1"
        );
    }
    Ok(())
}

fn fchdir_test() -> anyhow::Result<()> {
    use std::{fs::File, os::unix::io::AsRawFd};

    // Open the current directory
    let file = File::open(".")?;
    let fd = file.as_raw_fd();

    // Call fchdir on the directory fd
    let ret = unsafe { libc::fchdir(fd) };
    assert_eq!(ret, 0, "fchdir failed");

    Ok(())
}

fn fcntl_test() -> anyhow::Result<()> {
    unsafe {
        // Open a file to test fcntl on
        let fd = libc::openat(
            libc::AT_FDCWD,
            c"pinchy/tests/GPLv2".as_ptr(),
            libc::O_RDONLY,
        );
        if fd < 0 {
            bail!("Failed to open test file");
        }

        // Test F_GETFL - get file status flags
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            bail!("Failed to get file flags");
        }

        // Test F_GETFD - get file descriptor flags
        let fd_flags = libc::fcntl(fd, libc::F_GETFD);
        if fd_flags < 0 {
            bail!("Failed to get fd flags");
        }

        // Test F_SETFD - set close-on-exec flag
        let result = libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        if result < 0 {
            bail!("Failed to set fd flags");
        }

        // Test F_DUPFD - duplicate file descriptor
        let new_fd = libc::fcntl(fd, libc::F_DUPFD, 10);
        if new_fd < 0 {
            bail!("Failed to duplicate fd");
        }

        // Test F_DUPFD_CLOEXEC - duplicate with close-on-exec
        let new_fd2 = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 20);
        if new_fd2 < 0 {
            bail!("Failed to duplicate fd with cloexec");
        }

        // Clean up
        libc::close(new_fd2);
        libc::close(new_fd);
        libc::close(fd);
    }

    Ok(())
}

fn network_test() -> anyhow::Result<()> {
    use std::{
        net::{TcpListener, TcpStream},
        os::unix::io::AsRawFd,
    };

    // Create a TCP listener on localhost
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    // Connect to ourselves - this is simpler than threading
    let client = TcpStream::connect(addr)?;

    // Accept the connection we just made - this generates accept4
    let (server, _client_addr) = listener.accept()?;

    // Get raw file descriptors for direct syscall usage
    let client_fd = client.as_raw_fd();
    let server_fd = server.as_raw_fd();

    // Send some test data using sendmsg syscall directly
    let test_message = b"Hello, network test!";
    unsafe {
        let mut iov = libc::iovec {
            iov_base: test_message.as_ptr() as *mut libc::c_void,
            iov_len: test_message.len(),
        };

        let msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let bytes_sent = libc::sendmsg(client_fd, &msg, 0);
        if bytes_sent < 0 {
            bail!("sendmsg failed");
        }
    }

    // Receive the data using recvmsg syscall directly
    let mut buffer = [0u8; 1024];
    unsafe {
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: buffer.len(),
        };

        let msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let bytes_received = libc::recvmsg(
            server_fd,
            &msg as *const libc::msghdr as *mut libc::msghdr,
            0,
        );
        if bytes_received < 0 {
            bail!("recvmsg failed");
        }

        // Verify we got the expected data
        assert_eq!(&buffer[..bytes_received as usize], test_message);
    }

    Ok(())
}

fn recvfrom_test() -> anyhow::Result<()> {
    use std::{net::UdpSocket, os::unix::io::AsRawFd};

    // Create UDP sockets for testing recvfrom
    let server_socket = UdpSocket::bind("127.0.0.1:0")?;
    let server_addr = server_socket.local_addr()?;

    let client_socket = UdpSocket::bind("127.0.0.1:0")?;

    // Get raw file descriptor for direct syscall usage
    let server_fd = server_socket.as_raw_fd();

    // Send test data from client to server using standard library (will generate some syscalls)
    let test_message = b"UDP recvfrom test!";
    client_socket.send_to(test_message, server_addr)?;

    // Use recvfrom syscall directly to receive data
    let mut buffer = [0u8; 1024];
    unsafe {
        let mut src_addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let bytes_received = libc::recvfrom(
            server_fd,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
            0, // flags
            &mut src_addr as *mut libc::sockaddr_storage as *mut libc::sockaddr,
            &mut addr_len,
        );

        if bytes_received < 0 {
            bail!("recvfrom failed: {}", std::io::Error::last_os_error());
        }

        // Verify we got the expected data
        assert_eq!(&buffer[..bytes_received as usize], test_message);

        // Also test recvfrom without source address (NULL parameters)
        client_socket.send_to(b"second message", server_addr)?;

        let bytes_received2 = libc::recvfrom(
            server_fd,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
            0,                    // flags
            std::ptr::null_mut(), // NULL src_addr
            std::ptr::null_mut(), // NULL addr_len
        );

        if bytes_received2 < 0 {
            bail!(
                "second recvfrom failed: {}",
                std::io::Error::last_os_error()
            );
        }

        assert_eq!(&buffer[..bytes_received2 as usize], b"second message");
    }

    Ok(())
}

fn accept_test() -> anyhow::Result<()> {
    unsafe {
        // Create a socket for listening
        let server_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if server_fd < 0 {
            bail!("socket() failed");
        }

        // Create sockaddr_in for binding
        let mut server_addr: libc::sockaddr_in = std::mem::zeroed();
        server_addr.sin_family = libc::AF_INET as u16;
        server_addr.sin_port = 0u16.to_be(); // Let the OS choose port
        server_addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be(); // 127.0.0.1

        let server_addr_ptr = &server_addr as *const libc::sockaddr_in as *const libc::sockaddr;

        // Bind the socket
        let bind_result = libc::bind(
            server_fd,
            server_addr_ptr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        if bind_result < 0 {
            bail!("bind() failed");
        }

        // Listen on the socket
        let listen_result = libc::listen(server_fd, 1);
        if listen_result < 0 {
            bail!("listen() failed");
        }

        // Get the actual port that was assigned
        let mut actual_addr: libc::sockaddr_in = std::mem::zeroed();
        let mut addr_len = std::mem::size_of::<libc::sockaddr_in>() as u32;
        let getsockname_result = libc::getsockname(
            server_fd,
            &mut actual_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut addr_len,
        );
        if getsockname_result < 0 {
            bail!("getsockname() failed");
        }

        // Create a client socket to connect to the server
        let client_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if client_fd < 0 {
            bail!("client socket() failed");
        }

        // Connect the client to the server
        let connect_result = libc::connect(
            client_fd,
            &actual_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        if connect_result < 0 {
            bail!("connect() failed");
        }

        // Use the accept() syscall (not accept4) to accept the connection
        let mut client_addr: libc::sockaddr_in = std::mem::zeroed();
        let mut client_addr_len = std::mem::size_of::<libc::sockaddr_in>() as u32;

        let accepted_fd = libc::accept(
            server_fd,
            &mut client_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut client_addr_len,
        );
        if accepted_fd < 0 {
            bail!("accept() failed");
        }

        // Clean up
        libc::close(accepted_fd);
        libc::close(client_fd);
        libc::close(server_fd);
    }

    Ok(())
}

fn identity_syscalls() -> anyhow::Result<()> {
    unsafe {
        // Call all identity-related syscalls
        let _pid = libc::getpid();
        let _tid = libc::gettid();
        let _uid = libc::getuid();
        let _euid = libc::geteuid();
        let _gid = libc::getgid();
        let _egid = libc::getegid();
        let _ppid = libc::getppid();
    }

    Ok(())
}

fn madvise_test() -> anyhow::Result<()> {
    unsafe {
        // Allocate a page of memory using mmap
        let page_size = 4096;
        let addr = libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );

        if addr == libc::MAP_FAILED {
            bail!("mmap failed: {}", std::io::Error::last_os_error());
        }

        // Test different madvise advice values

        // MADV_WILLNEED - tell kernel we will need these pages soon
        let result = libc::madvise(addr, page_size, libc::MADV_WILLNEED);
        if result != 0 {
            bail!(
                "madvise WILLNEED failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // MADV_DONTNEED - tell kernel we don't need these pages
        let result = libc::madvise(addr, page_size, libc::MADV_DONTNEED);
        if result != 0 {
            bail!(
                "madvise DONTNEED failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // MADV_NORMAL - reset to normal behavior
        let result = libc::madvise(addr, page_size, libc::MADV_NORMAL);
        if result != 0 {
            bail!("madvise NORMAL failed: {}", std::io::Error::last_os_error());
        }

        // Test with an invalid address (should fail)
        let result = libc::madvise(std::ptr::null_mut(), page_size, libc::MADV_WILLNEED);
        assert_eq!(result, -1, "madvise with NULL address should fail");

        // Clean up
        let result = libc::munmap(addr, page_size);
        if result != 0 {
            bail!("munmap failed: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn mlock_test() -> anyhow::Result<()> {
    unsafe {
        // Allocate a page of memory using mmap
        let page_size = 4096;
        let addr = libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );

        if addr == libc::MAP_FAILED {
            bail!("mmap failed: {}", std::io::Error::last_os_error());
        }

        // Lock the memory page
        let result = libc::mlock(addr, page_size);
        if result != 0 {
            bail!("mlock failed: {}", std::io::Error::last_os_error());
        }

        // Unlock all locked memory using munlockall
        let result = libc::munlockall();
        if result != 0 {
            bail!("munlockall failed: {}", std::io::Error::last_os_error());
        }

        // Clean up
        let result = libc::munmap(addr, page_size);
        if result != 0 {
            bail!("munmap failed: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn file_descriptor_test() -> anyhow::Result<()> {
    unsafe {
        // Open a file to get a file descriptor
        let fd = libc::openat(
            libc::AT_FDCWD,
            c"pinchy/tests/GPLv2".as_ptr(),
            libc::O_RDONLY,
        );
        if fd < 0 {
            bail!("Failed to open file: {}", std::io::Error::last_os_error());
        }

        // Test dup - duplicate the file descriptor
        let dup_fd = libc::dup(fd);
        if dup_fd < 0 {
            bail!("dup failed: {}", std::io::Error::last_os_error());
        }

        // Test close_range - close a range of file descriptors
        // We'll close from dup_fd to dup_fd (just one fd)
        let result = libc::syscall(libc::SYS_close_range, dup_fd, dup_fd, 0);
        if result != 0 {
            // close_range might not be available on all systems, so we'll just close manually
            libc::close(dup_fd);
        }

        libc::close(fd);
    }

    Ok(())
}

fn session_process_test() -> anyhow::Result<()> {
    unsafe {
        // Get current process group ID
        let current_pgid = libc::getpgid(0);
        if current_pgid < 0 {
            bail!("getpgid failed: {}", std::io::Error::last_os_error());
        }

        // Get current session ID
        let current_sid = libc::getsid(0);
        if current_sid < 0 {
            bail!("getsid failed: {}", std::io::Error::last_os_error());
        }

        // Set process group (should work with root privileges)
        let result = libc::setpgid(0, current_pgid);
        if result != 0 {
            bail!("setpgid failed: {}", std::io::Error::last_os_error());
        }

        // Create new session (should work with root privileges)
        let result = libc::setsid();
        if result < 0 {
            bail!("setsid failed: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn uid_gid_test() -> anyhow::Result<()> {
    unsafe {
        // Get current IDs
        let uid = libc::getuid();
        let gid = libc::getgid();

        // Set to same values (should work with root privileges)

        // Test setuid
        let result = libc::setuid(uid);
        if result != 0 {
            bail!("setuid failed: {}", std::io::Error::last_os_error());
        }

        // Test setgid
        let result = libc::setgid(gid);
        if result != 0 {
            bail!("setgid failed: {}", std::io::Error::last_os_error());
        }

        // Test setreuid
        let result = libc::setreuid(uid, uid);
        if result != 0 {
            bail!("setreuid failed: {}", std::io::Error::last_os_error());
        }

        // Test setregid
        let result = libc::setregid(gid, gid);
        if result != 0 {
            bail!("setregid failed: {}", std::io::Error::last_os_error());
        }

        // Test setresuid
        let result = libc::syscall(libc::SYS_setresuid, uid, uid, uid);
        if result != 0 {
            bail!("setresuid failed: {}", std::io::Error::last_os_error());
        }

        // Test setresgid
        let result = libc::syscall(libc::SYS_setresgid, gid, gid, gid);
        if result != 0 {
            bail!("setresgid failed: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}
fn system_operations_test() -> anyhow::Result<()> {
    unsafe {
        // Test umask - get current mask and set it to 0o22, then back
        let old_mask = libc::umask(0o22);
        libc::umask(old_mask); // Restore original mask

        // Test sync - synchronize file systems
        libc::sync();
    }

    Ok(())
}

fn ioprio_test() -> anyhow::Result<()> {
    unsafe {
        // Test ioprio_get - get I/O priority
        let current_prio = libc::syscall(libc::SYS_ioprio_get, 1, 0); // IOPRIO_WHO_PROCESS, current process
        if current_prio < 0 {
            bail!("ioprio_get failed: {}", std::io::Error::last_os_error());
        }

        // Test ioprio_set - set I/O priority (should work with root privileges)
        let result = libc::syscall(libc::SYS_ioprio_set, 1, 0, current_prio); // IOPRIO_WHO_PROCESS, current process
        if result != 0 {
            bail!("ioprio_set failed: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn scheduler_test() -> anyhow::Result<()> {
    unsafe {
        // Test sched_getscheduler - get current scheduling policy
        let current_policy = libc::sched_getscheduler(0); // 0 = current process
        if current_policy < 0 {
            bail!(
                "sched_getscheduler failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test sched_setscheduler - set scheduling policy back to SCHED_OTHER
        // Create a sched_param structure with priority 0 (required for SCHED_OTHER)
        let param = libc::sched_param { sched_priority: 0 };

        let result = libc::sched_setscheduler(0, libc::SCHED_OTHER, &param);
        if result != 0 {
            bail!(
                "sched_setscheduler failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    Ok(())
}

fn pread_pwrite_test() -> anyhow::Result<()> {
    unsafe {
        // Create a temporary file for testing pread/pwrite
        let fd = libc::openat(
            libc::AT_FDCWD,
            c"/tmp/pread_pwrite_test".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );

        if fd < 0 {
            bail!(
                "Failed to create temporary file: {}",
                std::io::Error::last_os_error()
            );
        }

        // Write some initial data using regular write
        let initial_data = b"Hello, world! This is test data for pread/pwrite.";
        let write_result = libc::write(
            fd,
            initial_data.as_ptr() as *const libc::c_void,
            initial_data.len(),
        );
        if write_result < 0 {
            bail!("Initial write failed: {}", std::io::Error::last_os_error());
        }

        // Test pwrite - write at offset 7 (overwriting "world")
        let pwrite_data = b"pinch";
        let pwrite_result = libc::pwrite64(
            fd,
            pwrite_data.as_ptr() as *const libc::c_void,
            pwrite_data.len(),
            7,
        );
        if pwrite_result < 0 {
            bail!("pwrite64 failed: {}", std::io::Error::last_os_error());
        }

        // Test pread - read from offset 3, skipping "Hel"
        let mut read_buffer = vec![0u8; 28];
        let pread_result = libc::pread64(
            fd,
            read_buffer.as_mut_ptr() as *mut libc::c_void,
            read_buffer.len(),
            3,
        );
        if pread_result < 0 {
            bail!("pread64 failed: {}", std::io::Error::last_os_error());
        }

        // Clean up
        libc::close(fd);
        libc::unlink(c"/tmp/pread_pwrite_test".as_ptr());
    }

    Ok(())
}

fn readv_writev_test() -> anyhow::Result<()> {
    unsafe {
        // Create a temporary file for testing readv/writev
        let fd = libc::openat(
            libc::AT_FDCWD,
            c"/tmp/readv_writev_test".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );

        if fd < 0 {
            bail!(
                "Failed to create temporary file: {}",
                std::io::Error::last_os_error()
            );
        }

        // Prepare some data to write
        let data1 = b"Hello, ";
        let data2 = b"world!";
        let iov = [
            libc::iovec {
                iov_base: data1.as_ptr() as *mut libc::c_void,
                iov_len: data1.len(),
            },
            libc::iovec {
                iov_base: data2.as_ptr() as *mut libc::c_void,
                iov_len: data2.len(),
            },
        ];

        // Test writev - write both buffers in one call
        let result = libc::writev(fd, iov.as_ptr(), iov.len() as i32);
        if result < 0 {
            bail!("writev failed: {}", std::io::Error::last_os_error());
        }

        // Prepare buffers for reading
        let mut buffer1 = vec![0u8; 7]; // Enough space for "Hello, "
        let mut buffer2 = vec![0u8; 6]; // Enough space for "world!"
        let read_iov = [
            libc::iovec {
                iov_base: buffer1.as_mut_ptr() as *mut libc::c_void,
                iov_len: buffer1.len(),
            },
            libc::iovec {
                iov_base: buffer2.as_mut_ptr() as *mut libc::c_void,
                iov_len: buffer2.len(),
            },
        ];

        // Reset the file descriptor's position to the beginning of the file
        let result = libc::lseek(fd, 0, libc::SEEK_SET);
        if result < 0 {
            bail!("lseek failed: {}", std::io::Error::last_os_error());
        }

        // Test readv - read into both buffers in one call
        let result = libc::readv(fd, read_iov.as_ptr(), read_iov.len() as i32);
        if result < 0 {
            bail!("readv failed: {}", std::io::Error::last_os_error());
        }

        // Verify the data
        assert_eq!(&buffer1[..], &data1[..]);
        assert_eq!(&buffer2[..], &data2[..]);

        // Clean up
        libc::close(fd);
        libc::unlink(c"/tmp/readv_writev_test".as_ptr());
    }

    Ok(())
}

fn socket_lifecycle_test() -> anyhow::Result<()> {
    unsafe {
        // Test socket() syscall - create a TCP socket
        let sock_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if sock_fd < 0 {
            bail!("socket() failed");
        }

        // Test socket() syscall - create a UDP socket
        let udp_fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if udp_fd < 0 {
            bail!("UDP socket() failed");
        }

        // Create sockaddr_in for binding
        let mut server_addr: libc::sockaddr_in = std::mem::zeroed();
        server_addr.sin_family = libc::AF_INET as u16;
        server_addr.sin_port = 0u16.to_be(); // Let the OS choose port
        server_addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be(); // 127.0.0.1 in network byte order

        let server_addr_ptr = &server_addr as *const libc::sockaddr_in as *const libc::sockaddr;

        // Test bind() syscall
        let bind_result = libc::bind(
            sock_fd,
            server_addr_ptr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        if bind_result < 0 {
            bail!("bind() failed");
        }

        // Test listen() syscall
        let listen_result = libc::listen(sock_fd, 5);
        if listen_result < 0 {
            bail!("listen() failed");
        }

        // Get the actual port that was assigned
        let mut actual_addr: libc::sockaddr_in = std::mem::zeroed();
        let mut addr_len = std::mem::size_of::<libc::sockaddr_in>() as u32;
        let getsockname_result = libc::getsockname(
            sock_fd,
            &mut actual_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut addr_len,
        );
        if getsockname_result < 0 {
            bail!("getsockname() failed");
        }

        // Create client socket for connection test
        let client_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if client_fd < 0 {
            bail!("client socket() failed");
        }

        // Test connect() syscall
        let connect_result = libc::connect(
            client_fd,
            &actual_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        if connect_result < 0 {
            bail!("connect() failed");
        }

        // Test shutdown() syscall with different modes
        let shutdown_read = libc::shutdown(client_fd, libc::SHUT_RD);
        if shutdown_read < 0 {
            bail!("shutdown(SHUT_RD) failed");
        }

        let shutdown_write = libc::shutdown(client_fd, libc::SHUT_WR);
        if shutdown_write < 0 {
            bail!("shutdown(SHUT_WR) failed");
        }

        // Create another client for SHUT_RDWR test
        let client_fd2 = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if client_fd2 < 0 {
            bail!("second client socket() failed");
        }

        let connect_result2 = libc::connect(
            client_fd2,
            &actual_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        if connect_result2 < 0 {
            bail!("second connect() failed");
        }

        let shutdown_rdwr = libc::shutdown(client_fd2, libc::SHUT_RDWR);
        if shutdown_rdwr < 0 {
            bail!("shutdown(SHUT_RDWR) failed");
        }

        // Clean up
        libc::close(client_fd);
        libc::close(client_fd2);
        libc::close(sock_fd);
        libc::close(udp_fd);
    }

    Ok(())
}

fn pselect6_test() -> anyhow::Result<()> {
    unsafe {
        // Create a pipe for the test
        let mut pipe_fds = [0i32; 2];
        let pipe_result = libc::pipe(pipe_fds.as_mut_ptr());
        if pipe_result < 0 {
            bail!("pipe() failed");
        }

        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];

        // Test pselect6 with timeout (should timeout)
        let mut readfds: libc::fd_set = std::mem::zeroed();
        libc::FD_ZERO(&mut readfds);
        libc::FD_SET(read_fd, &mut readfds);

        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000, // 100ms
        };

        let nfds = read_fd + 1;
        let result = libc::pselect(
            nfds,
            &mut readfds,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &timeout,
            std::ptr::null(),
        );

        // Should timeout (return 0)
        if result != 0 {
            bail!("pselect6 should have timed out, got: {}", result);
        }

        // Write some data to make fd ready
        let test_data = b"test";
        let write_result = libc::write(
            write_fd,
            test_data.as_ptr() as *const c_void,
            test_data.len(),
        );
        if write_result < 0 {
            bail!("write() failed");
        }

        // Test pselect6 with ready fd (should return immediately)
        libc::FD_ZERO(&mut readfds);
        libc::FD_SET(read_fd, &mut readfds);

        let timeout2 = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };

        let result2 = libc::pselect(
            nfds,
            &mut readfds,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &timeout2,
            std::ptr::null(),
        );

        // Should return 1 (one fd ready)
        if result2 != 1 {
            bail!("pselect6 should have found 1 ready fd, got: {}", result2);
        }

        // Verify the fd is still set
        if !libc::FD_ISSET(read_fd, &readfds) {
            bail!("read_fd should be set in readfds");
        }

        // Clean up
        libc::close(read_fd);
        libc::close(write_fd);
    }

    Ok(())
}

fn filesystem_sync_test() -> anyhow::Result<()> {
    use std::{fs::OpenOptions, io::Write, os::fd::AsRawFd};

    // Create a temporary file for testing
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("test_sync_file.tmp")?;

    let fd = file.as_raw_fd();

    // Write some data to the file
    file.write_all(b"Hello, fsync and fdatasync test!")?;

    // Test fsync syscall
    let result = unsafe { libc::fsync(fd) };
    if result != 0 {
        bail!("fsync failed with error: {}", result);
    }

    // Test fdatasync syscall
    let result = unsafe { libc::fdatasync(fd) };
    if result != 0 {
        bail!("fdatasync failed with error: {}", result);
    }

    // Test ftruncate syscall - truncate to 10 bytes
    let result = unsafe { libc::ftruncate(fd, 10) };
    if result != 0 {
        bail!("ftruncate failed with error: {}", result);
    }

    // Test ftruncate syscall - expand to 50 bytes
    let result = unsafe { libc::ftruncate(fd, 50) };
    if result != 0 {
        bail!("ftruncate expand failed with error: {}", result);
    }

    // Test fchmod syscall - change permissions to 644
    let result = unsafe { libc::fchmod(fd, 0o644) };
    if result != 0 {
        bail!("fchmod failed with error: {}", result);
    }

    // Test fchmod syscall - change permissions to 755
    let result = unsafe { libc::fchmod(fd, 0o755) };
    if result != 0 {
        bail!("fchmod 755 failed with error: {}", result);
    }

    // Clean up - the file will be closed when it goes out of scope
    drop(file);
    let _ = std::fs::remove_file("test_sync_file.tmp");

    Ok(())
}

fn epoll_test() -> anyhow::Result<()> {
    unsafe {
        let epfd = libc::epoll_create1(libc::EPOLL_CLOEXEC);
        if epfd < 0 {
            bail!("epoll_create1 failed: {}", std::io::Error::last_os_error());
        }

        let efd = libc::eventfd(0, 0);
        if efd < 0 {
            bail!("eventfd failed: {}", std::io::Error::last_os_error());
        }

        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 0x1234,
        };
        if libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, efd, &mut event) != 0 {
            bail!("epoll_ctl add failed: {}", std::io::Error::last_os_error());
        }

        let val: u64 = 1;
        if libc::write(
            efd,
            &val as *const u64 as *const c_void,
            std::mem::size_of::<u64>(),
        ) < 0
        {
            bail!("eventfd write failed: {}", std::io::Error::last_os_error());
        }

        let mut events: [libc::epoll_event; 8] = std::mem::zeroed();
        let nfds = libc::epoll_pwait(epfd, events.as_mut_ptr(), 8, 0, std::ptr::null());
        if nfds < 0 {
            bail!("epoll_pwait failed: {}", std::io::Error::last_os_error());
        }
        assert_eq!(nfds, 1, "epoll_pwait should return 1");

        if libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, efd, std::ptr::null_mut()) != 0 {
            bail!("epoll_ctl del failed: {}", std::io::Error::last_os_error());
        }

        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // epoll_pwait2 requires a valid events buffer if maxevents > 0.
        // Passing maxevents == 0 can yield EINVAL on some kernels.
        // Use a small buffer and expect a timeout with 0 events.
        let mut events2: [libc::epoll_event; 8] = std::mem::zeroed();
        let nfds2 = libc::syscall(
            libc::SYS_epoll_pwait2,
            epfd,
            events2.as_mut_ptr(),
            events2.len() as libc::c_int,
            &timeout as *const libc::timespec,
            std::ptr::null::<libc::sigset_t>(),
            0usize,
        );
        if nfds2 < 0 {
            bail!("epoll_pwait2 failed: {}", std::io::Error::last_os_error());
        }
        assert_eq!(nfds2, 0);

        // Similarly, ensure maxevents > 0 for epoll_wait to avoid EINVAL.
        let mut events3: [libc::epoll_event; 8] = std::mem::zeroed();
        let nfds3 = libc::epoll_wait(epfd, events3.as_mut_ptr(), events3.len() as libc::c_int, 0);
        if nfds3 < 0 {
            bail!("epoll_wait failed: {}", std::io::Error::last_os_error());
        }
        assert_eq!(nfds3, 0);

        libc::close(efd);
        libc::close(epfd);
    }
    Ok(())
}

fn eventfd_test() -> anyhow::Result<()> {
    unsafe {
        // Test eventfd2 syscall with no flags (available on both x86_64 and aarch64)
        let efd = libc::syscall(libc::SYS_eventfd2, 0, 0);
        if efd < 0 {
            bail!("eventfd2 failed: {}", std::io::Error::last_os_error());
        }

        // Test eventfd2 with EFD_CLOEXEC flag
        let efd_cloexec = libc::syscall(libc::SYS_eventfd2, 5, libc::O_CLOEXEC);
        if efd_cloexec < 0 {
            bail!(
                "eventfd2 with EFD_CLOEXEC failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test eventfd2 with EFD_NONBLOCK flag
        let efd_nonblock = libc::syscall(libc::SYS_eventfd2, 10, libc::O_NONBLOCK);
        if efd_nonblock < 0 {
            bail!(
                "eventfd2 with EFD_NONBLOCK failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // On x86_64, also test the original eventfd syscall
        #[cfg(target_arch = "x86_64")]
        {
            let efd_old = libc::syscall(libc::SYS_eventfd, 42, 0);
            if efd_old < 0 {
                bail!("eventfd failed: {}", std::io::Error::last_os_error());
            }

            // Close the old eventfd
            libc::close(efd_old as i32);
        }

        // Close all the eventfds
        libc::close(efd as i32);
        libc::close(efd_cloexec as i32);
        libc::close(efd_nonblock as i32);
    }

    Ok(())
}

fn timer_test() -> anyhow::Result<()> {
    unsafe {
        // Test timer_create with different clock types and signal events
        let mut timerid: libc::timer_t = std::ptr::null_mut();

        // Test 1: timer_create with CLOCK_REALTIME and a sigevent structure
        // We'll create the sigevent structure manually due to libc complexity
        let mut sevp: libc::sigevent = std::mem::zeroed();
        sevp.sigev_notify = libc::SIGEV_SIGNAL;
        sevp.sigev_signo = libc::SIGUSR1;
        // Set the value using raw bytes since sigval is a union
        let value_ptr = &mut sevp.sigev_value as *mut libc::sigval as *mut i32;
        *value_ptr = 42;

        let result = libc::syscall(
            libc::SYS_timer_create,
            libc::CLOCK_REALTIME,
            &sevp as *const libc::sigevent,
            &mut timerid as *mut libc::timer_t,
        );

        if result != 0 {
            bail!("timer_create failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: timer_settime with relative time
        let new_value = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 1,
                tv_nsec: 0,
            }, // 1 second interval
            it_value: libc::timespec {
                tv_sec: 2,
                tv_nsec: 500_000_000,
            }, // 2.5 second initial
        };

        let mut old_value: libc::itimerspec = std::mem::zeroed();

        let result = libc::syscall(
            libc::SYS_timer_settime,
            timerid,
            0, // flags: 0 = relative time
            &new_value as *const libc::itimerspec,
            &mut old_value as *mut libc::itimerspec,
        );

        if result != 0 {
            bail!("timer_settime failed: {}", std::io::Error::last_os_error());
        }

        // Test 3: timer_gettime
        let mut curr_value: libc::itimerspec = std::mem::zeroed();

        let result = libc::syscall(
            libc::SYS_timer_gettime,
            timerid,
            &mut curr_value as *mut libc::itimerspec,
        );

        if result != 0 {
            bail!("timer_gettime failed: {}", std::io::Error::last_os_error());
        }

        // Test 4: timer_getoverrun
        let result = libc::syscall(libc::SYS_timer_getoverrun, timerid);

        if result < 0 {
            bail!(
                "timer_getoverrun failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 5: timer_delete
        let result = libc::syscall(libc::SYS_timer_delete, timerid);

        if result != 0 {
            bail!("timer_delete failed: {}", std::io::Error::last_os_error());
        }

        // Test 6: timer_create with NULL sigevent (should use default SIGEV_SIGNAL/SIGALRM)
        let mut timerid2: libc::timer_t = std::ptr::null_mut();

        let result = libc::syscall(
            libc::SYS_timer_create,
            libc::CLOCK_MONOTONIC,
            std::ptr::null::<libc::sigevent>(),
            &mut timerid2 as *mut libc::timer_t,
        );

        if result != 0 {
            bail!(
                "timer_create with NULL sigevent failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Clean up the second timer
        let result = libc::syscall(libc::SYS_timer_delete, timerid2);

        if result != 0 {
            bail!(
                "timer_delete for second timer failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    Ok(())
}

fn pipe_operations_test() -> anyhow::Result<()> {
    unsafe {
        // Test 1: pipe2 with no flags
        let mut pipe_fds = [0i32; 2];
        let result = libc::syscall(libc::SYS_pipe2, pipe_fds.as_mut_ptr(), 0);
        if result != 0 {
            bail!(
                "pipe2 with no flags failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let pipe1_read = pipe_fds[0];
        let pipe1_write = pipe_fds[1];

        // Test 2: pipe2 with O_NONBLOCK
        let mut pipe_fds2 = [0i32; 2];
        let result = libc::syscall(libc::SYS_pipe2, pipe_fds2.as_mut_ptr(), libc::O_NONBLOCK);
        if result != 0 {
            bail!(
                "pipe2 with O_NONBLOCK failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let pipe2_read = pipe_fds2[0];
        let pipe2_write = pipe_fds2[1];

        // Test 3: pipe2 with O_CLOEXEC
        let mut pipe_fds3 = [0i32; 2];
        let result = libc::syscall(libc::SYS_pipe2, pipe_fds3.as_mut_ptr(), libc::O_CLOEXEC);
        if result != 0 {
            bail!(
                "pipe2 with O_CLOEXEC failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let pipe3_read = pipe_fds3[0];
        let pipe3_write = pipe_fds3[1];

        // Test 4: pipe2 with O_NONBLOCK|O_CLOEXEC
        let mut pipe_fds4 = [0i32; 2];
        let result = libc::syscall(
            libc::SYS_pipe2,
            pipe_fds4.as_mut_ptr(),
            libc::O_NONBLOCK | libc::O_CLOEXEC,
        );
        if result != 0 {
            bail!(
                "pipe2 with O_NONBLOCK|O_CLOEXEC failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let pipe4_read = pipe_fds4[0];
        let pipe4_write = pipe_fds4[1];

        // Write some data to the first pipe for splice operations
        let test_data = b"Hello, splice world!";
        let bytes_written = libc::write(
            pipe1_write,
            test_data.as_ptr() as *const libc::c_void,
            test_data.len(),
        );
        if bytes_written != test_data.len() as isize {
            bail!("Failed to write test data to pipe");
        }

        // Test 5: splice from pipe1 to pipe2
        let bytes_spliced = libc::syscall(
            libc::SYS_splice,
            pipe1_read,
            std::ptr::null_mut::<libc::loff_t>(),
            pipe2_write,
            std::ptr::null_mut::<libc::loff_t>(),
            test_data.len(),
            libc::SPLICE_F_MOVE,
        );
        if bytes_spliced != test_data.len() as i64 {
            bail!(
                "splice failed: expected {}, got {}",
                test_data.len(),
                bytes_spliced
            );
        }

        // Test 6: tee from pipe2 to pipe3 (duplicate data)
        let bytes_teed = libc::syscall(
            libc::SYS_tee,
            pipe2_read,
            pipe3_write,
            test_data.len(),
            libc::SPLICE_F_NONBLOCK,
        );
        if bytes_teed != test_data.len() as i64 {
            bail!(
                "tee failed: expected {}, got {}",
                test_data.len(),
                bytes_teed
            );
        }

        // Test 7: vmsplice to write data from user space to pipe4
        let vmsplice_data = b"vmsplice test data";
        let iov = libc::iovec {
            iov_base: vmsplice_data.as_ptr() as *mut libc::c_void,
            iov_len: vmsplice_data.len(),
        };
        let bytes_vmspliced = libc::syscall(
            libc::SYS_vmsplice,
            pipe4_write,
            &iov as *const libc::iovec,
            1,
            libc::SPLICE_F_GIFT,
        );
        if bytes_vmspliced != vmsplice_data.len() as i64 {
            bail!(
                "vmsplice failed: expected {}, got {}",
                vmsplice_data.len(),
                bytes_vmspliced
            );
        }

        // Clean up - close all file descriptors
        libc::close(pipe1_read);
        libc::close(pipe1_write);
        libc::close(pipe2_read);
        libc::close(pipe2_write);
        libc::close(pipe3_read);
        libc::close(pipe3_write);
        libc::close(pipe4_read);
        libc::close(pipe4_write);
    }

    Ok(())
}

fn execveat_test() -> anyhow::Result<()> {
    use std::{ffi::CString, fs::File, os::unix::io::AsRawFd};

    // Open the directory containing the binary
    let dir = File::open("/bin")?;
    let dirfd = dir.as_raw_fd();

    // Test execveat with directory fd and relative path
    let argv = [
        CString::new("this-does-not-exist-for-sure")?,
        CString::new("arg1")?,
        CString::new("arg2")?,
    ];
    let envp = [
        CString::new("PATH=/bin:/usr/bin")?,
        CString::new("TEST_VAR=execveat_value")?,
    ];

    let pathname = CString::new("this-does-not-exist-for-sure")?;

    // Convert CString vectors to pointer arrays
    let argv_ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|arg| arg.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let envp_ptrs: Vec<*const libc::c_char> = envp
        .iter()
        .map(|env| env.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    unsafe {
        let _ = libc::syscall(
            libc::SYS_execveat,
            dirfd,
            pathname.as_ptr(),
            argv_ptrs.as_ptr(),
            envp_ptrs.as_ptr(),
            0, // flags
        );
    }

    Ok(())
}

fn io_multiplexing_test() -> anyhow::Result<()> {
    unsafe {
        // Create a pipe for testing I/O readiness
        let mut pipe_fds = [0i32; 2];
        let pipe_result = libc::pipe(pipe_fds.as_mut_ptr());
        if pipe_result < 0 {
            bail!("pipe() failed");
        }

        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];

        // Test 1: select (x86_64 only) - timeout case
        #[cfg(target_arch = "x86_64")]
        {
            let mut readfds: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut readfds);
            libc::FD_SET(read_fd, &mut readfds);

            let mut timeout = libc::timeval {
                tv_sec: 0,
                tv_usec: 0, // Immediate timeout
            };

            let nfds = read_fd + 1;
            let result = libc::syscall(
                libc::SYS_select,
                nfds,
                &mut readfds as *mut libc::fd_set,
                std::ptr::null_mut::<libc::fd_set>(),
                std::ptr::null_mut::<libc::fd_set>(),
                &mut timeout as *mut libc::timeval,
            );

            // Should timeout (return 0)
            if result != 0 {
                bail!("select should have timed out, got: {}", result);
            }
        }

        // Test 2: poll - timeout case
        #[cfg(target_arch = "x86_64")]
        {
            let mut pollfd = libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN,
                revents: 0,
            };

            let result = libc::poll(&mut pollfd, 1, 0); // 0ms timeout
            if result != 0 {
                bail!("poll should have timed out, got: {}", result);
            }
        }

        // Test 3: ppoll - timeout case (skip extra timeout, just test once)
        // Note: This test starts after some initial polling by the test framework

        // Write some data to make the fd ready
        let test_data = b"test data for multiplexing";
        let write_result = libc::write(
            write_fd,
            test_data.as_ptr() as *const c_void,
            test_data.len(),
        );
        if write_result < 0 {
            bail!("write() failed");
        }

        // Test 4: select (x86_64 only) - ready case
        #[cfg(target_arch = "x86_64")]
        {
            let mut readfds: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut readfds);
            libc::FD_SET(read_fd, &mut readfds);

            let mut timeout = libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            };

            let nfds = read_fd + 1;
            let result = libc::syscall(
                libc::SYS_select,
                nfds,
                &mut readfds as *mut libc::fd_set,
                std::ptr::null_mut::<libc::fd_set>(),
                std::ptr::null_mut::<libc::fd_set>(),
                &mut timeout as *mut libc::timeval,
            );

            // Should return 1 (one fd ready)
            if result != 1 {
                bail!("select should have found 1 ready fd, got: {}", result);
            }

            // Verify the fd is still set
            if !libc::FD_ISSET(read_fd, &readfds) {
                bail!("read_fd should be set in readfds");
            }
        }

        // Test 5: poll (x86_64 only) - ready case
        #[cfg(target_arch = "x86_64")]
        {
            let mut pollfd = libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN,
                revents: 0,
            };

            let result = libc::poll(&mut pollfd, 1, 1000); // 1 second timeout
            if result != 1 {
                bail!("poll should have found 1 ready fd, got: {}", result);
            }

            // Verify the fd is ready for reading
            if pollfd.revents & libc::POLLIN == 0 {
                bail!("read_fd should be ready for reading");
            }
        }

        // Test 6: ppoll - ready case
        let mut pollfd_ppoll_ready = libc::pollfd {
            fd: read_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let timeout_ppoll_ready = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };

        let result = libc::ppoll(
            &mut pollfd_ppoll_ready,
            1,
            &timeout_ppoll_ready,
            std::ptr::null(),
        );
        if result != 1 {
            bail!("ppoll should have found 1 ready fd, got: {}", result);
        }

        // Verify the fd is ready for reading
        if pollfd_ppoll_ready.revents & libc::POLLIN == 0 {
            bail!("read_fd should be ready for reading in ppoll");
        }

        // Clean up
        libc::close(read_fd);
        libc::close(write_fd);
    }

    Ok(())
}

fn xattr_test() -> anyhow::Result<()> {
    use std::{ffi::CString, fs::File, io::Write, os::unix::io::AsRawFd};

    // Create a temporary file for testing extended attributes
    let mut file = File::create("/tmp/xattr_test_file")?;
    file.write_all(b"test file for xattr operations")?;
    file.sync_all()?;
    let fd = file.as_raw_fd();

    // File path for path-based xattr operations
    let file_path = CString::new("/tmp/xattr_test_file")?;

    // Test attribute names and values
    let attr_name1 = CString::new("user.test_attr1")?;
    let attr_value1 = b"test_value_1";

    let attr_name2 = CString::new("user.test_attr2")?;
    let attr_value2 = b"another_test_value";

    unsafe {
        // Test 1: setxattr - set extended attribute via path
        let result = libc::setxattr(
            file_path.as_ptr(),
            attr_name1.as_ptr(),
            attr_value1.as_ptr() as *const libc::c_void,
            attr_value1.len(),
            0, // flags
        );
        if result != 0 {
            bail!("setxattr failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: fsetxattr - set extended attribute via file descriptor
        let result = libc::fsetxattr(
            fd,
            attr_name2.as_ptr(),
            attr_value2.as_ptr() as *const libc::c_void,
            attr_value2.len(),
            0, // flags
        );
        if result != 0 {
            bail!("fsetxattr failed: {}", std::io::Error::last_os_error());
        }

        // Test 3: getxattr - get extended attribute via path
        let mut buffer1 = vec![0u8; 64];
        let result = libc::getxattr(
            file_path.as_ptr(),
            attr_name1.as_ptr(),
            buffer1.as_mut_ptr() as *mut libc::c_void,
            buffer1.len(),
        );
        if result < 0 {
            bail!("getxattr failed: {}", std::io::Error::last_os_error());
        }
        // Verify we got the expected value
        assert_eq!(&buffer1[..result as usize], attr_value1);

        // Test 4: fgetxattr - get extended attribute via file descriptor
        let mut buffer2 = vec![0u8; 64];
        let result = libc::fgetxattr(
            fd,
            attr_name2.as_ptr(),
            buffer2.as_mut_ptr() as *mut libc::c_void,
            buffer2.len(),
        );
        if result < 0 {
            bail!("fgetxattr failed: {}", std::io::Error::last_os_error());
        }
        // Verify we got the expected value
        assert_eq!(&buffer2[..result as usize], attr_value2);

        // Test 5: listxattr - list all extended attributes via path
        let mut list_buffer = vec![0u8; 256];
        let result = libc::listxattr(
            file_path.as_ptr(),
            list_buffer.as_mut_ptr() as *mut libc::c_char,
            list_buffer.len(),
        );
        if result < 0 {
            bail!("listxattr failed: {}", std::io::Error::last_os_error());
        }
        // The result should contain both attribute names we set
        let list_str =
            std::str::from_utf8(&list_buffer[..result as usize]).unwrap_or("invalid_utf8");
        assert!(list_str.contains("user.test_attr1"));
        assert!(list_str.contains("user.test_attr2"));

        // Test 6: flistxattr - list all extended attributes via file descriptor
        let mut flist_buffer = vec![0u8; 256];
        let result = libc::flistxattr(
            fd,
            flist_buffer.as_mut_ptr() as *mut libc::c_char,
            flist_buffer.len(),
        );
        if result < 0 {
            bail!("flistxattr failed: {}", std::io::Error::last_os_error());
        }

        // Test 7: Test getxattr with NULL buffer to get size
        let size = libc::getxattr(
            file_path.as_ptr(),
            attr_name1.as_ptr(),
            std::ptr::null_mut(),
            0,
        );
        if size < 0 {
            bail!(
                "getxattr size query failed: {}",
                std::io::Error::last_os_error()
            );
        }
        assert_eq!(size as usize, attr_value1.len());

        // Test 8: Test error case - non-existent attribute
        let nonexistent_attr = CString::new("user.nonexistent")?;
        let mut error_buffer = vec![0u8; 64];
        let result = libc::getxattr(
            file_path.as_ptr(),
            nonexistent_attr.as_ptr(),
            error_buffer.as_mut_ptr() as *mut libc::c_void,
            error_buffer.len(),
        );
        // This should fail with ENODATA
        assert_eq!(result, -1);
    }

    // Clean up
    drop(file);
    let _ = std::fs::remove_file("/tmp/xattr_test_file");

    Ok(())
}

fn sysv_ipc_test() -> anyhow::Result<()> {
    unsafe {
        // === SHARED MEMORY TESTS ===

        // Test 1: shmget - create a shared memory segment
        let shm_key = 0x12345678; // IPC_PRIVATE would be 0, but we want a specific key
        let shm_size = 4096;
        let shm_id = libc::shmget(shm_key, shm_size, libc::IPC_CREAT | 0o666);
        if shm_id < 0 {
            bail!("shmget failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: shmat - attach the shared memory segment
        let shm_addr = libc::shmat(shm_id, std::ptr::null(), 0);
        if shm_addr == (-1isize) as *mut libc::c_void {
            bail!("shmat failed: {}", std::io::Error::last_os_error());
        }

        // Test 3: shmctl with IPC_STAT - get shared memory info
        let mut shm_ds: libc::shmid_ds = std::mem::zeroed();
        let result = libc::shmctl(shm_id, libc::IPC_STAT, &mut shm_ds);
        if result != 0 {
            bail!(
                "shmctl IPC_STAT failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 4: shmdt - detach the shared memory segment
        let result = libc::shmdt(shm_addr);
        if result != 0 {
            bail!("shmdt failed: {}", std::io::Error::last_os_error());
        }

        // Test 5: shmctl with IPC_RMID - remove the shared memory segment
        let result = libc::shmctl(shm_id, libc::IPC_RMID, std::ptr::null_mut());
        if result != 0 {
            bail!(
                "shmctl IPC_RMID failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // === MESSAGE QUEUE TESTS ===

        // Test 6: msgget - create a message queue
        let msg_key = 0x12345679; // Use a smaller key to avoid overflow
        let msg_id = libc::msgget(msg_key, libc::IPC_CREAT | 0o666);
        if msg_id < 0 {
            bail!("msgget failed: {}", std::io::Error::last_os_error());
        }

        // Prepare a test message
        #[repr(C)]
        struct TestMessage {
            mtype: libc::c_long,
            mtext: [libc::c_char; 32],
        }

        let mut test_msg = TestMessage {
            mtype: 1, // Message type 1
            mtext: [0; 32],
        };

        // Copy test data into message
        let test_data = b"Hello, SysV IPC message queue!";
        let copy_len = std::cmp::min(test_data.len(), test_msg.mtext.len() - 1);
        for (i, &byte) in test_data.iter().take(copy_len).enumerate() {
            test_msg.mtext[i] = byte as libc::c_char;
        }

        // Test 7: msgsnd - send a message
        let result = libc::msgsnd(
            msg_id,
            &test_msg as *const TestMessage as *const libc::c_void,
            test_data.len(),
            0, // no flags
        );
        if result != 0 {
            bail!("msgsnd failed: {}", std::io::Error::last_os_error());
        }

        // Test 8: msgctl with IPC_STAT - get message queue info
        let mut msg_ds: libc::msqid_ds = std::mem::zeroed();
        let result = libc::msgctl(msg_id, libc::IPC_STAT, &mut msg_ds);
        if result != 0 {
            bail!(
                "msgctl IPC_STAT failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 9: msgrcv - receive the message
        let mut recv_msg = TestMessage {
            mtype: 0,
            mtext: [0; 32],
        };
        let result = libc::msgrcv(
            msg_id,
            &mut recv_msg as *mut TestMessage as *mut libc::c_void,
            32, // max size
            0,  // any message type
            0,  // no flags
        );
        if result < 0 {
            bail!("msgrcv failed: {}", std::io::Error::last_os_error());
        }

        // Test 10: msgctl with IPC_RMID - remove the message queue
        let result = libc::msgctl(msg_id, libc::IPC_RMID, std::ptr::null_mut());
        if result != 0 {
            bail!(
                "msgctl IPC_RMID failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // === SEMAPHORE TESTS ===

        // Test 11: semget - create a semaphore set
        let sem_key = 0x11223344;
        let sem_count = 2; // Create 2 semaphores
        let sem_id = libc::semget(sem_key, sem_count, libc::IPC_CREAT | 0o666);
        if sem_id < 0 {
            bail!("semget failed: {}", std::io::Error::last_os_error());
        }

        // Test 12: semctl with SETVAL - set semaphore value
        let result = libc::semctl(sem_id, 0, libc::SETVAL, 5); // Set semaphore 0 to value 5
        if result != 0 {
            bail!("semctl SETVAL failed: {}", std::io::Error::last_os_error());
        }

        // Test 13: semctl with GETVAL - get semaphore value
        let sem_val = libc::semctl(sem_id, 0, libc::GETVAL, 0);
        if sem_val < 0 {
            bail!("semctl GETVAL failed: {}", std::io::Error::last_os_error());
        }
        assert_eq!(sem_val, 5, "Semaphore value should be 5");

        // Test 14: semop - perform semaphore operations
        let mut sem_ops = [
            libc::sembuf {
                sem_num: 0,                       // semaphore 0
                sem_op: -1,                       // decrement by 1
                sem_flg: libc::IPC_NOWAIT as i16, // don't block
            },
            libc::sembuf {
                sem_num: 1, // semaphore 1
                sem_op: 1,  // increment by 1
                sem_flg: 0, // default flags
            },
        ];

        let result = libc::semop(sem_id, sem_ops.as_mut_ptr(), sem_ops.len());
        if result != 0 {
            bail!("semop failed: {}", std::io::Error::last_os_error());
        }

        // Test 15: semctl with IPC_RMID - remove the semaphore set
        let result = libc::semctl(sem_id, 0, libc::IPC_RMID, 0);
        if result != 0 {
            bail!(
                "semctl IPC_RMID failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    Ok(())
}

fn socketpair_sendmmsg_test() -> anyhow::Result<()> {
    unsafe {
        // Test 1: Create a socket pair (AF_UNIX SOCK_STREAM)
        let mut sv = [0i32; 2];
        let result = libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr());
        if result != 0 {
            bail!("socketpair failed: {}", std::io::Error::last_os_error());
        }

        let sock1 = sv[0];
        let sock2 = sv[1];

        // Test 2: Create another socket pair (AF_UNIX SOCK_DGRAM) for variety
        let mut sv_dgram = [0i32; 2];
        let result = libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv_dgram.as_mut_ptr());
        if result != 0 {
            bail!(
                "socketpair DGRAM failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Test 3: Prepare messages for sendmmsg
        let msg1 = b"First message";
        let msg2 = b"Second message";

        let mut iov1 = libc::iovec {
            iov_base: msg1.as_ptr() as *mut libc::c_void,
            iov_len: msg1.len(),
        };

        let mut iov2 = libc::iovec {
            iov_base: msg2.as_ptr() as *mut libc::c_void,
            iov_len: msg2.len(),
        };

        let msghdr1 = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov1,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let msghdr2 = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov2,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let mut mmsghdr = [
            libc::mmsghdr {
                msg_hdr: msghdr1,
                msg_len: 0,
            },
            libc::mmsghdr {
                msg_hdr: msghdr2,
                msg_len: 0,
            },
        ];

        // Test 4: Send multiple messages using sendmmsg
        let sent = libc::sendmmsg(sock1, mmsghdr.as_mut_ptr(), 2, 0);
        if sent < 0 {
            bail!("sendmmsg failed: {}", std::io::Error::last_os_error());
        }

        // Test 5: Prepare buffers for recvmmsg
        let mut recv_buf1 = [0u8; 64];
        let mut recv_buf2 = [0u8; 64];

        let mut recv_iov1 = libc::iovec {
            iov_base: recv_buf1.as_mut_ptr() as *mut libc::c_void,
            iov_len: recv_buf1.len(),
        };

        let mut recv_iov2 = libc::iovec {
            iov_base: recv_buf2.as_mut_ptr() as *mut libc::c_void,
            iov_len: recv_buf2.len(),
        };

        let recv_msghdr1 = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut recv_iov1,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let recv_msghdr2 = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut recv_iov2,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let mut recv_mmsghdr = [
            libc::mmsghdr {
                msg_hdr: recv_msghdr1,
                msg_len: 0,
            },
            libc::mmsghdr {
                msg_hdr: recv_msghdr2,
                msg_len: 0,
            },
        ];

        // Test 6: Receive multiple messages using recvmmsg
        let timeout = libc::timespec {
            tv_sec: 0,          // Make timeout very short to avoid hanging
            tv_nsec: 100000000, // 100ms
        };

        let received = libc::recvmmsg(
            sock2,
            recv_mmsghdr.as_mut_ptr(),
            2,
            libc::MSG_DONTWAIT, // Non-blocking to avoid hanging
            &timeout as *const libc::timespec as *mut libc::timespec,
        );
        if received < 0 {
            // It's ok if this fails in some cases, we just want to trigger the syscall
            eprintln!(
                "recvmmsg failed (expected in some cases): {}",
                std::io::Error::last_os_error()
            );
        } else {
            // For SOCK_STREAM, messages might be concatenated, so just verify we got some data
            eprintln!("recvmmsg received {} messages successfully", received);
            eprintln!(
                "Message 1 length: {}, Message 2 length: {}",
                recv_mmsghdr[0].msg_len, recv_mmsghdr[1].msg_len
            );
        }

        // Close all file descriptors
        libc::close(sock1);
        libc::close(sock2);
        libc::close(sv_dgram[0]);
        libc::close(sv_dgram[1]);
    }

    Ok(())
}

fn system_info_test() -> anyhow::Result<()> {
    unsafe {
        // Test 1: uname - get system information
        let mut utsname: libc::utsname = std::mem::zeroed();
        let result = libc::uname(&mut utsname);
        if result != 0 {
            bail!("uname failed: {}", std::io::Error::last_os_error());
        }

        // Test 2: sysinfo - get system statistics
        let mut info: libc::sysinfo = std::mem::zeroed();
        let result = libc::sysinfo(&mut info);
        if result != 0 {
            bail!("sysinfo failed: {}", std::io::Error::last_os_error());
        }

        // Verify we got reasonable values
        assert!(info.uptime > 0, "System uptime should be positive");
        assert!(info.totalram > 0, "Total RAM should be positive");
    }

    Ok(())
}
