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
