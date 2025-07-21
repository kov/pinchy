use std::{
    env::{current_dir, set_current_dir},
    ffi::c_void,
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

    assert!(fs::exists("pinchy/tests/GPLv2").expect("probably not on the correct cwd"));

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
            "recvfrom_test" => recvfrom_test(),
            "identity_syscalls" => identity_syscalls(),
            name => bail!("Unknown test name: {name}"),
        }
    } else {
        bail!("Need a test name as the first argument, nothing provided.")
    }
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
