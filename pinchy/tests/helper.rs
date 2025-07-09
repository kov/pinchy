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
