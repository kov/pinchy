use std::{
    ffi::{CString, OsString, c_char},
    os::{fd::OwnedFd, unix::ffi::OsStrExt as _},
};

use zbus::{Error as ZBusError, fdo, names::WellKnownName, proxy};

#[proxy(interface = "org.pinchy.Service", default_path = "/org/pinchy/Service")]
pub trait Pinchy {
    fn trace_pid(&self, pid: u32, syscalls: Vec<i64>) -> zbus::Result<zbus::zvariant::OwnedFd>;
}

pub async fn attach(pid: u32, syscalls: Vec<i64>) -> OwnedFd {
    let proxy = match connect_to_server().await {
        Ok(proxy) => proxy,
        Err(e) => handle_dbus_error(e),
    };

    match proxy.trace_pid(pid, syscalls).await {
        Ok(fd) => OwnedFd::from(fd),
        Err(e) => handle_dbus_error(e),
    }
}

pub async fn trace_child(command: Vec<OsString>, syscalls: Vec<i64>) -> (i32, OwnedFd) {
    let proxy = match connect_to_server().await {
        Ok(proxy) => proxy,
        Err(e) => handle_dbus_error(e),
    };

    let command: Vec<CString> = command
        .into_iter()
        .map(|s| CString::new(s.as_bytes()).unwrap())
        .collect();
    let mut argv: Vec<*const c_char> = command
        .iter()
        .map(|s| s.as_ptr() as *const c_char)
        .collect();
    argv.push(std::ptr::null());

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!(
            "Failed to fork a new process: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }
    if pid == 0 {
        unsafe {
            // Wait for a signal before we exec
            libc::raise(libc::SIGSTOP);
            let result = libc::execvp(command[0].as_ptr(), argv.as_ptr());
            std::process::exit(result);
        }
    }

    let mut status = 0;
    unsafe {
        libc::waitpid(pid, &mut status, libc::WUNTRACED);
        if !libc::WIFSTOPPED(status) {
            eprintln!("Child process did not stop as expected (status: {status:#x})");
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                std::process::exit(128 + libc::WTERMSIG(status));
            }
            std::process::exit(1);
        }
    }
    let fd = match proxy.trace_pid(pid as u32, syscalls).await {
        Ok(fd) => OwnedFd::from(fd),
        Err(e) => handle_dbus_error(e),
    };

    // Signal we can exec the child
    unsafe {
        libc::kill(pid, libc::SIGCONT);
    }

    (pid, fd)
}

async fn connect_to_server<'d>() -> Result<PinchyProxy<'d>, ZBusError> {
    // Handle D-Bus connection with proper error handling

    let (connection, bus_type) = match std::env::var("PINCHYD_USE_SESSION_BUS") {
        Ok(value) if value == "true" => (zbus::Connection::session().await?, "session"),
        _ => (zbus::Connection::system().await?, "system"),
    };

    log::trace!("Connected to {bus_type} bus");

    let destination = WellKnownName::try_from("org.pinchy.Service")?;

    // Handle proxy creation with proper error handling
    PinchyProxy::new(&connection, destination).await
}

pub fn cleanup_and_quit(child_pid: i32) -> ! {
    unsafe {
        let mut status = 0;
        libc::waitpid(child_pid, &mut status, libc::WUNTRACED);
        if libc::WIFEXITED(status) {
            std::process::exit(libc::WEXITSTATUS(status));
        } else if libc::WIFSIGNALED(status) {
            std::process::exit(128 + libc::WTERMSIG(status));
        }
        std::process::exit(1);
    }
}

fn handle_dbus_error(error: ZBusError) -> ! {
    match error {
        // Connection-related errors
        ZBusError::InputOutput(io_err) => {
            eprintln!("Failed to connect to D-Bus: {io_err}");
            eprintln!("Make sure the D-Bus system bus is running and accessible.");
            std::process::exit(2);
        }
        ZBusError::Address(addr) => {
            eprintln!("Invalid D-Bus address: {addr}");
            eprintln!("The D-Bus system bus address may be misconfigured.");
            std::process::exit(2);
        }
        ZBusError::Handshake(msg) => {
            eprintln!("D-Bus authentication failed: {msg}");
            eprintln!("You may not have permission to access the system D-Bus.");
            std::process::exit(2);
        }

        // Service-related errors
        ZBusError::MethodError(error_name, description, _) => match error_name.as_str() {
            "org.freedesktop.DBus.Error.ServiceUnknown" => {
                eprintln!("Pinchy service is not running.");
                eprintln!("Please start the pinchyd daemon first.");
                std::process::exit(3);
            }
            "org.freedesktop.DBus.Error.AccessDenied" | "org.freedesktop.DBus.Error.AuthFailed" => {
                eprintln!("Permission denied: You don't have access to trace this process.");
                eprintln!("Make sure you own the process or run with appropriate privileges.");
                std::process::exit(4);
            }
            "org.freedesktop.DBus.Error.NoReply" | "org.freedesktop.DBus.Error.TimedOut" => {
                eprintln!("Timeout: The pinchy service didn't respond in time.");
                eprintln!("The service may be overloaded or the process may not exist.");
                std::process::exit(5);
            }
            "org.freedesktop.DBus.Error.InvalidArgs" => {
                if let Some(desc) = description {
                    eprintln!("Invalid arguments: {desc}");
                } else {
                    eprintln!("Invalid arguments provided to the pinchy service.");
                }
                std::process::exit(6);
            }
            _ => {
                eprintln!("D-Bus method call failed: {error_name}");
                if let Some(desc) = description {
                    eprintln!("Details: {desc}");
                }
                std::process::exit(7);
            }
        },

        // Proxy/Interface errors
        ZBusError::InterfaceNotFound => {
            eprintln!("Pinchy service interface not found.");
            eprintln!("The running pinchyd may be incompatible with this client version.");
            std::process::exit(8);
        }

        // FDO standard errors
        ZBusError::FDO(fdo_error) => match *fdo_error {
            fdo::Error::ServiceUnknown(_) => {
                eprintln!("Pinchy service is not running.");
                eprintln!("Please start the pinchyd daemon first.");
                std::process::exit(3);
            }
            fdo::Error::AccessDenied(_) | fdo::Error::AuthFailed(_) => {
                eprintln!("Permission denied: You don't have access to trace this process.");
                eprintln!("Make sure you own the process or run with appropriate privileges.");
                std::process::exit(4);
            }
            fdo::Error::NoReply(_) | fdo::Error::TimedOut(_) => {
                eprintln!("Timeout: The pinchy service didn't respond in time.");
                eprintln!("The service may be overloaded or the process may not exist.");
                std::process::exit(5);
            }
            fdo::Error::InvalidArgs(ref msg) => {
                eprintln!("Invalid arguments: {msg}");
                std::process::exit(6);
            }
            fdo::Error::UnknownMethod(ref msg) => {
                eprintln!("Method not supported: {msg}");
                eprintln!("The running pinchyd may be incompatible with this client version.");
                std::process::exit(8);
            }
            _ => {
                eprintln!("D-Bus error: {fdo_error}");
                std::process::exit(7);
            }
        },

        // Generic/Other errors
        _ => {
            eprintln!("Unexpected D-Bus error: {error}");
            std::process::exit(1);
        }
    }
}
