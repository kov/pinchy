use std::{
    io::{Read as _, Write as _},
    os::fd::AsRawFd,
};

use zbus::{names::WellKnownName, proxy, Connection};

#[proxy(interface = "org.pinchy.Service", default_path = "/org/pinchy/Service")]
trait Pinchy {
    fn trace_pid(&self, pid: u32) -> zbus::Result<zbus::zvariant::OwnedFd>;
}

#[tokio::main]
async fn main() -> zbus::Result<()> {
    let connection = Connection::system().await?;
    let destination = WellKnownName::try_from("org.pinchy.Service").unwrap();
    let proxy = PinchyProxy::new(&connection, destination).await?;
    let pid = std::env::args()
        .nth(1)
        .expect("Usage: pinchy <pid>")
        .parse()
        .expect("Invalid PID");

    let fd: std::os::fd::OwnedFd = proxy.trace_pid(pid).await?.into();

    println!("Received file descriptor: {}", fd.as_raw_fd());

    let mut reader = std::fs::File::from(fd);
    let mut buf = [0u8; 4096];
    let mut stdout = std::io::stdout().lock();
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                stdout.write_all(&buf[..n])?;
            }
            Err(e) => {
                eprintln!("Read error: {e}");
                break;
            }
        }
    }

    Ok(())
}
