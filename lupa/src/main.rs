#![allow(non_snake_case, non_upper_case_globals)]
#![feature(mapped_lock_guards)]
use std::{
    ffi::OsString,
    io,
    sync::{
        Arc, RwLock,
        mpsc::{Receiver, TryRecvError, channel},
    },
    time::Duration,
};

use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use pinchy_common::syscalls::{SYS_close, SYS_openat, SYS_read, SYS_write};
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
};

mod app;
mod tracker;
mod ui;

use app::App;

use crate::tracker::TrackerNotification;

#[derive(Parser, Debug)]
#[command(author, version, about, trailing_var_arg = true)]
struct Args {
    /// PID to trace
    #[arg(short = 'p', long = "pid", action = clap::ArgAction::Set, conflicts_with = "command")]
    pid: Option<u32>,

    /// Command to run and its arguments
    #[arg(conflicts_with = "pid")]
    command: Option<Vec<OsString>>,
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    let (pid, fd) = tokio::runtime::Runtime::new()?.block_on(async move {
        let syscalls = vec![SYS_openat, SYS_close, SYS_read, SYS_write];
        let (pid, fd) = if let Some(pid) = args.pid {
            let fd = pinchy_client::attach(pid, syscalls).await;
            (pid, fd)
        } else if let Some(command) = args.command {
            let (pid, fd) = pinchy_client::trace_child(command, syscalls).await;
            (pid as u32, fd)
        } else {
            anyhow::bail!("Need one of -p <pid> or command")
        };
        Ok((pid, fd))
    })?;

    // Initialize the TUI
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Clear the terminal
    terminal.clear()?;

    // Initialize app state
    let open_files = Arc::new(RwLock::new(tracker::OpenFiles::new(pid)?));
    let mut app = App::new(pid, open_files.clone());

    // Setup reader for syscall events
    let (notify_tx, notify_rx) = channel();

    let reader = std::io::BufReader::new(std::fs::File::from(std::fs::File::from(fd)));
    std::thread::spawn(move || tracker::run(open_files, reader, notify_tx));

    let result = run_app(&mut terminal, &mut app, notify_rx);

    // Restore terminal
    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = terminal.show_cursor();

    match result {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    notify_rx: Receiver<tracker::TrackerNotification>,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui::render(f, app))?;

        if event::poll(Duration::from_millis(100))? {
            let event = event::read()?;
            app.handle_event(event)?;
        }

        // Check if we should quit after processing any events
        if app.should_quit {
            break;
        }

        match notify_rx.try_recv() {
            Ok(notification) => {
                match notification {
                    // TODO: we should probably update the header of the application to say
                    // the PID we are tracking has exited, or some such.
                    TrackerNotification::Error(_e) => (),
                    TrackerNotification::Finished => (),
                }
            }
            Err(TryRecvError::Disconnected) => (), // No longer have a peer
            Err(TryRecvError::Empty) => (),        // Did not get notification yet, still running
        };
    }

    Ok(())
}
