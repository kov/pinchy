use std::{
    collections::HashMap,
    sync::{Arc, MappedRwLockReadGuard, RwLock, RwLockReadGuard},
};

use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};

use crate::tracker::{FdMeta, OpenFiles};

#[derive(Debug)]
pub struct App {
    pub should_quit: bool,
    pub open_files: Arc<RwLock<OpenFiles>>,
    pub table_state: ratatui::widgets::TableState,
    pub pid: u32,
}

impl App {
    pub fn new(pid: u32, open_files: Arc<RwLock<OpenFiles>>) -> Self {
        Self {
            should_quit: false,
            open_files,
            table_state: ratatui::widgets::TableState::default(),
            pid,
        }
    }

    pub fn fd_map(&self) -> MappedRwLockReadGuard<'_, HashMap<u32, FdMeta>> {
        RwLockReadGuard::map(self.open_files.read().unwrap(), |open_files| {
            &open_files.fd_map
        })
    }

    pub fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        if key.kind != KeyEventKind::Press {
            return Ok(());
        }

        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Down | KeyCode::Char('j') => self.next(),
            KeyCode::Up | KeyCode::Char('k') => self.previous(),
            KeyCode::Home => self.first(),
            KeyCode::End => self.last(),
            _ => {}
        }

        Ok(())
    }

    pub fn handle_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Key(key) => self.handle_key_event(key)?,
            _ => {}
        }
        Ok(())
    }

    fn next(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.fd_map().len().saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.fd_map().len().saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn first(&mut self) {
        self.table_state.select(Some(0));
    }

    fn last(&mut self) {
        let len = self.fd_map().len();
        if len > 0 {
            self.table_state.select(Some(len - 1));
        }
    }
}
