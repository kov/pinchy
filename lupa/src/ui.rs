use human_bytes::human_bytes;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Row, Table},
};

use crate::app::App;

pub fn render(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();

    // Create the main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Table
            Constraint::Length(1), // Status bar
        ])
        .split(area);

    // Render header
    render_header(frame, chunks[0], app);

    // Render table
    render_table(frame, chunks[1], app);

    // Render status bar
    render_status_bar(frame, chunks[2], app);
}

fn render_header(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let header_block = Block::default()
        .title(format!(" Lupa - PID: {} ", app.pid))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    frame.render_widget(header_block, area);
}

fn render_table(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let fd_map = app.fd_map();

    let mut metas: Vec<_> = fd_map.values().collect();
    metas.sort_by_key(|&meta| meta.fd);

    let rows: Vec<Row> = metas
        .iter()
        .map(|meta| {
            Row::new(vec![
                meta.fd.to_string(),
                human_bytes(meta.bytes_read_per_sec()),
                human_bytes(meta.bytes_written_per_sec()),
                human_bytes(meta.bytes_read as f64),
                human_bytes(meta.bytes_written as f64),
                meta.path.to_string_lossy().to_string(),
            ])
        })
        .collect();

    let header = Row::new(vec!["FD", "Read/s", "Written/s", "Read", "Written", "Path"])
        .style(Style::default().fg(Color::Yellow))
        .height(1);

    let table = Table::new(
        rows,
        &[
            Constraint::Length(6),  // Fd
            Constraint::Length(10), // Read/s
            Constraint::Length(10), // Written/s
            Constraint::Length(10), // Read
            Constraint::Length(10), // Written
            Constraint::Min(20),    // Path
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" Open Files ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White)),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .column_spacing(1);

    let mut table_state = app.table_state.clone();
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn render_status_bar(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let status_text = format!(
        " Files: {} | Press 'q' to quit, ↑/↓ or j/k to navigate ",
        app.fd_map().len()
    );

    let status = Line::from(vec![Span::styled(
        status_text,
        Style::default().fg(Color::White),
    )]);

    frame.render_widget(status, area);
}
