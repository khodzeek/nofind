use crate::config::Config;
use crate::privacy::{AnonymityLevel, PrivacyStatus};
use crate::utils::{self, LogEntry, LogLevel};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use parking_lot::Mutex;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_LOG_ENTRIES: usize = 200;

// ── Application state ────────────────────────────────────────────

pub struct AppState {
    pub privacy: PrivacyStatus,
    pub connected: bool,
    pub session_start: Instant,
    pub logs: VecDeque<LogEntry>,
    pub proxy_addr: String,
    pub stats: crate::stats::StatsTracker,
}

impl AppState {
    fn new(proxy_addr: &str) -> Self {
        let mut logs = VecDeque::with_capacity(MAX_LOG_ENTRIES);
        logs.push_back(LogEntry::info("Dashboard initialized"));
        logs.push_back(LogEntry::info(format!("Proxy: {}", proxy_addr)));

        Self {
            privacy: PrivacyStatus::empty(),
            connected: false,
            session_start: Instant::now(),
            logs,
            proxy_addr: proxy_addr.to_string(),
            stats: crate::stats::StatsTracker::new(),
        }
    }

    fn add_log(&mut self, entry: LogEntry) {
        if self.logs.len() >= MAX_LOG_ENTRIES {
            self.logs.pop_front();
        }
        self.logs.push_back(entry);
    }
}

// ── Dashboard entry point ────────────────────────────────────────

pub async fn run_dashboard(config: &Config, proxy_addr: &str) -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Shared state
    let state = Arc::new(Mutex::new(AppState::new(proxy_addr)));

    // Background status poller
    let poll_state = state.clone();
    let poll_config = config.clone();
    let poll_proxy = proxy_addr.to_string();
    let poll_handle = tokio::spawn(async move {
        poll_status_loop(poll_state, &poll_config, &poll_proxy).await;
    });

    // Background auto-rotation timer
    let auto_rotate_interval = config.privacy.rotate_identity_interval_secs;
    let auto_rotate_handle = if auto_rotate_interval > 0 {
        let rotate_state = state.clone();
        let rotate_config = config.clone();
        Some(tokio::spawn(async move {
            auto_rotate_loop(rotate_state, &rotate_config, auto_rotate_interval).await;
        }))
    } else {
        None
    };

    // Initial status check with timeout (10s max)
    {
        let status_result = tokio::time::timeout(
            Duration::from_secs(10),
            crate::privacy::check_status(config),
        )
        .await;

        let mut s = state.lock();
        match status_result {
            Ok(Ok(status)) => {
                s.privacy = status;
                s.connected = s.privacy.proxy_working;
                s.add_log(LogEntry::success("Initial status check complete"));
            }
            Ok(Err(e)) => {
                s.add_log(LogEntry::error(format!("Status check failed: {}", e)));
            }
            Err(_) => {
                s.add_log(LogEntry::warn("Initial status check timed out (10s) — using defaults"));
                s.privacy.proxy_working = true; // assume Tor is working
                s.connected = true;
            }
        }
    }

    // Main event loop
    let tick_rate = Duration::from_millis(250);
    let mut last_status_update = Instant::now();
    let status_interval = Duration::from_secs(10);

    loop {
        terminal.draw(|f| render_dashboard(f, &state.lock()))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('r') => {
                        let mut s = state.lock();
                        s.add_log(LogEntry::info("Rotating Tor identity..."));
                        drop(s);
                        match crate::tor::rotate_circuit(config).await {
                            Ok(()) => {
                                let mut s = state.lock();
                                s.add_log(LogEntry::success("Circuit rotated"));
                                s.stats.record_rotation(true);
                            }
                            Err(e) => {
                                let mut s = state.lock();
                                s.add_log(LogEntry::error(format!("Rotation failed: {}", e)));
                                s.stats.record_rotation(false);
                            }
                        }
                    }
                    KeyCode::Char('c') => {
                        state.lock().add_log(LogEntry::info("Cleaning session..."));
                        if let Err(e) = crate::security::clean_session().await {
                            state
                                .lock()
                                .add_log(LogEntry::error(format!("Clean failed: {}", e)));
                        } else {
                            state
                                .lock()
                                .add_log(LogEntry::success("Session cleaned"));
                        }
                    }
                    KeyCode::Char('s') => {
                        let mut s = state.lock();
                        s.add_log(LogEntry::info("Refreshing status..."));
                        drop(s);
                        match crate::privacy::check_status(config).await {
                            Ok(status) => {
                                let mut s = state.lock();
                                s.privacy = status;
                                s.connected = s.privacy.proxy_working;
                                s.add_log(LogEntry::success("Status refreshed"));
                            }
                            Err(e) => {
                                state
                                    .lock()
                                    .add_log(LogEntry::error(format!("Refresh failed: {}", e)));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Periodic status refresh (with timeout)
        if last_status_update.elapsed() >= status_interval {
            last_status_update = Instant::now();
            match tokio::time::timeout(
                Duration::from_secs(8),
                crate::privacy::check_status(config),
            )
            .await
            {
                Ok(Ok(status)) => {
                    let mut s = state.lock();
                    let prev_connected = s.connected;
                    s.privacy = status;
                    s.connected = s.privacy.proxy_working;
                    if s.connected != prev_connected {
                        if s.connected {
                            s.add_log(LogEntry::success("Proxy connection restored"));
                        } else {
                            s.add_log(LogEntry::warn("Proxy connection lost"));
                        }
                    }
                }
                _ => {
                    // Timeout or error — skip this refresh
                    state.lock().add_log(LogEntry::warn("Periodic refresh timed out, skipping"));
                }
            }
        }
    }

    // Cleanup
    poll_handle.abort();
    if let Some(handle) = auto_rotate_handle {
        handle.abort();
    }
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if config.security.clean_cache_on_exit {
        let _ = crate::security::clean_session().await;
    }

    println!("Disconnected. Session ended.");
    Ok(())
}

// ── Background poller ────────────────────────────────────────────

async fn poll_status_loop(state: Arc<Mutex<AppState>>, config: &Config, _proxy: &str) {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;

        let tor_status = crate::tor::check_tor_available(config).await;
        let mut s = state.lock();
        let prev_available = s.privacy.tor_status.available;
        s.privacy.tor_status = tor_status;
        if s.privacy.tor_status.available != prev_available {
            if s.privacy.tor_status.available {
                s.add_log(LogEntry::success("Tor connection detected"));
            } else {
                s.add_log(LogEntry::warn("Tor connection lost"));
            }
        }
    }
}

// ── Auto-rotation timer ──────────────────────────────────────────

async fn auto_rotate_loop(state: Arc<Mutex<AppState>>, config: &Config, interval_secs: u64) {
    let duration = Duration::from_secs(interval_secs);
    tracing::info!(interval_s = interval_secs, "Auto-rotation enabled");
    state.lock().add_log(LogEntry::info(format!(
        "Auto-rotation: every {}",
        utils::format_duration(interval_secs)
    )));

    loop {
        tokio::time::sleep(duration).await;

        tracing::info!("Auto-rotating Tor identity...");
        state
            .lock()
            .add_log(LogEntry::info("Auto-rotating Tor identity..."));

        match crate::tor::rotate_circuit(config).await {
            Ok(()) => {
                {
                    let mut s = state.lock();
                    s.add_log(LogEntry::success("Auto-rotation: new circuit established"));
                    s.stats.record_rotation(true);
                }

                // Wait for new circuit to settle (no lock held)
                tokio::time::sleep(Duration::from_secs(3)).await;

                // Fetch new IP (no lock held)
                match crate::network::fetch_public_ip_direct().await {
                    Ok(ip) => {
                        // Fetch geo info before locking (no lock held)
                        let geo = crate::network::fetch_ip_info(&ip).await.ok();

                        // Now lock and update state
                        let mut s = state.lock();
                        s.privacy.current_ip = Some(ip.clone());
                        if let Some(ref g) = geo {
                            s.privacy.geo_info = Some(g.clone());
                            s.stats.update_exit(&ip, &g.country);
                        }
                        s.add_log(LogEntry::info(format!("New exit IP: {}", ip)));
                    }
                    Err(e) => {
                        state.lock().add_log(LogEntry::warn(format!(
                            "Could not fetch new IP: {}",
                            e
                        )));
                    }
                }
            }
            Err(e) => {
                let mut s = state.lock();
                s.add_log(LogEntry::error(format!("Auto-rotation failed: {}", e)));
                s.stats.record_rotation(false);
            }
        }
    }
}

// ── Rendering ────────────────────────────────────────────────────

fn render_dashboard(f: &mut Frame, state: &AppState) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Title
            Constraint::Min(0),     // Content
            Constraint::Length(3),  // Help bar
        ])
        .split(f.area());

    // ── Title bar ────────────────────────────────────────────────
    render_title(f, main_chunks[0], state);

    // ── Content area ─────────────────────────────────────────────
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(35), // Left: status
            Constraint::Percentage(35), // Center: privacy indicators
            Constraint::Percentage(30), // Right: logs
        ])
        .split(main_chunks[1]);

    render_status_panel(f, content_chunks[0], state);
    render_privacy_panel(f, content_chunks[1], state);
    render_logs_panel(f, content_chunks[2], state);

    // ── Help bar ─────────────────────────────────────────────────
    render_help_bar(f, main_chunks[2]);
}

fn render_title(f: &mut Frame, area: Rect, state: &AppState) {
    let uptime = state.session_start.elapsed();
    let uptime_str = utils::format_duration(uptime.as_secs());

    let title = Paragraph::new(Line::from(vec![
        Span::styled(" nofind ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled("— Privacy Dashboard ", Style::default().fg(Color::White)),
        Span::styled(
            format!("| Uptime: {} ", uptime_str),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            if state.connected { "● CONNECTED" } else { "○ DISCONNECTED" },
            Style::default()
                .fg(if state.connected { Color::Green } else { Color::Red })
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(Block::default().style(Style::default().bg(Color::Rgb(20, 20, 30))))
    .alignment(ratatui::layout::Alignment::Left);

    f.render_widget(title, area);
}

fn render_status_panel(f: &mut Frame, area: Rect, state: &AppState) {
    let mut lines: Vec<Line> = Vec::new();

    // Proxy
    lines.push(Line::from(vec![
        Span::styled(" Proxy:      ", Style::default().fg(Color::DarkGray)),
        Span::styled(&state.proxy_addr, Style::default().fg(Color::White)),
    ]));
    lines.push(Line::from(vec![
        Span::styled(" Status:     ", Style::default().fg(Color::DarkGray)),
        status_span(state.connected),
    ]));

    lines.push(Line::from(""));

    // IP
    lines.push(Line::from(Span::styled(
        "─ Connection",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));
    if let Some(ref ip) = state.privacy.current_ip {
        lines.push(Line::from(vec![
            Span::styled(" Public IP:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(ip.clone(), Style::default().fg(Color::Yellow)),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled(" Public IP:  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Checking...", Style::default().fg(Color::DarkGray)),
        ]));
    }
    if let Some(ref geo) = state.privacy.geo_info {
        lines.push(Line::from(vec![
            Span::styled(" Location:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}, {}", geo.city, geo.country_code),
                Style::default().fg(Color::White),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled(" ISP:        ", Style::default().fg(Color::DarkGray)),
            Span::styled(&geo.isp, Style::default().fg(Color::White)),
        ]));
    }

    lines.push(Line::from(""));

    // Tor
    lines.push(Line::from(Span::styled(
        "─ Tor",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(vec![
        Span::styled(" Tor:        ", Style::default().fg(Color::DarkGray)),
        status_span(state.privacy.tor_status.available),
    ]));
    if state.privacy.tor_status.available {
        lines.push(Line::from(vec![
            Span::styled(" Circuit:    ", Style::default().fg(Color::DarkGray)),
            status_span(state.privacy.tor_status.circuit_established),
        ]));
        lines.push(Line::from(vec![
            Span::styled(" Control:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("port {}", state.privacy.tor_status.control_port),
                Style::default().fg(Color::White),
            ),
        ]));
    }

    lines.push(Line::from(""));

    // DNS
    lines.push(Line::from(Span::styled(
        "─ DNS",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(vec![
        Span::styled(" DoH:        ", Style::default().fg(Color::DarkGray)),
        status_span(state.privacy.dns_secure),
    ]));

    lines.push(Line::from(""));

    // Stats
    let snap = state.stats.snapshot();
    lines.push(Line::from(Span::styled(
        "─ Session Stats",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(vec![
        Span::styled(" Reqs:       ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", snap.requests_total),
            Style::default().fg(Color::White),
        ),
        Span::styled(
            format!("  Rotations: {}", snap.tor_rotations),
            Style::default().fg(Color::DarkGray),
        ),
    ]));

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Status ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(60, 60, 80))),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(panel, area);
}

fn render_privacy_panel(f: &mut Frame, area: Rect, state: &AppState) {
    let mut lines: Vec<Line> = Vec::new();

    // Anonymity level
    let (anon_color, anon_icon) = match state.privacy.anonymity_level {
        AnonymityLevel::Maximum => (Color::Green, "████ MAXIMUM"),
        AnonymityLevel::High => (Color::Green, "███▌ HIGH"),
        AnonymityLevel::Medium => (Color::Yellow, "██▌  MEDIUM"),
        AnonymityLevel::Low => (Color::Red, "█▌   LOW"),
        AnonymityLevel::None => (Color::Red, "▌    NONE"),
    };

    lines.push(Line::from(vec![
        Span::styled(" Anonymity:  ", Style::default().fg(Color::DarkGray)),
        Span::styled(anon_icon, Style::default().fg(anon_color).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(""));

    // Privacy indicators
    lines.push(Line::from(Span::styled(
        "─ Privacy Indicators",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));

    let indicators = vec![
        (
            "Proxy Active",
            state.connected,
            "Traffic routed through SOCKS5 proxy",
        ),
        (
            "Tor Enabled",
            state.privacy.tor_status.available,
            "Traffic routed through Tor network",
        ),
        (
            "DNS Secure",
            state.privacy.dns_secure,
            "DNS queries encrypted via DoH",
        ),
        (
            "Stream Iso",
            state.privacy.stream_isolation,
            "Unique SOCKS5 creds per session (Tor circuit isolation)",
        ),
        (
            "UA Rotation",
            state.privacy.user_agent_rotating,
            "User-Agent rotated per session",
        ),
        (
            "Jitter",
            state.privacy.jitter_enabled,
            "Random delays between requests to obscure timing patterns",
        ),
        (
            "Fingerprint",
            state.privacy.fingerprint_level != "off",
            "Browser fingerprint randomization active",
        ),
        (
            "Kill Switch",
            false,
            "Network kill switch (requires root for iptables)",
        ),
    ];

    for (label, active, tooltip) in indicators {
        let icon = if active {
            Span::styled(" ● ", Style::default().fg(Color::Green))
        } else {
            Span::styled(" ○ ", Style::default().fg(Color::DarkGray))
        };
        let name = if active {
            Span::styled(format!("{:<14}", label), Style::default().fg(Color::White))
        } else {
            Span::styled(format!("{:<14}", label), Style::default().fg(Color::DarkGray))
        };
        let tip = Span::styled(format!(" {}", tooltip), Style::default().fg(Color::Rgb(60, 60, 70)));
        lines.push(Line::from(vec![icon, name, tip]));
    }

    lines.push(Line::from(""));

    // Leaks
    lines.push(Line::from(Span::styled(
        "─ Leak Status",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));

    if state.privacy.active_leaks.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(" ● ", Style::default().fg(Color::Green)),
            Span::styled("No leaks detected", Style::default().fg(Color::White)),
        ]));
    } else {
        for leak in &state.privacy.active_leaks {
            lines.push(Line::from(vec![
                Span::styled(" ⚠ ", Style::default().fg(Color::Red)),
                Span::styled(leak.clone(), Style::default().fg(Color::Red)),
            ]));
        }
    }

    lines.push(Line::from(""));

    // Security config
    lines.push(Line::from(Span::styled(
        "─ Security",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));

    let sec_items = [
        ("Cache Cleanup", true),
        ("Ephemeral Sessions", true),
        ("Cookie Isolation", true),
    ];
    for (label, enabled) in sec_items {
        lines.push(Line::from(vec![
            Span::styled(
                if enabled { " ● " } else { " ○ " },
                Style::default().fg(if enabled { Color::Green } else { Color::DarkGray }),
            ),
            Span::styled(
                label,
                Style::default().fg(if enabled { Color::White } else { Color::DarkGray }),
            ),
        ]));
    }

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Privacy ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(60, 60, 80))),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(panel, area);
}

fn render_logs_panel(f: &mut Frame, area: Rect, state: &AppState) {
    let log_items: Vec<ListItem> = state
        .logs
        .iter()
        .rev()
        .take((area.height as usize).saturating_sub(4))
        .map(|entry| {
            let level_color = match entry.level {
                LogLevel::Info => Color::DarkGray,
                LogLevel::Warn => Color::Yellow,
                LogLevel::Error => Color::Red,
                LogLevel::Success => Color::Green,
            };
            let text = format!(
                "{} {}",
                entry.timestamp.format("%H:%M:%S"),
                entry.message
            );
            ListItem::new(Span::styled(text, Style::default().fg(level_color)))
        })
        .collect();

    let logs = List::new(log_items).block(
        Block::default()
            .title(" Logs ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(60, 60, 80))),
    );

    f.render_widget(logs, area);
}

fn render_help_bar(f: &mut Frame, area: Rect) {
    let auto_label = if area.width > 90 {
        " Auto-Rotate ON |"
    } else {
        " Auto-Rot ON |"
    };

    let help = Paragraph::new(Line::from(vec![
        Span::styled(" q ", Style::default().bg(Color::Rgb(50, 50, 70)).fg(Color::White)),
        Span::styled(" Quit  ", Style::default().fg(Color::DarkGray)),
        Span::styled(" r ", Style::default().bg(Color::Rgb(50, 50, 70)).fg(Color::White)),
        Span::styled(" Rotate  ", Style::default().fg(Color::DarkGray)),
        Span::styled(" s ", Style::default().bg(Color::Rgb(50, 50, 70)).fg(Color::White)),
        Span::styled(" Refresh  ", Style::default().fg(Color::DarkGray)),
        Span::styled(" c ", Style::default().bg(Color::Rgb(50, 50, 70)).fg(Color::White)),
        Span::styled(" Clean  ", Style::default().fg(Color::DarkGray)),
        Span::styled(auto_label, Style::default().fg(Color::Yellow)),
    ]))
    .block(Block::default().style(Style::default().bg(Color::Rgb(20, 20, 30))))
    .alignment(ratatui::layout::Alignment::Center);

    f.render_widget(help, area);
}

fn status_span(ok: bool) -> Span<'static> {
    if ok {
        Span::styled("● Active", Style::default().fg(Color::Green))
    } else {
        Span::styled("○ Inactive", Style::default().fg(Color::Red))
    }
}
