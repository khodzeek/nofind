use chrono::Local;
use rand::seq::SliceRandom;
use std::fmt;

// ── Logging helpers ──────────────────────────────────────────────

pub struct LogEntry {
    pub timestamp: chrono::DateTime<Local>,
    pub level: LogLevel,
    pub message: String,
}

impl LogEntry {
    pub fn info(msg: impl Into<String>) -> Self {
        Self {
            timestamp: Local::now(),
            level: LogLevel::Info,
            message: msg.into(),
        }
    }

    pub fn warn(msg: impl Into<String>) -> Self {
        Self {
            timestamp: Local::now(),
            level: LogLevel::Warn,
            message: msg.into(),
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            timestamp: Local::now(),
            level: LogLevel::Error,
            message: msg.into(),
        }
    }

    pub fn success(msg: impl Into<String>) -> Self {
        Self {
            timestamp: Local::now(),
            level: LogLevel::Success,
            message: msg.into(),
        }
    }
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] [{}] {}",
            self.timestamp.format("%H:%M:%S"),
            self.level,
            self.message
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Success,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Success => write!(f, "OK"),
        }
    }
}

// ── User-Agent rotation ──────────────────────────────────────────

#[allow(dead_code)]
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
];

pub fn random_user_agent() -> String {
    USER_AGENTS
        .choose(&mut rand::thread_rng())
        .unwrap_or(&USER_AGENTS[0])
        .to_string()
}

// ── Display helpers ───────────────────────────────────────────────

pub fn status_icon(ok: bool) -> &'static str {
    if ok {
        "✓"
    } else {
        "✗"
    }
}

pub fn colored_status(ok: bool) -> String {
    if ok {
        "\x1b[32m✓\x1b[0m".to_string()
    } else {
        "\x1b[31m✗\x1b[0m".to_string()
    }
}

pub fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

// ── File system helpers ───────────────────────────────────────────

pub fn ensure_dir(path: &std::path::Path) -> anyhow::Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

pub fn temp_dir() -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push("nofind");
    path
}
