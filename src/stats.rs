use parking_lot::Mutex;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Traffic and privacy statistics.
#[derive(Debug, Clone, Serialize)]
pub struct PrivacyStats {
    pub session_start: chrono::DateTime<chrono::Local>,
    pub uptime_secs: u64,
    pub requests_total: u64,
    pub requests_proxied: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub tor_rotations: u64,
    pub tor_rotation_failures: u64,
    pub dns_queries: u64,
    pub dns_leaks_detected: u64,
    pub ip_changes: u64,
    pub avg_latency_ms: f64,
    pub peak_bandwidth_bytes_per_sec: f64,
    pub current_exit_ip: String,
    pub exit_countries: Vec<String>,
}

impl Default for PrivacyStats {
    fn default() -> Self {
        Self {
            session_start: chrono::Local::now(),
            uptime_secs: 0,
            requests_total: 0,
            requests_proxied: 0,
            bytes_sent: 0,
            bytes_received: 0,
            tor_rotations: 0,
            tor_rotation_failures: 0,
            dns_queries: 0,
            dns_leaks_detected: 0,
            ip_changes: 0,
            avg_latency_ms: 0.0,
            peak_bandwidth_bytes_per_sec: 0.0,
            current_exit_ip: String::new(),
            exit_countries: Vec::new(),
        }
    }
}

/// Thread-safe statistics tracker.
pub struct StatsTracker {
    inner: Arc<Mutex<PrivacyStats>>,
    session_start: Instant,
}

impl StatsTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(PrivacyStats::default())),
            session_start: Instant::now(),
        }
    }

    pub fn snapshot(&self) -> PrivacyStats {
        let mut stats = self.inner.lock().clone();
        stats.uptime_secs = self.session_start.elapsed().as_secs();
        stats
    }

    pub fn record_request(&self, proxied: bool, sent: u64, received: u64, latency: Duration) {
        let mut s = self.inner.lock();
        s.requests_total += 1;
        if proxied {
            s.requests_proxied += 1;
        }
        s.bytes_sent += sent;
        s.bytes_received += received;
        let latency_ms = latency.as_millis() as f64;
        let n = s.requests_total as f64;
        s.avg_latency_ms = (s.avg_latency_ms * (n - 1.0) + latency_ms) / n;

        // Peak bandwidth (bytes/sec over this request)
        if latency.as_secs_f64() > 0.0 {
            let bw = received as f64 / latency.as_secs_f64();
            if bw > s.peak_bandwidth_bytes_per_sec {
                s.peak_bandwidth_bytes_per_sec = bw;
            }
        }
    }

    pub fn record_rotation(&self, success: bool) {
        let mut s = self.inner.lock();
        if success {
            s.tor_rotations += 1;
            s.ip_changes += 1;
        } else {
            s.tor_rotation_failures += 1;
        }
    }

    pub fn record_dns(&self, leak: bool) {
        let mut s = self.inner.lock();
        s.dns_queries += 1;
        if leak {
            s.dns_leaks_detected += 1;
        }
    }

    pub fn update_exit(&self, ip: &str, country: &str) {
        let mut s = self.inner.lock();
        if s.current_exit_ip != ip {
            s.ip_changes += 1;
        }
        s.current_exit_ip = ip.to_string();
        if !country.is_empty() && !s.exit_countries.contains(&country.to_string()) {
            s.exit_countries.push(country.to_string());
        }
    }

    pub fn arc_clone(&self) -> Arc<Mutex<PrivacyStats>> {
        self.inner.clone()
    }
}

/// Export privacy report as JSON.
pub fn export_report_json(stats: &PrivacyStats) -> anyhow::Result<String> {
    let json = serde_json::to_string_pretty(stats)?;
    Ok(json)
}

/// Export privacy report as formatted text.
pub fn export_report_text(stats: &PrivacyStats) -> String {
    let mut report = String::new();
    report.push_str("╔══════════════════════════════════════════════╗\n");
    report.push_str("║        nofind — Privacy Report               ║\n");
    report.push_str("╠══════════════════════════════════════════════╣\n");
    report.push_str(&format!(
        "║  Session:     {:<32}║\n",
        stats.session_start.format("%Y-%m-%d %H:%M:%S")
    ));
    report.push_str(&format!(
        "║  Uptime:      {:<32}║\n",
        crate::utils::format_duration(stats.uptime_secs)
    ));
    report.push_str("╠══════════════════════════════════════════════╣\n");
    report.push_str(&format!(
        "║  Requests:    {:<32}║\n",
        stats.requests_total
    ));
    report.push_str(&format!(
        "║  Proxied:     {:<32}║\n",
        stats.requests_proxied
    ));
    report.push_str(&format!(
        "║  Data Sent:   {:<32}║\n",
        format_bytes(stats.bytes_sent)
    ));
    report.push_str(&format!(
        "║  Data Recv:   {:<32}║\n",
        format_bytes(stats.bytes_received)
    ));
    report.push_str(&format!(
        "║  Avg Latency: {:<32}║\n",
        format!("{:.1} ms", stats.avg_latency_ms)
    ));
    report.push_str("╠══════════════════════════════════════════════╣\n");
    report.push_str(&format!(
        "║  Rotations:   {} ok / {} fail\n",
        stats.tor_rotations, stats.tor_rotation_failures
    ));
    report.push_str(&format!(
        "║  IP Changes:  {:<32}║\n",
        stats.ip_changes
    ));
    report.push_str(&format!(
        "║  Exit IPs:    {:<32}║\n",
        stats.exit_countries.len()
    ));
    report.push_str(&format!(
        "║  DNS Queries: {} ({} leaks)\n",
        stats.dns_queries, stats.dns_leaks_detected
    ));
    report.push_str("╚══════════════════════════════════════════════╝\n");

    if !stats.exit_countries.is_empty() {
        report.push_str("\nExit countries used:\n");
        for country in &stats.exit_countries {
            report.push_str(&format!("  • {}\n", country));
        }
    }

    report
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size > 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    format!("{:.1} {}", size, UNITS[unit_idx])
}

// ── Command handler ──────────────────────────────────────────────

pub async fn cmd_report() -> anyhow::Result<()> {
    // Create a dummy tracker just for report generation
    // In real usage, the tracker is shared with the dashboard
    let tracker = StatsTracker::new();
    {
        let mut s = tracker.inner.lock();
        s.uptime_secs = 1; // would be set from actual session
    }
    let stats = tracker.snapshot();

    println!();
    println!("{}", export_report_text(&stats));

    // Also save JSON
    let report_dir = dirs::data_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let report_path = report_dir.join("nofind").join("privacy-report.json");
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let json = export_report_json(&stats)?;
    std::fs::write(&report_path, &json)?;
    println!("JSON report saved to: {}", report_path.display());
    println!();

    Ok(())
}
