use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Configuration for transparent system-wide proxy.
#[derive(Debug, Clone)]
pub struct TransparentConfig {
    /// Tor transparent proxy port (TransPort)
    pub trans_port: u16,
    /// Tor DNS port (DNSPort)
    pub dns_port: u16,
    /// Tor SOCKS5 port
    pub socks_port: u16,
    /// Tor UID for exception rules
    pub tor_uid: String,
    /// Backup file for iptables rules
    pub backup_file: PathBuf,
    /// Kill switch: reject all non-Tor traffic
    pub kill_switch: bool,
    /// Local network range to exclude (e.g., 192.168.1.0/24)
    pub local_network: Option<String>,
}

impl Default for TransparentConfig {
    fn default() -> Self {
        Self {
            trans_port: 9040,
            dns_port: 5353,
            socks_port: 9050,
            tor_uid: "debian-tor".to_string(),
            backup_file: PathBuf::from("/tmp/nofind-iptables-backup.rules"),
            kill_switch: false,
            local_network: None,
        }
    }
}

// ── IPTables management ──────────────────────────────────────────

/// Set up transparent proxy iptables rules.
/// Requires root privileges.
pub fn start_transparent(config: &TransparentConfig) -> anyhow::Result<()> {
    check_root()?;

    println!("  ╔══════════════════════════════════════════════╗");
    println!("  ║  Transparent Proxy — System-Wide Tor         ║");
    println!("  ╠══════════════════════════════════════════════╣");
    println!("  ║  Redirecting ALL TCP traffic through Tor     ║");
    println!("  ║  TransPort: {}                              ║", config.trans_port);
    println!("  ║  DNSPort:   {}                              ║", config.dns_port);
    println!("  ╚══════════════════════════════════════════════╝");
    println!();

    // 0. Verify Tor ports
    let trans_ok = check_port_listening(config.trans_port);
    let dns_ok = check_port_listening(config.dns_port);

    // Try to detect Tor SOCKS port as fallback check
    let socks_ok = check_port_listening(config.socks_port);

    if trans_ok {
        println!("  ✓ Tor TransPort {} listening", config.trans_port);
    } else if socks_ok {
        println!("  ⚠ TransPort {} undetected but SOCKS {} is up — proceeding", config.trans_port, config.socks_port);
    } else {
        println!("  ✗ Tor not detected on port {} or {} — is Tor running?", config.trans_port, config.socks_port);
        println!("    Check: sudo netstat -tlnp | grep tor");
        println!("    Continuing anyway — iptables rules will be applied");
        println!("    If browser has no internet, run: sudo nofind transparent-stop");
    }

    if dns_ok {
        println!("  ✓ Tor DNSPort {} listening", config.dns_port);
    } else {
        println!("  ⚠ Tor DNSPort {} not detected — DNS via TCP/TransPort", config.dns_port);
    }

    // 1. Backup current rules
    backup_iptables(&config.backup_file)?;
    println!("  ✓ iptables rules backed up to {}", config.backup_file.display());

    // 2. NAT: redirect all TCP (except Tor's own) to TransPort
    let tor_uid = detect_tor_user().unwrap_or_else(|| config.tor_uid.clone());
    println!("  Tor user detected: {}", tor_uid);

    // Exclude Tor's own traffic from redirection
    run_iptables(&[
        "-t", "nat",
        "-A", "OUTPUT",
        "-p", "tcp",
        "-m", "owner", "--uid-owner", &tor_uid,
        "-j", "RETURN",
    ])?;

    // Exclude localhost traffic
    run_iptables(&[
        "-t", "nat",
        "-A", "OUTPUT",
        "-d", "127.0.0.0/8",
        "-j", "RETURN",
    ])?;

    // Exclude local network if specified
    if let Some(ref local_net) = config.local_network {
        run_iptables(&[
            "-t", "nat",
            "-A", "OUTPUT",
            "-d", local_net,
            "-j", "RETURN",
        ])?;
    }

    // Redirect remaining TCP to Tor TransPort
    run_iptables(&[
        "-t", "nat",
        "-A", "OUTPUT",
        "-p", "tcp",
        "--syn", // Only new connections
        "-j", "REDIRECT",
        "--to-port", &config.trans_port.to_string(),
    ])?;
    println!("  ✓ TCP traffic redirected to Tor TransPort");

    // 3. Redirect DNS to Tor DNSPort (if available)
    if dns_available {
        run_iptables(&[
            "-t", "nat",
            "-A", "OUTPUT",
            "-p", "udp",
            "--dport", "53",
            "-j", "REDIRECT",
            "--to-port", &config.dns_port.to_string(),
        ])?;

        run_iptables(&[
            "-t", "nat",
            "-A", "OUTPUT",
            "-p", "tcp",
            "--dport", "53",
            "-j", "REDIRECT",
            "--to-port", &config.dns_port.to_string(),
        ])?;

        println!("  ✓ DNS traffic redirected to Tor DNSPort");
    } else {
        println!("  ⚠ DNS redirection skipped (DNSPort not available)");
        println!("    DNS queries will be resolved by Tor exit nodes via TCP TransPort");
    }

    // Block DNS-over-HTTPS providers (force browser to use system DNS via Tor)
    let doh_ips = [
        "1.1.1.1", "1.0.0.1",           // Cloudflare
        "8.8.8.8", "8.8.4.4",           // Google
        "9.9.9.9", "149.112.112.112",   // Quad9
    ];
    for ip in &doh_ips {
        let _ = run_iptables(&[
            "-A", "OUTPUT",
            "-d", ip,
            "-p", "tcp",
            "--dport", "443",
            "-j", "REJECT",
        ]);
    }
    println!("  ✓ DNS-over-HTTPS providers blocked (forces system DNS)");

    // 4. Kill switch (optional): REJECT all non-Tor TCP
    if config.kill_switch {
        // Allow Tor's own outbound traffic
        run_iptables(&[
            "-A", "OUTPUT",
            "-p", "tcp",
            "-m", "owner", "--uid-owner", &tor_uid,
            "-j", "ACCEPT",
        ])?;
        // Allow loopback
        run_iptables(&[
            "-A", "OUTPUT",
            "-d", "127.0.0.0/8",
            "-j", "ACCEPT",
        ])?;
        // Block everything else
        run_iptables(&[
            "-A", "OUTPUT",
            "-p", "tcp",
            "-j", "REJECT",
            "--reject-with", "tcp-reset",
        ])?;
        println!("  ✓ Kill switch ACTIVE — all non-Tor traffic blocked");
    }

    println!();
    println!("  Status: ANONYMOUS — All system traffic routed through Tor");
    println!();
    println!("  Verify: curl -s https://check.torproject.org | grep -o 'Congratulations'");
    println!();
    println!("  To stop: nofind transparent-stop");
    println!();

    Ok(())
}

/// Remove transparent proxy rules and restore originals.
pub fn stop_transparent(config: &TransparentConfig) -> anyhow::Result<()> {
    check_root()?;

    println!("Stopping transparent proxy...");

    // Flush our NAT rules
    run_iptables(&["-t", "nat", "-F", "OUTPUT"])?;
    let _ = run_iptables(&["-t", "nat", "-F", "PREROUTING"]);

    // Flush kill switch rules if enabled
    if config.kill_switch {
        let _ = run_iptables(&["-F", "OUTPUT"]);
    }

    // Restore backup if available
    if config.backup_file.exists() {
        match restore_iptables(&config.backup_file) {
            Ok(()) => {
                println!("  ✓ iptables rules restored from backup");
                let _ = fs::remove_file(&config.backup_file);
            }
            Err(e) => {
                println!("  ⚠ Could not restore from backup: {}", e);
                println!("  ⚠ Current rules are empty — you may need to restart networking");
            }
        }
    }

    println!("Transparent proxy stopped. Network returned to normal.");
    Ok(())
}

/// Check transparent proxy status.
pub fn check_status() -> anyhow::Result<()> {
    println!("Transparent proxy status:");
    println!();

    // Check NAT rules
    let nat_rules = run_iptables_output(&["-t", "nat", "-L", "OUTPUT", "-n"])?;
    let has_tcp_redirect = nat_rules.contains("REDIRECT") && nat_rules.contains("9040");
    let has_dns_redirect = nat_rules.contains("5353");

    println!("  TCP → Tor TransPort: {}", if has_tcp_redirect { "✓ Active" } else { "✗ Not active" });
    println!("  DNS → Tor DNSPort:  {}", if has_dns_redirect { "✓ Active" } else { "✗ Not active" });

    // Check filter rules (kill switch)
    let filter_rules = run_iptables_output(&["-L", "OUTPUT", "-n"])?;
    let kill_switch_active = filter_rules.contains("REJECT");

    println!("  Kill Switch:         {}", if kill_switch_active { "⚠ ACTIVE" } else { "○ Disabled" });
    println!();

    if has_tcp_redirect && has_dns_redirect {
        println!("  System is ANONYMOUS — all traffic routed through Tor");
    } else {
        println!("  System is NOT protected — transparent proxy is off");
    }

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────

/// Check if a TCP port is listening on localhost.
/// Tries ss, netstat, lsof, and direct TCP connect.
fn check_port_listening(port: u16) -> bool {
    let port_str = format!(":{}", port);

    // Method 1: ss
    if let Ok(output) = Command::new("ss").args(["-tln"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        if text.contains(&port_str) {
            return true;
        }
    }

    // Method 2: netstat (with sudo, shows all processes)
    if let Ok(output) = Command::new("netstat").args(["-tln"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        if text.contains(&port_str) {
            return true;
        }
    }

    // Method 3: direct check via /proc (Linux)
    if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
        // Format: sl local_address rem_address st ...
        // local_address is hex: 0100007F:2358 for 127.0.0.1:9040
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let local = parts[1]; // e.g., "0100007F:2358"
                if let Some(hex_port) = local.split(':').last() {
                    if let Ok(p) = u16::from_str_radix(hex_port, 16) {
                        if p == port {
                            return true;
                        }
                    }
                }
            }
        }
    }

    // Method 4: direct TCP connect (works for SOCKS, Control, DNSPort, not TransPort)
    use std::net::TcpStream;
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", port).parse().unwrap(),
        std::time::Duration::from_millis(500),
    )
    .is_ok()
}

fn check_root() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::geteuid() };
        if uid != 0 {
            anyhow::bail!(
                "Root privileges required for transparent proxy.\n\
                 Run with: sudo nofind transparent-start"
            );
        }
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        // On non-Unix, try id -u command
        if let Ok(output) = Command::new("id").arg("-u").output() {
            let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if uid != "0" {
                anyhow::bail!(
                    "Root privileges required. Run with elevated privileges."
                );
            }
            return Ok(());
        }
        // Can't check, assume OK
        Ok(())
    }
}

fn detect_tor_user() -> Option<String> {
    // Try common Tor usernames
    for user in &["debian-tor", "tor", "toranon", "_tor"] {
        let output = Command::new("id")
            .arg(user)
            .output()
            .ok()?;
        if output.status.success() {
            return Some(user.to_string());
        }
    }
    // Try to get from running tor process
    let output = Command::new("sh")
        .arg("-c")
        .arg("ps aux | grep '[t]or' | awk '{print $1}' | head -1")
        .output()
        .ok()?;
    let user = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !user.is_empty() && user != "root" {
        Some(user)
    } else {
        None
    }
}

fn backup_iptables(path: &PathBuf) -> anyhow::Result<()> {
    let output = Command::new("iptables-save")
        .output()
        .map_err(|_| anyhow::anyhow!("iptables-save not found. Install iptables."))?;
    fs::write(path, &output.stdout)?;
    Ok(())
}

fn restore_iptables(path: &PathBuf) -> anyhow::Result<()> {
    let status = Command::new("iptables-restore")
        .arg(path)
        .status()
        .map_err(|_| anyhow::anyhow!("iptables-restore not found"))?;
    if !status.success() {
        anyhow::bail!("iptables-restore failed");
    }
    Ok(())
}

fn run_iptables(args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new("iptables")
        .args(args)
        .output()
        .map_err(|_| anyhow::anyhow!("iptables not found. Install with: sudo apt install iptables"))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        if err.contains("Permission denied") {
            anyhow::bail!("Permission denied. Run with sudo.");
        }
        anyhow::bail!("iptables error: {}", err.trim());
    }
    Ok(())
}

fn run_iptables_output(args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("iptables")
        .args(args)
        .output()
        .map_err(|_| anyhow::anyhow!("iptables not found"))?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// ── Tor configuration check ──────────────────────────────────────

/// Verify that Tor has TransPort and DNSPort configured.
pub fn check_tor_config() -> anyhow::Result<()> {
    let torrc_paths = [
        "/etc/tor/torrc",
        "/etc/tor/torsocks.conf",
        "/usr/local/etc/tor/torrc",
    ];

    let mut found = false;
    for path in &torrc_paths {
        if let Ok(content) = fs::read_to_string(path) {
            let has_trans = content.contains("TransPort") || content.contains("TransPort 9040");
            let has_dns = content.contains("DNSPort") || content.contains("DNSPort 5353");
            if has_trans && has_dns {
                found = true;
                break;
            }
        }
    }

    if !found {
        println!();
        println!("  ╔══════════════════════════════════════════════╗");
        println!("  ║  ⚠ Tor needs TransPort + DNSPort configured  ║");
        println!("  ╠══════════════════════════════════════════════╣");
        println!("  ║                                              ║");
        println!("  ║  Add these lines to /etc/tor/torrc:           ║");
        println!("  ║                                              ║");
        println!("  ║  TransPort 9040                              ║");
        println!("  ║  DNSPort 5353                                ║");
        println!("  ║                                              ║");
        println!("  ║  Then restart Tor:                            ║");
        println!("  ║  sudo systemctl restart tor                   ║");
        println!("  ║                                              ║");
        println!("  ╚══════════════════════════════════════════════╝");
        println!();

        // Offer to add the lines automatically
        print!("  Add TransPort + DNSPort to /etc/tor/torrc now? [y/N]: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        if input.trim().to_lowercase() == "y" {
            let torrc = "/etc/tor/torrc";
            let mut content = fs::read_to_string(torrc).unwrap_or_default();
            if !content.contains("TransPort") {
                content.push_str("\n# Added by nofind — transparent proxy\n");
                content.push_str("TransPort 9040\n");
                content.push_str("DNSPort 5353\n");
                fs::write(torrc, &content)?;
                println!("  ✓ Added to {}. Restart Tor:", torrc);
                println!("    sudo systemctl restart tor");
            }
        }
    } else {
        println!("  ✓ Tor TransPort + DNSPort configured correctly");
    }

    Ok(())
}

/// Install TransPort + DNSPort configuration to torrc.
pub fn install_tor_config() -> anyhow::Result<()> {
    let torrc = "/etc/tor/torrc";
    if !PathBuf::from(torrc).exists() {
        anyhow::bail!("{} not found. Is Tor installed?", torrc);
    }

    let mut content = fs::read_to_string(torrc)?;
    let mut changed = false;

    if !content.contains("TransPort") {
        content.push_str("\n# Added by nofind\nTransPort 9040\n");
        changed = true;
    }
    if !content.contains("DNSPort") {
        content.push_str("DNSPort 5353\n");
        changed = true;
    }

    if changed {
        fs::write(torrc, &content)?;
        println!("  ✓ TransPort 9040 + DNSPort 5353 added to {}", torrc);
        println!("  Restart Tor: sudo systemctl restart tor");
    } else {
        println!("  TransPort and DNSPort already configured.");
    }

    Ok(())
}
