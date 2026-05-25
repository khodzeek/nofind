use crate::config::Config;
use crate::network::{self, IpGeoInfo};
use crate::tor::TorStatus;
use crate::utils;

/// Overall privacy/anonymity assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnonymityLevel {
    None,
    Low,
    Medium,
    High,
    Maximum,
}

impl AnonymityLevel {
    pub fn label(&self) -> &str {
        match self {
            AnonymityLevel::None => "None",
            AnonymityLevel::Low => "Low",
            AnonymityLevel::Medium => "Medium",
            AnonymityLevel::High => "High",
            AnonymityLevel::Maximum => "Maximum",
        }
    }

    pub fn from_checks(tor_active: bool, dns_secure: bool, proxy_ok: bool) -> Self {
        match (tor_active, dns_secure, proxy_ok) {
            (true, true, true) => AnonymityLevel::High,
            (true, true, false) => AnonymityLevel::Medium,
            (true, false, _) => AnonymityLevel::Medium,
            (false, true, true) => AnonymityLevel::Low,
            (false, true, false) => AnonymityLevel::Low,
            _ => AnonymityLevel::None,
        }
    }
}

/// Comprehensive privacy status.
#[derive(Debug, Clone)]
pub struct PrivacyStatus {
    pub current_ip: Option<String>,
    pub geo_info: Option<IpGeoInfo>,
    pub tor_status: TorStatus,
    pub dns_secure: bool,
    pub proxy_working: bool,
    pub anonymity_level: AnonymityLevel,
    pub active_leaks: Vec<String>,
    pub user_agent_rotating: bool,
    pub session_isolation: bool,
    pub stream_isolation: bool,
    pub jitter_enabled: bool,
    pub fingerprint_level: String,
    pub browser_profile: String,
}

impl PrivacyStatus {
    pub fn empty() -> Self {
        Self {
            current_ip: None,
            geo_info: None,
            tor_status: TorStatus::unavailable(),
            dns_secure: false,
            proxy_working: false,
            anonymity_level: AnonymityLevel::None,
            active_leaks: Vec::new(),
            user_agent_rotating: false,
            session_isolation: false,
            stream_isolation: false,
            jitter_enabled: false,
            fingerprint_level: "off".into(),
            browser_profile: "none".into(),
        }
    }
}

/// Run a full privacy status check (max 15s total).
pub async fn check_status(config: &Config) -> anyhow::Result<PrivacyStatus> {
    let tor_status = crate::tor::check_tor_available(config).await;

    // Check current IP (via proxy or direct)
    let (current_ip, geo_info) = if tor_status.available {
        match network::fetch_public_ip_direct().await {
            Ok(ip) => {
                let geo = network::fetch_ip_info(&ip).await.ok();
                (Some(ip), geo)
            }
            Err(_) => (None, None),
        }
    } else {
        match network::fetch_public_ip_direct().await {
            Ok(ip) => {
                let geo = network::fetch_ip_info(&ip).await.ok();
                (Some(ip), geo)
            }
            Err(_) => (None, None),
        }
    };

    // Check DNS security (DoH configured)
    let dns_secure = match &config.dns.doh_provider {
        p if !p.is_empty() => true,
        _ => false,
    };

    // Check proxy (with timeout)
    let proxy_working = {
        let proxy_parts: Vec<&str> = config.network.socks5_proxy.split(':').collect();
        if proxy_parts.len() == 2 {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::net::TcpStream::connect(format!(
                    "{}:{}",
                    proxy_parts[0], proxy_parts[1]
                )),
            )
            .await
            .map_or(false, |r| r.is_ok())
        } else {
            false
        }
    };

    let anonymity_level =
        AnonymityLevel::from_checks(tor_status.available, dns_secure, proxy_working);

    Ok(PrivacyStatus {
        current_ip,
        geo_info,
        tor_status,
        dns_secure,
        proxy_working,
        anonymity_level,
        active_leaks: Vec::new(),
        user_agent_rotating: config.privacy.user_agent_rotation,
        session_isolation: config.privacy.session_isolation,
        stream_isolation: config.privacy.stream_isolation,
        jitter_enabled: config.privacy.jitter_enabled,
        fingerprint_level: config.privacy.fingerprint_level.clone(),
        browser_profile: config.privacy.browser_profile.clone(),
    })
}

/// Print a formatted status report to the terminal.
pub async fn print_status() -> anyhow::Result<()> {
    let config = Config::load_or_default(None)?;
    let status = check_status(&config).await?;

    println!();
    println!("  ╔══════════════════════════════════════════╗");
    println!("  ║        nofind — Privacy Status            ║");
    println!("  ╠══════════════════════════════════════════╣");

    // Connection
    println!(
        "  ║  Proxy:        {} {}",
        config.network.socks5_proxy,
        if status.proxy_working {
            "\x1b[32m● connected\x1b[0m"
        } else {
            "\x1b[31m● disconnected\x1b[0m"
        }
    );

    // IP
    if let Some(ref ip) = status.current_ip {
        println!("  ║  Public IP:    {}", ip);
        if let Some(ref geo) = status.geo_info {
            println!(
                "  ║  Location:     {}, {} ({})",
                geo.city, geo.country, geo.region
            );
            println!("  ║  ISP:          {}", geo.isp);
        }
    } else {
        println!("  ║  Public IP:    Unable to determine");
    }

    // Tor
    println!(
        "  ║  Tor:          {}",
        if status.tor_status.available {
            "\x1b[32m✓ Active\x1b[0m"
        } else {
            "\x1b[31m✗ Not detected\x1b[0m"
        }
    );
    if status.tor_status.available {
        println!(
            "  ║  Circuit:      {}",
            if status.tor_status.circuit_established {
                "\x1b[32m● Established\x1b[0m"
            } else {
                "\x1b[33m● Pending\x1b[0m"
            }
        );
    }

    // DNS
    println!(
        "  ║  DNS Secure:   {}",
        if status.dns_secure {
            "\x1b[32m✓ DoH enabled\x1b[0m"
        } else {
            "\x1b[31m✗ Standard DNS\x1b[0m"
        }
    );

    // Anonymity
    let anon_color = match status.anonymity_level {
        AnonymityLevel::High | AnonymityLevel::Maximum => "\x1b[32m",
        AnonymityLevel::Medium => "\x1b[33m",
        _ => "\x1b[31m",
    };
    println!(
        "  ║  Anonymity:    {}{}\x1b[0m",
        anon_color,
        status.anonymity_level.label()
    );

    // Features
    println!("  ╠══════════════════════════════════════════╣");
    println!(
        "  ║  UA Rotation:  {}",
        utils::colored_status(status.user_agent_rotating)
    );
    println!(
        "  ║  Session Iso:  {}",
        utils::colored_status(status.session_isolation)
    );
    println!(
        "  ║  Stream Iso:   {}",
        utils::colored_status(status.stream_isolation)
    );
    println!(
        "  ║  Jitter:       {}",
        utils::colored_status(status.jitter_enabled)
    );
    println!(
        "  ║  Fingerprint:  {}",
        status.fingerprint_level
    );
    println!(
        "  ║  Browser:      {}",
        status.browser_profile
    );
    println!(
        "  ║  Kill Switch:  {}",
        utils::colored_status(config.privacy.kill_switch)
    );
    println!(
        "  ║  Bridges:      {} configured",
        config.privacy.tor_bridges.len()
    );
    println!(
        "  ║  Profile:      {}",
        config.profile
    );

    // Leaks
    if !status.active_leaks.is_empty() {
        println!("  ╠══════════════════════════════════════════╣");
        println!("  ║  ⚠ Leaks detected:");
        for leak in &status.active_leaks {
            println!("  ║    - {}", leak);
        }
    }

    println!("  ╚══════════════════════════════════════════╝");
    println!();

    Ok(())
}
