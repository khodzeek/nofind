use crate::config::Config;
use crate::network;
use std::time::Duration;

/// Types of privacy leaks that can be detected.
#[derive(Debug, Clone)]
pub struct LeakReport {
    pub dns_leak: bool,
    pub ip_exposed: bool,
    pub webrtc_leak_possible: bool,
    pub fingerprint_issues: Vec<String>,
    pub details: Vec<String>,
}

/// Test domains used for DNS leak detection.
const LEAK_TEST_DOMAINS: &[&str] = &[
    "whoami.akamai.net",
    "myip.opendns.com",
    "resolver.dnscrypt.info",
];

/// Run comprehensive leak checks.
pub async fn run_checks() -> anyhow::Result<()> {
    let config = Config::load_or_default(None)?;

    println!();
    println!("  Running privacy leak checks...");
    println!("  ─────────────────────────────────");
    println!();

    let mut report = LeakReport {
        dns_leak: false,
        ip_exposed: false,
        webrtc_leak_possible: false,
        fingerprint_issues: Vec::new(),
        details: Vec::new(),
    };

    // 1. IP exposure check
    println!("  [1/4] Checking IP exposure...");
    check_ip_exposure(&mut report).await;
    if report.ip_exposed {
        println!("    ⚠ IP is publicly visible");
    } else {
        println!("    ✓ IP check passed");
    }

    // 2. DNS leak check
    println!("  [2/4] Checking DNS leaks...");
    check_dns_leaks(&config, &mut report).await;
    if report.dns_leak {
        println!("    ⚠ DNS leak detected");
    } else {
        println!("    ✓ No DNS leaks detected");
    }

    // 3. WebRTC leak check
    println!("  [3/4] Checking WebRTC exposure...");
    check_webrtc_leak(&mut report).await;
    if report.webrtc_leak_possible {
        println!("    ⚠ WebRTC may expose real IP");
    } else {
        println!("    ✓ WebRTC check passed");
    }

    // 4. Fingerprint check
    println!("  [4/4] Checking browser fingerprint...");
    check_fingerprint(&mut report).await;
    if report.fingerprint_issues.is_empty() {
        println!("    ✓ No fingerprint issues");
    } else {
        for issue in &report.fingerprint_issues {
            println!("    ⚠ {}", issue);
        }
    }

    // Summary
    println!();
    println!("  ╔══════════════════════════════════╗");
    println!("  ║     Leak Check Summary           ║");
    println!("  ╠══════════════════════════════════╣");

    let issues = [
        ("IP Exposed", report.ip_exposed),
        ("DNS Leak", report.dns_leak),
        ("WebRTC Leak", report.webrtc_leak_possible),
        (
            "Fingerprint",
            !report.fingerprint_issues.is_empty(),
        ),
    ];

    let mut total_issues = 0;
    for (label, has_issue) in &issues {
        let status = if *has_issue { "⚠" } else { "✓" };
        if *has_issue {
            total_issues += 1;
        }
        println!("  ║  {} {}", status, label);
    }

    let overall = if total_issues == 0 {
        "\x1b[32mGOOD — No leaks detected\x1b[0m"
    } else {
        "\x1b[31mISSUES FOUND — Review above\x1b[0m"
    };
    println!("  ╠══════════════════════════════════╣");
    println!("  ║  Overall: {}", overall);
    println!("  ╚══════════════════════════════════╝");
    println!();

    if total_issues > 0 {
        println!("  Recommendations:");
        for detail in &report.details {
            println!("    • {}", detail);
        }
        println!();
    }

    Ok(())
}

async fn check_ip_exposure(report: &mut LeakReport) {
    // Check if IP is visible through direct connection
    match network::fetch_public_ip_direct().await {
        Ok(ip) => {
            report.ip_exposed = true;
            report
                .details
                .push(format!("Public IP visible: {}", ip));
            tracing::info!(ip = %ip, "IP exposure check: visible");
        }
        Err(e) => {
            report.ip_exposed = false;
            report
                .details
                .push("Could not determine public IP (may be behind proxy)".into());
            tracing::warn!(error = %e, "IP exposure check: could not reach IP service");
        }
    }
}

async fn check_dns_leaks(config: &Config, report: &mut LeakReport) {
    let dns_client = match crate::dns::DohClient::new(config) {
        Ok(c) => c,
        Err(e) => {
            report.details.push(format!("DNS client init failed: {}", e));
            return;
        }
    };

    for domain in LEAK_TEST_DOMAINS {
        match dns_client.leak_test(domain).await {
            Ok(result) => {
                if result.leak_detected {
                    report.dns_leak = true;
                    report.details.push(format!(
                        "DNS leak for {}: DoH returned {:?}, direct returned {:?}",
                        domain, result.doh_ips, result.alternative_ips
                    ));
                } else {
                    report
                        .details
                        .push(format!("DNS resolution consistent for {}", domain));
                }
            }
            Err(e) => {
                report
                    .details
                    .push(format!("DNS leak test failed for {}: {}", domain, e));
            }
        }
    }
}

async fn check_webrtc_leak(report: &mut LeakReport) {
    // WebRTC can leak local IPs through STUN/TURN servers.
    // In a terminal application, WebRTC isn't directly applicable,
    // but we can check if common STUN servers respond.
    let stun_servers = ["stun.l.google.com:19302", "stun1.l.google.com:19302"];

    let mut reachable = false;
    for server in &stun_servers {
        if tokio::net::TcpStream::connect(server).await.is_ok() {
            reachable = true;
            break;
        }
    }

    if reachable {
        report.webrtc_leak_possible = true;
        report.details.push(
            "STUN servers reachable: WebRTC may be able to leak local IP in browsers"
                .into(),
        );
    } else {
        report
            .details
            .push("STUN servers not reachable via TCP (UDP may differ)".into());
    }
}

async fn check_fingerprint(report: &mut LeakReport) {
    // Test what headers/info we expose
    let client = match reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            report.details.push(format!("Fingerprint check failed: {}", e));
            return;
        }
    };

    // Check headers via httpbin
    match client
        .get("https://httpbin.org/headers")
        .send()
        .await
    {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(headers) = json.get("headers") {
                    // Check for identifying headers
                    if let Some(ua) = headers.get("User-Agent").and_then(|v| v.as_str()) {
                        report
                            .details
                            .push(format!("User-Agent exposed: {}", ua));
                    }
                    if headers.get("Accept-Language").is_some() {
                        report
                            .fingerprint_issues
                            .push("Accept-Language header exposed".into());
                    }
                    if headers.get("Accept-Encoding").is_some() {
                        // Common, but track it
                        report.details.push("Accept-Encoding header present".into());
                    }
                }
            }
        }
        Err(e) => {
            report
                .details
                .push(format!("Fingerprint HTTP check failed: {}", e));
        }
    }

    // Check TLS fingerprint via a service
    match client
        .get("https://tls.peet.ws/api/all")
        .send()
        .await
    {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(tls) = json.get("tls") {
                    if let Some(version) = tls.get("version").and_then(|v| v.as_str()) {
                        report
                            .details
                            .push(format!("TLS version: {}", version));
                    }
                    if let Some(cipher) = tls.get("cipher").and_then(|v| v.as_str()) {
                        report
                            .details
                            .push(format!("TLS cipher: {}", cipher));
                    }
                }
            }
        }
        Err(e) => {
            report
                .details
                .push(format!("TLS fingerprint check failed: {}", e));
        }
    }
}
