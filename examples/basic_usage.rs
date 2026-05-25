/// Example: Basic nofind usage as a library
///
/// Run with:
///   cargo run --example basic_usage
///
/// Note: Requires Tor to be running on localhost:9050

use nofind::config::Config;
use nofind::network::PrivacyClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    println!("=== nofind Basic Usage Example ===\n");

    // Load configuration
    let config = Config::load_or_default(None)?;
    println!("Profile: {}", config.profile);
    println!("Proxy: {}", config.network.socks5_proxy);

    // Create privacy client with SOCKS5 proxy
    let client = PrivacyClient::new(&config, &config.network.socks5_proxy)?;
    println!("Session ID: {}", client.session_id);
    println!("User-Agent: {}", client.user_agent);

    // Check if proxy is reachable
    println!("\nChecking proxy connectivity...");
    if client.check_proxy_reachable().await {
        println!("✓ Proxy is reachable");
    } else {
        println!("✗ Proxy is unreachable — is Tor running?");
    }

    // Check Tor status
    println!("\nChecking Tor status...");
    let tor_status = nofind::tor::check_tor_available(&config).await;
    println!(
        "Tor available: {}",
        if tor_status.available { "Yes" } else { "No" }
    );
    println!(
        "Circuit established: {}",
        if tor_status.circuit_established {
            "Yes"
        } else {
            "No"
        }
    );

    // Check current public IP
    println!("\nFetching public IP...");
    match nofind::network::fetch_public_ip_direct().await {
        Ok(ip) => {
            println!("Public IP: {}", ip);
            match nofind::network::fetch_ip_info(&ip).await {
                Ok(info) => {
                    println!(
                        "Location: {}, {}, {}",
                        info.city, info.region, info.country
                    );
                    println!("ISP: {}", info.isp);
                }
                Err(_) => println!("Could not fetch geo info"),
            }
        }
        Err(e) => println!("Failed to fetch IP: {}", e),
    }

    // DNS over HTTPS example
    println!("\nTesting DNS over HTTPS...");
    let dns_client = nofind::dns::DohClient::new(&config)?;
    match dns_client.resolve("example.com").await {
        Ok(ips) => {
            println!("example.com resolves to: {:?}", ips);
        }
        Err(e) => println!("DNS resolution failed: {}", e),
    }

    // Privacy status
    println!("\nRunning privacy status check...");
    let status = nofind::privacy::check_status(&config).await?;
    if let Some(ref ip) = status.current_ip {
        println!("Current IP: {}", ip);
    }
    println!("Anonymity level: {}", status.anonymity_level.label());
    println!("Tor active: {}", status.tor_status.available);
    println!("DNS secure: {}", status.dns_secure);

    println!("\n=== Example complete ===");
    Ok(())
}
