use crate::config::Config;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Status of the Tor connection.
#[derive(Debug, Clone)]
pub struct TorStatus {
    pub available: bool,
    pub socks_port: u16,
    pub control_port: u16,
    pub circuit_established: bool,
    pub exit_node_ip: Option<String>,
    pub exit_node_country: Option<String>,
}

impl TorStatus {
    pub fn unavailable() -> Self {
        Self {
            available: false,
            socks_port: 0,
            control_port: 0,
            circuit_established: false,
            exit_node_ip: None,
            exit_node_country: None,
        }
    }
}

/// Check if Tor is running on the expected SOCKS5 port.
pub async fn check_tor_available(config: &Config) -> TorStatus {
    let addr = format!("127.0.0.1:{}", config.network.tor_control_port);
    let socks_port = config
        .network
        .socks5_proxy
        .split(':')
        .last()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9050);

    let connect_timeout = std::time::Duration::from_secs(3);
    match tokio::time::timeout(connect_timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);

            // Read banner (with timeout)
            let mut banner = String::new();
            let banner_ok = tokio::time::timeout(
                connect_timeout,
                buf_reader.read_line(&mut banner),
            )
            .await
            .map_or(false, |r| r.is_ok());

            if !banner_ok {
                return check_socks_port(socks_port, config).await;
            }
            // banner read ok

            // Try cookie auth or password
            let authed = if config.network.tor_control_password.is_empty() {
                writer.write_all(b"AUTHENTICATE\r\n").await.is_ok()
                    && tokio::time::timeout(
                        connect_timeout,
                        read_response(&mut buf_reader),
                    )
                    .await
                    .map_or(false, |r| r.map_or(false, |resp| resp.starts_with("250")))
            } else {
                let cmd = format!("AUTHENTICATE \"{}\"\r\n", config.network.tor_control_password);
                writer.write_all(cmd.as_bytes()).await.is_ok()
                    && tokio::time::timeout(
                        connect_timeout,
                        read_response(&mut buf_reader),
                    )
                    .await
                    .map_or(false, |r| r.map_or(false, |resp| resp.starts_with("250")))
            };

            if !authed {
                tracing::warn!("Tor control port reachable but authentication failed");
                return check_socks_port(socks_port, config).await;
            }

            // Check circuit status
            writer.write_all(b"GETINFO status/circuit-established\r\n").await.ok();
            let circuit_line = tokio::time::timeout(
                connect_timeout,
                read_response(&mut buf_reader),
            )
            .await
            .map_or(Ok(String::new()), |r| r)
            .unwrap_or_default();
            let circuit_established = circuit_line.contains("circuit-established=1");

            writer.write_all(b"QUIT\r\n").await.ok();

            TorStatus {
                available: true,
                socks_port,
                control_port: config.network.tor_control_port,
                circuit_established,
                exit_node_ip: None,
                exit_node_country: None,
            }
        }
        _ => {
            // Control port not reachable, check SOCKS
            let socks_ok = tokio::time::timeout(
                connect_timeout,
                TcpStream::connect(format!("127.0.0.1:{}", socks_port)),
            )
            .await
            .map_or(false, |r| r.is_ok());
            TorStatus {
                available: socks_ok,
                socks_port,
                control_port: 0,
                circuit_established: socks_ok,
                exit_node_ip: None,
                exit_node_country: None,
            }
        }
    }
}

/// Rotate the Tor circuit by sending NEWNYM signal to the control port.
pub async fn rotate_circuit(config: &Config) -> anyhow::Result<()> {
    let addr = format!("127.0.0.1:{}", config.network.tor_control_port);
    let connect_timeout = std::time::Duration::from_secs(3);
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow::anyhow!(
            "Connection to Tor control port timed out ({}). Is Tor running?\n\
             Enable the control port:\n  echo 'ControlPort 9051' | sudo tee -a /etc/tor/torrc\n  echo 'CookieAuthentication 1' | sudo tee -a /etc/tor/torrc\n  sudo systemctl restart tor",
            addr
        ))?
        .map_err(|e| {
            if e.to_string().contains("Connection refused") {
                anyhow::anyhow!(
                    "Tor control port refused connection ({}).\n\
                     Enable it in /etc/tor/torrc:\n  ControlPort 9051\n  CookieAuthentication 1\n\
                     Then: sudo systemctl restart tor",
                    addr
                )
            } else {
                anyhow::anyhow!("Tor control port error ({}): {}", addr, e)
            }
        })?;
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    // Read banner
    let mut banner = String::new();
    buf_reader.read_line(&mut banner).await?;
    tracing::debug!(banner = %banner.trim(), "Tor control port connected");

    // Authenticate
    if config.network.tor_control_password.is_empty() {
        writer.write_all(b"AUTHENTICATE\r\n").await?;
    } else {
        let cmd = format!(
            "AUTHENTICATE \"{}\"\r\n",
            config.network.tor_control_password
        );
        writer.write_all(cmd.as_bytes()).await?;
    }
    let auth_resp = read_response(&mut buf_reader).await?;
    if !auth_resp.starts_with("250") {
        anyhow::bail!("Tor authentication failed: {}", auth_resp.trim());
    }
    tracing::debug!("Tor control: authenticated");

    // Send NEWNYM
    writer.write_all(b"SIGNAL NEWNYM\r\n").await?;
    let signal_resp = read_response(&mut buf_reader).await?;
    if !signal_resp.starts_with("250") {
        anyhow::bail!("Tor NEWNYM signal failed: {}", signal_resp.trim());
    }

    writer.write_all(b"QUIT\r\n").await.ok();

    tracing::info!("Tor circuit rotated successfully (NEWNYM)");
    println!("Tor circuit rotated successfully. New exit node assigned.");
    Ok(())
}

/// Command handler for 'cargo run -- rotate-identity'
pub async fn rotate_identity_command(config: &Config) -> anyhow::Result<()> {
    println!("Requesting Tor circuit rotation...");
    rotate_circuit(config).await?;

    // Wait a moment for the new circuit to establish
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Fetch new exit node info
    match crate::network::fetch_public_ip_direct().await {
        Ok(ip) => {
            println!("New exit node IP: {}", ip);
            match crate::network::fetch_ip_info(&ip).await {
                Ok(info) => {
                    println!(
                        "Exit location: {}, {} ({})",
                        info.city, info.region, info.country
                    );
                }
                Err(_) => {
                    println!("Could not fetch geo info for new exit node");
                }
            }
        }
        Err(_) => {
            println!("Could not determine new exit node IP (may not be fully established yet)");
        }
    }

    Ok(())
}

async fn check_socks_port(socks_port: u16, config: &Config) -> TorStatus {
    let connect_timeout = std::time::Duration::from_secs(2);
    let socks_ok = tokio::time::timeout(
        connect_timeout,
        TcpStream::connect(format!("127.0.0.1:{}", socks_port)),
    )
    .await
    .map_or(false, |r| r.is_ok());
    TorStatus {
        available: socks_ok,
        socks_port,
        control_port: config.network.tor_control_port,
        circuit_established: socks_ok,
        exit_node_ip: None,
        exit_node_country: None,
    }
}

async fn read_response<R: tokio::io::AsyncRead + Unpin>(reader: &mut BufReader<R>) -> anyhow::Result<String> {
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(line)
}
