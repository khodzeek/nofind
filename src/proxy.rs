use crate::config::Config;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

/// Local HTTP forward proxy that routes browser traffic through Tor SOCKS5.
///
/// The browser connects to this proxy, and the proxy forwards all requests
/// through the Tor SOCKS5 tunnel. Each browser connection gets unique SOCKS5
/// credentials for stream isolation, so different tabs/sessions get different
/// Tor circuits.
pub struct LocalProxy {
    pub listen_addr: String,
    pub tor_proxy: String,
    config: Config,
    active: Arc<std::sync::atomic::AtomicBool>,
}

impl LocalProxy {
    pub fn new(config: &Config, tor_proxy: &str, port: u16) -> Self {
        Self {
            listen_addr: format!("127.0.0.1:{}", port),
            tor_proxy: tor_proxy.to_string(),
            config: config.clone(),
            active: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    /// Start the proxy server. This runs until cancelled.
    pub async fn serve(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        tracing::info!(addr = %self.listen_addr, "Local proxy listening");
        println!("  ┌─────────────────────────────────────────┐");
        println!("  │  Proxy HTTP local iniciado              │");
        println!("  │  Escutando em: {:<24} │", self.listen_addr);
        println!("  │                                         │");
        println!("  │  Configure seu navegador:                │");
        println!("  │  HTTP Proxy: {}                   │", self.listen_addr);
        println!("  │  HTTPS Proxy: {}                  │", self.listen_addr);
        println!("  │                                         │");
        println!("  │  Firefox: Preferences → Network Settings │");
        println!("  │  Chrome:  Settings → System → Proxy      │");
        println!("  └─────────────────────────────────────────┘");
        println!();

        let active = self.active.clone();
        let config = self.config.clone();
        let tor_proxy = self.tor_proxy.clone();

        loop {
            if !active.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            let (stream, addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!(error = %e, "Proxy accept error");
                    continue;
                }
            };

            let cfg = config.clone();
            let tp = tor_proxy.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, &cfg, &tp).await {
                    tracing::debug!(client = %addr, error = %e, "Proxy connection closed");
                }
            });
        }

        Ok(())
    }

    /// Stop the proxy server.
    pub fn stop(&self) {
        self.active.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Handle a single browser connection.
async fn handle_connection(
    mut client: TcpStream,
    _config: &Config,
    tor_proxy: &str,
) -> anyhow::Result<()> {
    // Read the first line to determine if it's HTTP or CONNECT
    let mut buf = vec![0u8; 8192];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request_head = String::from_utf8_lossy(&buf[..n]);
    let first_line = request_head.lines().next().unwrap_or("");

    if first_line.starts_with("CONNECT ") {
        // HTTPS tunnel
        handle_connect_tunnel(client, first_line, _config, tor_proxy).await
    } else {
        // Plain HTTP — forward through our Tor client
        handle_http_request(client, &buf[..n], _config, tor_proxy).await
    }
}

/// Handle HTTPS CONNECT tunnel — relay bytes through Tor SOCKS5.
async fn handle_connect_tunnel(
    mut client: TcpStream,
    connect_line: &str,
    _config: &Config,
    tor_proxy: &str,
) -> anyhow::Result<()> {
    // Parse: CONNECT example.com:443 HTTP/1.1
    let parts: Vec<&str> = connect_line.split_whitespace().collect();
    if parts.len() < 2 {
        anyhow::bail!("Invalid CONNECT request");
    }
    let target = parts[1]; // example.com:443

    tracing::debug!(target = %target, "CONNECT tunnel");

    // Create a direct TCP connection to the Tor SOCKS5 proxy
    let tor_parts: Vec<&str> = tor_proxy.split(':').collect();
    let tor_host = tor_parts[0];
    let tor_port: u16 = tor_parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(9050);

    let socks_addr = format!("{}:{}", tor_host, tor_port);
    let mut tor_conn = TcpStream::connect(&socks_addr).await?;

    // SOCKS5 handshake with authentication (stream isolation)
    let socks_user = format!("nofind-{}", Uuid::new_v4());
    let socks_pass = Uuid::new_v4().to_string();

    // SOCKS5: method negotiation
    tor_conn.write_all(&[0x05, 0x02, 0x00, 0x02]).await?; // 2 methods: none, user/pass
    let mut resp = [0u8; 2];
    tor_conn.read_exact(&mut resp).await?;

    if resp[1] == 0x02 {
        // User/password auth
        let mut auth_msg = Vec::new();
        auth_msg.push(0x01); // version
        auth_msg.push(socks_user.len() as u8);
        auth_msg.extend_from_slice(socks_user.as_bytes());
        auth_msg.push(socks_pass.len() as u8);
        auth_msg.extend_from_slice(socks_pass.as_bytes());
        tor_conn.write_all(&auth_msg).await?;
        let mut auth_resp = [0u8; 2];
        tor_conn.read_exact(&mut auth_resp).await?;
        if auth_resp[1] != 0x00 {
            anyhow::bail!("SOCKS5 authentication failed");
        }
    }

    // SOCKS5: CONNECT command
    let (host, port_str) = target.split_once(':').unwrap_or((target, "443"));
    let port: u16 = port_str.parse().unwrap_or(443);

    let mut cmd = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    cmd.extend_from_slice(host.as_bytes());
    cmd.extend_from_slice(&port.to_be_bytes());
    tor_conn.write_all(&cmd).await?;

    let mut cmd_resp = [0u8; 10];
    tor_conn.read_exact(&mut cmd_resp).await?;
    if cmd_resp[1] != 0x00 {
        anyhow::bail!("SOCKS5 CONNECT failed for {}", target);
    }

    // Tell the browser we're connected
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    // Bidirectional relay — use into_split for owned halves
    let (mut client_r, mut client_w) = client.into_split();
    let (mut tor_r, mut tor_w) = tor_conn.into_split();

    let c2t = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = client_r.read(&mut buf).await?;
            if n == 0 { break; }
            tor_w.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    });

    let t2c = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = tor_r.read(&mut buf).await?;
            if n == 0 { break; }
            client_w.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    });

    let _ = tokio::try_join!(c2t, t2c);
    Ok(())
}

/// Handle a plain HTTP request — forward through our reqwest Tor client.
async fn handle_http_request(
    mut client: TcpStream,
    request_data: &[u8],
    _config: &Config,
    tor_proxy: &str,
) -> anyhow::Result<()> {
    // Parse the HTTP request to extract method and URL
    let head = String::from_utf8_lossy(request_data);
    let first_line = head.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        anyhow::bail!("Invalid HTTP request");
    }

    let method = parts[0];
    let url = parts[1];

    tracing::debug!(method = method, url = %url, "HTTP proxy");

    // Build a full URL if it's a relative path
    let full_url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        // Extract Host header
        let host = head
            .lines()
            .find(|l| l.to_lowercase().starts_with("host:"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, h)| h.trim())
            .unwrap_or("localhost");
        format!("http://{}{}", host, url)
    };

    // Extract headers from the original request
    let mut headers = reqwest::header::HeaderMap::new();
    for line in head.lines().skip(1) {
        if line.is_empty() || line == "\r" { break; }
        if let Some((key, value)) = line.split_once(':') {
            if let (Ok(k), Ok(v)) = (
                reqwest::header::HeaderName::from_bytes(key.trim().as_bytes()),
                reqwest::header::HeaderValue::from_str(value.trim()),
            ) {
                // Skip hop-by-hop headers
                let lower = key.to_lowercase();
                if lower != "proxy-connection" && lower != "proxy-authorization" {
                    headers.insert(k, v);
                }
            }
        }
    }

    // Create a fresh Tor-routed client with stream isolation
    let socks_user = format!("nofind-{}", Uuid::new_v4());
    let socks_pass = Uuid::new_v4().to_string();
    let proxy_url = format!("socks5://{}:{}@{}", socks_user, socks_pass, tor_proxy);
    let proxy = reqwest::Proxy::all(&proxy_url)?;

    let req_client = reqwest::Client::builder()
        .proxy(proxy)
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(60))
        .no_gzip()
        .build()?;

    // Make the proxied request
    let req_builder = match method {
        "GET" => req_client.get(&full_url),
        "POST" => {
            let body = request_data[head.find("\r\n\r\n").unwrap_or(head.len())..].to_vec();
            req_client.post(&full_url).body(body)
        }
        "HEAD" => req_client.head(&full_url),
        "PUT" => {
            let body = request_data[head.find("\r\n\r\n").unwrap_or(head.len())..].to_vec();
            req_client.put(&full_url).body(body)
        }
        _ => req_client.get(&full_url),
    };

    let req = req_builder.headers(headers).build()?;
    let resp = req_client.execute(req).await?;

    // Send response back to browser
    let status = resp.status();
    // Capture headers before consuming body
    let resp_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = resp.bytes().await?;

    let response_line = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status.canonical_reason().unwrap_or("OK"));
    client.write_all(response_line.as_bytes()).await?;

    // Forward response headers
    for (key, value) in &resp_headers {
        let lower = key.to_lowercase();
        if lower != "transfer-encoding" && lower != "content-encoding" {
            let line = format!("{}: {}\r\n", key, value);
            client.write_all(line.as_bytes()).await?;
        }
    }

    client.write_all(format!("Content-Length: {}\r\n", body.len()).as_bytes()).await?;
    client.write_all(b"\r\n").await?;
    client.write_all(&body).await?;
    client.flush().await?;

    Ok(())
}

/// Quick check if a string looks like an HTTP request.
fn _is_http_request(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    let methods: &[&[u8]] = &[b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"CONN", b"OPTI", b"PATC"];
    methods.iter().any(|m| data.starts_with(*m))
}
