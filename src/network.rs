use crate::config::Config;
use crate::fingerprint::{self, BrowserProfile, HeaderSet, JitterConfig};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

// ── Privacy-preserving HTTP client ───────────────────────────────

/// Stream-isolated HTTP client with SOCKS5 proxy and full fingerprint defense.
///
/// Uses unique SOCKS5 credentials per client instance so Tor assigns
/// a separate circuit to each session.
#[allow(dead_code)]
pub struct PrivacyClient {
    pub client: reqwest::Client,
    pub proxy_addr: String,
    pub user_agent: String,
    pub session_id: String,
    /// Unique SOCKS5 credentials for circuit isolation
    pub socks_username: String,
    pub browser_profile: BrowserProfile,
    pub jitter: JitterConfig,
    inner: Arc<Mutex<ClientState>>,
}

struct ClientState {
    current_headers: HeaderSet,
    request_count: u64,
}

impl PrivacyClient {
    /// Create a new stream-isolated client.
    ///
    /// Tor assigns a unique circuit to each SOCKS5 username/password pair.
    pub fn new(config: &Config, proxy_addr: &str) -> anyhow::Result<Self> {
        let profile = BrowserProfile::from_str("random");
        let headers = HeaderSet::generate(&profile);

        let socks_username = format!("nofind-{}", Uuid::new_v4());
        let socks_password = Uuid::new_v4().to_string();
        let session_id = Uuid::new_v4().to_string();

        // Build SOCKS5 proxy URL with credentials for circuit isolation
        let proxy_url = build_socks5_url(proxy_addr, &socks_username, &socks_password);
        let proxy = reqwest::Proxy::all(&proxy_url)?;

        let client = reqwest::Client::builder()
            .proxy(proxy)
            .user_agent(&headers.user_agent)
            .connect_timeout(Duration::from_secs(config.network.connect_timeout_secs))
            .timeout(Duration::from_secs(config.network.request_timeout_secs))
            .default_headers(headers_to_reqwest(&headers.to_hashmap()))
            .build()?;

        let jitter = if config.privacy.user_agent_rotation {
            JitterConfig::default()
        } else {
            JitterConfig::disabled()
        };

        tracing::info!(
            session_id = %session_id,
            profile = ?profile,
            proxy = %proxy_addr,
            stream_isolated = true,
            jitter_enabled = jitter.enabled,
            "Created privacy client with stream isolation"
        );

        Ok(Self {
            client,
            proxy_addr: proxy_addr.to_string(),
            user_agent: headers.user_agent.clone(),
            session_id: session_id.clone(),
            socks_username,
            browser_profile: profile,
            jitter,
            inner: Arc::new(Mutex::new(ClientState {
                current_headers: headers,
                request_count: 0,
            })),
        })
    }

    /// Create a direct client (no proxy) for leak testing.
    pub fn new_direct() -> anyhow::Result<Self> {
        let headers = HeaderSet::generate(&BrowserProfile::Firefox);
        let client = reqwest::Client::builder()
            .user_agent(&headers.user_agent)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(8))
            .no_proxy()
            .build()?;

        Ok(Self {
            client,
            proxy_addr: "direct".to_string(),
            user_agent: headers.user_agent.clone(),
            session_id: Uuid::new_v4().to_string(),
            socks_username: String::new(),
            browser_profile: BrowserProfile::Firefox,
            jitter: JitterConfig::disabled(),
            inner: Arc::new(Mutex::new(ClientState {
                current_headers: headers,
                request_count: 0,
            })),
        })
    }

    /// Create a client with full fingerprint randomization per request.
    pub fn new_fingerprint_randomized(config: &Config, proxy_addr: &str) -> anyhow::Result<Self> {
        let mut client = Self::new(config, proxy_addr)?;
        client.browser_profile = BrowserProfile::Random;
        client.rotate_fingerprint();
        Ok(client)
    }

    /// Perform a GET request with jitter and fingerprint headers.
    pub async fn get(&self, url: &str) -> anyhow::Result<reqwest::Response> {
        self.jitter.apply().await;
        tracing::debug!(url = %url, "GET via proxy");

        let mut req = self.client.get(url);

        // Add randomized headers per request
        {
            let mut state = self.inner.lock();
            state.request_count += 1;

            // Rotate headers every ~5 requests
            if state.request_count % 5 == 0 && self.jitter.enabled {
                *state = ClientState {
                    current_headers: HeaderSet::generate(&self.browser_profile),
                    request_count: state.request_count,
                };
            }

            for (key, value) in state.current_headers.to_hashmap() {
                req = req.header(key, value);
            }

            // Add random viewport fingerprint noise
            let (w, h) = fingerprint::random_viewport();
            req = req
                .header("X-Fingerprint-Viewport-W", format!("{}", w))
                .header("X-Fingerprint-Viewport-H", format!("{}", h));
        }

        let resp = req.send().await?;
        Ok(resp)
    }

    /// Perform a GET request and return the body as text.
    pub async fn get_text(&self, url: &str) -> anyhow::Result<String> {
        let resp = self.get(url).await?;
        let text = resp.text().await?;
        Ok(text)
    }

    /// Rotate the entire fingerprint (User-Agent + all headers).
    pub fn rotate_fingerprint(&self) {
        let new_headers = HeaderSet::generate(&self.browser_profile);
        let mut state = self.inner.lock();
        state.current_headers = new_headers;
        tracing::debug!("Rotated full fingerprint");
    }

    /// Check if the proxy is reachable.
    pub async fn check_proxy_reachable(&self) -> bool {
        match self
            .client
            .head("http://check.torproject.org")
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success(),
            Err(e) => {
                tracing::warn!(error = %e, "Proxy unreachable");
                false
            }
        }
    }
}

// ── Public API functions ─────────────────────────────────────────

/// Fetch public IP (bypasses proxy).
pub async fn fetch_public_ip_direct() -> anyhow::Result<String> {
    let headers = HeaderSet::generate(&BrowserProfile::Firefox);
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(8))
        .no_proxy()
        .build()?;

    let mut req = client.get("https://api.ipify.org");
    for (key, value) in headers.to_hashmap() {
        req = req.header(key, value);
    }

    let resp = req.send().await?;
    let ip = resp.text().await?;
    Ok(ip.trim().to_string())
}

/// Fetch IP geolocation info with random fingerprint.
pub async fn fetch_ip_info(ip: &str) -> anyhow::Result<IpGeoInfo> {
    let headers = HeaderSet::generate(&BrowserProfile::Firefox);
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(8))
        .no_proxy()
        .build()?;

    let url = format!(
        "http://ip-api.com/json/{}?fields=country,countryCode,regionName,city,isp,org,as",
        ip
    );

    let mut req = client.get(&url);
    for (key, value) in headers.to_hashmap() {
        req = req.header(key, value);
    }

    let resp: serde_json::Value = req.send().await?.json().await?;

    Ok(IpGeoInfo {
        country: resp["country"].as_str().unwrap_or("Unknown").to_string(),
        country_code: resp["countryCode"].as_str().unwrap_or("??").to_string(),
        region: resp["regionName"].as_str().unwrap_or("Unknown").to_string(),
        city: resp["city"].as_str().unwrap_or("Unknown").to_string(),
        isp: resp["isp"].as_str().unwrap_or("Unknown").to_string(),
        org: resp["org"].as_str().unwrap_or("Unknown").to_string(),
    })
}

// ── Helpers ──────────────────────────────────────────────────────

fn build_socks5_url(addr: &str, username: &str, password: &str) -> String {
    // Tor uses different circuits for different SOCKS5 credentials
    // Format: socks5://username:password@host:port
    format!("socks5://{}:{}@{}", username, password, addr)
}

fn headers_to_reqwest(map: &HashMap<String, String>) -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    for (key, value) in map {
        if let (Ok(k), Ok(v)) = (
            reqwest::header::HeaderName::from_bytes(key.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            headers.insert(k, v);
        }
    }
    headers
}

#[derive(Debug, Clone)]
pub struct IpGeoInfo {
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub city: String,
    pub isp: String,
    pub org: String,
}
