use crate::config::Config;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Instant;

/// Providers for DNS over HTTPS.
#[derive(Debug, Clone)]
pub enum DohProvider {
    Cloudflare,
    Google,
    Quad9,
}

impl DohProvider {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "google" => DohProvider::Google,
            "quad9" => DohProvider::Quad9,
            _ => DohProvider::Cloudflare,
        }
    }

    pub fn endpoint(&self) -> &str {
        match self {
            DohProvider::Cloudflare => "https://cloudflare-dns.com/dns-query",
            DohProvider::Google => "https://dns.google/resolve",
            DohProvider::Quad9 => "https://dns.quad9.net:5053/dns-query",
        }
    }

    pub fn name(&self) -> &str {
        match self {
            DohProvider::Cloudflare => "Cloudflare",
            DohProvider::Google => "Google",
            DohProvider::Quad9 => "Quad9",
        }
    }
}

#[derive(Debug, Deserialize)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

#[derive(Debug, Deserialize)]
struct DohAnswer {
    #[allow(dead_code)]
    name: String,
    #[serde(rename = "type")]
    record_type: u32,
    #[serde(rename = "TTL")]
    #[allow(dead_code)]
    ttl: u32,
    data: String,
}

/// DNS-over-HTTPS client.
pub struct DohClient {
    provider: DohProvider,
    http_client: reqwest::Client,
    cache: parking_lot::Mutex<HashMap<String, (Instant, Vec<String>)>>,
    cache_enabled: bool,
    cache_ttl: std::time::Duration,
}

impl DohClient {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let provider = DohProvider::from_str(&config.dns.doh_provider);
        let http_client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(15))
            .build()?;

        Ok(Self {
            provider,
            http_client,
            cache: parking_lot::Mutex::new(HashMap::new()),
            cache_enabled: config.dns.dns_cache_enabled,
            cache_ttl: std::time::Duration::from_secs(300), // 5 min default TTL
        })
    }

    /// Resolve a domain to IP addresses via DoH.
    pub async fn resolve(&self, domain: &str) -> anyhow::Result<Vec<String>> {
        // Check cache first
        if self.cache_enabled {
            let cache = self.cache.lock();
            if let Some((timestamp, ips)) = cache.get(domain) {
                if timestamp.elapsed() < self.cache_ttl {
                    tracing::debug!(domain = %domain, cached = true, "DNS cache hit");
                    return Ok(ips.clone());
                }
            }
        }

        let url = format!("{}?name={}&type=A", self.provider.endpoint(), domain);
        tracing::debug!(url = %url, provider = %self.provider.name(), "DoH query");

        let resp = self
            .http_client
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "DoH query failed: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }

        let doh: DohResponse = resp.json().await?;

        if doh.status != 0 {
            anyhow::bail!("DNS resolution failed with status: {}", doh.status);
        }

        let ips: Vec<String> = doh
            .answer
            .iter()
            .filter(|a| a.record_type == 1) // A records only
            .map(|a| a.data.clone())
            .collect();

        if self.cache_enabled && !ips.is_empty() {
            let mut cache = self.cache.lock();
            cache.insert(domain.to_string(), (Instant::now(), ips.clone()));
        }

        Ok(ips)
    }

    /// Resolve a domain bypassing the proxy (for leak testing).
    pub async fn resolve_direct(&self, domain: &str) -> anyhow::Result<Vec<String>> {
        let url = format!("{}?name={}&type=A", self.provider.endpoint(), domain);
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(15))
            .no_proxy() // Ensure no proxy
            .build()?;

        let resp = client
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await?;

        let doh: DohResponse = resp.json().await?;
        let ips: Vec<String> = doh
            .answer
            .iter()
            .filter(|a| a.record_type == 1)
            .map(|a| a.data.clone())
            .collect();

        Ok(ips)
    }

    /// Check for DNS leaks by resolving the same domain through multiple providers
    /// and checking for inconsistencies that might indicate a leak.
    pub async fn leak_test(&self, domain: &str) -> anyhow::Result<DnsLeakResult> {
        // Resolve through our configured DoH provider
        let doh_ips = self.resolve(domain).await?;

        // Resolve through an alternative provider directly
        let alt_url = format!(
            "https://dns.google/resolve?name={}&type=A",
            domain
        );
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(15))
            .no_proxy()
            .build()?;

        let alt_resp = client
            .get(&alt_url)
            .header("Accept", "application/dns-json")
            .send()
            .await?;

        let alt_doh: DohResponse = alt_resp.json().await?;
        let alt_ips: Vec<String> = alt_doh
            .answer
            .iter()
            .filter(|a| a.record_type == 1)
            .map(|a| a.data.clone())
            .collect();

        let leak_detected = !doh_ips.is_empty()
            && !alt_ips.is_empty()
            && doh_ips != alt_ips;

        Ok(DnsLeakResult {
            domain: domain.to_string(),
            doh_ips,
            alternative_ips: alt_ips,
            leak_detected,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DnsLeakResult {
    pub domain: String,
    pub doh_ips: Vec<String>,
    pub alternative_ips: Vec<String>,
    pub leak_detected: bool,
}
