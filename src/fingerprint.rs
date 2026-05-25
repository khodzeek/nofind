use rand::Rng;
use std::collections::HashMap;
use std::time::Duration;

/// Browser profile for header emulation.
#[derive(Debug, Clone)]
pub enum BrowserProfile {
    Firefox,
    Chrome,
    Safari,
    Random,
}

impl BrowserProfile {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "chrome" => BrowserProfile::Chrome,
            "safari" => BrowserProfile::Safari,
            "random" => BrowserProfile::Random,
            _ => BrowserProfile::Firefox,
        }
    }
}

/// Headers that should be randomized per request or per session.
#[derive(Debug, Clone)]
pub struct HeaderSet {
    pub user_agent: String,
    pub accept: String,
    pub accept_language: String,
    pub accept_encoding: String,
    pub sec_fetch_dest: String,
    pub sec_fetch_mode: String,
    pub sec_fetch_site: String,
    pub sec_ch_ua: Option<String>,
    pub sec_ch_ua_platform: Option<String>,
    pub dnt: String,
    pub upgrade_insecure_requests: String,
}

impl HeaderSet {
    /// Generate headers matching a specific browser profile.
    pub fn generate(profile: &BrowserProfile) -> Self {
        let profile = match profile {
            BrowserProfile::Random => {
                let opts = [BrowserProfile::Firefox, BrowserProfile::Chrome, BrowserProfile::Safari];
                opts[rand::thread_rng().gen_range(0..opts.len())].clone()
            }
            other => other.clone(),
        };

        match profile {
            BrowserProfile::Firefox => Self::firefox_headers(),
            BrowserProfile::Chrome => Self::chrome_headers(),
            BrowserProfile::Safari => Self::safari_headers(),
            BrowserProfile::Random => Self::firefox_headers(),
        }
    }

    fn firefox_headers() -> Self {
        let versions = ["124.0", "125.0", "126.0", "127.0"];
        let ver = versions[rand::thread_rng().gen_range(0..versions.len())];
        let platforms = [
            "Windows NT 10.0; Win64; x64; rv:VER",
            "X11; Linux x86_64; rv:VER",
            "Macintosh; Intel Mac OS X 14.4; rv:VER",
        ];
        let plat = platforms[rand::thread_rng().gen_range(0..platforms.len())]
            .replace("VER", ver);

        let langs = [
            "en-US,en;q=0.9",
            "en-US,en;q=0.8,fr;q=0.5",
            "en-GB,en;q=0.9,de;q=0.7",
            "pt-BR,pt;q=0.9,en;q=0.8,es;q=0.5",
        ];

        Self {
            user_agent: format!("Mozilla/5.0 ({}) Gecko/20100101 Firefox/{}", plat, ver),
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8".into(),
            accept_language: langs[rand::thread_rng().gen_range(0..langs.len())].into(),
            accept_encoding: "gzip, deflate, br".into(),
            sec_fetch_dest: "document".into(),
            sec_fetch_mode: "navigate".into(),
            sec_fetch_site: "none".into(),
            sec_ch_ua: None,
            sec_ch_ua_platform: None,
            dnt: "1".into(),
            upgrade_insecure_requests: "1".into(),
        }
    }

    fn chrome_headers() -> Self {
        let versions = ["124.0.6367.155", "125.0.6422.141", "126.0.6478.126"];
        let ver = versions[rand::thread_rng().gen_range(0..versions.len())];
        let platforms = [
            "Windows NT 10.0; Win64; x64",
            "X11; Linux x86_64",
            "Macintosh; Intel Mac OS X 14_4",
        ];
        let plat = platforms[rand::thread_rng().gen_range(0..platforms.len())];
        let webkit_ver = "537.36";

        let langs = [
            "en-US,en;q=0.9",
            "en-US,en;q=0.8,es;q=0.5",
            "pt-BR,pt;q=0.9,en;q=0.8",
        ];

        Self {
            user_agent: format!(
                "Mozilla/5.0 ({}) AppleWebKit/{} (KHTML, like Gecko) Chrome/{} Safari/{}",
                plat, webkit_ver, ver, webkit_ver
            ),
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".into(),
            accept_language: langs[rand::thread_rng().gen_range(0..langs.len())].into(),
            accept_encoding: "gzip, deflate, br, zstd".into(),
            sec_fetch_dest: "document".into(),
            sec_fetch_mode: "navigate".into(),
            sec_fetch_site: "none".into(),
            sec_ch_ua: Some(format!(
                "\"Chromium\";v=\"{}\", \"Google Chrome\";v=\"{}\", \"Not=A?Brand\";v=\"99\"",
                ver, ver
            )),
            sec_ch_ua_platform: Some(match plat {
                p if p.contains("Windows") => "\"Windows\"".into(),
                p if p.contains("Linux") => "\"Linux\"".into(),
                _ => "\"macOS\"".into(),
            }),
            dnt: "1".into(),
            upgrade_insecure_requests: "1".into(),
        }
    }

    fn safari_headers() -> Self {
        let versions = ["17.4", "17.5", "18.0"];
        let ver = versions[rand::thread_rng().gen_range(0..versions.len())];
        let webkit_ver = match ver {
            "17.4" => "619.2.5.1",
            "17.5" => "619.2.7.1",
            _ => "619.2.11.1",
        };

        let langs = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "ja-JP,ja;q=0.9"];

        Self {
            user_agent: format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/{webkit_ver} (KHTML, like Gecko) Version/{ver} Safari/{webkit_ver}",
                webkit_ver = webkit_ver, ver = ver
            ),
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
            accept_language: langs[rand::thread_rng().gen_range(0..langs.len())].into(),
            accept_encoding: "gzip, deflate, br".into(),
            sec_fetch_dest: "document".into(),
            sec_fetch_mode: "navigate".into(),
            sec_fetch_site: "none".into(),
            sec_ch_ua: None,
            sec_ch_ua_platform: None,
            dnt: "1".into(),
            upgrade_insecure_requests: "1".into(),
        }
    }

    /// Convert to a HashMap for easy insertion into reqwest headers.
    pub fn to_hashmap(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("User-Agent".into(), self.user_agent.clone());
        map.insert("Accept".into(), self.accept.clone());
        map.insert("Accept-Language".into(), self.accept_language.clone());
        map.insert("Accept-Encoding".into(), self.accept_encoding.clone());
        map.insert("Sec-Fetch-Dest".into(), self.sec_fetch_dest.clone());
        map.insert("Sec-Fetch-Mode".into(), self.sec_fetch_mode.clone());
        map.insert("Sec-Fetch-Site".into(), self.sec_fetch_site.clone());
        map.insert("DNT".into(), self.dnt.clone());
        map.insert(
            "Upgrade-Insecure-Requests".into(),
            self.upgrade_insecure_requests.clone(),
        );
        if let Some(ref ch_ua) = self.sec_ch_ua {
            map.insert("Sec-CH-UA".into(), ch_ua.clone());
        }
        if let Some(ref ch_plat) = self.sec_ch_ua_platform {
            map.insert("Sec-CH-UA-Platform".into(), ch_plat.clone());
        }
        map
    }
}

// ── Jitter / Timing obfuscation ──────────────────────────────────

/// Configuration for request timing obfuscation.
#[derive(Debug, Clone)]
pub struct JitterConfig {
    /// Base delay before each request (milliseconds)
    pub base_delay_ms: u64,
    /// Random additional jitter range (±ms)
    pub jitter_range_ms: u64,
    /// Whether jitter is enabled
    pub enabled: bool,
}

impl Default for JitterConfig {
    fn default() -> Self {
        Self {
            base_delay_ms: 50,
            jitter_range_ms: 150,
            enabled: true,
        }
    }
}

impl JitterConfig {
    pub fn new(base_ms: u64, jitter_ms: u64, enabled: bool) -> Self {
        Self {
            base_delay_ms: base_ms,
            jitter_range_ms: jitter_ms,
            enabled,
        }
    }

    pub fn disabled() -> Self {
        Self {
            base_delay_ms: 0,
            jitter_range_ms: 0,
            enabled: false,
        }
    }

    /// Calculate the actual delay for this request.
    pub fn calculate_delay(&self) -> Duration {
        if !self.enabled {
            return Duration::ZERO;
        }
        let mut rng = rand::thread_rng();
        let jitter = if self.jitter_range_ms > 0 {
            rng.gen_range(0..=self.jitter_range_ms) as i64
                - (self.jitter_range_ms / 2) as i64
        } else {
            0
        };
        let total = (self.base_delay_ms as i64 + jitter).max(0);
        Duration::from_millis(total as u64)
    }

    /// Apply the jitter delay (await this before making a request).
    pub async fn apply(&self) {
        if self.enabled {
            tokio::time::sleep(self.calculate_delay()).await;
        }
    }
}

// ── Traffic padding ──────────────────────────────────────────────

/// Padding strategy for HTTP responses.
#[derive(Debug, Clone)]
pub enum PaddingStrategy {
    /// No padding
    None,
    /// Pad responses to multiples of a fixed block size
    BlockSize(usize),
    /// Add random padding within a range
    RandomRange { min_bytes: usize, max_bytes: usize },
}

impl Default for PaddingStrategy {
    fn default() -> Self {
        PaddingStrategy::RandomRange {
            min_bytes: 16,
            max_bytes: 256,
        }
    }
}

impl PaddingStrategy {
    /// Calculate the amount of padding to add.
    pub fn calculate_padding(&self, content_length: usize) -> usize {
        match self {
            PaddingStrategy::None => 0,
            PaddingStrategy::BlockSize(block) => {
                let remainder = content_length % block;
                if remainder == 0 {
                    0
                } else {
                    block - remainder
                }
            }
            PaddingStrategy::RandomRange {
                min_bytes,
                max_bytes,
            } => {
                let mut rng = rand::thread_rng();
                rng.gen_range(*min_bytes..=*max_bytes)
            }
        }
    }

    /// Generate a padding header value.
    pub fn to_header(&self, content_length: usize) -> Option<String> {
        let pad = self.calculate_padding(content_length);
        if pad > 0 {
            Some(format!("{}", pad))
        } else {
            None
        }
    }
}

// ── Viewport / Screen fingerprint noise ─────────────────────────

/// Generate a plausible screen resolution for fingerprint noise.
pub fn random_viewport() -> (u32, u32) {
    let resolutions = [
        (1920, 1080),
        (1366, 768),
        (2560, 1440),
        (3840, 2160),
        (1680, 1050),
        (1440, 900),
        (1536, 864),
        (1280, 720),
        (1920, 1200),
        (1600, 900),
        (2048, 1152),
        (1280, 800),
    ];
    resolutions[rand::thread_rng().gen_range(0..resolutions.len())]
}

/// Generate a plausible timezone offset for fingerprint noise.
pub fn random_timezone_offset() -> i32 {
    let offsets = [
        -480, -420, -360, -300, -240, -180, -120, -60, 0, 60, 120, 180, 240, 300, 330, 360, 420, 480, 540, 570, 600, 660, 720,
    ];
    offsets[rand::thread_rng().gen_range(0..offsets.len())]
}

/// Generate plausible Accept-Language values.
pub fn random_accept_language() -> &'static str {
    let langs = [
        "en-US,en;q=0.9",
        "en-US,en;q=0.8,fr;q=0.5",
        "en-GB,en;q=0.9,de;q=0.7",
        "pt-BR,pt;q=0.9,en;q=0.8,es;q=0.5",
        "de-DE,de;q=0.9,en;q=0.8,fr;q=0.4",
        "fr-FR,fr;q=0.9,en;q=0.7",
        "ja-JP,ja;q=0.9,en;q=0.5",
        "es-ES,es;q=0.9,en;q=0.7,pt;q=0.4",
        "ru-RU,ru;q=0.9,en;q=0.5",
        "zh-CN,zh;q=0.9,en;q=0.4",
    ];
    langs[rand::thread_rng().gen_range(0..langs.len())]
}
