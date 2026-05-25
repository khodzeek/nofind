use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub privacy: PrivacyConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default = "default_profile")]
    pub profile: String,
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_socks5")]
    pub socks5_proxy: String,
    #[serde(default = "default_control_port")]
    pub tor_control_port: u16,
    #[serde(default)]
    pub tor_control_password: String,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_doh_provider")]
    pub doh_provider: String,
    #[serde(default = "default_true")]
    pub dns_leak_protection: bool,
    #[serde(default = "default_true")]
    pub dns_cache_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    #[serde(default)]
    pub rotate_identity_interval_secs: u64,
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default = "default_true")]
    pub session_isolation: bool,
    #[serde(default = "default_true")]
    pub cookie_isolation: bool,
    #[serde(default = "default_true")]
    pub user_agent_rotation: bool,
    /// Stream isolation via unique SOCKS5 credentials per session
    #[serde(default = "default_true")]
    pub stream_isolation: bool,
    /// Fingerprint randomization level: off, basic, full
    #[serde(default = "default_fp_level")]
    pub fingerprint_level: String,
    /// Browser profile to emulate: firefox, chrome, safari, random
    #[serde(default = "default_browser_profile")]
    pub browser_profile: String,
    /// Jitter timing obfuscation (ms)
    #[serde(default = "default_true")]
    pub jitter_enabled: bool,
    #[serde(default = "default_jitter_base_ms")]
    pub jitter_base_delay_ms: u64,
    #[serde(default = "default_jitter_range_ms")]
    pub jitter_range_ms: u64,
    /// Traffic padding strategy: none, block, random
    #[serde(default = "default_padding_strategy")]
    pub padding_strategy: String,
    /// Tor bridges for censored networks
    #[serde(default)]
    pub tor_bridges: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Obfs4Bridge {
    pub address: String,
    pub fingerprint: String,
    pub cert: String,
    pub iat_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_true")]
    pub clean_cache_on_exit: bool,
    #[serde(default = "default_true")]
    pub clean_history_on_exit: bool,
    #[serde(default = "default_true")]
    pub ephemeral_sessions: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    #[serde(default = "default_true")]
    pub user_agent_rotation: bool,
    #[serde(default = "default_true")]
    pub dns_over_https: bool,
    #[serde(default = "default_true")]
    pub tor_enabled: bool,
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default)]
    pub rotate_identity_interval_secs: u64,
    #[serde(default = "default_true")]
    pub stream_isolation: bool,
    #[serde(default = "default_true")]
    pub jitter_enabled: bool,
    #[serde(default = "default_fp_level")]
    pub fingerprint_level: String,
    #[serde(default = "default_browser_profile")]
    pub browser_profile: String,
}

fn default_profile() -> String {
    "standard".to_string()
}
fn default_socks5() -> String {
    "127.0.0.1:9050".to_string()
}
fn default_control_port() -> u16 {
    9051
}
fn default_connect_timeout() -> u64 {
    15
}
fn default_request_timeout() -> u64 {
    30
}
fn default_doh_provider() -> String {
    "cloudflare".to_string()
}
fn default_true() -> bool {
    true
}
fn default_fp_level() -> String {
    "basic".into()
}
fn default_browser_profile() -> String {
    "random".into()
}
fn default_jitter_base_ms() -> u64 {
    30
}
fn default_jitter_range_ms() -> u64 {
    120
}
fn default_padding_strategy() -> String {
    "random".into()
}

impl Default for Config {
    fn default() -> Self {
        let mut profiles = HashMap::new();
        profiles.insert(
            "standard".to_string(),
            ProfileConfig {
                user_agent_rotation: true,
                dns_over_https: true,
                tor_enabled: true,
                kill_switch: false,
                rotate_identity_interval_secs: 0,
                stream_isolation: true,
                jitter_enabled: true,
                fingerprint_level: "basic".into(),
                browser_profile: "firefox".into(),
            },
        );
        profiles.insert(
            "paranoid".to_string(),
            ProfileConfig {
                user_agent_rotation: true,
                dns_over_https: true,
                tor_enabled: true,
                kill_switch: true,
                rotate_identity_interval_secs: 120,
                stream_isolation: true,
                jitter_enabled: true,
                fingerprint_level: "full".into(),
                browser_profile: "random".into(),
            },
        );

        Self {
            network: NetworkConfig::default(),
            dns: DnsConfig::default(),
            privacy: PrivacyConfig::default(),
            security: SecurityConfig::default(),
            profile: "standard".to_string(),
            profiles,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            socks5_proxy: default_socks5(),
            tor_control_port: default_control_port(),
            tor_control_password: String::new(),
            connect_timeout_secs: default_connect_timeout(),
            request_timeout_secs: default_request_timeout(),
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            doh_provider: default_doh_provider(),
            dns_leak_protection: true,
            dns_cache_enabled: true,
        }
    }
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            rotate_identity_interval_secs: 0,
            kill_switch: false,
            session_isolation: true,
            cookie_isolation: true,
            user_agent_rotation: true,
            stream_isolation: true,
            fingerprint_level: default_fp_level(),
            browser_profile: default_browser_profile(),
            jitter_enabled: true,
            jitter_base_delay_ms: default_jitter_base_ms(),
            jitter_range_ms: default_jitter_range_ms(),
            padding_strategy: default_padding_strategy(),
            tor_bridges: Vec::new(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            clean_cache_on_exit: true,
            clean_history_on_exit: true,
            ephemeral_sessions: true,
        }
    }
}

impl Config {
    fn config_path(config_arg: Option<&str>) -> PathBuf {
        if let Some(path) = config_arg {
            PathBuf::from(path)
        } else {
            let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
            path.push("nofind");
            path.push("config.toml");
            path
        }
    }

    pub fn load_or_default(config_arg: Option<&str>) -> anyhow::Result<Self> {
        let path = Self::config_path(config_arg);
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let config: Config = toml::from_str(&content)?;
            tracing::info!("Loaded config from {}", path.display());
            Ok(config)
        } else {
            tracing::info!("No config file found, using defaults");
            Ok(Config::default())
        }
    }

    pub fn init_default() -> anyhow::Result<()> {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("nofind");
        std::fs::create_dir_all(&path)?;
        path.push("config.toml");

        if path.exists() {
            anyhow::bail!(
                "Config file already exists at {}. Use 'config show' to view it.",
                path.display()
            );
        }

        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config)?;
        std::fs::write(&path, toml_str)?;
        println!("Default configuration written to {}", path.display());
        tracing::info!("Initialized config at {}", path.display());
        Ok(())
    }

    pub fn show_current() -> anyhow::Result<()> {
        let path = Self::config_path(None);
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            println!("Configuration ({})", path.display());
            println!("{}", content);
        } else {
            let config = Config::default();
            let toml_str = toml::to_string_pretty(&config)?;
            println!("Using default configuration (no config file found):");
            println!("{}", toml_str);
        }
        Ok(())
    }

    pub fn active_profile(&self) -> &ProfileConfig {
        self.profiles
            .get(&self.profile)
            .unwrap_or_else(|| {
                tracing::warn!("Profile '{}' not found, using defaults", self.profile);
                self.profiles.get("standard").unwrap()
            })
    }
}
