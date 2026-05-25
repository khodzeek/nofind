use clap::{CommandFactory, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "nofind",
    version = env!("CARGO_PKG_VERSION"),
    about = "Privacy-first anonymous browsing tool",
    long_about = "A defensive digital privacy tool to protect browsing metadata, \
                  reduce tracking, and increase legitimate user anonymity on \
                  public networks or insecure environments."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Connect through proxy and launch interactive dashboard
    Connect {
        /// SOCKS5 proxy address (default: 127.0.0.1:9050 for Tor)
        #[arg(short, long, default_value = "127.0.0.1:9050")]
        proxy: String,
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<String>,
        /// Auto-rotate Tor identity every N seconds (overrides config)
        #[arg(long, default_value_t = 60)]
        rotate_interval: u64,
        /// Start local HTTP proxy for browser (default port: 8080)
        #[arg(long, default_value_t = 8080)]
        proxy_port: u16,
        /// Run in RAM-only mode (no traces on disk, Linux tmpfs)
        #[arg(long)]
        ram_only: bool,
        /// Password to unlock encrypted vault config
        #[arg(long)]
        vault_password: Option<String>,
    },
    /// Show current privacy and connection status
    Status,
    /// Rotate Tor identity (request new circuit)
    RotateIdentity,
    /// Run comprehensive privacy leak checks
    CheckLeaks,
    /// Clean all local session data (cache, history, temp files)
    CleanSession,
    /// Manage nofind configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Change MAC address of a network interface
    #[command(name = "change-mac")]
    ChangeMac {
        /// Network interface name (e.g., eth0, wlan0)
        #[arg(short, long)]
        interface: Option<String>,
        /// Specific MAC address (random if not specified)
        #[arg(long)]
        mac: Option<String>,
        /// List available interfaces instead of changing
        #[arg(short, long)]
        list: bool,
    },
    /// Initialize encrypted configuration vault
    #[command(name = "vault-init")]
    VaultInit {
        /// Vault password
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Destroy encrypted configuration vault
    #[command(name = "vault-destroy")]
    VaultDestroy,
    /// Export privacy report (text + JSON)
    Report,
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Start transparent system-wide proxy (REQUIRES ROOT)
    #[command(name = "transparent-start")]
    TransparentStart {
        /// Enable kill switch (block all non-Tor traffic)
        #[arg(long)]
        kill_switch: bool,
        /// Local network to exclude (e.g., 192.168.1.0/24)
        #[arg(long)]
        local_network: Option<String>,
    },
    /// Stop transparent system-wide proxy (REQUIRES ROOT)
    #[command(name = "transparent-stop")]
    TransparentStop,
    /// Check transparent proxy status
    #[command(name = "transparent-status")]
    TransparentStatus,
    /// Install Tor TransPort + DNSPort config to /etc/tor/torrc
    #[command(name = "transparent-setup")]
    TransparentSetup,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Initialize default configuration file
    Init,
    /// Display current configuration
    Show,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        match self.command {
            Commands::Connect {
                proxy,
                config,
                rotate_interval,
                proxy_port,
                ram_only,
                vault_password,
            } => {
                let mut cfg = if let Some(ref pw) = vault_password {
                    crate::vault::cmd_vault_load(pw).await?
                } else {
                    crate::config::Config::load_or_default(config.as_deref())?
                };

                cfg.privacy.rotate_identity_interval_secs = rotate_interval;

                if ram_only {
                    let ram = crate::vault::RamMode::detect();
                    if ram.enabled {
                        let ram_path = ram.init()?;
                        tracing::info!(path = %ram_path.display(), "RAM-only mode active");
                        std::env::set_var("TMPDIR", ram_path.to_string_lossy().as_ref());
                    } else {
                        tracing::warn!("RAM-only mode requested but /dev/shm not available");
                    }
                }

                tracing::info!(
                    "Connecting via proxy: {} (rotate every {}s, local proxy: {})",
                    proxy,
                    rotate_interval,
                    proxy_port
                );

                // Start local HTTP proxy in background for browser
                let local_proxy = crate::proxy::LocalProxy::new(&cfg, &proxy, proxy_port);
                let proxy_handle = tokio::spawn(async move {
                    if let Err(e) = local_proxy.serve().await {
                        tracing::error!(error = %e, "Local proxy error");
                    }
                });

                // Run dashboard
                crate::ui::run_dashboard(&cfg, &proxy).await?;

                // Cleanup
                proxy_handle.abort();
            }
            Commands::Status => {
                crate::privacy::print_status().await?;
            }
            Commands::RotateIdentity => {
                let cfg = crate::config::Config::load_or_default(None)?;
                crate::tor::rotate_identity_command(&cfg).await?;
            }
            Commands::CheckLeaks => {
                crate::leaks::run_checks().await?;
            }
            Commands::CleanSession => {
                crate::security::clean_session().await?;
            }
            Commands::Config { action } => match action {
                ConfigAction::Init => {
                    crate::config::Config::init_default()?;
                }
                ConfigAction::Show => {
                    crate::config::Config::show_current()?;
                }
            },
            Commands::ChangeMac {
                interface,
                mac,
                list,
            } => {
                if list {
                    crate::mac::print_interfaces().await?;
                } else {
                    crate::mac::change_mac_command(interface.as_deref(), mac.as_deref()).await?;
                }
            }
            Commands::VaultInit { password } => {
                let pw = password.unwrap_or_else(|| {
                    print!("Enter vault password: ");
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).ok();
                    input.trim().to_string()
                });
                if pw.is_empty() {
                    anyhow::bail!("Password cannot be empty");
                }
                crate::vault::cmd_vault_init(&pw).await?;
            }
            Commands::VaultDestroy => {
                crate::vault::cmd_vault_destroy().await?;
            }
            Commands::Report => {
                crate::stats::cmd_report().await?;
            }
            Commands::TransparentStart {
                kill_switch,
                local_network,
            } => {
                let config = crate::transparent::TransparentConfig {
                    kill_switch,
                    local_network,
                    ..Default::default()
                };
                crate::transparent::start_transparent(&config)?;
            }
            Commands::TransparentStop => {
                let config = crate::transparent::TransparentConfig::default();
                crate::transparent::stop_transparent(&config)?;
            }
            Commands::TransparentStatus => {
                crate::transparent::check_status()?;
            }
            Commands::TransparentSetup => {
                crate::transparent::install_tor_config()?;
            }
            Commands::Completions { shell } => {
                let mut cmd = Cli::command();
                let name = cmd.get_name().to_string();
                match shell {
                    Shell::Bash => {
                        clap_complete::generate(
                            clap_complete::shells::Bash,
                            &mut cmd,
                            &name,
                            &mut std::io::stdout(),
                        );
                    }
                    Shell::Zsh => {
                        clap_complete::generate(
                            clap_complete::shells::Zsh,
                            &mut cmd,
                            &name,
                            &mut std::io::stdout(),
                        );
                    }
                    Shell::Fish => {
                        clap_complete::generate(
                            clap_complete::shells::Fish,
                            &mut cmd,
                            &name,
                            &mut std::io::stdout(),
                        );
                    }
                }
            }
        }
        Ok(())
    }
}
