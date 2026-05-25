# nofind

**Privacy-first anonymous browsing tool with Tor integration and DNS over HTTPS.**

A defensive digital privacy tool to protect browsing metadata, reduce tracking, and increase legitimate user anonymity on public networks or insecure environments.

> **Disclaimer:** Esta ferramenta destina-se exclusivamente à proteção de privacidade, segurança pessoal e navegação segura em ambientes autorizados.

---

## Features

### Transparent System-Wide Proxy
- **Zero browser configuration** — `sudo nofind transparent-start`
- iptables NAT rules redirect ALL machine TCP traffic through Tor
- DNS leak prevention via Tor DNSPort redirection
- Local network exclusion support
- Automatic iptables backup and restore on exit
- Kill switch mode: block all non-Tor traffic

### Local HTTP Proxy
- Built-in forward proxy on 127.0.0.1:8080
- Browser traffic routed through Tor with stream isolation
- CONNECT tunnel support for HTTPS
- Unique SOCKS5 credentials per connection (different circuits per tab)

### Anonymous Browsing
- SOCKS5 proxy with Tor integration
- Tor circuit rotation via control port (SIGNAL NEWNYM)
- Automatic IP rotation every N seconds (default: 60s)
- Stream isolation — unique Tor circuits per session
- DNS over HTTPS (DoH) — Cloudflare, Google, Quad9
- DNS leak prevention and detection
- Random User-Agent rotation per session
- Cookie isolation

### Fingerprint Defense
- 3 browser profiles: Firefox, Chrome, Safari (randomizable)
- Full HTTP header emulation: Accept, Accept-Language, Sec-CH-UA, etc.
- Header rotation every ~5 requests
- Timing obfuscation: configurable jitter with random delays
- Traffic padding: random-size padding to defeat packet analysis
- TLS fingerprint masking via reqwest rustls

### Network Privacy
- Public IP exposure check with geolocation
- DNS leak detection (cross-provider consistency)
- WebRTC leak awareness
- HTTP and TLS fingerprint assessment
- Anonymity level indicator (None → Maximum)

### MAC Address Management
- List all physical network interfaces with MAC detection
- Generate cryptographically-random locally-administered MACs
- Change MAC via `ip link` (Linux, requires root)
- Original MAC backup and restore instructions

### Local Security
- Encrypted config vault — AES-256-GCM with SHA-256 key derivation
- RAM-only ephemeral mode (/dev/shm, no disk traces)
- Automatic cache and history cleanup on exit
- Secure file deletion with overwrite before removal
- Secure memory wiping (zeroize on drop)

### Terminal Interface
- Interactive TUI dashboard (ratatui + crossterm)
- Real-time: connection status, IP, location, Tor, DNS, stats
- Privacy indicator panel (8 indicators)
- Scrollable log viewer
- Session statistics (requests, bandwidth, rotations)

### Configuration & Automation
- TOML-based configuration with privacy profiles
- Shell completions for bash, zsh, fish
- Encrypted config vault (optional password-protected storage)
- JSON + text privacy reports
- Tor bridge support (obfs4)

---

## Installation

### Prerequisites

- **Rust** stable (1.75+)
- **Tor** daemon (for Tor features)
- **iptables** (for transparent proxy)

#### Install Tor

**Ubuntu/Debian:**
```bash
sudo apt install tor iptables
sudo systemctl enable --now tor
```

**Arch Linux:**
```bash
sudo pacman -S tor iptables
sudo systemctl enable --now tor
```

#### Enable Tor Control Port (circuit rotation)

Add to `/etc/tor/torrc`:
```
ControlPort 9051
CookieAuthentication 1
```

Then:
```bash
sudo systemctl restart tor
```

#### Enable TransPort (transparent proxy)

```bash
sudo nofind transparent-setup
sudo systemctl restart tor
```

### Build from source

```bash
git clone https://github.com/khodzeek/nofind.git
cd nofind
cargo build --release
```

Binary: `target/release/nofind`

Or install globally:
```bash
cargo install --path .
```

If it's your first Rust binary, add `~/.cargo/bin` to your PATH:
```bash
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

For fish shell:
```fish
fish_add_path ~/.cargo/bin
```

---

## Usage

### Quick start — anonymous browser (no config needed)

```bash
nofind connect --proxy-port 8080
```

Configure browser to `127.0.0.1:8080` (HTTP + HTTPS proxy). Every 60s your IP changes.

### Full system anonymity (no browser config)

```bash
sudo nofind transparent-setup        # One-time Tor config
sudo systemctl restart tor
sudo nofind transparent-start        # All traffic → Tor
```

**Nothing to configure in any application.** Everything goes through Tor.

```bash
sudo nofind transparent-start --kill-switch        # Block all non-Tor traffic
sudo nofind transparent-start --local-network 192.168.1.0/24  # Exclude LAN
sudo nofind transparent-stop                       # Restore normal networking
nofind transparent-status                          # Check status
```

### Check privacy status

```bash
nofind status
```

Output:
```
╔══════════════════════════════════════════╗
║        nofind — Privacy Status          ║
╠══════════════════════════════════════════╣
║  Proxy:        127.0.0.1:9050 ● connected
║  Public IP:    185.220.101.42
║  Location:     Frankfurt, DE
║  ISP:          Tor Exit Node
║  Tor:          ✓ Active
║  Circuit:      ● Established
║  DNS Secure:   ✓ DoH enabled
║  Anonymity:    HIGH
╠══════════════════════════════════════════╣
║  UA Rotation:  ✓
║  Session Iso:  ✓
║  Stream Iso:   ✓
║  Jitter:       ✓
║  Fingerprint:  basic
║  Browser:      random
║  Kill Switch:  ✗
║  Bridges:      0 configured
║  Profile:      standard
╚══════════════════════════════════════════╝
```

### Rotate Tor identity (new IP)

```bash
nofind rotate-identity
```

### Run leak checks

```bash
nofind check-leaks
```

### Change MAC address

```bash
nofind change-mac --list                  # List interfaces
sudo nofind change-mac --interface eth0   # Random MAC
sudo nofind change-mac --mac 02:42:ac:11:00:ff  # Specific MAC
```

### Manage config

```bash
nofind config init      # Create ~/.config/nofind/config.toml
nofind config show       # Display current config
```

### Encrypted config vault

```bash
nofind vault-init --password "my-secret"   # Create encrypted vault
nofind connect --vault-password "my-secret" # Connect using vault config
nofind vault-destroy                       # Destroy vault
```

### Session cleanup

```bash
nofind clean-session
```

### Privacy report

```bash
nofind report   # Text + JSON report
```

### Shell completions

```bash
source <(nofind completions bash)   # bash
source <(nofind completions zsh)    # zsh
nofind completions fish | source    # fish
```

---

## Dashboard Controls

| Key | Action |
|-----|--------|
| `q` / `Esc` | Quit dashboard |
| `r` | Rotate Tor identity (manual) |
| `s` | Refresh status |
| `c` | Clean session data |

Help bar shows `Auto-Rot ON` when automatic identity rotation is active.

---

## All Commands

| Command | Description |
|---------|-------------|
| `nofind connect` | Dashboard + local proxy + auto-rotation |
| `nofind status` | Privacy status overview |
| `nofind rotate-identity` | New Tor circuit (new IP) |
| `nofind check-leaks` | DNS, IP, WebRTC, fingerprint leak tests |
| `nofind clean-session` | Wipe cache, history, temp files |
| `nofind config init` | Create config file |
| `nofind config show` | Display config |
| `nofind change-mac` | MAC address management |
| `nofind vault-init` | Encrypted config vault |
| `nofind vault-destroy` | Destroy vault |
| `nofind report` | Privacy report (text + JSON) |
| `nofind completions <shell>` | Shell completions |
| `sudo nofind transparent-start` | System-wide transparent proxy |
| `sudo nofind transparent-stop` | Disable transparent proxy |
| `nofind transparent-status` | Check transparent proxy status |
| `sudo nofind transparent-setup` | Install Tor TransPort config |

---

## Configuration

Config file: `~/.config/nofind/config.toml`

### Privacy Profiles

| Profile | Description |
|---------|-------------|
| `standard` | Tor + DoH + stream isolation + jitter |
| `paranoid` | All above + kill switch + 120s rotation + full fingerprint defense |

```toml
profile = "paranoid"
```

### Key Settings

```toml
[network]
socks5_proxy = "127.0.0.1:9050"
tor_control_port = 9051

[dns]
doh_provider = "cloudflare"          # cloudflare | google | quad9

[privacy]
rotate_identity_interval_secs = 60   # Auto-rotate IP every 60s
stream_isolation = true              # Unique Tor circuits per session
fingerprint_level = "full"           # off | basic | full
browser_profile = "random"           # firefox | chrome | safari | random
jitter_enabled = true
jitter_base_delay_ms = 30
jitter_range_ms = 120
padding_strategy = "random"          # none | block | random
kill_switch = false
tor_bridges = []                     # obfs4 bridge lines

[security]
clean_cache_on_exit = true
clean_history_on_exit = true
ephemeral_sessions = true
```

---

## Architecture

```
nofind/
├── Cargo.toml
├── README.md
├── config/default.toml
├── examples/basic_usage.rs
├── src/
│   ├── main.rs           # Entry point
│   ├── lib.rs            # Library root
│   ├── cli.rs            # 16 CLI commands (clap)
│   ├── config.rs         # TOML config with profiles
│   ├── network.rs        # SOCKS5 HTTP client + fingerprint headers
│   ├── tor.rs            # Tor control protocol + circuit rotation
│   ├── dns.rs            # DNS over HTTPS + leak detection
│   ├── privacy.rs        # Privacy status + anonymity assessment
│   ├── proxy.rs          # Local HTTP forward proxy
│   ├── transparent.rs    # System-wide iptables transparent proxy
│   ├── leaks.rs          # DNS, IP, WebRTC, fingerprint leak tests
│   ├── fingerprint.rs    # Browser fingerprint emulation + jitter
│   ├── mac.rs            # MAC address changer
│   ├── vault.rs          # Encrypted config vault
│   ├── security.rs       # Session cleanup + secure deletion
│   ├── stats.rs          # Traffic statistics + report export
│   ├── ui.rs             # Ratatui TUI dashboard
│   └── utils.rs          # User agents, logging, helpers
```

### Technology Stack

- **Rust** 1.95+ — Systems programming
- **Tokio** — Async runtime
- **Reqwest** 0.13 — HTTP client with SOCKS5 + rustls
- **Clap** 4 — CLI argument parsing with shell completions
- **Serde + TOML** 1 — Configuration
- **Ratatui** 0.30 + **Crossterm** 0.29 — Terminal UI
- **Sha2 + Zeroize** — Encryption and secure memory
- **Parking Lot** — Fast synchronization primitives
- **iptables** — Kernel-level transparent proxy

---

## Security Model

nofind is designed exclusively for **defensive privacy**:

- **Protect metadata** from network observers
- **Reduce tracking** surface through isolation and rotation
- **Increase anonymity** on public/untrusted networks
- **Defend against fingerprinting** via header emulation and jitter

The tool is NOT designed for and must NOT be used for:
- Illegal bypass of security controls
- Fraud, spam, or botnets
- DDoS or network attacks
- Malware distribution
- Criminal evasion or offensive exploitation

---

## Platform Support

| Platform | Status |
|----------|--------|
| Linux (x86_64) | Full support — all features |
| Linux (aarch64) | Supported |
| Windows | Partial — Tor via external daemon, no iptables/MAC |
| macOS | Untested |

---

## Building on Linux

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install system dependencies
sudo apt install build-essential pkg-config libssl-dev tor iptables

# Build
cargo build --release

# Run
./target/release/nofind connect --proxy-port 8080
```

---

## License

MIT

---

**nofind** — Sua privacidade, suas regras.
