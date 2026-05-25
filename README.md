# nofind

**Privacy-first anonymous browsing tool with Tor integration and DNS over HTTPS.**

A defensive digital privacy tool to protect browsing metadata, reduce tracking, and increase legitimate user anonymity on public networks or insecure environments.

> **Disclaimer:** Esta ferramenta destina-se exclusivamente à proteção de privacidade, segurança pessoal e navegação segura em ambientes autorizados.

---

## Features

### Anonymous Browsing
- SOCKS5 proxy support with optional Tor integration
- Secure Tor circuit rotation via control port (NEWNYM)
- **Automatic IP rotation** — change exit node every N seconds (default: 60s)
- Session isolation with unique identifiers
- DNS over HTTPS (DoH) — Cloudflare, Google, Quad9
- DNS leak prevention
- Random User-Agent rotation per session
- Cookie isolation

### Network Privacy
- Public IP exposure check
- DNS leak detection
- WebRTC leak awareness
- Basic browser fingerprint assessment
- Anonymity level indicator (None → Maximum)

### MAC Address Management
- List all physical network interfaces
- Generate cryptographically-random MAC addresses
- Change MAC address via `ip link` (Linux, requires root)
- Original MAC backup and restore instructions
- Locally-administered unicast MACs (no vendor conflicts)

### Local Security
- Automatic cache cleanup on exit
- Local history cleaning
- Ephemeral sessions (temp directories)
- Secure file deletion (overwrite before removal)

### Terminal Interface
- Interactive TUI dashboard (ratatui + crossterm)
- Real-time connection status
- Current IP and geolocation
- Tor circuit status with auto-rotation indicator
- DNS security indicators
- Privacy indicator panel
- Scrollable log viewer

### Advanced Features
- Automatic Tor identity rotation (configurable interval, default 60s)
- TOML-based configuration
- Privacy profiles (standard, paranoid)
- Soft kill switch (advisory mode)
- Rate limiting and auto-retry
- Async/await throughout (tokio)

---

## Installation

### Prerequisites

- **Rust** stable (1.75+)
- **Tor** daemon running (for Tor features)

#### Install Tor

**Ubuntu/Debian:**
```bash
sudo apt install tor
sudo systemctl enable --now tor
```

**Arch Linux:**
```bash
sudo pacman -S tor
sudo systemctl enable --now tor
```

**Enable Tor Control Port** (required for circuit rotation):

Edit `/etc/tor/torrc`:
```
ControlPort 9051
CookieAuthentication 1
```

Then restart Tor:
```bash
sudo systemctl restart tor
```

### Build from source

```bash
git clone https://github.com/khodzeek/nofind.git
cd nofind
cargo build --release
```

The binary will be at `target/release/nofind`.

---

## Usage

### Initialize configuration

```bash
nofind config init
```

This creates `~/.config/nofind/config.toml` with defaults.

### Launch the interactive dashboard

```bash
nofind connect
```

With auto-rotation every 60 seconds (default):
```bash
nofind connect --rotate-interval 60
```

With custom proxy:
```bash
nofind connect --proxy 127.0.0.1:9150
```

With custom config:
```bash
nofind connect --config /path/to/config.toml
```

### Check privacy status

```bash
nofind status
```

### Rotate Tor identity manually

```bash
nofind rotate-identity
```

Output:
```
Requesting Tor circuit rotation...
Tor circuit rotated successfully. New exit node assigned.
New exit node IP: 185.220.101.XX
Exit location: Frankfurt, Hesse (Germany)
```

### Change MAC address

List available interfaces:
```bash
nofind change-mac --list
```

Change MAC on a specific interface (random MAC):
```bash
sudo nofind change-mac --interface eth0
```

Change to a specific MAC:
```bash
sudo nofind change-mac --interface wlan0 --mac 02:42:ac:11:00:ff
```

Auto-select first active interface:
```bash
sudo nofind change-mac
```

### Run leak checks

```bash
nofind check-leaks
```

### Clean session data

```bash
nofind clean-session
```

### View configuration

```bash
nofind config show
```

---

## Dashboard Controls

| Key | Action |
|-----|--------|
| `q` / `Esc` | Quit dashboard |
| `r` | Rotate Tor identity (manual) |
| `s` | Refresh status |
| `c` | Clean session data |

The dashboard also shows `Auto-Rot ON` in the help bar when automatic identity rotation is active.

---

## Auto-Rotation

By default, `nofind connect` rotates your Tor identity every **60 seconds**:

```bash
nofind connect --rotate-interval 60
```

Set any interval (in seconds):
```bash
nofind connect --rotate-interval 300   # Every 5 minutes
nofind connect --rotate-interval 30    # Every 30 seconds (aggressive)
```

Disable auto-rotation:
```bash
nofind connect --rotate-interval 0
```

Or configure permanently in `~/.config/nofind/config.toml`:
```toml
[privacy]
rotate_identity_interval_secs = 60
```

The dashboard will:
1. Automatically request a new Tor circuit at the interval
2. Wait for the new circuit to establish
3. Fetch and display the new exit node IP and location
4. Log each rotation in the dashboard

---

## Configuration

The config file is at `~/.config/nofind/config.toml` (or `$XDG_CONFIG_HOME/nofind/config.toml`).

### Privacy Profiles

**Standard** — Balanced privacy with Tor and DoH:
```toml
profile = "standard"
```

**Paranoid** — Maximum privacy with kill switch and 120s auto-rotation:
```toml
profile = "paranoid"
```

### Key Settings

```toml
[network]
socks5_proxy = "127.0.0.1:9050"    # Your SOCKS5 proxy (Tor default)
tor_control_port = 9051              # Tor control port
tor_control_password = ""            # Control port password (cookie auth if empty)

[dns]
doh_provider = "cloudflare"          # cloudflare | google | quad9

[privacy]
rotate_identity_interval_secs = 60   # Auto-rotate Tor circuit every 60s
kill_switch = false                  # Enable network kill switch
```

---

## Architecture

```
nofind/
├── Cargo.toml
├── README.md
├── config/
│   └── default.toml
├── src/
│   ├── main.rs          # Entry point
│   ├── lib.rs           # Library root
│   ├── cli.rs           # CLI commands (clap) — 7 commands
│   ├── config.rs        # Configuration (serde + TOML)
│   ├── network.rs       # HTTP client with SOCKS5 proxy
│   ├── tor.rs           # Tor SOCKS5 & control protocol
│   ├── dns.rs           # DNS over HTTPS (DoH)
│   ├── privacy.rs       # Privacy status & anonymity assessment
│   ├── leaks.rs         # Leak detection (DNS, IP, WebRTC, fingerprint)
│   ├── mac.rs           # MAC address management (list, change, random)
│   ├── security.rs      # Session cleanup & secure deletion
│   ├── ui.rs            # Ratatui TUI dashboard with auto-rotation
│   └── utils.rs         # User agents, logging, helpers
├── logs/
└── examples/
```

### Technology Stack

- **Rust** — Systems programming language
- **Tokio** — Async runtime
- **Reqwest** — HTTP client with SOCKS5 support
- **Clap** — CLI argument parsing
- **Serde** — Serialization/deserialization
- **TOML** — Configuration format
- **Tracing** — Structured logging
- **Ratatui** — Terminal UI framework
- **Crossterm** — Terminal manipulation
- **Parking Lot** — Fast synchronization primitives

---

## Security Model

nofind is designed exclusively for **defensive privacy**:

- **Protect metadata** from network observers
- **Reduce tracking** surface through isolation and rotation
- **Increase anonymity** on public/untrusted networks
- **Defend against fingerprinting** via UA rotation and header control

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
| Linux (x86_64) | Full support (Tor + MAC changer) |
| Linux (aarch64) | Supported |
| Windows | Partial (Tor via external daemon, no MAC changer) |
| macOS | Untested |

---

## Building on Linux

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install dependencies
sudo apt install build-essential pkg-config libssl-dev tor

# Build
cargo build --release

# Run
./target/release/nofind connect
```

---

## License

MIT

---

**nofind** — Your privacy, your rules.
