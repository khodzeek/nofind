use rand::Rng;
use std::process::Command;

/// Represents a detected network interface.
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub current_mac: Option<String>,
    pub state: InterfaceState,
    pub is_loopback: bool,
    pub is_wireless: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceState {
    Up,
    Down,
    Unknown,
}

impl std::fmt::Display for InterfaceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceState::Up => write!(f, "UP"),
            InterfaceState::Down => write!(f, "DOWN"),
            InterfaceState::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Generate a cryptographically-random locally-administered unicast MAC address.
///
/// Bit 0 of first byte = 0 (unicast)
/// Bit 1 of first byte = 1 (locally administered — not assigned to any vendor)
/// Remaining 5 bytes are random.
pub fn generate_random_mac() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 6];
    rng.fill(&mut bytes);
    // Unicast (bit 0 = 0) + Locally administered (bit 1 = 1)
    bytes[0] = (bytes[0] & 0xFC) | 0x02;
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// List all non-loopback physical network interfaces with their MAC addresses.
pub fn list_interfaces() -> anyhow::Result<Vec<NetworkInterface>> {
    let output = Command::new("ip")
        .args(["link", "show"])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run 'ip link show': {}. Is iproute2 installed?", e))?;

    if !output.status.success() {
        anyhow::bail!(
            "'ip link show' failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let text = String::from_utf8_lossy(&output.stdout);
    parse_ip_link_output(&text)
}

fn parse_ip_link_output(text: &str) -> anyhow::Result<Vec<NetworkInterface>> {
    let mut interfaces = Vec::new();
    let mut current_name = String::new();
    let mut current_mac: Option<String> = None;
    let mut current_state = InterfaceState::Unknown;
    let mut is_loopback = false;

    for line in text.lines() {
        // New interface starts with a number + colon
        if let Some((_num, rest)) = line.trim().split_once(':') {
            // Save previous interface if any
            if !current_name.is_empty() && !is_loopback {
                let is_wl = current_name.starts_with("wl")
                    || current_name.starts_with("wlan");
                interfaces.push(NetworkInterface {
                    name: current_name.clone(),
                    current_mac: current_mac.clone(),
                    state: current_state.clone(),
                    is_loopback,
                    is_wireless: is_wl,
                });
            }
            // Reset for new interface
            let name = rest.trim();
            // Strip @<parent> suffix if present (e.g., eth0@if5)
            current_name = name.split('@').next().unwrap_or(name).to_string();
            current_mac = None;
            current_state = InterfaceState::Unknown;
            is_loopback = current_name == "lo";
        }

        let trimmed = line.trim();

        if trimmed.contains("link/ether") {
            // Format: link/ether xx:xx:xx:xx:xx:xx brd ...
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                current_mac = Some(parts[1].to_string());
            }
        }

        if trimmed.contains("LOOPBACK") {
            is_loopback = true;
        }

        if trimmed.contains("state UP") || trimmed.contains(",UP,") {
            current_state = InterfaceState::Up;
        } else if trimmed.contains("state DOWN") || trimmed.contains(",DOWN,") {
            current_state = InterfaceState::Down;
        }
    }

    // Don't forget last interface
    if !current_name.is_empty() && !is_loopback {
        let is_wl = current_name.starts_with("wl") || current_name.starts_with("wlan");
        interfaces.push(NetworkInterface {
            name: current_name,
            current_mac,
            state: current_state,
            is_loopback,
            is_wireless: is_wl,
        });
    }

    Ok(interfaces)
}

/// Change the MAC address of a network interface.
/// Requires root privileges (uses sudo for `ip link` commands).
pub async fn change_mac(interface: &str, new_mac: &str) -> anyhow::Result<MacChangeResult> {
    // Validate MAC format
    if !is_valid_mac(new_mac) {
        anyhow::bail!("Invalid MAC address format: {}. Expected XX:XX:XX:XX:XX:XX", new_mac);
    }

    // Check if we have permission
    let is_root = std::env::var("USER")
        .map(|u| u == "root")
        .unwrap_or(false)
        || std::env::var("UID")
            .map(|u| u == "0")
            .unwrap_or(false);

    let sudo = if is_root {
        vec![]
    } else {
        vec!["sudo".to_string()]
    };

    // Step 1: Bring interface down
    tracing::info!(interface = %interface, "Bringing interface down");
    let mut down_cmd = build_command(&sudo, "ip", &["link", "set", "dev", interface, "down"]);
    let down_output = down_cmd.output()?;
    if !down_output.status.success() {
        let err = String::from_utf8_lossy(&down_output.stderr);
        if err.contains("Permission denied") {
            anyhow::bail!(
                "Permission denied. Root privileges are required to change MAC addresses.\n\
                 Run with: sudo nofind change-mac"
            );
        }
        anyhow::bail!("Failed to bring interface down: {}", err);
    }

    // Step 2: Change MAC
    tracing::info!(interface = %interface, new_mac = %new_mac, "Changing MAC address");
    let mut set_cmd = build_command(
        &sudo,
        "ip",
        &["link", "set", "dev", interface, "address", new_mac],
    );
    let set_output = set_cmd.output()?;
    if !set_output.status.success() {
        let err = String::from_utf8_lossy(&set_output.stderr);
        // Try to bring interface back up before failing
        let _ = build_command(&sudo, "ip", &["link", "set", "dev", interface, "up"]).output();
        anyhow::bail!("Failed to set MAC address: {}", err);
    }

    // Step 3: Bring interface up
    tracing::info!(interface = %interface, "Bringing interface up");
    let mut up_cmd = build_command(&sudo, "ip", &["link", "set", "dev", interface, "up"]);
    let up_output = up_cmd.output()?;
    if !up_output.status.success() {
        let err = String::from_utf8_lossy(&up_output.stderr);
        anyhow::bail!("Failed to bring interface up: {}", err);
    }

    Ok(MacChangeResult {
        interface: interface.to_string(),
        new_mac: new_mac.to_string(),
        success: true,
    })
}

#[derive(Debug, Clone)]
pub struct MacChangeResult {
    pub interface: String,
    pub new_mac: String,
    pub success: bool,
}

/// Validate MAC address format (XX:XX:XX:XX:XX:XX).
fn is_valid_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok())
}

/// Build a Command with optional sudo prefix.
fn build_command(sudo: &[String], program: &str, args: &[&str]) -> Command {
    let mut cmd = if sudo.is_empty() {
        Command::new(program)
    } else {
        let mut c = Command::new(&sudo[0]);
        c.arg(program);
        c
    };

    for arg in args {
        cmd.arg(arg);
    }

    cmd
}

/// Command handler: print all available interfaces and their MACs.
pub async fn print_interfaces() -> anyhow::Result<()> {
    let interfaces = list_interfaces()?;

    if interfaces.is_empty() {
        println!("No physical network interfaces found.");
        return Ok(());
    }

    println!();
    println!("  Available network interfaces:");
    println!("  ─────────────────────────────");
    println!();

    for iface in &interfaces {
        let mac = iface
            .current_mac
            .as_deref()
            .unwrap_or("unknown");
        let wl_icon = if iface.is_wireless { "📶" } else { "🔌" };

        println!(
            "  {}  {:<12} MAC: {:<18} State: {}",
            wl_icon, iface.name, mac, iface.state
        );
    }

    println!();
    println!("  To change MAC: nofind change-mac <interface>");
    println!();

    Ok(())
}

/// Command handler: change MAC for specified or interactive interface.
pub async fn change_mac_command(
    interface: Option<&str>,
    new_mac: Option<&str>,
) -> anyhow::Result<()> {
    let interfaces = list_interfaces()?;

    // Filter out loopback
    let valid: Vec<&NetworkInterface> = interfaces
        .iter()
        .filter(|i| !i.is_loopback)
        .collect();

    if valid.is_empty() {
        anyhow::bail!("No network interfaces available to change.");
    }

    let target = match interface {
        Some(name) => {
            let found = valid.iter().find(|i| i.name == name);
            match found {
                Some(_) => name.to_string(),
                None => anyhow::bail!(
                    "Interface '{}' not found. Available: {}",
                    name,
                    valid
                        .iter()
                        .map(|i| i.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        }
        None => {
            // Pick the first non-loopback interface that's UP
            let up_iface = valid.iter().find(|i| i.state == InterfaceState::Up);
            match up_iface {
                Some(iface) => {
                    println!(
                        "Auto-selected interface: {} (current MAC: {})",
                        iface.name,
                        iface.current_mac.as_deref().unwrap_or("unknown")
                    );
                    iface.name.clone()
                }
                None => anyhow::bail!(
                    "No active interface found. Specify one: {}",
                    valid
                        .iter()
                        .map(|i| i.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        }
    };

    let original_mac = valid
        .iter()
        .find(|i| i.name == target)
        .and_then(|i| i.current_mac.clone());

    let mac = match new_mac {
        Some(m) => m.to_string(),
        None => generate_random_mac(),
    };

    println!();
    println!("  ╔══════════════════════════════════════════╗");
    println!("  ║  MAC Address Changer                      ║");
    println!("  ╠══════════════════════════════════════════╣");
    println!("  ║  Interface:  {:<30}║", target);
    if let Some(ref orig) = original_mac {
        println!("  ║  Original:   {:<30}║", orig);
    }
    println!("  ║  New MAC:    {:<30}║", mac);
    println!("  ╚══════════════════════════════════════════╝");
    println!();

    // Confirm
    println!("  ⚠  This will temporarily disconnect the network interface.");
    println!("  ⚠  Requires root/sudo privileges.");
    print!("  Continue? [y/N]: ");

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    if input != "y" && input != "yes" {
        println!("  Cancelled.");
        return Ok(());
    }

    println!();
    println!("  Changing MAC address...");

    match change_mac(&target, &mac).await {
        Ok(result) => {
            if result.success {
                println!();
                println!("  ✓ MAC address changed successfully!");
                println!("    Interface: {}", result.interface);
                println!("    New MAC:   {}", result.new_mac);
                println!();
                println!(
                    "    Original MAC was: {}",
                    original_mac.as_deref().unwrap_or("unknown")
                );
                println!("    To restore: nofind change-mac {} --mac {}", target,
                    original_mac.as_deref().unwrap_or("xx:xx:xx:xx:xx:xx"));
                println!();
            }
        }
        Err(e) => {
            println!();
            println!("  ✗ Failed to change MAC: {}", e);
            println!();
            println!("  Troubleshooting:");
            println!("    - Are you running as root? (sudo nofind change-mac)");
            println!("    - Is the interface name correct?");
            println!("    - Does your network driver support MAC spoofing?");
            println!();
            return Err(e);
        }
    }

    Ok(())
}
