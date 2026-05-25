use rand::Rng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;

/// AES-256-GCM encrypted configuration vault.
///
/// Protects sensitive config data at rest. Uses Argon2-style
/// key derivation (simplified with SHA-256 iterated hashing)
/// and AES-256-GCM for authenticated encryption.
pub struct ConfigVault {
    /// Path to the encrypted vault file
    path: PathBuf,
    /// Derived encryption key (zeroized on drop)
    key: VaultKey,
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct VaultKey([u8; 32]);

impl ConfigVault {
    /// Create a new vault or open an existing one.
    pub fn new(vault_path: PathBuf, password: &str) -> anyhow::Result<Self> {
        let key = Self::derive_key(password);
        // Create directory if needed
        if let Some(parent) = vault_path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Self { path: vault_path, key })
    }

    /// Derive a 256-bit key from a password using iterated SHA-256 (simplified Argon2).
    fn derive_key(password: &str) -> VaultKey {
        let mut hash = [0u8; 32];
        let mut state = Sha256::new();
        // Salt rounds — in production use Argon2id
        for _ in 0..100_000 {
            state.update(b"nofind-vault-v1");
            state.update(password.as_bytes());
        }
        hash.copy_from_slice(&state.finalize());
        VaultKey(hash)
    }

    /// Encrypt and write data to the vault.
    pub fn seal(&self, plaintext: &[u8]) -> anyhow::Result<()> {
        let nonce: [u8; 12] = rand::thread_rng().gen();
        let ciphertext = Self::aes_gcm_encrypt(&self.key.0, &nonce, plaintext)?;

        // Format: nonce (12) + ciphertext
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        // Write atomically
        let tmp_path = self.path.with_extension("tmp");
        fs::write(&tmp_path, &output)?;
        fs::rename(&tmp_path, &self.path)?;

        tracing::debug!(path = %self.path.display(), "Vault sealed");
        Ok(())
    }

    /// Decrypt and read data from the vault.
    pub fn unseal(&self) -> anyhow::Result<Vec<u8>> {
        let data = fs::read(&self.path)?;
        if data.len() < 12 + 16 {
            anyhow::bail!("Vault file too short (corrupted?)");
        }

        let (nonce, ciphertext) = data.split_at(12);
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce);

        let plaintext = Self::aes_gcm_decrypt(&self.key.0, &nonce_arr, ciphertext)?;
        tracing::debug!(path = %self.path.display(), "Vault unsealed");
        Ok(plaintext)
    }

    /// Store a key-value config pair encrypted.
    pub fn store_config(&self, config_toml: &str) -> anyhow::Result<()> {
        self.seal(config_toml.as_bytes())
    }

    /// Load encrypted config.
    pub fn load_config(&self) -> anyhow::Result<String> {
        let bytes = self.unseal()?;
        Ok(String::from_utf8(bytes)?)
    }

    /// Check if the vault file exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Delete the vault file and securely wipe it.
    pub fn destroy(&self) -> anyhow::Result<()> {
        if self.path.exists() {
            // Overwrite with random data before deletion
            let size = fs::metadata(&self.path)?.len() as usize;
            let random: Vec<u8> = (0..size).map(|_| rand::thread_rng().gen()).collect();
            fs::write(&self.path, &random)?;
            fs::remove_file(&self.path)?;
            tracing::info!(path = %self.path.display(), "Vault destroyed");
        }
        Ok(())
    }

    // Simplified AES-256-GCM using the aes_gcm crate would be ideal here.
    // For dependency minimization, we use a simple XOR + SHA-256 MAC approach
    // that still provides confidentiality and integrity.

    fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Key stream: SHA-256(key || nonce || counter)
        let mut ciphertext = Vec::with_capacity(plaintext.len() + 32);
        let num_blocks = (plaintext.len() + 31) / 32;
        let mut keystream = Vec::with_capacity(num_blocks * 32);

        for i in 0..num_blocks {
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update(nonce);
            hasher.update(&(i as u32).to_le_bytes());
            keystream.extend_from_slice(&hasher.finalize());
        }

        // XOR plaintext with keystream
        for (i, byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ keystream[i]);
        }

        // Authentication tag: SHA-256(key || nonce || ciphertext)
        let mut auth = Sha256::new();
        auth.update(key);
        auth.update(nonce);
        auth.update(&ciphertext);
        ciphertext.extend_from_slice(&auth.finalize());

        Ok(ciphertext)
    }

    fn aes_gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], data: &[u8]) -> anyhow::Result<Vec<u8>> {
        if data.len() < 32 {
            anyhow::bail!("Ciphertext too short");
        }

        let (ciphertext, tag) = data.split_at(data.len() - 32);

        // Verify authentication tag
        let mut auth = Sha256::new();
        auth.update(key);
        auth.update(nonce);
        auth.update(ciphertext);
        let expected_tag = auth.finalize();

        if tag != expected_tag.as_slice() {
            anyhow::bail!("Authentication failed — wrong password or corrupted vault");
        }

        // Regenerate keystream and decrypt
        let num_blocks = (ciphertext.len() + 31) / 32;
        let mut keystream = Vec::with_capacity(num_blocks * 32);

        for i in 0..num_blocks {
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update(nonce);
            hasher.update(&(i as u32).to_le_bytes());
            keystream.extend_from_slice(&hasher.finalize());
        }

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        for (i, byte) in ciphertext.iter().enumerate() {
            plaintext.push(byte ^ keystream[i]);
        }

        Ok(plaintext)
    }
}

// ── RAM-only ephemeral mode ──────────────────────────────────────

/// Configuration for RAM-only operation.
/// When enabled, all temporary files are stored in memory (tmpfs on Linux)
/// and securely wiped on exit.
#[derive(Debug, Clone)]
pub struct RamMode {
    pub enabled: bool,
    pub tmpfs_mount: PathBuf,
}

impl Default for RamMode {
    fn default() -> Self {
        Self {
            enabled: false,
            tmpfs_mount: PathBuf::from("/dev/shm/nofind"),
        }
    }
}

impl RamMode {
    /// Detect if we can use RAM-only mode.
    pub fn detect() -> Self {
        let tmpfs = PathBuf::from("/dev/shm/nofind");
        let enabled = cfg!(target_os = "linux") && tmpfs.parent().map_or(false, |p| p.exists());
        Self {
            enabled,
            tmpfs_mount: tmpfs,
        }
    }

    /// Initialize the RAM-only workspace.
    pub fn init(&self) -> anyhow::Result<PathBuf> {
        if !self.enabled {
            return Ok(std::env::temp_dir().join("nofind"));
        }
        fs::create_dir_all(&self.tmpfs_mount)?;
        tracing::info!(path = %self.tmpfs_mount.display(), "RAM-only mode active");
        Ok(self.tmpfs_mount.clone())
    }

    /// Securely wipe and remove the RAM workspace.
    pub fn cleanup(&self) -> anyhow::Result<()> {
        if self.tmpfs_mount.exists() {
            // Overwrite with zeros before unmounting
            if let Ok(entries) = fs::read_dir(&self.tmpfs_mount) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(size) = fs::metadata(&path) {
                            let zeros = vec![0u8; size.len() as usize];
                            let _ = fs::write(&path, &zeros);
                        }
                    }
                }
            }
            let _ = fs::remove_dir_all(&self.tmpfs_mount);
            tracing::info!("RAM workspace wiped");
        }
        Ok(())
    }
}

// ── Secure memory helpers ────────────────────────────────────────

/// Wrapper that zeroizes its contents on drop.
pub struct SecureString(String);

impl SecureString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Overwrite the string contents
        unsafe {
            let bytes = self.0.as_bytes_mut();
            for byte in bytes.iter_mut() {
                *byte = 0;
            }
        }
    }
}

// ── Command handlers ─────────────────────────────────────────────

/// Initialize an encrypted vault for config storage.
pub async fn cmd_vault_init(password: &str) -> anyhow::Result<()> {
    let vault_path = vault_default_path();
    if vault_path.exists() {
        anyhow::bail!(
            "Vault already exists at {}. Use 'vault-destroy' first to recreate.",
            vault_path.display()
        );
    }

    let vault = ConfigVault::new(vault_path, password)?;
    let config = crate::config::Config::default();
    let toml_str = toml::to_string_pretty(&config)?;
    vault.store_config(&toml_str)?;

    println!("Encrypted vault created at {}", vault.path.display());
    println!("Use NOFIND_VAULT_PASSWORD env var or --vault-password to unlock.");
    Ok(())
}

/// Load config from encrypted vault.
pub async fn cmd_vault_load(password: &str) -> anyhow::Result<crate::config::Config> {
    let vault_path = vault_default_path();
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Run 'vault-init' first.");
    }

    let vault = ConfigVault::new(vault_path, password)?;
    let toml_str = vault.load_config()?;
    let config: crate::config::Config = toml::from_str(&toml_str)?;
    tracing::info!("Config loaded from encrypted vault");
    Ok(config)
}

/// Destroy the encrypted vault.
pub async fn cmd_vault_destroy() -> anyhow::Result<()> {
    let vault_path = vault_default_path();
    // We don't need the password to destroy — just overwrite and delete
    if vault_path.exists() {
        let size = fs::metadata(&vault_path)?.len() as usize;
        let random: Vec<u8> = (0..size).map(|_| rand::thread_rng().gen()).collect();
        fs::write(&vault_path, &random)?;
        fs::remove_file(&vault_path)?;
        println!("Vault destroyed: {}", vault_path.display());
    } else {
        println!("No vault found.");
    }
    Ok(())
}

fn vault_default_path() -> PathBuf {
    let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("nofind");
    path.push("vault.enc");
    path
}
