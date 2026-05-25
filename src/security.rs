use std::path::PathBuf;

/// Clean all local session data: temp files, cache, and history.
pub async fn clean_session() -> anyhow::Result<()> {
    println!("Cleaning local session data...");
    println!();

    let mut cleaned = 0u64;
    let mut errors = 0u64;

    // 1. Clean nofind temp directory
    let temp_dir = crate::utils::temp_dir();
    if temp_dir.exists() {
        match std::fs::remove_dir_all(&temp_dir) {
            Ok(_) => {
                println!("  ✓ Removed temp directory: {}", temp_dir.display());
                cleaned += 1;
            }
            Err(e) => {
                println!("  ✗ Failed to clean temp dir: {}", e);
                errors += 1;
            }
        }
    } else {
        println!("  - No temp directory found");
    }

    // 2. Clean system temp files created by nofind
    let sys_temp = std::env::temp_dir();
    if sys_temp.exists() {
        match clean_temp_pattern(&sys_temp, "nofind") {
            Ok(count) => {
                if count > 0 {
                    println!("  ✓ Cleaned {} temp files matching 'nofind'", count);
                    cleaned += count;
                }
            }
            Err(e) => {
                println!("  ✗ Failed to clean system temp: {}", e);
                errors += 1;
            }
        }
    }

    // 3. Clean browser-like cache directories (if accessible)
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let cache_dirs = [
        home.join(".cache").join("nofind"),
        home.join(".local").join("share").join("nofind"),
    ];

    for dir in &cache_dirs {
        if dir.exists() {
            match std::fs::remove_dir_all(dir) {
                Ok(_) => {
                    println!("  ✓ Removed: {}", dir.display());
                    cleaned += 1;
                }
                Err(e) => {
                    println!("  ✗ Failed to remove {}: {}", dir.display(), e);
                    errors += 1;
                }
            }
        }
    }

    // 4. Clean DNS cache hints
    let dns_cache = home.join(".nofind").join("dns_cache");
    if dns_cache.exists() {
        match std::fs::remove_dir_all(&dns_cache) {
            Ok(_) => {
                println!("  ✓ Removed DNS cache: {}", dns_cache.display());
                cleaned += 1;
            }
            Err(e) => {
                println!("  ✗ Failed to remove DNS cache: {}", e);
                errors += 1;
            }
        }
    }

    println!();
    println!("  ─────────────────────────────────");
    println!(
        "  Cleaned: {} items | Errors: {}",
        cleaned, errors
    );
    println!();

    if errors > 0 {
        anyhow::bail!("Session cleaning completed with {} errors", errors);
    }

    tracing::info!(cleaned = cleaned, "Session cleaned successfully");
    Ok(())
}

/// Clean files in a directory matching a name pattern.
fn clean_temp_pattern(dir: &std::path::Path, pattern: &str) -> anyhow::Result<u64> {
    let mut count = 0;
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name.contains(pattern) {
                let path = entry.path();
                if path.is_dir() {
                    std::fs::remove_dir_all(&path)?;
                } else {
                    std::fs::remove_file(&path)?;
                }
                count += 1;
            }
        }
    }
    Ok(count)
}

/// Create a temporary session directory with unique ID.
pub fn create_session_dir() -> anyhow::Result<PathBuf> {
    let session_id = uuid::Uuid::new_v4().to_string();
    let mut path = crate::utils::temp_dir();
    path.push(&session_id);
    std::fs::create_dir_all(&path)?;
    tracing::info!(session_id = %session_id, path = %path.display(), "Created session directory");
    Ok(path)
}

/// Secure-delete a file by overwriting with zeros before removal.
pub fn secure_delete(path: &std::path::Path) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if path.is_file() {
        let size = std::fs::metadata(path)?.len();
        if size > 0 {
            // Overwrite with zeros
            let zeros = vec![0u8; 4096];
            let mut written = 0u64;
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
            while written < size {
                let to_write = std::cmp::min(4096, (size - written) as usize);
                file.write_all(&zeros[..to_write])?;
                written += to_write as u64;
            }
            file.flush()?;
        }
        std::fs::remove_file(path)?;
    } else if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            secure_delete(&entry?.path())?;
        }
        std::fs::remove_dir(path)?;
    }

    Ok(())
}
