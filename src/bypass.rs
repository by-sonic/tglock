use std::path::{Path, PathBuf};
use std::process::Command;

pub fn check_admin() -> bool {
    let output = Command::new("net")
        .args(["session"])
        .output();
    matches!(output, Ok(o) if o.status.success())
}

pub fn set_dns(adapter: &str, primary: &str, secondary: &str) -> Result<(), String> {
    let out1 = Command::new("netsh")
        .args([
            "interface", "ipv4", "set", "dnsservers",
            adapter, "static", primary, "primary", "validate=no",
        ])
        .output()
        .map_err(|e| format!("netsh error: {}", e))?;

    if !out1.status.success() {
        let stderr = String::from_utf8_lossy(&out1.stderr);
        return Err(format!("Failed to set primary DNS: {}", stderr));
    }

    let out2 = Command::new("netsh")
        .args([
            "interface", "ipv4", "add", "dnsservers",
            adapter, secondary, "index=2", "validate=no",
        ])
        .output()
        .map_err(|e| format!("netsh error: {}", e))?;

    if !out2.status.success() {
        // Non-critical: secondary DNS may already exist
    }

    Ok(())
}

pub fn reset_dns(adapter: &str) -> Result<(), String> {
    let out = Command::new("netsh")
        .args([
            "interface", "ipv4", "set", "dnsservers",
            adapter, "dhcp",
        ])
        .output()
        .map_err(|e| format!("netsh error: {}", e))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("Failed to reset DNS: {}", stderr));
    }
    Ok(())
}

pub fn flush_dns() {
    let _ = Command::new("ipconfig")
        .args(["/flushdns"])
        .output();
}

pub fn find_goodbyedpi() -> Option<String> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let search_dirs = vec![
        exe_dir.join("tools"),
        exe_dir.join("tools").join("goodbyedpi"),
        exe_dir.clone(),
        PathBuf::from("tools"),
        PathBuf::from("tools").join("goodbyedpi"),
        PathBuf::from("."),
    ];

    for dir in &search_dirs {
        // Check common locations
        for sub in &["x86_64", "x86", ""] {
            let candidate = if sub.is_empty() {
                dir.join("goodbyedpi.exe")
            } else {
                dir.join(sub).join("goodbyedpi.exe")
            };
            if candidate.exists() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }

    // Recursive search in tools/
    if let Ok(entries) = find_file_recursive(Path::new("tools"), "goodbyedpi.exe") {
        if !entries.is_empty() {
            return Some(entries[0].to_string_lossy().to_string());
        }
    }

    None
}

fn find_file_recursive(dir: &Path, filename: &str) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut results = Vec::new();
    if !dir.exists() {
        return Ok(results);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.file_name().map(|n| n == filename).unwrap_or(false) {
            results.push(path);
        } else if path.is_dir() {
            results.extend(find_file_recursive(&path, filename)?);
        }
    }
    Ok(results)
}

pub fn get_blacklist_path() -> Option<String> {
    let candidates = vec![
        PathBuf::from("tg_blacklist.txt"),
        PathBuf::from("tools").join("tg_blacklist.txt"),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("tg_blacklist.txt")))
            .unwrap_or_default(),
    ];

    for path in candidates {
        if path.exists() {
            return Some(path.to_string_lossy().to_string());
        }
    }
    None
}

pub fn start_goodbyedpi(exe_path: &str, args: &[&str], blacklist: Option<&str>) -> Result<(), String> {
    let mut cmd = Command::new(exe_path);
    cmd.args(args);

    if let Some(bl) = blacklist {
        cmd.args(["--blacklist", bl]);
    }

    cmd.spawn().map_err(|e| format!("Failed to start GoodbyeDPI: {}", e))?;
    Ok(())
}

pub fn kill_goodbyedpi() {
    let _ = Command::new("taskkill")
        .args(["/f", "/im", "goodbyedpi.exe"])
        .output();
}

pub fn download_goodbyedpi() -> Result<String, String> {
    let tools_dir = PathBuf::from("tools");
    std::fs::create_dir_all(&tools_dir)
        .map_err(|e| format!("Cannot create tools dir: {}", e))?;

    let zip_path = tools_dir.join("goodbyedpi.zip");
    let url = "https://github.com/ValdikSS/GoodbyeDPI/releases/download/0.2.3rc3/goodbyedpi-0.2.3rc3-2.zip";

    // Download using powershell
    let dl_script = format!(
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '{}' -OutFile '{}' -UseBasicParsing",
        url,
        zip_path.to_string_lossy()
    );

    let output = Command::new("powershell")
        .args(["-Command", &dl_script])
        .output()
        .map_err(|e| format!("Download failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Download failed: {}", stderr));
    }

    // Extract
    let extract_script = format!(
        "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
        zip_path.to_string_lossy(),
        tools_dir.to_string_lossy()
    );

    let output = Command::new("powershell")
        .args(["-Command", &extract_script])
        .output()
        .map_err(|e| format!("Extraction failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Extraction failed: {}", stderr));
    }

    // Clean up zip
    let _ = std::fs::remove_file(&zip_path);

    // Find the exe
    find_goodbyedpi().ok_or_else(|| "goodbyedpi.exe not found after extraction".to_string())
}
