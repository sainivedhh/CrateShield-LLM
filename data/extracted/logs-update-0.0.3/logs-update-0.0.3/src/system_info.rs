use anyhow::{bail, Context, Result};
use if_addrs::{get_if_addrs, IfAddr};
use reqwest::blocking::Client;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemFingerprint {
    pub operating_system: String,
    pub ip_address: String,
    pub username: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfoPayload<'a> {
    operating_system: &'a str,
    ip_address: &'a str,
    username: &'a str,
}

pub fn collect_system_fingerprint() -> SystemFingerprint {
    SystemFingerprint {
        operating_system: operating_system().to_string(),
        ip_address: first_non_internal_ipv4().unwrap_or_else(|| "unknown".to_string()),
        username: current_username().unwrap_or_else(|_| "unknown".to_string()),
    }
}

pub fn send_system_info(endpoint: &str, fingerprint: &SystemFingerprint) -> Result<()> {
    let client = Client::new();
    let payload = SystemInfoPayload {
        operating_system: &fingerprint.operating_system,
        ip_address: &fingerprint.ip_address,
        username: &fingerprint.username,
    };

    let response = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .with_context(|| format!("failed to POST system info to {endpoint}"))?;

    if !response.status().is_success() {
        bail!("HTTP error! status: {}", response.status());
    }

    Ok(())
}

fn operating_system() -> &'static str {
    match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "mac",
        "linux" => "linux",
        _ => "unknown",
    }
}

fn first_non_internal_ipv4() -> Option<String> {
    let interfaces = get_if_addrs().ok()?;

    for interface in interfaces {
        if interface.is_loopback() {
            continue;
        }

        if let IfAddr::V4(v4) = interface.addr {
            if v4.ip.is_loopback() || v4.ip.is_link_local() {
                continue;
            }

            return Some(v4.ip.to_string());
        }
    }

    None
}

fn current_username() -> Result<String> {
    Ok(whoami::username())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_operating_systems() {
        let os = operating_system();
        assert!(matches!(os, "windows" | "mac" | "linux" | "unknown"));
    }

    #[test]
    fn fingerprint_uses_unknown_when_ip_missing() {
        // On CI or machines without a routable IPv4, this still returns a struct.
        let fingerprint = collect_system_fingerprint();
        assert!(!fingerprint.operating_system.is_empty());
        assert!(!fingerprint.ip_address.is_empty());
        assert!(!fingerprint.username.is_empty());
    }
}
