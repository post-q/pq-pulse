use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;

pub(crate) fn resolve(host: &str) -> Option<IpAddr> {
    (host, 443)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(|a| a.ip())
}

pub(crate) fn dig_cname(domain: &str) -> Option<String> {
    let output = Command::new("dig")
        .args(["+short", domain, "CNAME"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.trim_end_matches('.').to_string())
    }
}

pub(crate) fn dig_ptr(ip: &str) -> Option<String> {
    let output = Command::new("dig")
        .args(["+short", "-x", ip])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.trim_end_matches('.').to_string())
    }
}
