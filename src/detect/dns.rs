use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;

use crate::model::MxRecord;

/// CNAME chains longer than this are cut off (loop guard).
const MAX_CNAME_HOPS: usize = 8;

pub(crate) fn resolve(host: &str) -> Option<IpAddr> {
    (host, 443)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(|a| a.ip())
}

pub(crate) fn resolve_all(host: &str) -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    for record_type in ["A", "AAAA"] {
        let output = Command::new("dig")
            .args(["+short", host, record_type])
            .output();
        let Ok(output) = output else {
            continue;
        };
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let Ok(ip) = line.trim().parse::<IpAddr>() else {
                continue;
            };
            if !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
    }
    addresses
}

pub(crate) fn dig_mx(domain: &str) -> Vec<MxRecord> {
    let output = match Command::new("dig").args(["+short", domain, "MX"]).output() {
        Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
        Err(_) => String::new(),
    };
    parse_mx_lines(&output)
}

pub(crate) fn parse_mx_lines(stdout: &str) -> Vec<MxRecord> {
    let mut records: Vec<MxRecord> = stdout
        .lines()
        .filter_map(|line| {
            let mut tokens = line.split_whitespace();
            let priority = tokens.next()?.parse::<u16>().ok()?;
            let host = tokens.next()?.trim_end_matches('.');
            (!host.is_empty() && host != ".").then(|| MxRecord {
                priority,
                host: host.to_string(),
            })
        })
        .collect();
    records.sort_by_key(|record| record.priority);
    records
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

/// The complete CNAME chain, following every hop until a name has no
/// CNAME, instead of inspecting only the first hop.
pub(crate) fn dig_cname_chain(domain: &str) -> Vec<String> {
    follow_cname_chain(domain, dig_cname, MAX_CNAME_HOPS)
}

fn follow_cname_chain<F>(domain: &str, lookup: F, max_hops: usize) -> Vec<String>
where
    F: Fn(&str) -> Option<String>,
{
    let mut chain = Vec::new();
    let mut current = domain.to_string();
    for _ in 0..max_hops {
        let Some(next) = lookup(&current) else { break };
        if next == domain || chain.contains(&next) {
            break;
        }
        current = next.clone();
        chain.push(next);
    }
    chain
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

/// First TXT record of a name, without the surrounding quotes.
pub(crate) fn dig_txt(name: &str) -> Option<String> {
    let output = Command::new("dig")
        .args(["+short", name, "TXT"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.trim_matches('"').to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_follows_every_hop_to_the_end() {
        let lookup = |name: &str| match name {
            "www.example.com" => Some("www.example.com.glb.example.org".to_string()),
            "www.example.com.glb.example.org" => Some("www.example.com.edgekey.net".to_string()),
            "www.example.com.edgekey.net" => Some("e970.dspg.akamaiedge.net".to_string()),
            _ => None,
        };
        let chain = follow_cname_chain("www.example.com", lookup, MAX_CNAME_HOPS);
        assert_eq!(
            chain,
            vec![
                "www.example.com.glb.example.org".to_string(),
                "www.example.com.edgekey.net".to_string(),
                "e970.dspg.akamaiedge.net".to_string(),
            ]
        );
    }

    #[test]
    fn chain_stops_on_loops() {
        let back_and_forth = |name: &str| match name {
            "a.example.com" => Some("b.example.com".to_string()),
            "b.example.com" => Some("a.example.com".to_string()),
            _ => None,
        };
        assert_eq!(
            follow_cname_chain("a.example.com", back_and_forth, MAX_CNAME_HOPS),
            vec!["b.example.com".to_string()]
        );

        let self_referential = |name: &str| Some(name.to_string());
        assert_eq!(
            follow_cname_chain("start.example.com", self_referential, MAX_CNAME_HOPS),
            Vec::<String>::new()
        );
    }

    #[test]
    fn chain_is_capped_at_max_hops() {
        let ever_growing = |name: &str| Some(format!("hop.{name}"));
        let chain = follow_cname_chain("start.example.com", ever_growing, 3);
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn mx_lines_keep_every_record_and_priority() {
        let stdout = "20 mx2.example.com.\n10 mx1.example.com.\n20 mx3.example.com.\n";
        let records = parse_mx_lines(stdout);
        assert_eq!(
            records,
            vec![
                MxRecord {
                    priority: 10,
                    host: "mx1.example.com".to_string()
                },
                MxRecord {
                    priority: 20,
                    host: "mx2.example.com".to_string()
                },
                MxRecord {
                    priority: 20,
                    host: "mx3.example.com".to_string()
                },
            ]
        );
    }

    #[test]
    fn mx_lines_skip_garbage_and_handle_no_mx() {
        assert!(parse_mx_lines("").is_empty());
        assert!(parse_mx_lines("\n\n").is_empty());
        assert!(parse_mx_lines("mail.example.com.\n").is_empty());
        assert!(parse_mx_lines("oops not a number mx.example.com.").is_empty());
        assert!(parse_mx_lines("0 .\n").is_empty());
        let records = parse_mx_lines("  5\tmx.example.com  ");
        assert_eq!(
            records,
            vec![MxRecord {
                priority: 5,
                host: "mx.example.com".to_string()
            }]
        );
    }
}
