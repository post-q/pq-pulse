use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;

/// CNAME chains longer than this are cut off (loop guard).
const MAX_CNAME_HOPS: usize = 8;

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
}
