use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use chrono::Local;
use ipnet::IpNet;
use serde_json::Value;

use crate::model::Vendor;

fn cache_path() -> PathBuf {
    std::env::temp_dir().join("pq-edge-ranges.json")
}

type VendorRanges = Vec<(Vendor, Vec<String>)>;

fn fetch_vendor_ranges() -> VendorRanges {
    let mut ranges: VendorRanges = Vec::new();

    if let Ok(resp) = ureq::get("https://www.cloudflare.com/ips-v4")
        .timeout(Duration::from_secs(10))
        .call()
        && let Ok(body) = resp.into_string()
    {
        let cf: Vec<String> = body
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if !cf.is_empty() {
            ranges.push((Vendor::Cloudflare, cf));
        }
    }

    if let Ok(resp) = ureq::get("https://api.fastly.com/public-ip-list")
        .timeout(Duration::from_secs(10))
        .call()
        && let Ok(json) = resp.into_json::<Value>()
    {
        let fastly: Vec<String> = json["addresses"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if !fastly.is_empty() {
            ranges.push((Vendor::Fastly, fastly));
        }
    }

    if let Ok(resp) = ureq::get("https://ip-ranges.amazonaws.com/ip-ranges.json")
        .timeout(Duration::from_secs(15))
        .call()
        && let Ok(json) = resp.into_json::<Value>()
    {
        let cf: Vec<String> = json["prefixes"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter(|v| v["service"].as_str() == Some("CLOUDFRONT"))
                    .filter_map(|v| v["ip_prefix"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if !cf.is_empty() {
            ranges.push((Vendor::CloudFront, cf));
        }
    }

    let cache = serde_json::json!({
        "cached_at": Local::now().timestamp(),
        "ranges": &ranges,
    });
    let _ = std::fs::write(cache_path(), cache.to_string());

    ranges
}

fn load_cached_ranges() -> Option<VendorRanges> {
    let content = std::fs::read_to_string(cache_path()).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;
    let cached_at = json["cached_at"].as_i64()?;
    let now = Local::now().timestamp();
    if now - cached_at > 86400 {
        return None;
    }
    serde_json::from_value(json["ranges"].clone()).ok()
}

pub(crate) fn get_vendor_ranges() -> VendorRanges {
    load_cached_ranges().unwrap_or_else(fetch_vendor_ranges)
}

/// Returns the owning vendor and the matched CIDR.
pub(crate) fn ip_in_ranges(ip: &IpAddr, ranges: &VendorRanges) -> Option<(Vendor, String)> {
    for (vendor, cidrs) in ranges {
        for cidr in cidrs {
            if let Ok(net) = cidr.parse::<IpNet>()
                && net.contains(ip)
            {
                return Some((*vendor, cidr.clone()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_in_ranges_returns_vendor_and_cidr() {
        let ranges = vec![(Vendor::Cloudflare, vec!["104.16.0.0/12".to_string()])];
        let inside: IpAddr = "104.16.132.229".parse().unwrap();
        assert_eq!(
            ip_in_ranges(&inside, &ranges),
            Some((Vendor::Cloudflare, "104.16.0.0/12".to_string()))
        );
        let outside: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(ip_in_ranges(&outside, &ranges), None);
    }
}
