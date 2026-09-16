use std::time::Duration;

use serde_json::Value;

use crate::model::RdapEvidence;

use super::vendors::match_vendor;

/// Tries each RIR endpoint until one returns data.
pub(crate) fn rdap_lookup(ip: &str) -> Option<RdapEvidence> {
    let rdap_urls = [
        format!("https://rdap.arin.net/registry/ip/{ip}"),
        format!("https://rdap.db.ripe.net/ip/{ip}"),
        format!("https://rdap.apnic.net/ip/{ip}"),
        format!("https://rdap.lacnic.net/rdap/ip/{ip}"),
        format!("https://rdap.afrinic.net/rdap/ip/{ip}"),
    ];

    for url in &rdap_urls {
        match ureq::get(url).timeout(Duration::from_secs(10)).call() {
            Ok(resp) => {
                if let Ok(json) = resp.into_json::<Value>() {
                    let netname = json["name"].as_str().unwrap_or("").to_string();

                    let mut org_name = String::new();
                    if let Some(entities) = json["entities"].as_array() {
                        for entity in entities {
                            if let Some(vcard) = entity["vcardArray"].as_array()
                                && vcard.len() > 1
                                && let Some(items) = vcard[1].as_array()
                            {
                                for item in items {
                                    if let Some(arr) = item.as_array()
                                        && arr.first().and_then(|f| f.as_str()) == Some("fn")
                                        && let Some(name) = arr.get(2).and_then(|v| v.as_str())
                                    {
                                        org_name = name.to_string();
                                    }
                                }
                            }
                        }
                    }

                    let combined = format!("{netname} {org_name}");
                    let vendor = match_vendor(&combined);
                    return Some(RdapEvidence { netname, vendor });
                }
            }
            Err(_) => continue,
        }
    }
    None
}
