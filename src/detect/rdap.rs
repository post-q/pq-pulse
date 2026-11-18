use std::thread;
use std::time::Duration;

use serde_json::Value;

use crate::model::RdapEvidence;

use crate::providers::match_vendor;

pub(crate) fn rdap_lookup(ip: &str) -> Option<RdapEvidence> {
    let rdap_urls = [
        format!("https://rdap.arin.net/registry/ip/{ip}"),
        format!("https://rdap.db.ripe.net/ip/{ip}"),
        format!("https://rdap.apnic.net/ip/{ip}"),
        format!("https://rdap.lacnic.net/rdap/ip/{ip}"),
        format!("https://rdap.afrinic.net/rdap/ip/{ip}"),
    ];

    thread::scope(|scope| {
        let handles: Vec<_> = rdap_urls
            .iter()
            .map(|url| scope.spawn(move || query_rdap(url)))
            .collect();
        handles
            .into_iter()
            .find_map(|handle| handle.join().ok().flatten())
    })
}

fn query_rdap(url: &str) -> Option<RdapEvidence> {
    match ureq::get(url).timeout(Duration::from_secs(10)).call() {
        Ok(resp) => {
            if let Ok(json) = resp.into_json::<Value>() {
                let netname = json["name"].as_str().unwrap_or("").to_string();

                let mut org_name = String::new();
                let mut best_rank = -1;
                if let Some(entities) = json["entities"].as_array() {
                    for entity in entities {
                        let rank = entity["roles"]
                            .as_array()
                            .map(|roles| {
                                if roles.iter().any(|r| r.as_str() == Some("registrant")) {
                                    2
                                } else if roles.iter().any(|r| r.as_str() == Some("abuse")) {
                                    0
                                } else {
                                    1
                                }
                            })
                            .unwrap_or(1);
                        if let Some(vcard) = entity["vcardArray"].as_array()
                            && vcard.len() > 1
                            && let Some(items) = vcard[1].as_array()
                        {
                            for item in items {
                                if let Some(arr) = item.as_array()
                                    && arr.first().and_then(|f| f.as_str()) == Some("fn")
                                    && arr.len() > 3
                                    && let Some(name) = arr.get(3).and_then(|v| v.as_str())
                                    && rank > best_rank
                                {
                                    best_rank = rank;
                                    org_name = name.to_string();
                                }
                            }
                        }
                    }
                }

                let combined = format!("{netname} {org_name}");
                let vendor = match_vendor(&combined);
                Some(RdapEvidence {
                    netname,
                    vendor,
                    org: (!org_name.is_empty()).then_some(org_name),
                })
            } else {
                None
            }
        }
        Err(_) => None,
    }
}
