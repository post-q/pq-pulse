use std::net::IpAddr;

use crate::model::AsnEvidence;

use super::dns::dig_txt;
use crate::providers::match_vendor;

/// Origin ASN of the resolved IP via the Team Cymru DNS service, plus
/// the AS name. Network-ownership attribution that corroborates PTR and
/// RDAP — or stands in when they say nothing.
pub(crate) fn asn_lookup(ip: IpAddr) -> Option<AsnEvidence> {
    let origin = dig_txt(&cymru_origin_domain(ip)?)?;
    let number = origin_asn(&origin)?;
    let name = dig_txt(&format!("AS{number}.asn.cymru.com")).and_then(|record| as_name(&record));

    let asn = match &name {
        Some(name) => format!("AS{number} {name}"),
        None => format!("AS{number}"),
    };
    let vendor = name.as_deref().and_then(match_vendor);
    Some(AsnEvidence { asn, vendor })
}

/// `<reversed IP>.origin[6].asn.cymru.com` — the Team Cymru lookup name.
fn cymru_origin_domain(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => {
            let labels: Vec<String> = v4.octets().iter().rev().map(|o| o.to_string()).collect();
            Some(format!("{}.origin.asn.cymru.com", labels.join(".")))
        }
        IpAddr::V6(v6) => {
            // Full 32 nibbles of the expanded address, reversed, one per label.
            let hex: String = v6
                .octets()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .concat();
            let labels: Vec<String> = hex.chars().rev().map(|c| c.to_string()).collect();
            Some(format!("{}.origin6.asn.cymru.com", labels.join(".")))
        }
    }
}

/// The origin ASN number from a Cymru origin record
/// ("20940 | 104.96.0.0/12 | US | arin | ..."), first of a multi-origin set.
fn origin_asn(record: &str) -> Option<String> {
    let first = record.split('|').next()?.trim();
    let number = first.split_whitespace().next()?;
    (!number.is_empty() && number.chars().all(|c| c.is_ascii_digit())).then(|| number.to_string())
}

/// The AS name from a Cymru AS record
/// ("20940 | NL | ripencc | 2001-07-10 | AKAMAI-ASN1 - Akamai International B.V., NL"):
/// the short name before the description.
fn as_name(record: &str) -> Option<String> {
    let field = record.split('|').nth(4)?.trim();
    let name = field.split(" - ").next().unwrap_or(field).trim();
    (!name.is_empty() && name != "NA").then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cymru_origin_domain_reverses_v4_octets() {
        let ip: IpAddr = "104.96.178.165".parse().unwrap();
        assert_eq!(
            cymru_origin_domain(ip).as_deref(),
            Some("165.178.96.104.origin.asn.cymru.com")
        );
    }

    #[test]
    fn cymru_origin_domain_expands_v6_nibbles() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let domain = cymru_origin_domain(ip).unwrap();
        assert!(domain.starts_with("1.0.0.0."));
        assert!(domain.ends_with("0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com"));
    }

    #[test]
    fn origin_asn_takes_the_first_of_multi_origin_sets() {
        assert_eq!(
            origin_asn("20940 | 104.96.0.0/12 | US | arin | 2007-10-04").as_deref(),
            Some("20940")
        );
        assert_eq!(
            origin_asn("20940 16625 | 23.32.0.0/11 | US | arin | 2013-05-31").as_deref(),
            Some("20940")
        );
        assert_eq!(
            origin_asn("NA | 104.96.0.0/12 | US | arin | 2007-10-04"),
            None
        );
        assert_eq!(origin_asn(""), None);
    }

    #[test]
    fn as_name_extracts_the_short_name_field() {
        assert_eq!(
            as_name(
                "20940 | NL | ripencc | 2001-07-10 | AKAMAI-ASN1 - Akamai International B.V., NL"
            )
            .as_deref(),
            Some("AKAMAI-ASN1")
        );
        assert_eq!(
            as_name("16625 | US | arin | 2000-05-30 | AKAMAI-AS - Akamai Technologies, Inc., US")
                .as_deref(),
            Some("AKAMAI-AS")
        );
        // A bare name without a description works too.
        assert_eq!(
            as_name("64512 | US | arin | 2000-05-30 | EXAMPLE-CORP").as_deref(),
            Some("EXAMPLE-CORP")
        );
        assert_eq!(as_name("16625 | US | arin | 2000-05-30 | NA"), None);
        assert_eq!(as_name("16625 | US | arin | 2000-05-30 | "), None);
    }

    #[test]
    fn akamai_asn_name_maps_to_the_akamai_vendor() {
        let name = as_name(
            "20940 | NL | ripencc | 2001-07-10 | AKAMAI-ASN1 - Akamai International B.V., NL",
        )
        .unwrap();
        assert_eq!(match_vendor(&name), Some(crate::model::Vendor::Akamai));
    }
}
