use crate::model::Vendor;

// Token-exact matching (case-insensitive): "THALES-IMPERVA-NA4-AGG" splits
// into tokens so "IMPERVA" matches Imperva, but "PALMYRA" does NOT match "MYRA".
pub(crate) const VENDOR_ALIASES: &[(&[&str], Vendor)] = &[
    (&["CLOUDFLARE", "CLOUDFLARENET"], Vendor::Cloudflare),
    (
        &["AKAMAI", "AKAMAITECHNOLOGIES", "AKAMAIEDGE", "AKAMAIHD"],
        Vendor::Akamai,
    ),
    (&["INCAPSULA", "THALES-IMPERVA", "IMPERVA"], Vendor::Imperva),
    (&["FASTLY"], Vendor::Fastly),
    (&["CLOUDFRONT", "AMAZON", "AMAZONAWS"], Vendor::CloudFront),
    (&["MYRA"], Vendor::Myra),
    (&["LINK11"], Vendor::Link11),
    (
        &["GOOGLE", "GOOGL", "GOOGLEUSERCONTENT", "GCLOUD"],
        Vendor::GoogleCloud,
    ),
    (&["MSFT", "MICROSOFT", "AZURE", "AZUREFD"], Vendor::Azure),
];

// Known vendor DNS zones for CNAME delegation
pub(crate) const VENDOR_ZONES: &[(&str, Vendor)] = &[
    ("cloudflare.com", Vendor::Cloudflare),
    ("cloudflare.net", Vendor::Cloudflare),
    ("akamai.net", Vendor::Akamai),
    ("akamaiedge.net", Vendor::Akamai),
    ("akamaihd.net", Vendor::Akamai),
    ("edgekey.net", Vendor::Akamai),
    ("edgesuite.net", Vendor::Akamai),
    ("akamaized.net", Vendor::Akamai),
    ("imperva.com", Vendor::Imperva),
    ("incapsula.com", Vendor::Imperva),
    ("impervadns.net", Vendor::Imperva),
    ("fastly.net", Vendor::Fastly),
    ("fastly.com", Vendor::Fastly),
    ("myra.cloud", Vendor::Myra),
    ("link11.com", Vendor::Link11),
    ("link11.net", Vendor::Link11),
    ("cloudfront.net", Vendor::CloudFront),
    ("amazonaws.com", Vendor::CloudFront),
    ("googleusercontent.com", Vendor::GoogleCloud),
    ("gc.googleusercontent.com", Vendor::GoogleCloud),
    ("azurefd.net", Vendor::Azure),
    ("azureedge.net", Vendor::Azure),
    ("cloudapp.net", Vendor::Azure),
];

// HTTP response header-name prefixes that are unambiguously vendor-
// specific. Generic headers (Server, Via, X-Cache) are deliberately
// absent: a header must carry the vendor's own name to be evidence.
const VENDOR_HEADER_PREFIXES: &[(&str, Vendor)] = &[
    ("x-akamai-", Vendor::Akamai),
    ("akamai-", Vendor::Akamai),
    ("x-iinfo-", Vendor::Imperva),
    ("x-iinfo", Vendor::Imperva),
];

pub(crate) fn match_vendor(text: &str) -> Option<Vendor> {
    let text_upper = text.to_uppercase();
    for (tokens, vendor) in VENDOR_ALIASES {
        for token in text_upper.split(|c: char| !c.is_alphanumeric()) {
            if tokens.contains(&token) {
                return Some(*vendor);
            }
        }
    }
    None
}

pub(crate) fn match_cname_vendor(cname: &str) -> Option<Vendor> {
    let cname_lower = cname.to_lowercase();
    for (zone, vendor) in VENDOR_ZONES {
        if cname_lower.ends_with(&format!(".{zone}")) || cname_lower == *zone {
            return Some(*vendor);
        }
    }
    None
}

/// First vendor match anywhere in a CNAME chain; vendor zones often
/// appear only in a later hop (edgekey -> akamaiedge).
pub(crate) fn match_cname_chain_vendor(chain: &[String]) -> Option<Vendor> {
    chain.iter().find_map(|hop| match_cname_vendor(hop))
}

/// Vendor match for an HTTP response header by name. Case-insensitive
/// prefix match; generic header names never match.
pub(crate) fn match_http_header_vendor(name: &str) -> Option<Vendor> {
    let lowered = name.to_lowercase();
    VENDOR_HEADER_PREFIXES
        .iter()
        .find(|(prefix, _)| lowered.starts_with(prefix))
        .map(|(_, vendor)| *vendor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_vendor_is_token_exact() {
        assert_eq!(
            match_vendor("THALES-IMPERVA-NA4-AGG"),
            Some(Vendor::Imperva)
        );
        assert_eq!(match_vendor("AKAMAI"), Some(Vendor::Akamai));
        assert_eq!(match_vendor("palmyra.example.com"), None);
    }

    #[test]
    fn match_cname_vendor_matches_zones() {
        assert_eq!(
            match_cname_vendor("cdn.example.com.edgekey.net"),
            Some(Vendor::Akamai)
        );
        assert_eq!(match_cname_vendor("cdn.example.net"), None);
    }

    #[test]
    fn edgesuite_and_akamaized_zones_match_akamai() {
        assert_eq!(
            match_cname_vendor("e970.g.akamaiedge.net"),
            Some(Vendor::Akamai)
        );
        assert_eq!(
            match_cname_vendor("a.b.edgesuite.net"),
            Some(Vendor::Akamai)
        );
        assert_eq!(
            match_cname_vendor("x.customer.akamaized.net"),
            Some(Vendor::Akamai)
        );
    }

    #[test]
    fn vendor_zone_in_a_later_cname_hop_matches() {
        let chain: Vec<String> = [
            "www.example.com.glb.example.org",
            "www.example.com.edgekey.net",
            "e970.dspg.akamaiedge.net",
        ]
        .iter()
        .map(|hop| hop.to_string())
        .collect();
        // The first hop alone matches nothing.
        assert_eq!(match_cname_vendor(&chain[0]), None);
        assert_eq!(match_cname_chain_vendor(&chain), Some(Vendor::Akamai));
    }

    #[test]
    fn chain_without_vendor_zones_matches_nothing() {
        let chain = vec![
            "cdn.example.org".to_string(),
            "origin.example.net".to_string(),
        ];
        assert_eq!(match_cname_chain_vendor(&chain), None);
    }

    #[test]
    fn only_vendor_prefixed_http_headers_match() {
        assert_eq!(
            match_http_header_vendor("X-Akamai-Request-ID"),
            Some(Vendor::Akamai)
        );
        assert_eq!(
            match_http_header_vendor("akamai-origin-hop"),
            Some(Vendor::Akamai)
        );
        // Generic headers never identify a vendor, whatever their values.
        assert_eq!(match_http_header_vendor("X-Cache"), None);
        assert_eq!(match_http_header_vendor("X-Cache-Remote"), None);
        assert_eq!(match_http_header_vendor("Server"), None);
        assert_eq!(match_http_header_vendor("Via"), None);
    }
}
