use crate::model::Vendor;

// Token-exact matching (case-insensitive): "THALES-IMPERVA-NA4-AGG" splits
// into tokens so "IMPERVA" matches Imperva, but "PALMYRA" does NOT match "MYRA".
const VENDOR_ALIASES: &[(&[&str], Vendor)] = &[
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
const VENDOR_ZONES: &[(&str, Vendor)] = &[
    ("cloudflare.com", Vendor::Cloudflare),
    ("cloudflare.net", Vendor::Cloudflare),
    ("akamai.net", Vendor::Akamai),
    ("akamaiedge.net", Vendor::Akamai),
    ("akamaihd.net", Vendor::Akamai),
    ("edgekey.net", Vendor::Akamai),
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
}
