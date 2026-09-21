use std::time::Duration;

use crate::model::HttpEvidence;

use super::vendors::match_http_header_vendor;

/// Akamai diagnostic request headers: with these enabled the edge echoes
/// back vendor-specific response headers. Non-Akamai servers ignore them.
const PRAGMA: &str = "akamai-x-cache-on, akamai-x-get-request-id, akamai-x-check-cacheable";

/// One lightweight HTTPS request against the host. A vendor-specific
/// response header — and only that — is HTTP evidence that the request
/// was actually processed by the vendor edge.
pub(crate) fn probe_http(host: &str) -> Option<HttpEvidence> {
    let url = format!("https://{host}/");
    let response = match ureq::get(&url)
        .timeout(Duration::from_secs(10))
        .set("Pragma", PRAGMA)
        .call()
    {
        Ok(response) => response,
        // 4xx/5xx responses are still edge responses; keep their headers.
        Err(ureq::Error::Status(_, response)) => response,
        Err(_) => return None,
    };
    http_evidence(&response.headers_names())
}

/// The evidence from a set of observed header names: the first
/// alphabetically (for determinism, since header order is not) header
/// whose name is unambiguously vendor-specific. Generic headers such as
/// Server, Via or X-Cache never qualify.
pub(crate) fn http_evidence(header_names: &[String]) -> Option<HttpEvidence> {
    let mut matched: Vec<&str> = header_names
        .iter()
        .map(String::as_str)
        .filter(|name| match_http_header_vendor(name).is_some())
        .collect();
    matched.sort_unstable();
    matched.dedup();
    let name = matched.first()?;
    let vendor = match_http_header_vendor(name)?;
    Some(HttpEvidence {
        header: canonical_header_name(name),
        vendor,
    })
}

/// "x-akamai-request-id" -> "X-Akamai-Request-ID": short segments (id, ip)
/// upper-case whole, longer segments capitalize the first letter.
fn canonical_header_name(name: &str) -> String {
    name.split('-')
        .map(|segment| {
            if segment.len() <= 2 {
                segment.to_uppercase()
            } else {
                format!("{}{}", segment[..1].to_uppercase(), &segment[1..])
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Vendor;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn akamai_is_identified_by_its_diagnostic_headers() {
        let evidence = http_evidence(&names(&[
            "server",
            "content-type",
            "x-cache",
            "x-akamai-request-id",
        ]))
        .expect("X-Akamai-Request-ID must match");
        assert_eq!(evidence.header, "X-Akamai-Request-ID");
        assert_eq!(evidence.vendor, Vendor::Akamai);
    }

    #[test]
    fn generic_headers_never_identify_a_vendor() {
        // Matching is on header names only, so a value like
        // "X-Cache: HIT from AkamaiGHost" can never count.
        assert_eq!(
            http_evidence(&names(&[
                "server",
                "via",
                "x-cache",
                "x-cache-remote",
                "age",
                "date"
            ])),
            None
        );
    }

    #[test]
    fn match_is_deterministic_across_several_vendor_headers() {
        let evidence =
            http_evidence(&names(&["x-akamai-session-info", "x-akamai-request-id"])).unwrap();
        assert_eq!(evidence.header, "X-Akamai-Request-ID");
    }

    #[test]
    fn header_names_are_canonicalized() {
        assert_eq!(
            canonical_header_name("x-akamai-request-id"),
            "X-Akamai-Request-ID"
        );
        assert_eq!(
            canonical_header_name("akamai-transformed"),
            "Akamai-Transformed"
        );
        assert_eq!(
            canonical_header_name("x-akamai-staging"),
            "X-Akamai-Staging"
        );
    }
}
