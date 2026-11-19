use std::time::Duration;

use crate::model::{HttpEvidence, PageSignals};

use crate::providers::match_http_header_vendor;

/// Akamai diagnostic request headers: with these enabled the edge echoes
/// back vendor-specific response headers. Non-Akamai servers ignore them.
const PRAGMA: &str = "akamai-x-cache-on, akamai-x-get-request-id, akamai-x-check-cacheable";

fn ascii_lower(text: &str) -> String {
    text.chars().map(|c| c.to_ascii_lowercase()).collect()
}

pub(crate) fn probe_http(host: &str) -> (Option<HttpEvidence>, Option<PageSignals>) {
    let url = format!("https://{host}/");
    let response = match ureq::get(&url)
        .timeout(Duration::from_secs(10))
        .set("Pragma", PRAGMA)
        .call()
    {
        Ok(response) => response,
        // 4xx/5xx responses are still edge responses; keep their headers.
        Err(ureq::Error::Status(_, response)) => response,
        Err(_) => return (None, None),
    };
    let evidence = http_evidence(&response.headers_names());
    let body = response.into_string().unwrap_or_default();
    let page = (!body.is_empty()).then(|| page_signals(&body));
    (evidence, page)
}

pub(crate) fn page_signals(html: &str) -> PageSignals {
    let lower = ascii_lower(html);

    let title = tag_contents(html, &lower, "<title", "</title>");
    let meta_description = meta_content(html, &lower, "name", "description");
    let og_title = meta_content(html, &lower, "property", "og:title");
    let og_description = meta_content(html, &lower, "property", "og:description");
    let industry = jsonld_industry(html, &lower);
    let headings = headings(html, &lower);
    let excerpt = excerpt(html, &lower);

    PageSignals {
        title,
        meta_description,
        og_title,
        og_description,
        industry,
        headings,
        excerpt,
    }
}

/// Contents of the first `<tag ...>...</tag>` occurrence, found via the
/// pre-lowercased copy so the returned slice keeps the original casing.
fn tag_contents(html: &str, lower: &str, open: &str, close: &str) -> Option<String> {
    let start = lower.find(open)?;
    let after_open = lower[start..].find('>')? + start + 1;
    let end = lower[after_open..].find(close)? + after_open;
    let text = html[after_open..end].trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// `content` attribute of the first `<meta>` tag whose `name`/`property`
/// attribute equals `key_value`.
fn meta_content(html: &str, lower: &str, attr: &str, key_value: &str) -> Option<String> {
    let mut offset = 0;
    while let Some(found) = lower[offset..].find("<meta") {
        let start = offset + found;
        let end = lower[start..].find('>')? + start;
        let tag_lower = &lower[start..=end];
        let boundary = format!("{attr}=\"{key_value}\"");
        let matches = tag_lower.contains(&boundary)
            || tag_lower.contains(&format!("{attr} = \"{key_value}\""));
        if matches && let Some(content) = tag_attribute_value(&html[start..=end], "content") {
            return (!content.is_empty()).then_some(content);
        }
        offset = start + 5;
    }
    None
}

/// Value of `attribute="value"` inside one raw tag, original casing.
fn tag_attribute_value(raw_tag: &str, attribute: &str) -> Option<String> {
    let lower = ascii_lower(raw_tag);
    let needle = format!("{attribute}=\"");
    let position = lower.find(&needle)? + needle.len();
    let rest = &raw_tag[position..];
    let end = rest.find('"')?;
    let value = rest[..end].trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// `industry` or `@type` string from the first parseable JSON-LD block.
fn jsonld_industry(html: &str, lower: &str) -> Option<String> {
    let marker = "application/ld+json";
    let mut offset = 0;
    while let Some(found) = lower[offset..].find(marker) {
        let start = offset + found;
        let block_open = lower[start..].find('>')? + start + 1;
        let block_close = lower[block_open..].find("</script>")? + block_open;
        if let Ok(value) =
            serde_json::from_str::<serde_json::Value>(html[block_open..block_close].trim())
            && let Some(industry) = value["industry"].as_str().or(value["@type"].as_str())
        {
            return (!industry.is_empty()).then(|| industry.to_string());
        }
        offset = block_close;
    }
    None
}

/// First H1/H2 heading texts, "; "-joined (capped at five).
fn headings(html: &str, lower: &str) -> Option<String> {
    let mut found = Vec::new();
    for tag in ["<h1", "<h2"] {
        let mut offset = 0;
        while let Some(start_rel) = lower[offset..].find(tag) {
            let start = offset + start_rel;
            let Some(after_open) = lower[start..].find('>') else {
                break;
            };
            let after_open = start + after_open + 1;
            let close = format!("</{}>", &tag[1..]);
            let Some(end_rel) = lower[after_open..].find(&close) else {
                break;
            };
            let end = after_open + end_rel;
            let text = html[after_open..end].trim();
            if !text.is_empty() {
                found.push(text.to_string());
            }
            offset = end + close.len();
            if found.len() >= 5 {
                return Some(found.join("; "));
            }
        }
    }
    (!found.is_empty()).then(|| found.join("; "))
}

/// First ~1 KB of visible body text: head, script and style content
/// removed, tags stripped, whitespace collapsed.
fn excerpt(html: &str, lower: &str) -> Option<String> {
    // Only the body is visible text; head carries title/meta scripts.
    let html = match lower.find("<body") {
        Some(start) => {
            let after_open = lower[start..].find('>').map(|p| start + p + 1);
            match after_open {
                Some(after_open) => {
                    let end = lower[after_open..]
                        .find("</body>")
                        .map(|p| after_open + p)
                        .unwrap_or(html.len());
                    &html[after_open..end]
                }
                None => html,
            }
        }
        None => html,
    };
    let lower = ascii_lower(html);
    let mut cleaned = String::with_capacity(html.len());
    let mut offset = 0;
    loop {
        match lower[offset..].find('<').map(|p| offset + p) {
            Some(start) => {
                cleaned.push_str(&html[offset..start]);
                let after_open = lower[start..]
                    .find('>')
                    .map(|p| start + p + 1)
                    .unwrap_or(html.len());
                let open = &lower[start..after_open.min(lower.len())];
                let close = if open.starts_with("<script") {
                    "</script>"
                } else if open.starts_with("<style") {
                    "</style>"
                } else {
                    ""
                };
                if close.is_empty() {
                    offset = after_open;
                    let name: String = open[1..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric())
                        .collect();
                    if matches!(
                        name.as_str(),
                        "h1" | "h2" | "h3" | "p" | "div" | "li" | "br" | "tr" | "section"
                    ) {
                        cleaned.push('\n');
                    }
                } else {
                    offset = lower[after_open..]
                        .find(close)
                        .map(|p| after_open + p + close.len())
                        .unwrap_or(html.len());
                }
            }
            None => {
                cleaned.push_str(&html[offset..]);
                break;
            }
        }
    }
    let mut result = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut end = 1024.min(result.len());
    while !result.is_char_boundary(end) {
        end -= 1;
    }
    result.truncate(end);
    (!result.is_empty()).then_some(result)
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

    #[test]
    fn excerpt_truncates_on_char_boundary() {
        let html = format!("<body>{}óóóóóó</body>", "x".repeat(1020));
        let excerpt = page_signals(&html).excerpt.expect("excerpt present");
        assert_eq!(excerpt.len(), 1024);
        assert!(excerpt.ends_with("óó"));

        let html = format!("<body>{}óóóóóó</body>", "x".repeat(1021));
        let excerpt = page_signals(&html).excerpt.expect("excerpt present");
        assert_eq!(excerpt.len(), 1023);
        assert!(excerpt.ends_with("xó"));
    }

    #[test]
    fn extracts_all_signals_from_full_markup() {
        let html = r#"<html><head>
            <title>Meridian Bank — Online Banking</title>
            <meta name="description" content="Personal and business banking.">
            <meta property="og:title" content="Meridian Bank">
            <meta property="og:description" content="Banking for everyone.">
            <script type="application/ld+json">{"@type": "BankOrCreditUnion", "industry": "Finance"}</script>
        </head><body>
            <h1>Welcome to Meridian</h1><h2>Accounts</h2>
            <p>Open an account today with low fees and instant approval.</p>
        </body></html>"#;
        let signals = page_signals(html);
        assert_eq!(
            signals.title.as_deref(),
            Some("Meridian Bank — Online Banking")
        );
        assert_eq!(
            signals.meta_description.as_deref(),
            Some("Personal and business banking.")
        );
        assert_eq!(signals.og_title.as_deref(), Some("Meridian Bank"));
        assert_eq!(
            signals.og_description.as_deref(),
            Some("Banking for everyone.")
        );
        assert_eq!(signals.industry.as_deref(), Some("Finance"));
        assert_eq!(
            signals.headings.as_deref(),
            Some("Welcome to Meridian; Accounts")
        );
        assert_eq!(
            signals.excerpt.as_deref(),
            Some(
                "Welcome to Meridian Accounts Open an account today with low fees and instant approval."
            )
        );
        assert!(!signals.is_empty());
    }

    #[test]
    fn thin_shell_yields_nothing() {
        let html = r#"<!DOCTYPE html><html><head><title>allegro.pl</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>"#;
        let signals = page_signals(html);
        assert_eq!(signals.title.as_deref(), Some("allegro.pl"));
        assert_eq!(signals.meta_description, None);
        assert_eq!(signals.industry, None);
        assert_eq!(signals.headings, None);
        assert_eq!(signals.excerpt, None);
    }

    #[test]
    fn absent_meta_tags_do_not_panic() {
        let signals = page_signals("<html><body>plain text only</body></html>");
        assert_eq!(signals.title, None);
        assert_eq!(signals.excerpt.as_deref(), Some("plain text only"));
    }

    #[test]
    fn unicode_expanding_lowercase_does_not_desynchronize_offsets() {
        let title = "İstanbul Bank — Online Banking";
        let html = format!(
            r#"<html><head>
            <title>{title}</title>
            <meta name="description" content="Banking for everyone.">
        </head><body>
            <h1>Merhaba</h1>
            <p>{}İstanbul.</p>
        </body></html>"#,
            "İ".repeat(8)
        );
        let signals = page_signals(&html);
        assert_eq!(signals.title.as_deref(), Some(title));
        assert_eq!(
            signals.meta_description.as_deref(),
            Some("Banking for everyone.")
        );
        assert_eq!(signals.headings.as_deref(), Some("Merhaba"));
        assert!(signals.excerpt.unwrap().contains("İstanbul."));
    }
}
