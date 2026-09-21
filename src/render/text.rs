use super::Renderer;
use crate::model::{DomainReport, SignalType, Signals, Vendor};

/// Human-readable presentation. Mirrors the JSON semantics:
/// the value is the raw observation, `-> Vendor` marks a signal,
/// `(none)` means nothing was observed for the slot.
pub struct TextRenderer;

impl Renderer for TextRenderer {
    /// Batch record: the document plus a blank-line separator.
    fn record(&self, report: &DomainReport) -> String {
        format!("{}\n", self.document(report))
    }

    fn document(&self, report: &DomainReport) -> String {
        let e = &report.evidence;
        let cname_value = e.cname.as_ref().map(|c| c.chain_text());
        let lines = vec![
            field("domain:", &report.domain),
            field(
                "checked_at:",
                &report.checked_at.format("%Y-%m-%d %H:%M:%S %Z").to_string(),
            ),
            field(
                "resolved_ip:",
                &report
                    .resolved_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "(unresolved)".to_string()),
            ),
            field(
                "kx group:",
                &format!(
                    "{} ({})",
                    report.tls.kx_group,
                    if report.tls.is_pq() { "PQ" } else { "no PQ" }
                ),
            ),
            field("symmetric_alg:", &report.tls.symmetric_alg.to_string()),
            String::new(),
            "evidence:".to_string(),
            evidence_line(
                SignalType::Cname.as_str(),
                cname_value.as_deref(),
                e.cname.as_ref().and_then(|c| c.vendor),
            ),
            evidence_line(
                SignalType::Range.as_str(),
                e.range.as_ref().map(|r| r.cidr.as_str()),
                e.range.as_ref().map(|r| r.vendor),
            ),
            evidence_line(
                SignalType::Cert.as_str(),
                e.cert.as_ref().map(|c| c.name.as_str()),
                e.cert.as_ref().and_then(|c| c.vendor),
            ),
            evidence_line(
                SignalType::Http.as_str(),
                e.http.as_ref().map(|h| h.header.as_str()),
                e.http.as_ref().map(|h| h.vendor),
            ),
            evidence_line(
                SignalType::Ptr.as_str(),
                e.ptr.as_ref().map(|p| p.record.as_str()),
                e.ptr.as_ref().and_then(|p| p.vendor),
            ),
            evidence_line(
                SignalType::Rdap.as_str(),
                e.rdap.as_ref().map(|r| r.netname.as_str()),
                e.rdap.as_ref().and_then(|r| r.vendor),
            ),
            evidence_line(
                SignalType::Asn.as_str(),
                e.asn.as_ref().map(|a| a.asn.as_str()),
                e.asn.as_ref().and_then(|a| a.vendor),
            ),
            String::new(),
            "signals:".to_string(),
            signals_line("infra:", &report.infra),
            signals_line("edge:", &report.edge),
            String::new(),
            field("verdict:", &report.verdict.to_string()),
        ];
        lines.join("\n")
    }

    fn error_record(&self, domain: &str, error: &str) -> String {
        format!("error checking {domain}: {error}")
    }
}

fn field(label: &str, value: &str) -> String {
    format!("{label:<15}{value}")
}

fn evidence_line(kind: &str, value: Option<&str>, vendor: Option<Vendor>) -> String {
    let value = value.unwrap_or("(none)");
    match vendor {
        Some(vendor) => format!("  {kind:<6}{value} -> {vendor}"),
        None => format!("  {kind:<6}{value}"),
    }
}

fn signals_line(label: &str, signals: &Signals) -> String {
    let vendor = signals.vendor.map(|v| v.as_str()).unwrap_or("(none)");
    format!(
        "  {label:<7}{vendor} (signals: {}, classes: {}, confidence: {})",
        signals.signal_count, signals.class_count, signals.confidence,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CnameEvidence, Evidence, SymmetricAlg, TlsFacts, Vendor, fixture};

    #[test]
    fn document_renders_all_slots_with_values_and_signals() {
        let text = TextRenderer.document(&fixture());

        let expected = [
            "domain:        citibankonline.pl",
            "resolved_ip:   104.96.178.165",
            "kx group:      X25519 (no PQ)",
            "symmetric_alg: AES256",
            "evidence:",
            "  CNAME (none)",
            "  RANGE (none)",
            "  CERT  www.citi.com",
            "  HTTP  X-Akamai-Request-ID -> Akamai",
            "  PTR   a104-96-178-165.deploy.static.akamaitechnologies.com -> Akamai",
            "  RDAP  AKAMAI -> Akamai",
            "  ASN   AS20940 AKAMAI-ASN1 -> Akamai",
            "signals:",
            "  infra: Akamai (signals: 4, classes: 2, confidence: confirmed)",
            "  edge:  Akamai (signals: 4, classes: 2, confidence: confirmed)",
            "verdict:       no_pq_edge (The public connection terminates at an identified edge/CDN/security provider, but no post-quantum key exchange was observed.)",
        ];
        for line in expected {
            assert!(text.contains(line), "missing line: {line}");
        }
        assert!(text.contains("checked_at: "));
        assert!(!text.contains("TLD:"));
        assert!(!text.ends_with('\n'));
    }

    #[test]
    fn cname_chain_renders_as_one_value() {
        let report = DomainReport::build(
            "www.example.com".to_string(),
            None,
            TlsFacts {
                kx_group: "X25519".to_string(),
                symmetric_alg: SymmetricAlg::Aes256,
            },
            Evidence {
                cname: Some(CnameEvidence {
                    chain: vec![
                        "www.example.com.glb.example.org".to_string(),
                        "www.example.com.edgekey.net".to_string(),
                        "e970.dspg.akamaiedge.net".to_string(),
                    ],
                    vendor: Some(Vendor::Akamai),
                }),
                ..Default::default()
            },
            chrono::Local::now(),
        );
        let text = TextRenderer.document(&report);
        assert!(text.contains("  CNAME www.example.com.glb.example.org -> www.example.com.edgekey.net -> e970.dspg.akamaiedge.net -> Akamai"));
    }

    #[test]
    fn record_adds_a_blank_line_for_batch_separation() {
        let record = TextRenderer.record(&fixture());
        assert!(record.ends_with('\n'));
        assert_eq!(record, format!("{}\n", TextRenderer.document(&fixture())));
    }

    #[test]
    fn error_record_is_one_line() {
        assert_eq!(
            TextRenderer.error_record("x.invalid", "no route"),
            "error checking x.invalid: no route"
        );
    }
}
