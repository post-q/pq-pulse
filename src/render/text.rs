use super::Renderer;
use crate::model::{Attribution, DomainReport, SignalType, Vendor};

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
                e.cname.as_ref().map(|c| c.target.as_str()),
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
                SignalType::Ptr.as_str(),
                e.ptr.as_ref().map(|p| p.record.as_str()),
                e.ptr.as_ref().and_then(|p| p.vendor),
            ),
            evidence_line(
                SignalType::Rdap.as_str(),
                e.rdap.as_ref().map(|r| r.netname.as_str()),
                e.rdap.as_ref().and_then(|r| r.vendor),
            ),
            String::new(),
            "attribution:".to_string(),
            attribution_line("infra:", &report.infra),
            attribution_line("edge:", &report.edge),
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

fn attribution_line(label: &str, attribution: &Attribution) -> String {
    let vendor = attribution.vendor.map(|v| v.as_str()).unwrap_or("(none)");
    format!(
        "  {label:<7}{vendor} (signals: {}, classes: {}, confidence: {})",
        attribution.signal_count, attribution.class_count, attribution.confidence,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::fixture;

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
            "  PTR   a104-96-178-165.deploy.static.akamaitechnologies.com -> Akamai",
            "  RDAP  AKAMAI -> Akamai",
            "attribution:",
            "  infra: Akamai (signals: 2, classes: 1, confidence: probable)",
            "  edge:  Akamai (signals: 2, classes: 1, confidence: probable)",
            "verdict:       no_pq_edge (classical key exchange, TLS terminated by an identified edge vendor)",
        ];
        for line in expected {
            assert!(text.contains(line), "missing line: {line}");
        }
        assert!(text.contains("checked_at: "));
        assert!(!text.contains("TLD:"));
        assert!(!text.ends_with('\n'));
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
