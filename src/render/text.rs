use std::collections::HashMap;

use super::Renderer;
use crate::model::{DomainReport, Operator, SignalType, Signals, registrable_zone};

pub struct TextRenderer;

impl Renderer for TextRenderer {
    /// Batch record: the document plus a blank-line separator.
    fn record(&self, report: &DomainReport) -> String {
        format!("{}\n", self.document(report))
    }

    fn document(&self, report: &DomainReport) -> String {
        let e = &report.evidence;
        let zone = registrable_zone(&report.domain).unwrap_or_default();
        let attributed: HashMap<SignalType, Operator> = report
            .evidence
            .signals(&report.domain)
            .into_iter()
            .map(|s| (s.kind, s.operator))
            .collect();
        let slot = |kind: SignalType| attributed.get(&kind).copied();
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
                slot(SignalType::Cname),
            ),
            evidence_line(
                SignalType::Range.as_str(),
                e.range.as_ref().map(|r| r.cidr.as_str()),
                slot(SignalType::Range),
            ),
            evidence_line(
                SignalType::Cert.as_str(),
                e.cert.as_ref().map(|c| c.name.as_str()),
                slot(SignalType::Cert),
            ),
            evidence_line(
                SignalType::Http.as_str(),
                e.http.as_ref().map(|h| h.header.as_str()),
                slot(SignalType::Http),
            ),
            evidence_line(
                SignalType::Ptr.as_str(),
                e.ptr.as_ref().map(|p| p.record.as_str()),
                slot(SignalType::Ptr),
            ),
            evidence_line(
                SignalType::Rdap.as_str(),
                e.rdap.as_ref().map(|r| r.netname.as_str()),
                slot(SignalType::Rdap),
            ),
            evidence_line(
                SignalType::Asn.as_str(),
                e.asn.as_ref().map(|a| a.asn.as_str()),
                slot(SignalType::Asn),
            ),
            String::new(),
            "signals:".to_string(),
            signals_line("termination:", &report.termination, &zone),
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

fn evidence_line(kind: &str, value: Option<&str>, operator: Option<Operator>) -> String {
    let value = value.unwrap_or("(none)");
    match operator {
        Some(operator) => format!("  {kind:<6}{value} -> {}", operator.short()),
        None => format!("  {kind:<6}{value}"),
    }
}

fn signals_line(label: &str, signals: &Signals, zone: &str) -> String {
    let subject = match &signals.operator {
        Some(operator) => operator.label(zone),
        None if !signals.candidates.is_empty() => {
            let names = signals
                .candidates
                .iter()
                .map(|op| op.short())
                .collect::<Vec<_>>()
                .join(", ");
            format!("candidates: {names}")
        }
        None => "unresolved".to_string(),
    };
    format!(
        "  {label:<13}{subject} (signals: {}, classes: {}, confidence: {})",
        signals.signal_count, signals.class_count, signals.confidence,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AsnEvidence, CertEvidence, CnameEvidence, Evidence, PtrEvidence, RdapEvidence,
        SymmetricAlg, TlsFacts, Vendor, fixture,
    };

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
            "  termination: Akamai (signals: 4, classes: 2, confidence: confirmed)",
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
    fn document_marks_self_attribution_for_own_infrastructure() {
        let report = DomainReport::build(
            "upload.allegro.pl".to_string(),
            None,
            TlsFacts {
                kx_group: "X25519".to_string(),
                symmetric_alg: SymmetricAlg::Aes256,
            },
            Evidence {
                cname: Some(CnameEvidence {
                    chain: vec!["upload.allegro.pl".to_string()],
                    vendor: None,
                }),
                cert: Some(CertEvidence {
                    name: "edge.business.allegro.pl".to_string(),
                    vendor: None,
                }),
                ptr: Some(PtrEvidence {
                    record: "upload.allegro.com.cz".to_string(),
                    vendor: None,
                }),
                rdap: Some(RdapEvidence {
                    netname: "ALLEGRO-NET".to_string(),
                    vendor: None,
                }),
                asn: Some(AsnEvidence {
                    asn: "AS42656 QXL-POLAND".to_string(),
                    vendor: None,
                }),
                ..Default::default()
            },
            chrono::Local::now(),
        );
        let text = TextRenderer.document(&report);
        assert!(text.contains("  CNAME upload.allegro.pl -> self"));
        assert!(text.contains("  CERT  edge.business.allegro.pl\n"));
        assert!(text.contains("  PTR   upload.allegro.com.cz\n"));
        assert!(text.contains("  RDAP  ALLEGRO-NET -> self"));
        assert!(text.contains("  ASN   AS42656 QXL-POLAND\n"));
        assert!(text.contains(
            "  termination: self (allegro.pl) (signals: 2, classes: 2, confidence: confirmed)"
        ));
        assert!(text.contains("verdict:       no_pq_own_infra"));
    }

    #[test]
    fn document_reports_candidates_when_attribution_is_contested() {
        let report = DomainReport::build(
            "www.allegro.pl".to_string(),
            None,
            TlsFacts {
                kx_group: "X25519".to_string(),
                symmetric_alg: SymmetricAlg::Aes256,
            },
            Evidence {
                rdap: Some(RdapEvidence {
                    netname: "ALLEGRO-HOSTING".to_string(),
                    vendor: None,
                }),
                asn: Some(AsnEvidence {
                    asn: "AS396982 GOOGLE-CLOUD-PLATFORM".to_string(),
                    vendor: Some(Vendor::GoogleCloud),
                }),
                ..Default::default()
            },
            chrono::Local::now(),
        );
        let text = TextRenderer.document(&report);
        assert!(text.contains("  RDAP  ALLEGRO-HOSTING -> self"));
        assert!(text.contains("  ASN   AS396982 GOOGLE-CLOUD-PLATFORM -> Google Cloud"));
        assert!(text.contains(
            "  termination: candidates: self, Google Cloud (signals: 2, classes: 1, confidence: undecided)"
        ));
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
