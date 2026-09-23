use super::Renderer;
use crate::model::{
    Confidence, DomainReport, EmailReport, Infrastructure, MxProbe, PortProbe, SmtpState, TlsState,
    Verdict,
};

pub struct TextRenderer;

const VALUE_COLUMN: usize = 17;

impl Renderer for TextRenderer {
    /// Batch record: the document plus a blank-line separator.
    fn record(&self, report: &DomainReport) -> String {
        format!("{}\n", self.document(report))
    }

    fn document(&self, report: &DomainReport) -> String {
        let mut lines = vec![
            report.domain.clone(),
            format!(
                "checked: {}",
                report.checked_at.format("%Y-%m-%d %H:%M %:z")
            ),
        ];

        lines.push(String::new());
        lines.push("WEB".to_string());
        lines.push("  endpoint".to_string());
        match &report.tls {
            TlsState::Unavailable => {
                lines.push(row(4, "443/tcp", "unreachable"));
            }
            TlsState::Tls(session) => {
                lines.push(row(4, "443/tcp", "reachable"));
                lines.push(row(4, "TLS", &session.version));
                lines.push(row(4, "KX", &session.facts.kx_group));
                lines.push(row(4, "symmetric", session.facts.symmetric_alg.as_str()));
                lines.push(row(4, "PQ", pq(session.is_pq())));
            }
        }

        if report.termination.confidence == Confidence::Confirmed {
            lines.push(String::new());
            lines.push("  termination".to_string());
            lines.push(row(4, "provider", &provider(&report.infrastructure)));
        }

        lines.push(String::new());
        lines.push("  network".to_string());
        lines.push(row(
            4,
            "IP",
            &report
                .resolved_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ));
        lines.push(row(
            4,
            "PTR",
            report
                .evidence
                .ptr
                .as_ref()
                .map(|p| p.record.as_str())
                .unwrap_or("-"),
        ));
        lines.push(row(
            4,
            "ASN",
            report
                .evidence
                .asn
                .as_ref()
                .map(|a| a.asn.as_str())
                .unwrap_or("-"),
        ));
        lines.push(row(
            4,
            "RDAP",
            report
                .evidence
                .rdap
                .as_ref()
                .map(|r| r.netname.as_str())
                .unwrap_or("-"),
        ));

        lines.push(String::new());
        lines.push(String::new());
        lines.push("MAIL".to_string());
        match &report.email {
            None => lines.push("  no MX records".to_string()),
            Some(email) if email.mx.is_empty() => {
                lines.push("  no MX records".to_string());
            }
            Some(email) => {
                for (index, probe) in email.mx.iter().enumerate() {
                    if index > 0 {
                        lines.push(String::new());
                    }
                    lines.extend(mx_lines(probe));
                }
            }
        }

        lines.push(String::new());
        lines.push(String::new());
        lines.push("SUMMARY".to_string());
        lines.push(row(2, "web", &web_summary(report)));
        lines.push(row(2, "mail", &mail_summary(report.email.as_ref())));
        lines.join("\n")
    }

    fn error_record(&self, domain: &str, error: &str) -> String {
        format!("error checking {domain}: {error}")
    }
}

fn row(indent: usize, label: &str, value: &str) -> String {
    let width = VALUE_COLUMN.saturating_sub(indent).max(label.len() + 2);
    format!(
        "{}{label:<width$}{value}",
        " ".repeat(indent),
        width = width
    )
}

fn pq(pq: bool) -> &'static str {
    if pq { "yes" } else { "no" }
}

fn provider(infrastructure: &Infrastructure) -> String {
    match infrastructure.owner {
        crate::model::InfraOwner::Organization => "self".to_string(),
        _ => infrastructure
            .provider
            .clone()
            .unwrap_or_else(|| "-".to_string()),
    }
}

fn mx_lines(probe: &MxProbe) -> Vec<String> {
    let mut lines = vec![format!("  MX {}  {}", probe.priority, probe.host)];
    lines.push(String::new());
    let mut previous_had_rows = false;
    for (index, port_probe) in probe.ports.iter().enumerate() {
        let port_lines = port_lines(port_probe);
        if index > 0 && previous_had_rows {
            lines.push(String::new());
        }
        previous_had_rows = port_lines.len() > 1;
        lines.extend(port_lines);
    }

    lines.push(String::new());
    lines.push("    network".to_string());

    lines.push(row(
        6,
        "IP",
        &probe
            .ip
            .map(|ip: std::net::IpAddr| ip.to_string())
            .unwrap_or_else(|| "-".to_string()),
    ));
    lines.push(row(
        6,
        "PTR",
        probe
            .evidence
            .ptr
            .as_ref()
            .map(|p| p.record.as_str())
            .unwrap_or("-"),
    ));
    lines.push(row(
        6,
        "ASN",
        probe
            .evidence
            .asn
            .as_ref()
            .map(|a| a.asn.as_str())
            .unwrap_or("-"),
    ));
    lines.push(row(
        6,
        "RDAP",
        probe
            .evidence
            .rdap
            .as_ref()
            .map(|r| r.netname.as_str())
            .unwrap_or("-"),
    ));

    lines.push("    attribution".to_string());
    lines.push(row(
        6,
        "infrastructure",
        probe.infrastructure.owner.as_str(),
    ));
    lines.push(row(
        6,
        "provider",
        &probe
            .infrastructure
            .provider
            .clone()
            .unwrap_or_else(|| "-".to_string()),
    ));
    lines.push(row(
        6,
        "confidence",
        probe.infrastructure.confidence.as_str(),
    ));
    lines
}

fn port_lines(port_probe: &PortProbe) -> Vec<String> {
    let label = format!("{}/tcp", port_probe.port.number());
    match &port_probe.state {
        SmtpState::Unreachable => vec![row(4, &label, "unreachable")],
        SmtpState::NoStarttls => {
            let mut lines = vec![row(4, &label, "reachable")];
            if port_probe.port.has_starttls() {
                lines.push(row(6, "STARTTLS", "no"));
            }
            lines
        }
        SmtpState::TlsFailed => {
            let mut lines = vec![row(4, &label, "reachable")];
            if port_probe.port.has_starttls() {
                lines.push(row(6, "STARTTLS", "yes"));
            }
            lines.push(row(6, "TLS", "failed"));
            lines
        }
        SmtpState::Tls(session) => {
            let mut lines = vec![row(4, &label, "reachable")];
            if port_probe.port.has_starttls() {
                lines.push(row(6, "STARTTLS", "yes"));
            }
            lines.push(row(6, "TLS", &session.version));
            lines.push(row(6, "KX", &session.facts.kx_group));
            lines.push(row(6, "symmetric", session.facts.symmetric_alg.as_str()));
            lines.push(row(6, "PQ", pq(session.is_pq())));
            lines
        }
    }
}

fn web_summary(report: &DomainReport) -> String {
    let crypto = match &report.tls {
        crate::model::TlsState::Tls(session) if session.is_pq() => "PQ",
        crate::model::TlsState::Tls(_) => "classical",
        crate::model::TlsState::Unavailable => return "web TLS unreachable".to_string(),
    };
    let provider = report
        .infrastructure
        .provider
        .as_deref()
        .unwrap_or("external");
    match report.verdict {
        Verdict::PqAtEdge | Verdict::NoPqAtEdge => {
            format!("{crypto} TLS at {provider} edge")
        }
        Verdict::PqLikelyAtEdge | Verdict::NoPqLikelyAtEdge => {
            format!("{crypto} TLS likely terminating at {provider} edge")
        }
        Verdict::PqOnOrgInfra | Verdict::NoPqOnOrgInfra => {
            format!("{crypto} TLS on organization-attributed infrastructure")
        }
        Verdict::PqOnThirdPartyInfra | Verdict::NoPqOnThirdPartyInfra => {
            format!("{crypto} TLS on {provider} infrastructure")
        }
        Verdict::PqUnattributed | Verdict::NoPqUnattributed => {
            format!("{crypto} TLS; infrastructure could not be attributed")
        }
        Verdict::TlsUnavailable => "web TLS unreachable".to_string(),
    }
}

fn mail_summary(email: Option<&EmailReport>) -> String {
    let Some(email) = email else {
        return "no MX records".to_string();
    };
    let states: Vec<&SmtpState> = email
        .mx
        .iter()
        .flat_map(|probe| probe.ports.iter().map(|port| &port.state))
        .collect();
    if states.is_empty() {
        return "no MX records".to_string();
    }
    if states
        .iter()
        .any(|state| matches!(state, SmtpState::Tls(session) if session.is_pq()))
    {
        return "PQ enabled".to_string();
    }
    if states
        .iter()
        .any(|state| matches!(state, SmtpState::Tls(_)))
    {
        return "classical TLS only".to_string();
    }
    if states
        .iter()
        .any(|state| matches!(state, SmtpState::TlsFailed))
    {
        return "TLS failed".to_string();
    }
    if states
        .iter()
        .any(|state| matches!(state, SmtpState::NoStarttls))
    {
        return "no TLS".to_string();
    }
    "unreachable".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AsnEvidence, CertEvidence, Evidence, Port, PtrEvidence, SymmetricAlg, TlsFacts, TlsSession,
        fixture,
    };

    fn session(version: &str, kx_group: &str) -> TlsSession {
        TlsSession {
            version: version.to_string(),
            facts: TlsFacts {
                kx_group: kx_group.to_string(),
                symmetric_alg: SymmetricAlg::Aes256,
            },
        }
    }

    #[test]
    fn document_renders_web_sections_and_summary() {
        let text = TextRenderer.document(&fixture());

        let expected = [
            "citibankonline.pl",
            "WEB",
            "  endpoint",
            "    443/tcp      reachable",
            "    TLS          TLS 1.2",
            "    KX           X25519",
            "    symmetric    AES-256",
            "    PQ           no",
            "  termination",
            "    provider     Akamai",
            "  network",
            "    IP           104.96.178.165",
            "    PTR          a104-96-178-165.deploy.static.akamaitechnologies.com",
            "    ASN          AS20940 AKAMAI-ASN1",
            "    RDAP         AKAMAI",
            "SUMMARY",
            "  web            classical TLS at Akamai edge",
        ];
        for line in expected {
            assert!(text.contains(line), "missing line: {line}");
        }
    }

    #[test]
    fn checked_line_uses_minute_precision() {
        let text = TextRenderer.document(&fixture());
        assert!(text.starts_with("citibankonline.pl\nchecked: "));
        assert!(!text.contains("checked_at:"));
    }

    #[test]
    fn web_tls_unreachable_renders_bare_endpoint() {
        let report = DomainReport::build(
            "gorlice.pinb.gov.pl".to_string(),
            None,
            TlsState::Unavailable,
            Evidence::default(),
            None,
            chrono::Local::now(),
        );
        let text = TextRenderer.document(&report);
        assert!(text.contains("    443/tcp      unreachable"));
        assert!(!text.contains("KX"));
        assert!(!text.contains("PQ"));
        assert!(!text.contains("  termination"));
        assert!(text.contains("    IP           -"));
        assert!(text.contains("  web            web TLS unreachable"));
        assert!(text.contains("  mail           no MX records"));
    }

    fn mx(ports: Vec<(Port, SmtpState)>, priority: u16, host: &str) -> MxProbe {
        MxProbe {
            priority,
            host: host.to_string(),
            addresses: vec!["192.0.2.1".parse().unwrap()],
            ip: Some("192.0.2.1".parse().unwrap()),
            infrastructure: crate::model::Infrastructure {
                owner: crate::model::InfraOwner::Organization,
                provider: None,
                org_score: 4,
                third_party_score: 0,
                confidence: crate::model::Confidence::Confirmed,
            },
            ports: ports
                .into_iter()
                .map(|(port, state)| PortProbe { port, state })
                .collect(),
            evidence: Evidence {
                cert: Some(CertEvidence {
                    name: host.to_string(),
                    vendor: None,
                    names: vec![host.to_string()],
                }),
                ptr: Some(PtrEvidence {
                    record: format!("ptr.{host}"),
                    vendor: None,
                }),
                asn: Some(AsnEvidence {
                    asn: "AS64512 EXAMPLE-AS".to_string(),
                    vendor: None,
                }),
                rdap: Some(crate::model::RdapEvidence {
                    netname: "EXAMPLE-NET".to_string(),
                    vendor: None,
                }),
                ..Default::default()
            },
        }
    }

    fn email_report(mx: Vec<MxProbe>) -> DomainReport {
        let mut report = fixture();
        report.email = Some(EmailReport { mx });
        report
    }

    #[test]
    fn mail_section_matches_layout() {
        let probe = mx(
            vec![
                (Port::Smtp25, SmtpState::Unreachable),
                (
                    Port::Submission587,
                    SmtpState::Tls(session("TLS 1.3", "X25519")),
                ),
                (Port::Smtps465, SmtpState::Tls(session("TLS 1.3", "X25519"))),
            ],
            10,
            "mx1.example.pl",
        );
        let text = TextRenderer.document(&email_report(vec![probe]));

        let expected = [
            "MAIL",
            "  MX 10  mx1.example.pl",
            "    25/tcp       unreachable",
            "    587/tcp      reachable",
            "      STARTTLS   yes",
            "      TLS        TLS 1.3",
            "      KX         X25519",
            "      symmetric  AES-256",
            "      PQ         no",
            "    465/tcp      reachable",
            "      TLS        TLS 1.3",
            "      KX         X25519",
            "    network",
            "      IP         192.0.2.1",
            "      PTR        ptr.mx1.example.pl",
            "      ASN        AS64512 EXAMPLE-AS",
            "      RDAP       EXAMPLE-NET",
            "    attribution",
            "      infrastructure  organization",
            "      provider   -",
            "      confidence  confirmed",
            "SUMMARY",
            "  mail           classical TLS only",
        ];
        for line in expected {
            assert!(text.contains(line), "missing line: {line}");
        }
        let mail_section = text.split("MAIL").nth(1).unwrap();
        assert!(!mail_section.contains("25/tcp\n    587"));
    }

    #[test]
    fn pq_session_reports_yes_and_summary_says_pq_enabled() {
        let probe = mx(
            vec![(
                Port::Smtp25,
                SmtpState::Tls(session("TLS 1.3", "X25519MLKEM768")),
            )],
            10,
            "mx1.example.pl",
        );
        let text = TextRenderer.document(&email_report(vec![probe]));
        assert!(text.contains("      KX         X25519MLKEM768"));
        assert!(text.contains("      PQ         yes"));
        assert!(text.contains("  mail           PQ enabled"));
    }

    #[test]
    fn smtps_465_never_renders_a_starttls_line() {
        let probe = mx(
            vec![(Port::Smtps465, SmtpState::TlsFailed)],
            10,
            "mail.example.com",
        );
        let text = TextRenderer.document(&email_report(vec![probe]));
        let mail_section = text.split("MAIL").nth(1).unwrap();
        assert!(mail_section.contains("    465/tcp      reachable"));
        assert!(mail_section.contains("      TLS        failed"));
        assert!(!mail_section.contains("STARTTLS"));
        assert!(text.contains("  mail           TLS failed"));
    }

    #[test]
    fn starttls_absent_and_all_unreachable_summaries() {
        let report = email_report(vec![
            mx(
                vec![(Port::Smtp25, SmtpState::NoStarttls)],
                10,
                "mx1.example.pl",
            ),
            mx(
                vec![(Port::Smtp25, SmtpState::Unreachable)],
                20,
                "mx2.example.pl",
            ),
        ]);
        let text = TextRenderer.document(&report);
        assert!(text.contains("    25/tcp       reachable\n      STARTTLS   no"));
        assert!(text.contains("  mail           no TLS"));

        let report = email_report(vec![mx(
            vec![
                (Port::Smtp25, SmtpState::Unreachable),
                (Port::Submission587, SmtpState::Unreachable),
                (Port::Smtps465, SmtpState::Unreachable),
            ],
            10,
            "mx1.example.pl",
        )]);
        let text = TextRenderer.document(&report);
        assert!(text.contains("  mail           unreachable"));
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
