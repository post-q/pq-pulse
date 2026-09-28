use serde::Serialize;
use std::borrow::Cow;

use super::Renderer;
use crate::model::{
    DomainReport, EmailReport, Infrastructure, MxProbe, Port, PortProbe, SmtpState, Termination,
    TlsState,
};

pub struct JsonRenderer;

#[derive(Serialize)]
struct SignalDto<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    value: Option<Cow<'a, str>>,
    operator: Option<&'a str>,
}

#[derive(Serialize)]
struct TlsDto<'a> {
    version: &'a str,
    kx_group: &'a str,
    symmetric_alg: &'a str,
    pq: bool,
}

#[derive(Serialize)]
struct InfrastructureDto {
    owner: &'static str,
    operator: Option<String>,
    provider: Option<String>,
    target_matches: u32,
    other_matches: u32,
    confidence: &'static str,
}

#[derive(Serialize)]
struct TerminationDto {
    role: &'static str,
    confidence: &'static str,
    edge_classes: Vec<&'static str>,
}

#[derive(Serialize)]
struct PortDto<'a> {
    port: u16,
    reachable: bool,
    starttls: Option<&'static str>,
    tls: Option<TlsDto<'a>>,
}

#[derive(Serialize)]
struct MxDto<'a> {
    priority: u16,
    host: &'a str,
    addresses: Vec<String>,
    ports: Vec<PortDto<'a>>,
    certificate: Option<&'a str>,
    ptr: Option<&'a str>,
    asn: Option<&'a str>,
    infrastructure: InfrastructureDto,
}

#[derive(Serialize)]
struct EmailDto<'a> {
    mx: Vec<MxDto<'a>>,
}

#[derive(Serialize)]
struct ReportDto<'a> {
    domain: &'a str,
    status: &'static str,
    checked_at: String,
    resolved_ip: Option<String>,
    tls: Option<TlsDto<'a>>,
    evidence: Vec<SignalDto<'a>>,
    infrastructure: InfrastructureDto,
    termination: TerminationDto,
    verdict: &'a str,
    email: Option<EmailDto<'a>>,
}

#[derive(Serialize)]
struct ErrorDto {
    domain: String,
    status: &'static str,
    checked_at: String,
    error: String,
}

impl JsonRenderer {
    fn report_dto(report: &DomainReport) -> ReportDto<'_> {
        ReportDto {
            domain: &report.domain,
            status: "ok",
            checked_at: report.checked_at.to_rfc3339(),
            resolved_ip: report.resolved_ip.map(|ip| ip.to_string()),
            tls: match &report.tls {
                TlsState::Unavailable => None,
                TlsState::Tls(session) => Some(TlsDto {
                    version: &session.version,
                    kx_group: &session.facts.kx_group,
                    symmetric_alg: session.facts.symmetric_alg.as_str(),
                    pq: session.is_pq(),
                }),
            },
            evidence: Self::signal_dtos(report),
            infrastructure: Self::infrastructure_dto(&report.infrastructure),
            termination: Self::termination_dto(&report.termination),
            verdict: report.verdict.as_str(),
            email: report.email.as_ref().map(Self::email_dto),
        }
    }

    fn infrastructure_dto(infrastructure: &Infrastructure) -> InfrastructureDto {
        InfrastructureDto {
            owner: infrastructure.owner.as_str(),
            operator: infrastructure.operator.clone(),
            provider: infrastructure.provider.clone(),
            target_matches: infrastructure.target_matches,
            other_matches: infrastructure.other_matches,
            confidence: infrastructure.confidence.as_str(),
        }
    }

    fn termination_dto(termination: &Termination) -> TerminationDto {
        TerminationDto {
            role: termination.role.as_str(),
            confidence: termination.confidence.as_str(),
            edge_classes: termination
                .edge_classes
                .iter()
                .map(|signal| signal.as_str())
                .collect(),
        }
    }

    fn email_dto(email: &EmailReport) -> EmailDto<'_> {
        EmailDto {
            mx: email.mx.iter().map(Self::mx_dto).collect(),
        }
    }

    fn port_dto(port_probe: &PortProbe) -> PortDto<'_> {
        let reachable = !matches!(port_probe.state, SmtpState::Unreachable);
        let starttls = match (&port_probe.port, &port_probe.state) {
            (Port::Smtps465, _) => None,
            (_, SmtpState::Unreachable) => None,
            (_, SmtpState::NoStarttls) => Some("no"),
            (_, SmtpState::TlsFailed | SmtpState::Tls(_)) => Some("yes"),
        };
        let tls = match &port_probe.state {
            SmtpState::Tls(session) => Some(TlsDto {
                version: &session.version,
                kx_group: &session.facts.kx_group,
                symmetric_alg: session.facts.symmetric_alg.as_str(),
                pq: session.is_pq(),
            }),
            _ => None,
        };
        PortDto {
            port: port_probe.port.number(),
            reachable,
            starttls,
            tls,
        }
    }

    fn mx_dto(probe: &MxProbe) -> MxDto<'_> {
        MxDto {
            priority: probe.priority,
            host: &probe.host,
            addresses: probe.addresses.iter().map(|ip| ip.to_string()).collect(),
            ports: probe.ports.iter().map(Self::port_dto).collect(),
            certificate: probe.evidence.cert.as_ref().map(|c| c.name.as_str()),
            ptr: probe.evidence.ptr.as_ref().map(|p| p.record.as_str()),
            asn: probe.evidence.asn.as_ref().map(|a| a.asn.as_str()),
            infrastructure: Self::infrastructure_dto(&probe.infrastructure),
        }
    }

    /// The seven evidence slots in a fixed order, present even when empty
    /// (value and operator null) so consumers can index positionally.
    fn signal_dtos(report: &DomainReport) -> Vec<SignalDto<'_>> {
        let e = &report.evidence;
        let cname_value = e.cname.as_ref().map(|c| c.chain_text());
        vec![
            SignalDto {
                kind: "CNAME",
                value: cname_value.map(Cow::Owned),
                operator: e
                    .cname
                    .as_ref()
                    .and_then(|c| c.vendor)
                    .map(|vendor| vendor.as_str()),
            },
            SignalDto {
                kind: "RANGE",
                value: e.range.as_ref().map(|r| Cow::Borrowed(r.cidr.as_str())),
                operator: e.range.as_ref().map(|r| r.vendor.as_str()),
            },
            SignalDto {
                kind: "CERT",
                value: e.cert.as_ref().map(|c| Cow::Borrowed(c.name.as_str())),
                operator: e
                    .cert
                    .as_ref()
                    .and_then(|c| c.vendor)
                    .map(|vendor| vendor.as_str()),
            },
            SignalDto {
                kind: "HTTP",
                value: e.http.as_ref().map(|h| Cow::Borrowed(h.header.as_str())),
                operator: e.http.as_ref().map(|h| h.vendor.as_str()),
            },
            SignalDto {
                kind: "PTR",
                value: e.ptr.as_ref().map(|p| Cow::Borrowed(p.record.as_str())),
                operator: e
                    .ptr
                    .as_ref()
                    .and_then(|p| p.vendor)
                    .map(|vendor| vendor.as_str()),
            },
            SignalDto {
                kind: "RDAP",
                value: e.rdap.as_ref().map(|r| Cow::Borrowed(r.netname.as_str())),
                operator: e
                    .rdap
                    .as_ref()
                    .and_then(|r| r.vendor)
                    .map(|vendor| vendor.as_str()),
            },
            SignalDto {
                kind: "ASN",
                value: e.asn.as_ref().map(|a| Cow::Borrowed(a.asn.as_str())),
                operator: e
                    .asn
                    .as_ref()
                    .and_then(|a| a.vendor)
                    .map(|vendor| vendor.as_str()),
            },
        ]
    }

    fn error_dto(domain: &str, error: &str) -> ErrorDto {
        ErrorDto {
            domain: domain.to_string(),
            status: "error",
            checked_at: chrono::Local::now().to_rfc3339(),
            error: error.to_string(),
        }
    }
}

impl Renderer for JsonRenderer {
    fn record(&self, report: &DomainReport) -> String {
        serde_json::to_string(&Self::report_dto(report)).expect("report serialization cannot fail")
    }

    fn document(&self, report: &DomainReport) -> String {
        serde_json::to_string_pretty(&Self::report_dto(report))
            .expect("report serialization cannot fail")
    }

    fn error_record(&self, domain: &str, error: &str) -> String {
        serde_json::to_string(&Self::error_dto(domain, error))
            .expect("error serialization cannot fail")
    }

    fn error_document(&self, domain: &str, error: &str) -> String {
        serde_json::to_string_pretty(&Self::error_dto(domain, error))
            .expect("error serialization cannot fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::fixture;
    use serde_json::Value;

    #[test]
    fn record_is_one_line_with_meaningful_values() {
        let line = JsonRenderer.record(&fixture());
        assert!(!line.contains('\n'));

        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["domain"], "citibankonline.pl");
        assert_eq!(value["status"], "ok");
        assert_eq!(value["resolved_ip"], "104.96.178.165");
        assert_eq!(value["tls"]["kx_group"], "X25519");
        assert_eq!(value["tls"]["symmetric_alg"], "AES-256");
        assert_eq!(value["tls"]["pq"], false);

        let signals = value["evidence"].as_array().unwrap();
        assert_eq!(signals.len(), 7);
        assert_eq!(signals[0]["type"], "CNAME");
        assert!(signals[0]["value"].is_null());
        assert_eq!(signals[1]["type"], "RANGE");
        assert_eq!(signals[2]["type"], "CERT");
        assert_eq!(signals[2]["value"], "www.citi.com");
        assert!(signals[2]["operator"].is_null());
        assert_eq!(signals[3]["type"], "HTTP");
        assert_eq!(signals[3]["value"], "X-Akamai-Request-ID");
        assert_eq!(signals[3]["operator"], "Akamai");
        assert_eq!(signals[4]["type"], "PTR");
        assert_eq!(
            signals[4]["value"],
            "a104-96-178-165.deploy.static.akamaitechnologies.com"
        );
        assert_eq!(signals[4]["operator"], "Akamai");
        assert_eq!(signals[5]["type"], "RDAP");
        assert_eq!(signals[5]["value"], "AKAMAI");
        assert_eq!(signals[5]["operator"], "Akamai");
        assert_eq!(signals[6]["type"], "ASN");
        assert_eq!(signals[6]["value"], "AS20940 AKAMAI-ASN1");
        assert_eq!(signals[6]["operator"], "Akamai");

        let infrastructure = &value["infrastructure"];
        assert_eq!(infrastructure["owner"], "third-party");
        assert_eq!(infrastructure["provider"], "Akamai");
        assert_eq!(infrastructure["confidence"], "confirmed");
        let termination = &value["termination"];
        assert_eq!(termination["role"], "edge");
        assert_eq!(termination["confidence"], "confirmed");
        assert_eq!(termination["edge_classes"].as_array().unwrap().len(), 2);
        assert_eq!(value["verdict"], "classical_at_edge");
    }

    #[test]
    fn json_marks_ambiguous_when_attribution_is_contested() {
        let report = crate::model::DomainReport::build(
            "www.allegro.pl".to_string(),
            None,
            crate::model::TlsState::Tls(crate::model::TlsSession {
                version: "TLS 1.3".to_string(),
                facts: crate::model::TlsFacts {
                    kx_group: "X25519".to_string(),
                    symmetric_alg: crate::model::SymmetricAlg::Aes256,
                },
            }),
            crate::model::Evidence {
                cname: Some(crate::model::CnameEvidence {
                    chain: vec!["www.allegro.pl".to_string()],
                    vendor: None,
                }),
                rdap: Some(crate::model::RdapEvidence {
                    netname: "ALLEGRO-HOSTING".to_string(),
                    vendor: None,
                }),
                asn: Some(crate::model::AsnEvidence {
                    asn: "AS396982 GOOGLE-CLOUD-PLATFORM".to_string(),
                    vendor: Some(crate::model::Vendor::GoogleCloud),
                }),
                ..Default::default()
            },
            None,
            chrono::Local::now(),
        );
        let value: Value = serde_json::from_str(&JsonRenderer.document(&report)).unwrap();
        let infrastructure = &value["infrastructure"];
        assert_eq!(infrastructure["owner"], "ambiguous");
        assert_eq!(infrastructure["target_matches"], 2);
        assert_eq!(infrastructure["other_matches"], 1);
        assert_eq!(infrastructure["confidence"], "mixed");
        assert_eq!(value["verdict"], "classical_unattributed");
    }

    #[test]
    fn json_marks_organization_owner_for_own_infrastructure() {
        let report = crate::model::DomainReport::build(
            "upload.allegro.pl".to_string(),
            None,
            crate::model::TlsState::Tls(crate::model::TlsSession {
                version: "TLS 1.3".to_string(),
                facts: crate::model::TlsFacts {
                    kx_group: "X25519".to_string(),
                    symmetric_alg: crate::model::SymmetricAlg::Aes256,
                },
            }),
            crate::model::Evidence {
                cname: Some(crate::model::CnameEvidence {
                    chain: vec!["upload.allegro.pl".to_string()],
                    vendor: None,
                }),
                cert: Some(crate::model::CertEvidence {
                    name: "edge.business.allegro.pl".to_string(),
                    vendor: None,
                    names: vec!["edge.business.allegro.pl".to_string()],
                    issuer_cn: None,
                }),
                rdap: Some(crate::model::RdapEvidence {
                    netname: "ALLEGRO-NET".to_string(),
                    vendor: None,
                }),
                asn: Some(crate::model::AsnEvidence {
                    asn: "AS42656 ALLEGRO".to_string(),
                    vendor: None,
                }),
                ..Default::default()
            },
            None,
            chrono::Local::now(),
        );
        let value: Value = serde_json::from_str(&JsonRenderer.document(&report)).unwrap();
        let infrastructure = &value["infrastructure"];
        assert_eq!(infrastructure["owner"], "organization-managed");
        assert_eq!(infrastructure["operator"], "Allegro");
        assert!(infrastructure["provider"].is_null());
        assert_eq!(infrastructure["target_matches"], 4);
        assert_eq!(infrastructure["other_matches"], 0);
        assert_eq!(infrastructure["confidence"], "confirmed");
        assert_eq!(value["verdict"], "classical_on_org_infra");
    }

    #[test]
    fn error_record_is_an_error_object() {
        let value: Value =
            serde_json::from_str(&JsonRenderer.error_record("x.invalid", "no route")).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["error"], "no route");
    }

    fn mx(
        ports: Vec<(crate::model::Port, crate::model::SmtpState)>,
        priority: u16,
        host: &str,
    ) -> crate::model::MxProbe {
        crate::model::MxProbe {
            priority,
            host: host.to_string(),
            addresses: vec![
                "192.0.2.1".parse().unwrap(),
                "2001:db8::25".parse().unwrap(),
            ],
            ip: Some("192.0.2.1".parse().unwrap()),
            infrastructure: crate::model::Infrastructure {
                owner: crate::model::InfraOwner::Unknown,
                operator: None,
                provider: None,
                target_matches: 0,
                other_matches: 0,
                confidence: crate::model::Confidence::None,
            },
            ports: ports
                .into_iter()
                .map(|(port, state)| crate::model::PortProbe { port, state })
                .collect(),
            evidence: crate::model::Evidence {
                cert: Some(crate::model::CertEvidence {
                    name: host.to_string(),
                    vendor: None,
                    names: vec![host.to_string()],
                    issuer_cn: None,
                }),
                ..Default::default()
            },
        }
    }

    fn tls_session(kx_group: &str) -> crate::model::SmtpState {
        crate::model::SmtpState::Tls(crate::model::TlsSession {
            version: "TLS 1.3".to_string(),
            facts: crate::model::TlsFacts {
                kx_group: kx_group.to_string(),
                symmetric_alg: crate::model::SymmetricAlg::Aes256,
            },
        })
    }

    #[test]
    fn json_email_section_reports_every_mx_independently() {
        let mut report = fixture();
        report.email = Some(crate::model::EmailReport {
            mx: vec![
                mx(
                    vec![(crate::model::Port::Smtp25, tls_session("X25519MLKEM768"))],
                    10,
                    "mx1.example.com",
                ),
                mx(
                    vec![(
                        crate::model::Port::Smtp25,
                        crate::model::SmtpState::Unreachable,
                    )],
                    20,
                    "mx2.example.com",
                ),
                mx(
                    vec![(
                        crate::model::Port::Smtp25,
                        crate::model::SmtpState::NoStarttls,
                    )],
                    30,
                    "mx3.example.com",
                ),
                mx(
                    vec![(
                        crate::model::Port::Smtp25,
                        crate::model::SmtpState::TlsFailed,
                    )],
                    40,
                    "mx4.example.com",
                ),
            ],
        });
        let value: Value = serde_json::from_str(&JsonRenderer.document(&report)).unwrap();

        let mx = &value["email"]["mx"];
        assert_eq!(mx.as_array().unwrap().len(), 4);

        assert_eq!(mx[0]["priority"], 10);
        assert_eq!(mx[0]["host"], "mx1.example.com");
        assert_eq!(mx[0]["addresses"][0], "192.0.2.1");
        assert_eq!(mx[0]["addresses"][1], "2001:db8::25");
        let ports0 = &mx[0]["ports"];
        assert_eq!(ports0.as_array().unwrap().len(), 1);
        assert_eq!(ports0[0]["port"], 25);
        assert_eq!(ports0[0]["reachable"], true);
        assert_eq!(ports0[0]["starttls"], "yes");
        assert_eq!(ports0[0]["tls"]["version"], "TLS 1.3");
        assert_eq!(ports0[0]["tls"]["kx_group"], "X25519MLKEM768");
        assert_eq!(ports0[0]["tls"]["symmetric_alg"], "AES-256");
        assert_eq!(ports0[0]["tls"]["pq"], true);
        assert_eq!(mx[0]["certificate"], "mx1.example.com");
        assert_eq!(mx[0]["infrastructure"]["owner"], "unknown");
        assert!(mx[0]["infrastructure"]["provider"].is_null());

        assert_eq!(mx[1]["ports"][0]["reachable"], false);
        assert!(mx[1]["ports"][0]["starttls"].is_null());
        assert!(mx[1]["ports"][0]["tls"].is_null());

        assert_eq!(mx[2]["ports"][0]["reachable"], true);
        assert_eq!(mx[2]["ports"][0]["starttls"], "no");
        assert!(mx[2]["ports"][0]["tls"].is_null());

        assert_eq!(mx[3]["ports"][0]["reachable"], true);
        assert_eq!(mx[3]["ports"][0]["starttls"], "yes");
        assert!(mx[3]["ports"][0]["tls"].is_null());
    }

    #[test]
    fn json_smtps_465_has_no_starttls_field_and_tls_null_when_failed() {
        let mut report = fixture();
        report.email = Some(crate::model::EmailReport {
            mx: vec![mx(
                vec![
                    (crate::model::Port::Smtps465, tls_session("X25519MLKEM768")),
                    (
                        crate::model::Port::Smtps465,
                        crate::model::SmtpState::TlsFailed,
                    ),
                ],
                10,
                "mail.example.com",
            )],
        });
        let value: Value = serde_json::from_str(&JsonRenderer.document(&report)).unwrap();
        let ports = &value["email"]["mx"][0]["ports"];
        assert_eq!(ports[0]["port"], 465);
        assert!(ports[0]["starttls"].is_null());
        assert_eq!(ports[0]["tls"]["pq"], true);
        assert_eq!(ports[1]["port"], 465);
        assert!(ports[1]["starttls"].is_null());
        assert!(ports[1]["tls"].is_null());
    }

    #[test]
    fn json_email_is_null_without_mx_records() {
        let mut report = fixture();
        report.email = None;
        let value: Value = serde_json::from_str(&JsonRenderer.document(&report)).unwrap();
        assert!(value["email"].is_null());
    }
}
