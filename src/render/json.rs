use std::borrow::Cow;
use std::collections::HashMap;

use serde::Serialize;

use super::Renderer;
use crate::model::{DomainReport, Operator, SignalType, Signals};

pub struct JsonRenderer;

#[derive(Serialize)]
struct SignalDto<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    class: &'a str,
    value: Option<Cow<'a, str>>,
    operator: Option<&'a str>,
}

#[derive(Serialize)]
struct TlsDto<'a> {
    kx_group: &'a str,
    symmetric_alg: &'a str,
    pq: bool,
}

#[derive(Serialize)]
struct AggregateDto<'a> {
    operator: Option<&'a str>,
    candidates: Vec<&'a str>,
    confidence: &'a str,
    signal_count: usize,
    class_count: usize,
}

#[derive(Serialize)]
struct SignalsDto<'a> {
    termination: AggregateDto<'a>,
}

#[derive(Serialize)]
struct ReportDto<'a> {
    domain: &'a str,
    status: &'static str,
    checked_at: String,
    resolved_ip: Option<String>,
    tls: TlsDto<'a>,
    evidence: Vec<SignalDto<'a>>,
    signals: SignalsDto<'a>,
    verdict: &'a str,
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
            tls: TlsDto {
                kx_group: &report.tls.kx_group,
                symmetric_alg: report.tls.symmetric_alg.as_str(),
                pq: report.tls.is_pq(),
            },
            evidence: Self::signal_dtos(report),
            signals: SignalsDto {
                termination: Self::aggregate_dto(&report.termination),
            },
            verdict: report.verdict.as_str(),
        }
    }

    fn aggregate_dto(signals: &Signals) -> AggregateDto<'_> {
        AggregateDto {
            operator: signals.operator.map(|op| op.short()),
            candidates: signals.candidates.iter().map(|op| op.short()).collect(),
            confidence: signals.confidence.as_str(),
            signal_count: signals.signal_count,
            class_count: signals.class_count,
        }
    }

    /// The seven evidence slots in a fixed order, present even when empty
    /// (value and operator null) so consumers can index positionally.
    fn signal_dtos(report: &DomainReport) -> Vec<SignalDto<'_>> {
        let attributed: HashMap<SignalType, Operator> = report
            .evidence
            .signals(&report.domain)
            .into_iter()
            .map(|s| (s.kind, s.operator))
            .collect();
        let operator_of = |kind: SignalType| attributed.get(&kind).copied().map(|op| op.short());
        let e = &report.evidence;
        let cname_value = e.cname.as_ref().map(|c| c.chain_text());
        vec![
            SignalDto {
                kind: SignalType::Cname.as_str(),
                class: SignalType::Cname.class().as_str(),
                value: cname_value.map(Cow::Owned),
                operator: operator_of(SignalType::Cname),
            },
            SignalDto {
                kind: SignalType::Range.as_str(),
                class: SignalType::Range.class().as_str(),
                value: e.range.as_ref().map(|r| Cow::Borrowed(r.cidr.as_str())),
                operator: operator_of(SignalType::Range),
            },
            SignalDto {
                kind: SignalType::Cert.as_str(),
                class: SignalType::Cert.class().as_str(),
                value: e.cert.as_ref().map(|c| Cow::Borrowed(c.name.as_str())),
                operator: operator_of(SignalType::Cert),
            },
            SignalDto {
                kind: SignalType::Http.as_str(),
                class: SignalType::Http.class().as_str(),
                value: e.http.as_ref().map(|h| Cow::Borrowed(h.header.as_str())),
                operator: operator_of(SignalType::Http),
            },
            SignalDto {
                kind: SignalType::Ptr.as_str(),
                class: SignalType::Ptr.class().as_str(),
                value: e.ptr.as_ref().map(|p| Cow::Borrowed(p.record.as_str())),
                operator: operator_of(SignalType::Ptr),
            },
            SignalDto {
                kind: SignalType::Rdap.as_str(),
                class: SignalType::Rdap.class().as_str(),
                value: e.rdap.as_ref().map(|r| Cow::Borrowed(r.netname.as_str())),
                operator: operator_of(SignalType::Rdap),
            },
            SignalDto {
                kind: SignalType::Asn.as_str(),
                class: SignalType::Asn.class().as_str(),
                value: e.asn.as_ref().map(|a| Cow::Borrowed(a.asn.as_str())),
                operator: operator_of(SignalType::Asn),
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
        assert_eq!(value["tls"]["symmetric_alg"], "AES256");
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
        assert_eq!(signals[3]["class"], "edge_processing");
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
        assert_eq!(signals[6]["class"], "ip_infra");
        assert_eq!(signals[6]["value"], "AS20940 AKAMAI-ASN1");
        assert_eq!(signals[6]["operator"], "Akamai");

        assert_eq!(value["signals"]["termination"]["operator"], "Akamai");
        assert_eq!(value["signals"]["termination"]["confidence"], "confirmed");
        assert_eq!(value["signals"]["termination"]["signal_count"], 4);
        assert_eq!(value["signals"]["termination"]["class_count"], 2);
        assert_eq!(value["verdict"], "no_pq_edge");
    }

    #[test]
    fn json_reports_candidates_when_attribution_is_contested() {
        let report = crate::model::DomainReport::build(
            "www.allegro.pl".to_string(),
            None,
            crate::model::TlsFacts {
                kx_group: "X25519".to_string(),
                symmetric_alg: crate::model::SymmetricAlg::Aes256,
            },
            crate::model::Evidence {
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
            chrono::Local::now(),
        );
        let value: Value = serde_json::from_str(&JsonRenderer.document(&report)).unwrap();
        let termination = &value["signals"]["termination"];
        assert!(termination["operator"].is_null());
        assert_eq!(termination["candidates"][0], "self");
        assert_eq!(termination["candidates"][1], "Google Cloud");
        assert_eq!(termination["confidence"], "undecided");
        assert_eq!(termination["signal_count"], 2);
        assert_eq!(termination["class_count"], 1);
    }

    #[test]
    fn json_marks_self_operator_for_own_infrastructure() {
        let report = crate::model::DomainReport::build(
            "upload.allegro.pl".to_string(),
            None,
            crate::model::TlsFacts {
                kx_group: "X25519".to_string(),
                symmetric_alg: crate::model::SymmetricAlg::Aes256,
            },
            crate::model::Evidence {
                cname: Some(crate::model::CnameEvidence {
                    chain: vec!["upload.allegro.pl".to_string()],
                    vendor: None,
                }),
                cert: Some(crate::model::CertEvidence {
                    name: "edge.business.allegro.pl".to_string(),
                    vendor: None,
                }),
                ptr: Some(crate::model::PtrEvidence {
                    record: "upload.allegro.com.cz".to_string(),
                    vendor: None,
                }),
                rdap: Some(crate::model::RdapEvidence {
                    netname: "ALLEGRO-NET".to_string(),
                    vendor: None,
                }),
                asn: Some(crate::model::AsnEvidence {
                    asn: "AS42656 QXL-POLAND".to_string(),
                    vendor: None,
                }),
                ..Default::default()
            },
            chrono::Local::now(),
        );
        let value: Value = serde_json::from_str(&JsonRenderer.document(&report)).unwrap();
        let signals = value["evidence"].as_array().unwrap();
        assert_eq!(signals[0]["operator"], "self");
        assert_eq!(signals[5]["operator"], "self");
        assert!(signals[2]["operator"].is_null());
        assert!(signals[3]["operator"].is_null());
        assert!(signals[4]["operator"].is_null());
        assert!(signals[6]["operator"].is_null());
        assert_eq!(value["signals"]["termination"]["operator"], "self");
        assert_eq!(value["signals"]["termination"]["signal_count"], 2);
        assert_eq!(value["signals"]["termination"]["class_count"], 2);
        assert_eq!(value["signals"]["termination"]["confidence"], "confirmed");
        assert_eq!(value["verdict"], "no_pq_own_infra");
    }

    #[test]
    fn error_record_is_an_error_object() {
        let value: Value =
            serde_json::from_str(&JsonRenderer.error_record("x.invalid", "no route")).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["error"], "no route");
    }
}
