use serde::Serialize;

use super::Renderer;
use crate::model::{Attribution, DomainReport, SignalType};

/// JSON presentation. `value` is the raw observation for each of the five
/// evidence slots, `vendor` the interpretation — a slot is a signal
/// exactly when `vendor` is non-null.
pub struct JsonRenderer;

#[derive(Serialize)]
struct SignalDto<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    class: &'a str,
    value: Option<&'a str>,
    vendor: Option<&'a str>,
}

#[derive(Serialize)]
struct TlsDto<'a> {
    kx_group: &'a str,
    symmetric_alg: &'a str,
    pq: bool,
}

#[derive(Serialize)]
struct AggregateDto<'a> {
    vendor: Option<&'a str>,
    confidence: &'a str,
    signal_count: usize,
    class_count: usize,
}

#[derive(Serialize)]
struct AttributionDto<'a> {
    infra: AggregateDto<'a>,
    edge: AggregateDto<'a>,
}

#[derive(Serialize)]
struct ReportDto<'a> {
    domain: &'a str,
    status: &'static str,
    checked_at: String,
    resolved_ip: Option<String>,
    tls: TlsDto<'a>,
    evidence: Vec<SignalDto<'a>>,
    attribution: AttributionDto<'a>,
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
            attribution: AttributionDto {
                infra: Self::aggregate_dto(&report.infra),
                edge: Self::aggregate_dto(&report.edge),
            },
            verdict: report.verdict.as_str(),
        }
    }

    fn aggregate_dto(attribution: &Attribution) -> AggregateDto<'_> {
        AggregateDto {
            vendor: attribution.vendor.map(|v| v.as_str()),
            confidence: attribution.confidence.as_str(),
            signal_count: attribution.signal_count,
            class_count: attribution.class_count,
        }
    }

    /// The five evidence slots in a fixed order, present even when empty
    /// (value and vendor null) so consumers can index positionally.
    fn signal_dtos(report: &DomainReport) -> Vec<SignalDto<'_>> {
        let e = &report.evidence;
        vec![
            SignalDto {
                kind: SignalType::Cname.as_str(),
                class: SignalType::Cname.class().as_str(),
                value: e.cname.as_ref().map(|c| c.target.as_str()),
                vendor: e.cname.as_ref().and_then(|c| c.vendor).map(|v| v.as_str()),
            },
            SignalDto {
                kind: SignalType::Range.as_str(),
                class: SignalType::Range.class().as_str(),
                value: e.range.as_ref().map(|r| r.cidr.as_str()),
                vendor: e.range.as_ref().map(|r| r.vendor.as_str()),
            },
            SignalDto {
                kind: SignalType::Cert.as_str(),
                class: SignalType::Cert.class().as_str(),
                value: e.cert.as_ref().map(|c| c.name.as_str()),
                vendor: e.cert.as_ref().and_then(|c| c.vendor).map(|v| v.as_str()),
            },
            SignalDto {
                kind: SignalType::Ptr.as_str(),
                class: SignalType::Ptr.class().as_str(),
                value: e.ptr.as_ref().map(|p| p.record.as_str()),
                vendor: e.ptr.as_ref().and_then(|p| p.vendor).map(|v| v.as_str()),
            },
            SignalDto {
                kind: SignalType::Rdap.as_str(),
                class: SignalType::Rdap.class().as_str(),
                value: e.rdap.as_ref().map(|r| r.netname.as_str()),
                vendor: e.rdap.as_ref().and_then(|r| r.vendor).map(|v| v.as_str()),
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
        assert_eq!(signals.len(), 5);
        assert_eq!(signals[0]["type"], "CNAME");
        assert!(signals[0]["value"].is_null());
        assert_eq!(signals[1]["type"], "RANGE");
        assert_eq!(signals[2]["type"], "CERT");
        assert_eq!(signals[2]["value"], "www.citi.com");
        assert!(signals[2]["vendor"].is_null());
        assert_eq!(signals[3]["type"], "PTR");
        assert_eq!(
            signals[3]["value"],
            "a104-96-178-165.deploy.static.akamaitechnologies.com"
        );
        assert_eq!(signals[3]["vendor"], "Akamai");
        assert_eq!(signals[4]["value"], "AKAMAI");
        assert_eq!(signals[4]["vendor"], "Akamai");

        assert_eq!(value["attribution"]["infra"]["vendor"], "Akamai");
        assert_eq!(value["attribution"]["infra"]["confidence"], "probable");
        assert_eq!(value["attribution"]["edge"]["class_count"], 1);
        assert_eq!(value["verdict"], "no_pq_edge");
    }

    #[test]
    fn error_record_is_an_error_object() {
        let value: Value =
            serde_json::from_str(&JsonRenderer.error_record("x.invalid", "no route")).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["error"], "no route");
    }
}
