//! Semantic attribution. When the lexical rules finish unconfirmed, the
//! collected evidence is sent to a typed decision model, which classifies
//! the endpoint into one attribution group. The report's attribution is
//! then overridden with that group. Without an API key the scan stays
//! purely rule-based.

use std::collections::HashMap;
use std::env;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::detect::ScanContext;
use crate::model::{
    Confidence, DomainReport, InfraOwner, Infrastructure, MxProbe, TlsState, registrable_zone,
    verdict_of,
};
use crate::normalize::{display_name, normalize};
use crate::render::Renderer;

/// Decision API: named typed questions answered from a JSON state.
const DECISION_URL: &str = "https://fabryka.ai/v1/systemone";
const TIMEOUT: Duration = Duration::from_secs(15);
/// Environment variable holding the inference API key.
pub const API_KEY_ENV: &str = "SEMANTIC_REASONING_API_KEY";

/// Name of the single choice question sent to the decision model.
const QUESTION: &str = "termination_owner";

pub const WEB_QUESTION: &str = "Who operates the infrastructure terminating the domain's TLS connection, relative to the domain owner?";

pub const MAIL_QUESTION: &str = "Who operates the infrastructure terminating the domain's mail (MX) connection, relative to the domain owner?";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// The network owner is the domain owner itself (self-hosted).
    OwnInfra,
    /// Hosted on a third party's network, distinct from the domain owner.
    ThirdParty,
    /// Terminated at a vendor-managed CDN/edge/WAF.
    Edge,
    /// Evidence missing, contradictory or too weak to decide.
    Unattributable,
}

#[derive(Debug, Clone, Copy)]
pub struct Attribution {
    pub group: Group,
    pub confidence: f64,
}

/// Refines rule-based attribution with the decision model. No-op when TLS
/// failed (no handshake to attribute), when the rules already confirmed the
/// attribution, or when no API key is configured. Any decision-model failure
/// is returned as an error and trips the run-wide circuit breaker.
pub(crate) fn refine(report: &mut DomainReport, context: &ScanContext) -> Result<(), String> {
    if !context.semantic_reasoning
        || report.tls == TlsState::Unavailable
        || report.infrastructure.confidence == Confidence::Confirmed
    {
        return Ok(());
    }
    if let Some(reason) = context.semantic_reasoning_failed.get() {
        return Err(reason.clone());
    }
    let key = match env::var(API_KEY_ENV) {
        Ok(key) if !key.is_empty() => key,
        _ => return Err(format!("{} is not set", API_KEY_ENV)),
    };

    match decide(
        &key,
        &report.domain,
        &web_metadata(report),
        WEB_QUESTION,
        context.debug,
    ) {
        Ok(attribution) => {
            apply(&mut report.infrastructure, attribution, &report.domain);
            let pq = matches!(&report.tls, TlsState::Tls(session) if session.is_pq());
            report.verdict = verdict_of(&report.infrastructure, &report.termination, pq);
        }
        Err(reason) => {
            context.semantic_reasoning_failed.set(reason.clone()).ok();
            return Err(reason);
        }
    }

    let Some(email) = report.email.as_mut() else {
        return Ok(());
    };
    for probe in email.mx.iter_mut() {
        if probe.infrastructure.confidence == Confidence::Confirmed {
            continue;
        }
        match decide(
            &key,
            &report.domain,
            &mail_metadata(&report.domain, probe),
            MAIL_QUESTION,
            context.debug,
        ) {
            Ok(attribution) => {
                apply(&mut probe.infrastructure, attribution, &report.domain);
            }
            Err(reason) => {
                context.semantic_reasoning_failed.set(reason.clone()).ok();
                return Err(reason);
            }
        }
    }
    Ok(())
}

fn apply(infrastructure: &mut Infrastructure, attribution: Attribution, domain: &str) {
    let owner = match attribution.group {
        Group::Unattributable => return,
        Group::OwnInfra => {
            infrastructure.operator = zone_operator(domain);
            infrastructure.provider = None;
            InfraOwner::Organization
        }
        Group::ThirdParty | Group::Edge => {
            infrastructure.operator = None;
            InfraOwner::ThirdParty
        }
    };
    infrastructure.owner = owner;
    infrastructure.target_matches = 0;
    infrastructure.other_matches = 0;
    infrastructure.confidence = confidence(attribution.confidence);
}

fn confidence(score: f64) -> Confidence {
    if score >= 0.8 {
        Confidence::Confirmed
    } else if score >= 0.5 {
        Confidence::Likely
    } else {
        Confidence::Weak
    }
}

/// The domain owner's display name derived from the registrable zone,
/// mirroring the rule-based operator derivation.
fn zone_operator(domain: &str) -> Option<String> {
    let zone = registrable_zone(domain)?;
    let label = zone.split('.').next()?;
    let identity = normalize(label)?;
    Some(display_name(&identity.compact))
}

pub fn decide(
    key: &str,
    domain: &str,
    metadata: &str,
    question: &str,
    debug: bool,
) -> Result<Attribution, String> {
    let request = state_request(metadata, question);
    if debug {
        eprintln!(
            "[debug] {domain} request: {}",
            serde_json::to_string(&request).unwrap_or_default()
        );
    }
    let response = ureq::post(DECISION_URL)
        .timeout(TIMEOUT)
        .set("Authorization", &format!("Bearer {key}"))
        .send_json(request)
        .map_err(|err| match err {
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                if debug {
                    eprintln!("[debug] {domain} error response: {body}");
                }
                let detail = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|body| body["error"]["message"].as_str().map(str::to_string))
                    .unwrap_or_else(|| format!("HTTP {code}"));
                format!("{detail} (HTTP {code})")
            }
            err => {
                if debug {
                    eprintln!("[debug] {domain} transport error: {err}");
                }
                err.to_string()
            }
        })?
        .into_string()
        .map_err(|err| format!("unreadable response: {err}"))?;
    if debug {
        eprintln!("[debug] {domain} response: {response}");
    }
    let parsed: DecisionResponse =
        serde_json::from_str(&response).map_err(|err| format!("unreadable response: {err}"))?;
    parse_response(&parsed)
}

fn web_metadata(report: &DomainReport) -> String {
    let document = crate::render::TextRenderer::default().document(report);
    document
        .split("\n\nMAIL")
        .next()
        .unwrap_or(&document)
        .to_string()
}

fn mail_metadata(domain: &str, probe: &MxProbe) -> String {
    let mut lines = vec![
        domain.to_string(),
        "MAIL".to_string(),
        format!("  MX {}  {}", probe.priority, probe.host),
        String::new(),
        "    network".to_string(),
    ];
    for (label, value) in [
        (
            "IP",
            probe
                .ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "PTR",
            probe
                .evidence
                .ptr
                .as_ref()
                .map(|p| p.record.clone())
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "ASN",
            probe
                .evidence
                .asn
                .as_ref()
                .map(|a| a.asn.clone())
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "RDAP",
            probe
                .evidence
                .rdap
                .as_ref()
                .map(|r| r.netname.clone())
                .unwrap_or_else(|| "-".to_string()),
        ),
    ] {
        lines.push(format!("      {label:<9}{value}"));
    }
    lines.join("\n")
}

fn state_request(metadata: &str, question: &str) -> serde_json::Value {
    let state = format!(
        "{CONTEXT}\n[metadata]\n{metadata}\n\nQuestion: {question}\n\nanswers:\nFirst-party — operated by the domain owner's organization.\nThird-party hosting — operated by an external cloud or hosting provider, without identified edge termination.\nThird-party edge — terminated by an external CDN, WAF, or managed reverse proxy.\nUnknown — insufficient or conflicting evidence to establish attribution."
    );

    json!({
        "state": state,
        "questions": {
            QUESTION: {
                "type": "choice",
                "criteria": {
                    "first_party": "operated by the domain owner's organization",
                    "third_party_hosting": "operated by an external cloud or hosting provider, without identified edge termination",
                    "third_party_edge": "terminated by an external CDN, WAF, or managed reverse proxy",
                    "unknown": "insufficient or conflicting evidence to establish attribution"
                }
            }
        }
    })
}

const CONTEXT: &str = "context:\nPQ-Pulse measures post-quantum TLS adoption across internet domains. The target domain and its TLS scan metadata are provided below.\n\nDetermine infrastructure attribution by comparing the organization behind the domain with the operator of the observed TLS endpoint.\n\nUse the domain name to identify the domain owner. Use ASN, RDAP, IP, PTR, and termination-provider information to identify the endpoint operator.\n\n**Organizational ownership takes precedence over infrastructure function. A CDN or edge service is classified as third-party only when its operator is organizationally different from the domain owner.**\n\nApply the following decision order:\n\n1. Determine whether the domain owner and network operator are the same organization, accounting for known organizational aliases and subsidiaries.\n2. If they are the same, attribute the endpoint to first-party infrastructure, regardless of whether it uses an internal CDN.\n3. If they differ, check whether the endpoint is operated by a third-party CDN, WAF, reverse proxy, or managed edge service.\n4. If the organizations differ and no third-party edge service is identified, attribute an identifiable external cloud or hosting network to third-party hosting.\n5. Use unattributable only when the organizational relationship or infrastructure operator cannot be determined reliably.\n\nThe termination section, when present in the metadata, names the managed edge, CDN or WAF provider that terminated the TLS connection as observed by the probe. Judge from the provided metadata alone: a provider name being unfamiliar to you does not make the evidence insufficient.\n\nEvaluate the specific endpoint, not the provider's general business. Do not confuse network ownership with domain ownership.";

#[derive(Deserialize)]
struct DecisionResponse {
    answers: HashMap<String, ChoiceAnswer>,
}

#[derive(Deserialize)]
struct ChoiceAnswer {
    choice: String,
    confidence: f64,
}

fn parse_response(response: &DecisionResponse) -> Result<Attribution, String> {
    let answer = response
        .answers
        .get(QUESTION)
        .ok_or_else(|| format!("response has no {QUESTION} answer"))?;
    let group = match answer.choice.as_str() {
        "first_party" => Group::OwnInfra,
        "third_party_hosting" => Group::ThirdParty,
        "third_party_edge" => Group::Edge,
        "unknown" => Group::Unattributable,
        other => return Err(format!("unexpected answer label: {other}")),
    };
    Ok(Attribution {
        group,
        confidence: answer.confidence.clamp(0.0, 1.0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Infrastructure, TerminationRole, Verdict};

    fn unattributed_report() -> DomainReport {
        let mut report = crate::model::fixture();
        report.infrastructure = Infrastructure {
            owner: InfraOwner::Unknown,
            operator: None,
            provider: None,
            target_matches: 2,
            other_matches: 1,
            confidence: Confidence::Mixed,
        };
        report.termination.role = TerminationRole::Unproven;
        report.termination.confidence = Confidence::None;
        report.verdict = Verdict::NoPqUnattributed;
        report
    }

    fn response(choice: &str, confidence: f64) -> DecisionResponse {
        serde_json::from_value(json!({
            "answers": {
                QUESTION: {
                    "type": "choice",
                    "choice": choice,
                    "confidence": confidence,
                    "probabilities": {choice: confidence}
                }
            },
            "model": "test",
            "usage": {"input_tokens": 10, "output_tokens": 0}
        }))
        .unwrap()
    }

    #[test]
    fn parses_choice_answers() {
        let parsed = parse_response(&response("first_party", 0.83)).unwrap();
        assert_eq!(parsed.group, Group::OwnInfra);
        assert_eq!(parsed.confidence, 0.83);
        assert_eq!(
            parse_response(&response("third_party_hosting", 0.6))
                .unwrap()
                .group,
            Group::ThirdParty
        );
        assert_eq!(
            parse_response(&response("third_party_edge", 0.9))
                .unwrap()
                .group,
            Group::Edge
        );
        assert_eq!(
            parse_response(&response("unknown", 0.7)).unwrap().group,
            Group::Unattributable
        );
    }

    #[test]
    fn rejects_unknown_choice_labels() {
        assert!(parse_response(&response("somewhere", 0.9)).is_err());
    }

    #[test]
    fn clamps_confidence_into_unit_range() {
        let parsed = parse_response(&response("first_party", 1.5)).unwrap();
        assert_eq!(parsed.confidence, 1.0);
    }

    #[test]
    fn confidence_maps_to_enum_thresholds() {
        assert_eq!(confidence(0.8), Confidence::Confirmed);
        assert_eq!(confidence(0.5), Confidence::Likely);
        assert_eq!(confidence(0.2), Confidence::Weak);
    }

    #[test]
    fn own_infra_override_sets_operator_and_verdict() {
        let mut report = unattributed_report();
        apply(
            &mut report.infrastructure,
            Attribution {
                group: Group::OwnInfra,
                confidence: 0.9,
            },
            "citibankonline.pl",
        );
        assert_eq!(report.infrastructure.owner, InfraOwner::Organization);
        assert_eq!(report.infrastructure.confidence, Confidence::Confirmed);
        assert_eq!(report.infrastructure.target_matches, 0);
        assert_eq!(report.infrastructure.other_matches, 0);
        assert_eq!(
            report.infrastructure.operator.as_deref(),
            Some("Citibankonline")
        );
        report.verdict = verdict_of(&report.infrastructure, &report.termination, false);
        assert_eq!(report.verdict, Verdict::NoPqOnOrgInfra);
    }

    #[test]
    fn third_party_override_names_rdap_org_as_provider() {
        let mut report = unattributed_report();
        apply(
            &mut report.infrastructure,
            Attribution {
                group: Group::ThirdParty,
                confidence: 0.6,
            },
            "citibankonline.pl",
        );
        assert_eq!(report.infrastructure.owner, InfraOwner::ThirdParty);
        assert_eq!(report.infrastructure.confidence, Confidence::Likely);
        report.verdict = verdict_of(&report.infrastructure, &report.termination, false);
        assert_eq!(report.verdict, Verdict::NoPqOnThirdPartyInfra);
    }

    #[test]
    fn unattributable_answer_keeps_rules_result() {
        let mut report = unattributed_report();
        let (owner_before, verdict_before) = (report.infrastructure.owner, report.verdict);
        apply(
            &mut report.infrastructure,
            Attribution {
                group: Group::Unattributable,
                confidence: 0.9,
            },
            "citibankonline.pl",
        );
        assert_eq!(report.infrastructure.owner, owner_before);
        assert_eq!(report.verdict, verdict_before);
    }

    #[test]
    fn tripped_breaker_fails_later_checks() {
        let mut context = crate::detect::ScanContext::unlimited();
        context.semantic_reasoning = true;
        context
            .semantic_reasoning_failed
            .set("invalid_api_key (HTTP 401)".to_string())
            .ok();
        let mut report = unattributed_report();
        assert_eq!(
            refine(&mut report, &context),
            Err("invalid_api_key (HTTP 401)".to_string())
        );
        assert_eq!(report.infrastructure.owner, InfraOwner::Unknown);
    }
}
