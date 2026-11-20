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
    Confidence, DomainReport, InfraOwner, Infrastructure, MxProbe, Sector, TerminationRole,
    TlsState, registrable_zone, verdict_of,
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

/// RIPE database search resolving opaque RDAP netnames when the model
/// answers `unknown`.
const RIPE_SEARCH_URL: &str = "https://rest.db.ripe.net/search.json";

/// Name of the sector classification question.
const SECTOR_QUESTION_NAME: &str = "domain_sector";

pub const WEB_QUESTION: &str = "Who operates the infrastructure terminating the domain's TLS connection, relative to the domain owner?";

pub const MAIL_QUESTION: &str = "Who operates the infrastructure terminating the domain's mail (MX) connection, relative to the domain owner?";

/// Question text for the sector classification.
const SECTOR_QUESTION_TEXT: &str =
    "What is the primary business sector of the organization associated with this domain?";

/// Preamble of the sector context; the evidence rows follow as
/// "Label: value" lines, absent rows omitted.
const SECTOR_CONTEXT_PREAMBLE: &str =
    "Use the provided context to determine the most likely sector.";

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

/// Refines rule-based attribution with the decision model whenever a TLS
/// handshake was established — post-quantum or classical — and classifies
/// the sector whenever evidence exists.
pub(crate) fn refine(report: &mut DomainReport, context: &ScanContext) -> Result<(), String> {
    if !context.semantic_reasoning {
        return Ok(());
    }
    if let Some(reason) = context.semantic_reasoning_failed.get() {
        return Err(reason.clone());
    }
    let key = match env::var(API_KEY_ENV) {
        Ok(key) if !key.is_empty() => key,
        _ => return Err(format!("{} is not set", API_KEY_ENV)),
    };

    if let TlsState::Tls(session) = &report.tls {
        let pq = session.is_pq();
        match decide_enriched(
            &key,
            &report.domain,
            &web_metadata(report),
            WEB_QUESTION,
            report.evidence.rdap.as_ref().map(|r| r.netname.as_str()),
            context.debug,
        ) {
            Ok(attribution) => {
                apply(&mut report.infrastructure, attribution, &report.domain);
                if report.termination.role == TerminationRole::Unproven {
                    report.termination.confidence = report.infrastructure.confidence;
                }
                report.verdict = verdict_of(&report.infrastructure, &report.termination, pq);
            }
            Err(reason) => {
                context.semantic_reasoning_failed.set(reason.clone()).ok();
                return Err(reason);
            }
        }

        if let Some(email) = report.email.as_mut() {
            for probe in email.mx.iter_mut() {
                if probe.infrastructure.confidence == Confidence::Confirmed {
                    continue;
                }
                match decide_enriched(
                    &key,
                    &report.domain,
                    &mail_metadata(&report.domain, probe),
                    MAIL_QUESTION,
                    probe.evidence.rdap.as_ref().map(|r| r.netname.as_str()),
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
        }
    }

    refine_sector(report, context, &key)
}

/// Classifies the domain's business sector from the page and identity
/// evidence. Skipped without any evidence rows beyond the domain name;
/// an `unknown` or low-confidence answer leaves the sector unset. Any
/// decision-model failure trips the run-wide circuit breaker.
fn refine_sector(
    report: &mut DomainReport,
    context: &ScanContext,
    key: &str,
) -> Result<(), String> {
    let metadata = sector_metadata(report);
    let Some(metadata) = metadata else {
        return Ok(());
    };
    match decide_sector(key, &report.domain, &metadata, context.debug) {
        Ok(Some(sector)) => report.sector = Some(sector),
        Ok(None) => {}
        Err(reason) => {
            context.semantic_reasoning_failed.set(reason.clone()).ok();
            return Err(reason);
        }
    }
    Ok(())
}

/// The sector context: the template rows that have a value, `None` when
/// nothing but the domain name is available (not worth a model call).
fn sector_metadata(report: &DomainReport) -> Option<String> {
    let mut rows = vec![(true, format!("Domain: {}", report.domain))];

    if let Some(page) = &report.page {
        for (label, value) in [
            ("Page title", &page.title),
            ("Meta description", &page.meta_description),
            ("Open Graph title", &page.og_title),
            ("Open Graph description", &page.og_description),
            ("Industry (JSON-LD)", &page.industry),
            ("Headings (H1/H2)", &page.headings),
            ("Page content excerpt", &page.excerpt),
        ] {
            if let Some(value) = value {
                rows.push((true, format!("{label}: {value}")));
            }
        }
    }
    let organization = report
        .evidence
        .cert
        .as_ref()
        .and_then(|cert| cert.org.as_ref())
        .or(report
            .evidence
            .rdap
            .as_ref()
            .and_then(|rdap| rdap.org.as_ref()));
    if let Some(organization) = organization {
        rows.push((true, format!("Organization name: {organization}")));
    }

    if rows.len() == 1 {
        return None;
    }
    Some(
        rows.into_iter()
            .map(|(_, row)| row)
            .collect::<Vec<_>>()
            .join("\n\n"),
    )
}

/// Posts the sector question and maps the answer. `Ok(None)` means the
/// model answered `unknown` or below the confidence floor.
pub fn decide_sector(
    key: &str,
    domain: &str,
    metadata: &str,
    debug: bool,
) -> Result<Option<Sector>, String> {
    let request = sector_request(metadata);
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
    let answer = parsed
        .answers
        .get(SECTOR_QUESTION_NAME)
        .ok_or_else(|| format!("response has no {SECTOR_QUESTION_NAME} answer"))?;
    if answer.choice == "unknown" {
        return Ok(None);
    }
    let sector = sector_label(&answer.choice)?;
    if answer.confidence < 0.5 {
        return Ok(None);
    }
    Ok(sector)
}

/// Maps a model answer label to the sector; `None` is not representable
/// here (`unknown` is handled by the caller), so this always yields one.
fn sector_label(choice: &str) -> Result<Option<Sector>, String> {
    let sector = match choice {
        "finance" => Sector::Finance,
        "retail" => Sector::Retail,
        "technology" => Sector::Technology,
        "telecommunications" => Sector::Telecommunications,
        "government" => Sector::Government,
        "healthcare" => Sector::Healthcare,
        "education" => Sector::Education,
        "media" => Sector::Media,
        "manufacturing" => Sector::Manufacturing,
        "energy" => Sector::Energy,
        "other" => Sector::Other,
        other => return Err(format!("unexpected answer label: {other}")),
    };
    Ok(Some(sector))
}

/// The sector state payload: preamble, evidence rows, question and the
/// fixed answer taxonomy with per-label criteria.
fn sector_request(metadata: &str) -> serde_json::Value {
    let state = format!("{SECTOR_CONTEXT_PREAMBLE}\n\n{metadata}");

    json!({
        "state": state,
        "questions": {
            SECTOR_QUESTION_NAME: {
                "type": "choice",
                "instructions": SECTOR_QUESTION_TEXT,
                "criteria": {
                    "finance": "banking, insurance, investment and financial services",
                    "retail": "e-commerce, marketplaces, online and physical shops",
                    "technology": "software, SaaS, IT services, hardware",
                    "telecommunications": "telecom operators, ISPs, hosting providers",
                    "government": "state institutions, municipalities, public agencies",
                    "healthcare": "hospitals, clinics, pharma, medical services",
                    "education": "universities, schools, e-learning",
                    "media": "news, journalism, publishing, encyclopedias, information and content platforms, entertainment",
                    "manufacturing": "industrial production, construction, engineering",
                    "energy": "energy production, utilities, mining",
                    "other": "a recognizable organization outside the listed sectors",
                    "unknown": "insufficient or conflicting evidence to determine the sector"
                }
            }
        }
    })
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

/// Attributes one question, retrying once on `unknown`: the RDAP netname
/// is resolved against the RIPE database and the org-name/descr/remarks
/// rows are appended to the metadata, which lets the model attribute
/// opaque registry handles like `TASK-UG`. A missing netname, an empty
/// lookup or a failed lookup (debug-logged, non-fatal) keeps the first
/// answer.
fn decide_enriched(
    key: &str,
    domain: &str,
    metadata: &str,
    question: &str,
    netname: Option<&str>,
    debug: bool,
) -> Result<Attribution, String> {
    let attribution = decide(key, domain, metadata, question, debug)?;
    if attribution.group != Group::Unattributable {
        return Ok(attribution);
    }
    let netname = netname
        .map(str::trim)
        .filter(|netname| !netname.is_empty() && *netname != "-");
    let netname = match netname {
        Some(netname) => netname,
        None => return Ok(attribution),
    };
    let extension = match ripe_lookup(netname) {
        Ok(Some(extension)) => extension,
        Ok(None) => return Ok(attribution),
        Err(reason) => {
            if debug {
                eprintln!("[debug] {domain} ripe lookup failed: {reason}");
            }
            return Ok(attribution);
        }
    };
    decide(
        key,
        domain,
        &format!("{metadata}\n\n{extension}"),
        question,
        debug,
    )
}

/// Queries the RIPE database for the netname and renders the collected
/// rows as a metadata block; `None` when nothing usable is returned.
fn ripe_lookup(netname: &str) -> Result<Option<String>, String> {
    let response = ureq::get(RIPE_SEARCH_URL)
        .timeout(TIMEOUT)
        .query("query-string", netname)
        .query("flags", "no-personal")
        .call()
        .map_err(|err| err.to_string())?;
    let body = response
        .into_string()
        .map_err(|err| format!("unreadable response: {err}"))?;
    let rows = ripe_rows(&body)?;
    if rows.is_empty() {
        return Ok(None);
    }
    Ok(Some(ripe_block(netname, &rows)))
}

/// The extension block: header naming the queried handle, then the
/// registry rows aligned with the metadata's value column.
fn ripe_block(netname: &str, rows: &[(String, String)]) -> String {
    let mut lines = vec![format!("  RIPE lookup ({netname})")];
    for (name, value) in rows {
        lines.push(format!("    {name:<13}{value}"));
    }
    lines.join("\n")
}

/// Collects unique org-name/descr/remarks attribute values from a RIPE
/// search response, in document order.
fn ripe_rows(body: &str) -> Result<Vec<(String, String)>, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(body).map_err(|err| format!("unreadable response: {err}"))?;
    let objects = parsed["objects"]["object"].as_array();
    let mut rows: Vec<(String, String)> = Vec::new();
    for object in objects.into_iter().flatten() {
        let Some(attributes) = object["attributes"]["attribute"].as_array() else {
            continue;
        };
        for attribute in attributes {
            let name = attribute["name"].as_str().unwrap_or_default();
            if !matches!(name, "org-name" | "descr" | "remarks") {
                continue;
            }
            let value = attribute["value"].as_str().unwrap_or_default().trim();
            if value.is_empty() {
                continue;
            }
            let row = (name.to_string(), value.to_string());
            if !rows.contains(&row) {
                rows.push(row);
            }
        }
    }
    Ok(rows)
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
    let state = format!("{CONTEXT}\n[metadata]\n{metadata}");

    json!({
        "state": state,
        "questions": {
            QUESTION: {
                "type": "choice",
                "instructions": question,
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

    #[test]
    fn sector_context_omits_absent_rows() {
        let mut report = unattributed_report();
        // Only the domain: no model call.
        assert_eq!(sector_metadata(&report), None);

        report.page = Some(crate::model::PageSignals {
            title: Some("Meridian Bank".to_string()),
            ..Default::default()
        });
        let metadata = sector_metadata(&report).expect("page title present");
        assert!(metadata.starts_with("Domain: citibankonline.pl"));
        assert!(metadata.contains("\n\nPage title: Meridian Bank"));
        assert!(!metadata.contains("Meta description"));
        assert!(!metadata.contains("Organization name"));
    }

    #[test]
    fn sector_context_prefers_cert_over_rdap_organization() {
        let mut report = unattributed_report();
        let cert = report.evidence.cert.as_mut().unwrap();
        cert.org = Some("Citibank S.A.".to_string());
        report.evidence.rdap = Some(crate::model::RdapEvidence {
            netname: "AKAMAI".to_string(),
            vendor: None,
            org: Some("Akamai Technologies".to_string()),
        });
        let metadata = sector_metadata(&report).expect("organization present");
        assert!(metadata.contains("Organization name: Citibank S.A."));
        assert!(!metadata.contains("Akamai"));
    }

    #[test]
    fn sector_labels_map_and_fail_loud() {
        assert_eq!(sector_label("finance").unwrap(), Some(Sector::Finance));
        assert_eq!(
            sector_label("manufacturing").unwrap(),
            Some(Sector::Manufacturing)
        );
        assert_eq!(sector_label("other").unwrap(), Some(Sector::Other));
        assert_eq!(
            sector_label("nosuchsector"),
            Err("unexpected answer label: nosuchsector".to_string())
        );
    }

    #[test]
    fn ripe_rows_collect_unique_relevant_attributes() {
        let body = r#"{
          "objects": {"object": [
            {"attributes": {"attribute": [
              {"name": "netname", "value": "TASK-UG"},
              {"name": "descr", "value": "TASK Academic Computer Network"},
              {"name": "descr", "value": "University of Gdansk"},
              {"name": "remarks", "value": "  "},
              {"name": "country", "value": "PL"}
            ]}},
            {"attributes": {"attribute": [
              {"name": "descr", "value": "University of Gdansk"},
              {"name": "org-name", "value": "TASK Academic Computer Network"}
            ]}}
          ]}
        }"#;
        assert_eq!(
            ripe_rows(body).unwrap(),
            vec![
                (
                    "descr".to_string(),
                    "TASK Academic Computer Network".to_string()
                ),
                ("descr".to_string(), "University of Gdansk".to_string()),
                (
                    "org-name".to_string(),
                    "TASK Academic Computer Network".to_string()
                ),
            ]
        );
    }

    #[test]
    fn ripe_rows_tolerate_empty_and_reject_unreadable_responses() {
        assert!(ripe_rows("{}").unwrap().is_empty());
        assert!(ripe_rows("not json").is_err());
    }

    #[test]
    fn ripe_block_aligns_rows_under_the_metadata_column() {
        let block = ripe_block(
            "TASK-UG",
            &[("descr".to_string(), "University of Gdansk".to_string())],
        );
        assert_eq!(
            block,
            "  RIPE lookup (TASK-UG)\n    descr        University of Gdansk"
        );
    }
}
