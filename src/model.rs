use std::net::IpAddr;

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::normalize::{Identity, display_name, matches_identity, normalize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Vendor {
    Cloudflare,
    Akamai,
    Imperva,
    Fastly,
    CloudFront,
    Myra,
    Link11,
    #[serde(rename = "Google Cloud")]
    GoogleCloud,
    Azure,
}

impl Vendor {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Vendor::Cloudflare => "Cloudflare",
            Vendor::Akamai => "Akamai",
            Vendor::Imperva => "Imperva",
            Vendor::Fastly => "Fastly",
            Vendor::CloudFront => "CloudFront",
            Vendor::Myra => "Myra",
            Vendor::Link11 => "Link11",
            Vendor::GoogleCloud => "Google Cloud",
            Vendor::Azure => "Azure",
        }
    }

    pub const fn is_cloud(&self) -> bool {
        matches!(self, Vendor::GoogleCloud | Vendor::Azure)
    }
}

impl std::fmt::Display for Vendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymmetricAlg {
    Aes128,
    Aes256,
    Chacha20,
    Other,
}

impl SymmetricAlg {
    pub fn from_suite_name(suite: &str) -> Self {
        if suite.contains("AES_128") {
            SymmetricAlg::Aes128
        } else if suite.contains("AES_256") {
            SymmetricAlg::Aes256
        } else if suite.contains("CHACHA20") {
            SymmetricAlg::Chacha20
        } else {
            SymmetricAlg::Other
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            SymmetricAlg::Aes128 => "AES-128",
            SymmetricAlg::Aes256 => "AES-256",
            SymmetricAlg::Chacha20 => "CHACHA20-POLY1305",
            SymmetricAlg::Other => "OTHER",
        }
    }
}

impl std::fmt::Display for SymmetricAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Confirmed,
    Likely,
    Weak,
    Mixed,
    None,
}

impl Confidence {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Confidence::Confirmed => "confirmed",
            Confidence::Likely => "likely",
            Confidence::Weak => "weak",
            Confidence::Mixed => "mixed",
            Confidence::None => "none",
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    PqAtEdge,
    PqLikelyAtEdge,
    PqOnOrgInfra,
    PqOnThirdPartyInfra,
    PqUnattributed,
    NoPqAtEdge,
    NoPqLikelyAtEdge,
    NoPqOnOrgInfra,
    NoPqOnThirdPartyInfra,
    NoPqUnattributed,
    TlsUnavailable,
}

impl Verdict {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Verdict::PqAtEdge => "pq_at_edge",
            Verdict::PqLikelyAtEdge => "pq_likely_at_edge",
            Verdict::PqOnOrgInfra => "pq_on_org_infra",
            Verdict::PqOnThirdPartyInfra => "pq_on_third_party_infra",
            Verdict::PqUnattributed => "pq_unattributed",
            Verdict::NoPqAtEdge => "classical_at_edge",
            Verdict::NoPqLikelyAtEdge => "classical_likely_at_edge",
            Verdict::NoPqOnOrgInfra => "classical_on_org_infra",
            Verdict::NoPqOnThirdPartyInfra => "classical_on_third_party_infra",
            Verdict::NoPqUnattributed => "classical_unattributed",
            Verdict::TlsUnavailable => "tls_unavailable",
        }
    }

    pub const fn explanation(&self) -> &'static str {
        match self {
            Verdict::PqAtEdge => {
                "Post-quantum or hybrid key exchange, with at least two independent pieces of evidence that the connection terminates at a provider edge/CDN/WAF."
            }
            Verdict::PqLikelyAtEdge => {
                "Post-quantum or hybrid key exchange, with one strong indication of provider-managed edge termination."
            }
            Verdict::PqOnOrgInfra => {
                "Post-quantum or hybrid key exchange on infrastructure attributed to the organization itself."
            }
            Verdict::PqOnThirdPartyInfra => {
                "Post-quantum or hybrid key exchange on infrastructure attributed to a third party."
            }
            Verdict::PqUnattributed => {
                "Post-quantum or hybrid key exchange; the infrastructure could not be attributed."
            }
            Verdict::NoPqAtEdge => {
                "No post-quantum key exchange, with at least two independent pieces of evidence that the connection terminates at a provider edge/CDN/WAF."
            }
            Verdict::NoPqLikelyAtEdge => {
                "No post-quantum key exchange, with one strong indication of provider-managed edge termination."
            }
            Verdict::NoPqOnOrgInfra => {
                "No post-quantum key exchange on infrastructure attributed to the organization itself."
            }
            Verdict::NoPqOnThirdPartyInfra => {
                "No post-quantum key exchange on infrastructure attributed to a third party."
            }
            Verdict::NoPqUnattributed => {
                "No post-quantum key exchange; the infrastructure could not be attributed."
            }
            Verdict::TlsUnavailable => {
                "No HTTPS/TLS endpoint was reachable, so no key exchange could be observed; the post-quantum status is unknown."
            }
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.as_str(), self.explanation())
    }
}

#[derive(Debug, Clone)]
pub struct CnameEvidence {
    /// The full CNAME chain in resolution order; the last hop is the
    /// terminal target. Vendor zones are matched anywhere in the chain.
    pub chain: Vec<String>,
    pub vendor: Option<Vendor>,
}

impl CnameEvidence {
    /// The chain as one display value: "hop1 -> hop2 -> ...".
    pub fn chain_text(&self) -> String {
        self.chain.join(" -> ")
    }
}

#[derive(Debug, Clone)]
pub struct RangeEvidence {
    pub cidr: String,
    pub vendor: Vendor,
}

#[derive(Debug, Clone)]
pub struct CertEvidence {
    pub name: String,
    pub vendor: Option<Vendor>,
    /// Every observed name: subject CN, issuer CN and SANs.
    pub names: Vec<String>,
    pub issuer_cn: Option<String>,
}

/// A vendor-specific HTTP response header observed on a live request.
/// Exists only when a vendor actually processed the request, so the
/// vendor is not optional here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEvidence {
    /// The header that produced the match, e.g. "X-Akamai-Request-ID".
    pub header: String,
    pub vendor: Vendor,
}

#[derive(Debug, Clone)]
pub struct PtrEvidence {
    pub record: String,
    pub vendor: Option<Vendor>,
}

#[derive(Debug, Clone)]
pub struct RdapEvidence {
    pub netname: String,
    pub vendor: Option<Vendor>,
}

#[derive(Debug, Clone)]
pub struct AsnEvidence {
    /// Origin ASN and its name, e.g. "AS20940 AKAMAI-ASN1".
    pub asn: String,
    pub vendor: Option<Vendor>,
}

/// Who owns the infrastructure the endpoint runs on: the organization
/// itself, an identifiable third party, contested, or unknown when the
/// evidence is absent or weak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfraOwner {
    Organization,
    PossiblyOrganization,
    ThirdParty,
    PossiblyThirdParty,
    Ambiguous,
    Unknown,
}

impl InfraOwner {
    pub const fn as_str(&self) -> &'static str {
        match self {
            InfraOwner::Organization => "organization-managed",
            InfraOwner::PossiblyOrganization => "possibly-organization-managed",
            InfraOwner::ThirdParty => "third-party",
            InfraOwner::PossiblyThirdParty => "possibly-third-party",
            InfraOwner::Ambiguous => "ambiguous",
            InfraOwner::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Infrastructure {
    pub owner: InfraOwner,
    pub operator: Option<String>,
    pub provider: Option<String>,
    pub target_matches: u32,
    pub other_matches: u32,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeSignal {
    Cname,
    Range,
    Http,
    Cert,
    Other,
}

impl EdgeSignal {
    pub const fn as_str(&self) -> &'static str {
        match self {
            EdgeSignal::Cname => "CNAME",
            EdgeSignal::Range => "RANGE",
            EdgeSignal::Http => "HTTP",
            EdgeSignal::Cert => "CERT",
            EdgeSignal::Other => "OTHER",
        }
    }

    pub const fn is_strong(&self) -> bool {
        matches!(
            self,
            EdgeSignal::Cname | EdgeSignal::Range | EdgeSignal::Http
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationRole {
    Edge,
    LikelyEdge,
    Unproven,
}

impl TerminationRole {
    pub const fn as_str(&self) -> &'static str {
        match self {
            TerminationRole::Edge => "edge",
            TerminationRole::LikelyEdge => "likely_edge",
            TerminationRole::Unproven => "unproven",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Termination {
    pub role: TerminationRole,
    pub confidence: Confidence,
    pub edge_classes: Vec<EdgeSignal>,
}

#[derive(Debug, Clone, Default)]
pub struct Evidence {
    pub cname: Option<CnameEvidence>,
    pub range: Option<RangeEvidence>,
    pub cert: Option<CertEvidence>,
    pub http: Option<HttpEvidence>,
    pub ptr: Option<PtrEvidence>,
    pub rdap: Option<RdapEvidence>,
    pub asn: Option<AsnEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Classification {
    Target,
    Other,
    Unknown,
}

/// Who owns the infrastructure the endpoint runs on.
pub fn attribute_infrastructure(evidence: &Evidence, domain: &str) -> Infrastructure {
    let zone = registrable_zone(domain);
    let target = zone
        .as_deref()
        .and_then(|zone| zone.split('.').next())
        .and_then(normalize);

    let in_target_zone = |name: &str| match (zone.as_deref(), registrable_zone(name)) {
        (Some(zone), Some(name_zone)) if name_zone == zone => Classification::Target,
        (Some(_), Some(_)) => Classification::Other,
        _ => Classification::Unknown,
    };
    let names_target = |identity: &Option<Identity>| {
        matches!(
            (identity, &target),
            (Some(identity), Some(target)) if matches_identity(identity, target)
        )
    };

    let names_signal_class = |text: &str, vendor: Option<Vendor>| {
        let identity = normalize(text);
        if names_target(&identity) {
            Classification::Target
        } else if vendor.is_some() || identity.is_some() {
            Classification::Other
        } else {
            Classification::Unknown
        }
    };

    let asn_class = match &evidence.asn {
        Some(asn) => names_signal_class(&asn.asn, asn.vendor),
        None => Classification::Unknown,
    };
    let rdap_class = match &evidence.rdap {
        Some(rdap) => names_signal_class(&rdap.netname, rdap.vendor),
        None => Classification::Unknown,
    };
    let ptr_class = match &evidence.ptr {
        Some(ptr) => match in_target_zone(&ptr.record) {
            Classification::Unknown if ptr.vendor.is_some() => Classification::Other,
            class => class,
        },
        None => Classification::Unknown,
    };
    let cname_class = match &evidence.cname {
        Some(cname) => match cname.chain.last().map(|hop| in_target_zone(hop)) {
            Some(Classification::Target) => Classification::Target,
            Some(Classification::Other) => Classification::Other,
            _ if cname.vendor.is_some() => Classification::Other,
            _ => Classification::Unknown,
        },
        None => Classification::Unknown,
    };
    let cert_class = match &evidence.cert {
        Some(cert) => {
            let subject_is_target = target.is_some()
                && cert
                    .names
                    .iter()
                    .filter(|name| Some(name.as_str()) != cert.issuer_cn.as_deref())
                    .any(|name| {
                        in_target_zone(name) == Classification::Target
                            || names_target(&normalize(name))
                    });
            if subject_is_target {
                Classification::Target
            } else if cert.vendor.is_some() {
                Classification::Other
            } else {
                Classification::Unknown
            }
        }
        None => Classification::Unknown,
    };

    let classes = [
        (asn_class, evidence.asn.as_ref().and_then(|a| a.vendor)),
        (rdap_class, evidence.rdap.as_ref().and_then(|r| r.vendor)),
        (ptr_class, evidence.ptr.as_ref().and_then(|p| p.vendor)),
        (cname_class, evidence.cname.as_ref().and_then(|c| c.vendor)),
        (cert_class, evidence.cert.as_ref().and_then(|c| c.vendor)),
    ];
    let target_matches = classes
        .iter()
        .filter(|(class, _)| *class == Classification::Target)
        .count() as u32;
    let mut other_matches = classes
        .iter()
        .filter(|(class, _)| *class == Classification::Other)
        .count() as u32;
    let vendor_others = classes
        .iter()
        .filter(|(class, vendor)| *class == Classification::Other && vendor.is_some())
        .count() as u32;

    let range_vendor = evidence.range.as_ref().map(|range| range.vendor);
    if range_vendor.is_some() {
        other_matches += 1;
    }

    let cert_is_sole_target = target_matches == 1 && cert_class == Classification::Target;

    let owner = if target_matches >= 2 && other_matches == 0 {
        InfraOwner::Organization
    } else if target_matches == 1 && other_matches == 0 {
        InfraOwner::PossiblyOrganization
    } else if other_matches >= 2
        && (target_matches == 0 || (cert_is_sole_target && vendor_others >= 2))
    {
        InfraOwner::ThirdParty
    } else if other_matches == 1 && target_matches == 0 {
        InfraOwner::PossiblyThirdParty
    } else if target_matches > 0 && other_matches > 0 {
        InfraOwner::Ambiguous
    } else {
        InfraOwner::Unknown
    };
    let winning_matches = match owner {
        InfraOwner::Organization | InfraOwner::PossiblyOrganization => target_matches,
        _ => other_matches,
    };
    let confidence = match owner {
        InfraOwner::Unknown => Confidence::None,
        InfraOwner::PossiblyOrganization | InfraOwner::PossiblyThirdParty => Confidence::Weak,
        InfraOwner::Ambiguous => Confidence::Mixed,
        _ if winning_matches >= 3 => Confidence::Confirmed,
        _ => Confidence::Likely,
    };

    let operator = (owner == InfraOwner::Organization)
        .then(|| {
            target
                .as_ref()
                .map(|identity| display_name(&identity.compact))
        })
        .flatten();
    let provider = range_vendor
        .or(evidence.asn.as_ref().and_then(|a| a.vendor))
        .or(evidence.rdap.as_ref().and_then(|r| r.vendor))
        .or(evidence.ptr.as_ref().and_then(|p| p.vendor))
        .or(evidence.cname.as_ref().and_then(|c| c.vendor))
        .or(evidence.cert.as_ref().and_then(|c| c.vendor))
        .map(|vendor| vendor.as_str().to_string())
        .or_else(|| agreed_provider(evidence, &target));

    Infrastructure {
        owner,
        operator,
        provider,
        target_matches,
        other_matches,
        confidence,
    }
}

/// A non-vendor third party named when the AS name and the RDAP netname
/// agree on the same non-target identity.
fn agreed_provider(evidence: &Evidence, target: &Option<Identity>) -> Option<String> {
    let asn = evidence.asn.as_ref().and_then(|a| normalize(&a.asn))?;
    let rdap = evidence.rdap.as_ref().and_then(|r| normalize(&r.netname))?;
    if target
        .as_ref()
        .is_some_and(|target| matches_identity(&asn, target) || matches_identity(&rdap, target))
    {
        return None;
    }
    let shorter = if asn.compact.len() <= rdap.compact.len() {
        &asn.compact
    } else {
        &rdap.compact
    };
    asn.tokens
        .iter()
        .any(|token| rdap.tokens.contains(token))
        .then(|| display_name(shorter))
}

/// Whether the endpoint sits behind a provider-managed edge/CDN/WAF,
/// and with how much confidence. Role evidence is independent of
/// ownership: an OVH ASN is hosting, never an edge, and an edge CNAME
/// alone is not proof either.
pub fn termination_role(evidence: &Evidence, domain: &str) -> Termination {
    let _ = domain;
    let mut edge_classes: Vec<EdgeSignal> = Vec::new();

    if evidence
        .cname
        .as_ref()
        .is_some_and(|cname| cname.vendor.is_some())
    {
        edge_classes.push(EdgeSignal::Cname);
    }
    if evidence.range.is_some() {
        edge_classes.push(EdgeSignal::Range);
    }
    if evidence.http.is_some() {
        edge_classes.push(EdgeSignal::Http);
    }
    if let Some(cert) = &evidence.cert
        && cert.names.iter().any(|name| {
            crate::providers::VENDOR_ZONES.iter().any(|(zone, _)| {
                let lowered = name.to_lowercase();
                lowered.ends_with(&format!(".{zone}")) || lowered == *zone
            })
        })
    {
        edge_classes.push(EdgeSignal::Cert);
    }
    if evidence
        .rdap
        .as_ref()
        .is_some_and(|rdap| rdap.vendor.is_some_and(|vendor| !vendor.is_cloud()))
        || evidence
            .asn
            .as_ref()
            .is_some_and(|asn| asn.vendor.is_some_and(|vendor| !vendor.is_cloud()))
    {
        edge_classes.push(EdgeSignal::Other);
    }

    let role = if edge_classes.len() >= 2 {
        TerminationRole::Edge
    } else if edge_classes.len() == 1 && edge_classes[0].is_strong() {
        TerminationRole::LikelyEdge
    } else {
        TerminationRole::Unproven
    };
    let confidence = match role {
        TerminationRole::Edge => Confidence::Confirmed,
        TerminationRole::LikelyEdge => Confidence::Likely,
        TerminationRole::Unproven => Confidence::None,
    };
    Termination {
        role,
        confidence,
        edge_classes,
    }
}

/// Trailing label pairs that act as public suffixes in their own right,
/// pushing the registrable label one position further left.
const SECOND_LEVEL_SUFFIXES: &[&str] = &[
    "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl", "info.pl", "waw.pl", "co.uk", "org.uk",
    "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.kr", "co.za", "com.br",
    "com.cn", "com.tr", "com.mx",
];

/// The registrable zone of a DNS name ("nbp.pl" for "e-zamowienia.nbp.pl"),
/// or None when the name is too short to hold one.
pub(crate) fn registrable_zone(name: &str) -> Option<String> {
    let lowered = name.trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = lowered
        .split('.')
        .filter(|label| !label.is_empty())
        .collect();
    let suffix2 = labels
        .len()
        .checked_sub(2)
        .map(|i| labels[i..].join("."))
        .unwrap_or_default();
    let take = if labels.len() >= 3 && SECOND_LEVEL_SUFFIXES.contains(&suffix2.as_str()) {
        3
    } else {
        2
    };
    (labels.len() >= take).then(|| labels[labels.len() - take..].join("."))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFacts {
    pub kx_group: String,
    pub symmetric_alg: SymmetricAlg,
}

impl TlsFacts {
    pub fn is_pq(&self) -> bool {
        self.kx_group == "X25519MLKEM768"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    pub priority: u16,
    pub host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsState {
    Unavailable,
    Tls(TlsSession),
}

/// A completed TLS session: protocol version, key-exchange group and
/// symmetric suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSession {
    pub version: String,
    pub facts: TlsFacts,
}

impl TlsSession {
    pub fn is_pq(&self) -> bool {
        self.facts.is_pq()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Port {
    Smtp25,
    Submission587,
    Smtps465,
}

impl Port {
    pub const ALL: [Port; 3] = [Port::Smtp25, Port::Submission587, Port::Smtps465];

    pub const fn number(&self) -> u16 {
        match self {
            Port::Smtp25 => 25,
            Port::Submission587 => 587,
            Port::Smtps465 => 465,
        }
    }

    pub const fn has_starttls(&self) -> bool {
        !matches!(self, Port::Smtps465)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpState {
    Unreachable,
    NoStarttls,
    TlsFailed,
    Tls(TlsSession),
}

#[derive(Debug, Clone)]
pub struct PortProbe {
    pub port: Port,
    pub state: SmtpState,
}

#[derive(Debug, Clone)]
pub struct MxProbe {
    pub priority: u16,
    pub host: String,
    pub addresses: Vec<IpAddr>,
    pub ip: Option<IpAddr>,
    pub ports: Vec<PortProbe>,
    pub evidence: Evidence,
    pub infrastructure: Infrastructure,
}

#[derive(Debug, Clone)]
pub struct EmailReport {
    pub mx: Vec<MxProbe>,
}

#[derive(Debug, Clone)]
pub struct DomainReport {
    pub domain: String,
    pub checked_at: DateTime<Local>,
    pub resolved_ip: Option<IpAddr>,
    pub tls: TlsState,
    pub evidence: Evidence,
    pub infrastructure: Infrastructure,
    pub termination: Termination,
    pub verdict: Verdict,
    pub email: Option<EmailReport>,
}

impl DomainReport {
    pub fn build(
        domain: String,
        resolved_ip: Option<IpAddr>,
        tls: TlsState,
        evidence: Evidence,
        email: Option<EmailReport>,
        checked_at: DateTime<Local>,
    ) -> Self {
        let infrastructure = attribute_infrastructure(&evidence, &domain);
        let mut termination = termination_role(&evidence, &domain);
        let verdict = match &tls {
            TlsState::Unavailable => Verdict::TlsUnavailable,
            TlsState::Tls(session) => {
                if termination.role == TerminationRole::Unproven {
                    termination.confidence = infrastructure.confidence;
                }
                verdict_of(&infrastructure, &termination, session.is_pq())
            }
        };
        Self {
            domain,
            checked_at,
            resolved_ip,
            tls,
            evidence,
            infrastructure,
            termination,
            verdict,
            email,
        }
    }
}

pub fn verdict_of(infrastructure: &Infrastructure, termination: &Termination, pq: bool) -> Verdict {
    match termination.role {
        TerminationRole::Edge => {
            if pq {
                Verdict::PqAtEdge
            } else {
                Verdict::NoPqAtEdge
            }
        }
        TerminationRole::LikelyEdge => {
            if pq {
                Verdict::PqLikelyAtEdge
            } else {
                Verdict::NoPqLikelyAtEdge
            }
        }
        TerminationRole::Unproven => match infrastructure.owner {
            InfraOwner::Organization | InfraOwner::PossiblyOrganization => {
                if pq {
                    Verdict::PqOnOrgInfra
                } else {
                    Verdict::NoPqOnOrgInfra
                }
            }
            InfraOwner::ThirdParty | InfraOwner::PossiblyThirdParty => {
                if pq {
                    Verdict::PqOnThirdPartyInfra
                } else {
                    Verdict::NoPqOnThirdPartyInfra
                }
            }
            InfraOwner::Ambiguous | InfraOwner::Unknown => {
                if pq {
                    Verdict::PqUnattributed
                } else {
                    Verdict::NoPqUnattributed
                }
            }
        },
    }
}

#[cfg(test)]
pub fn fixture() -> DomainReport {
    let evidence = Evidence {
        cname: None,
        range: None,
        cert: Some(CertEvidence {
            vendor: None,
            name: "www.citi.com".to_string(),
            names: vec!["www.citi.com".to_string(), "citibankonline.pl".to_string()],
            issuer_cn: Some("DigiCert TLS RSA SHA256 2020 CA1".to_string()),
        }),
        http: Some(HttpEvidence {
            header: "X-Akamai-Request-ID".to_string(),
            vendor: Vendor::Akamai,
        }),
        ptr: Some(PtrEvidence {
            record: "a104-96-178-165.deploy.static.akamaitechnologies.com".to_string(),
            vendor: Some(Vendor::Akamai),
        }),
        rdap: Some(RdapEvidence {
            netname: "AKAMAI".to_string(),
            vendor: Some(Vendor::Akamai),
        }),
        asn: Some(AsnEvidence {
            asn: "AS20940 AKAMAI-ASN1".to_string(),
            vendor: Some(Vendor::Akamai),
        }),
    };
    DomainReport::build(
        "citibankonline.pl".to_string(),
        Some("104.96.178.165".parse().unwrap()),
        TlsState::Tls(TlsSession {
            version: "TLS 1.2".to_string(),
            facts: TlsFacts {
                kx_group: "X25519".to_string(),
                symmetric_alg: SymmetricAlg::Aes256,
            },
        }),
        evidence,
        None,
        Local::now(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_evidence_alone_leans_third_party_and_names_the_provider() {
        let evidence = Evidence {
            range: Some(RangeEvidence {
                cidr: "104.16.0.0/12".to_string(),
                vendor: Vendor::Cloudflare,
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "pqpulse.dev");
        assert_eq!(infra.owner, InfraOwner::PossiblyThirdParty);
        assert_eq!(infra.provider.as_deref(), Some("Cloudflare"));
        assert_eq!(infra.other_matches, 1);
        assert_eq!(infra.target_matches, 0);
        assert_eq!(infra.confidence, Confidence::Weak);

        let termination = termination_role(&evidence, "pqpulse.dev");
        assert_eq!(termination.role, TerminationRole::LikelyEdge);
        assert_eq!(termination.edge_classes, vec![EdgeSignal::Range]);
        assert_eq!(
            verdict_of(&infra, &termination, true),
            Verdict::PqLikelyAtEdge
        );
    }

    #[test]
    fn a_vendor_range_and_a_vendor_asn_agree_on_third_party() {
        let evidence = Evidence {
            range: Some(RangeEvidence {
                cidr: "104.16.0.0/12".to_string(),
                vendor: Vendor::Cloudflare,
            }),
            asn: Some(AsnEvidence {
                asn: "AS13335 CLOUDFLARENET".to_string(),
                vendor: Some(Vendor::Cloudflare),
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "pqpulse.dev");
        assert_eq!(infra.owner, InfraOwner::ThirdParty);
        assert_eq!(infra.provider.as_deref(), Some("Cloudflare"));
        assert_eq!(infra.other_matches, 2);
        assert_eq!(infra.confidence, Confidence::Likely);
    }

    #[test]
    fn mbank_names_are_recognized_as_the_organization() {
        let evidence = Evidence {
            asn: Some(AsnEvidence {
                asn: "AS13274 MBANK-SA".to_string(),
                vendor: None,
            }),
            rdap: Some(RdapEvidence {
                netname: "PL-MBANKPL".to_string(),
                vendor: None,
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "mbank.pl");
        assert_eq!(infra.owner, InfraOwner::Organization);
        assert_eq!(infra.operator.as_deref(), Some("Mbank"));
        assert_eq!(infra.provider, None);
        assert_eq!(infra.target_matches, 2);
        assert_eq!(infra.other_matches, 0);
        assert_eq!(infra.confidence, Confidence::Likely);
    }

    #[test]
    fn a_foreign_ptr_contests_mbank_target_evidence() {
        let evidence = Evidence {
            asn: Some(AsnEvidence {
                asn: "AS13274 MBANK-SA".to_string(),
                vendor: None,
            }),
            rdap: Some(RdapEvidence {
                netname: "PL-MBANKPL".to_string(),
                vendor: None,
            }),
            ptr: Some(PtrEvidence {
                record: "war01mail1.brebank.com.pl".to_string(),
                vendor: None,
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "mbank.pl");
        assert_eq!(infra.owner, InfraOwner::Ambiguous);
        assert_eq!(infra.target_matches, 2);
        assert_eq!(infra.other_matches, 1);
        assert_eq!(infra.confidence, Confidence::Mixed);
    }

    #[test]
    fn a_lone_foreign_ptr_leans_third_party() {
        let evidence = Evidence {
            ptr: Some(PtrEvidence {
                record: "mail.mfinanse.sk".to_string(),
                vendor: None,
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "mbank.pl");
        assert_eq!(infra.owner, InfraOwner::PossiblyThirdParty);
        assert_eq!(infra.provider, None);
        assert_eq!(infra.confidence, Confidence::Weak);
    }

    #[test]
    fn an_org_cert_on_vendor_evidence_resolves_third_party_not_ambiguous() {
        let evidence = Evidence {
            cert: Some(CertEvidence {
                name: "mail.example.com".to_string(),
                vendor: None,
                names: vec!["mail.example.com".to_string()],
                issuer_cn: Some("DigiCert Global CA".to_string()),
            }),
            asn: Some(AsnEvidence {
                asn: "AS20940 AKAMAI-ASN1".to_string(),
                vendor: Some(Vendor::Akamai),
            }),
            rdap: Some(RdapEvidence {
                netname: "AKAMAI".to_string(),
                vendor: Some(Vendor::Akamai),
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "example.com");
        assert_eq!(infra.owner, InfraOwner::ThirdParty);
        assert_eq!(infra.provider.as_deref(), Some("Akamai"));
        assert_eq!(infra.confidence, Confidence::Likely);
    }

    #[test]
    fn ovh_network_is_contested_evidence_never_an_edge() {
        let evidence = Evidence {
            ptr: Some(PtrEvidence {
                record: "mail.krakowski.pinb.gov.pl".to_string(),
                vendor: None,
            }),
            rdap: Some(RdapEvidence {
                netname: "OVH-DEDICATED-FO".to_string(),
                vendor: None,
            }),
            asn: Some(AsnEvidence {
                asn: "AS16276 OVH".to_string(),
                vendor: None,
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "mail.krakowski.pinb.gov.pl");
        assert_eq!(infra.owner, InfraOwner::Ambiguous);
        assert_eq!(infra.provider.as_deref(), Some("OVH"));
        assert_eq!(infra.target_matches, 1);
        assert_eq!(infra.other_matches, 2);
        assert_eq!(infra.confidence, Confidence::Mixed);

        let termination = termination_role(&evidence, "mail.krakowski.pinb.gov.pl");
        assert_eq!(termination.role, TerminationRole::Unproven);
        assert!(termination.edge_classes.is_empty());
        assert_eq!(
            verdict_of(&infra, &termination, false),
            Verdict::NoPqUnattributed
        );
        assert_eq!(
            verdict_of(&infra, &termination, true),
            Verdict::PqUnattributed
        );
    }

    #[test]
    fn provider_identity_alone_never_proves_edge_role() {
        let evidence = Evidence {
            asn: Some(AsnEvidence {
                asn: "AS15169 GOOGLE-CLOUD-PLATFORM".to_string(),
                vendor: Some(Vendor::GoogleCloud),
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "example.com");
        assert_eq!(infra.owner, InfraOwner::PossiblyThirdParty);
        assert_eq!(infra.confidence, Confidence::Weak);
        assert_eq!(infra.provider.as_deref(), Some("Google Cloud"));

        let termination = termination_role(&evidence, "example.com");
        assert!(termination.edge_classes.is_empty());
        assert_eq!(termination.role, TerminationRole::Unproven);
    }

    #[test]
    fn two_edge_classes_confirm_edge_termination() {
        let evidence = Evidence {
            range: Some(RangeEvidence {
                cidr: "104.16.0.0/12".to_string(),
                vendor: Vendor::Cloudflare,
            }),
            http: Some(HttpEvidence {
                header: "X-Akamai-Request-ID".to_string(),
                vendor: Vendor::Akamai,
            }),
            ..Default::default()
        };
        let termination = termination_role(&evidence, "example.com");
        assert_eq!(termination.role, TerminationRole::Edge);
        assert_eq!(termination.confidence, Confidence::Confirmed);
        assert_eq!(
            termination.edge_classes,
            vec![EdgeSignal::Range, EdgeSignal::Http]
        );
    }

    #[test]
    fn weak_alone_signals_stay_unproven() {
        let evidence = Evidence {
            cert: Some(CertEvidence {
                name: "edge.example.com.akamaiedge.net".to_string(),
                vendor: None,
                names: vec!["edge.example.com.akamaiedge.net".to_string()],
                issuer_cn: None,
            }),
            ..Default::default()
        };
        let termination = termination_role(&evidence, "example.com");
        assert_eq!(termination.edge_classes, vec![EdgeSignal::Cert]);
        assert_eq!(termination.role, TerminationRole::Unproven);
    }

    #[test]
    fn a_single_strong_signal_is_likely_edge() {
        let evidence = Evidence {
            cname: Some(CnameEvidence {
                chain: vec![
                    "www.example.com.edgekey.net".to_string(),
                    "e970.dspg.akamaiedge.net".to_string(),
                ],
                vendor: Some(Vendor::Akamai),
            }),
            ..Default::default()
        };
        let termination = termination_role(&evidence, "www.example.com");
        assert_eq!(termination.edge_classes, vec![EdgeSignal::Cname]);
        assert_eq!(termination.role, TerminationRole::LikelyEdge);
        assert_eq!(termination.confidence, Confidence::Likely);
        let infra = attribute_infrastructure(&evidence, "www.example.com");
        assert_eq!(
            verdict_of(&infra, &termination, true),
            Verdict::PqLikelyAtEdge
        );
    }

    #[test]
    fn own_zone_dns_and_netname_attribute_to_the_organization() {
        let evidence = Evidence {
            ptr: Some(PtrEvidence {
                record: "www.allegro.pl".to_string(),
                vendor: None,
            }),
            rdap: Some(RdapEvidence {
                netname: "ALLEGRO-NET".to_string(),
                vendor: None,
            }),
            asn: Some(AsnEvidence {
                asn: "AS42656 ALLEGRO".to_string(),
                vendor: None,
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "www.allegro.pl");
        assert_eq!(infra.owner, InfraOwner::Organization);
        assert_eq!(infra.operator.as_deref(), Some("Allegro"));
        assert_eq!(infra.provider, None);
        assert_eq!(infra.target_matches, 3);
        assert_eq!(infra.other_matches, 0);
        assert_eq!(infra.confidence, Confidence::Confirmed);
    }

    #[test]
    fn a_foreign_as_name_contests_own_zone_target_evidence() {
        let evidence = Evidence {
            ptr: Some(PtrEvidence {
                record: "www.allegro.pl".to_string(),
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
        };
        let infra = attribute_infrastructure(&evidence, "www.allegro.pl");
        assert_eq!(infra.owner, InfraOwner::Ambiguous);
        assert_eq!(infra.target_matches, 2);
        assert_eq!(infra.other_matches, 1);
        assert_eq!(infra.confidence, Confidence::Mixed);
    }

    #[test]
    fn a_lone_own_zone_ptr_leans_organization() {
        let evidence = Evidence {
            ptr: Some(PtrEvidence {
                record: "www.example.com".to_string(),
                vendor: None,
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "www.example.com");
        assert_eq!(infra.owner, InfraOwner::PossiblyOrganization);
        assert_eq!(infra.target_matches, 1);
        assert_eq!(infra.confidence, Confidence::Weak);
        let termination = termination_role(&evidence, "www.example.com");
        assert_eq!(
            verdict_of(&infra, &termination, true),
            Verdict::PqOnOrgInfra
        );
    }

    #[test]
    fn a_foreign_ptr_against_a_matching_netname_is_ambiguous() {
        let evidence = Evidence {
            ptr: Some(PtrEvidence {
                record: "host.fov.club".to_string(),
                vendor: None,
            }),
            rdap: Some(RdapEvidence {
                netname: "EXAMPLE-NET".to_string(),
                vendor: None,
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "www.example.com");
        assert_eq!(infra.owner, InfraOwner::Ambiguous);
        assert_eq!(infra.confidence, Confidence::Mixed);
    }

    #[test]
    fn a_foreign_cname_leans_third_party_and_an_own_cname_leans_organization() {
        let evidence = Evidence {
            cname: Some(CnameEvidence {
                chain: vec!["cdn.vendor.example.net".to_string()],
                vendor: None,
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "www.example.com");
        assert_eq!(infra.owner, InfraOwner::PossiblyThirdParty);
        assert_eq!(infra.other_matches, 1);
        assert_eq!(infra.confidence, Confidence::Weak);

        let own = Evidence {
            cname: Some(CnameEvidence {
                chain: vec!["cdn.example.com".to_string()],
                vendor: None,
            }),
            ..Default::default()
        };
        let own_infra = attribute_infrastructure(&own, "www.example.com");
        assert_eq!(own_infra.owner, InfraOwner::PossiblyOrganization);
        assert_eq!(own_infra.target_matches, 1);
        assert_eq!(own_infra.confidence, Confidence::Weak);
    }

    #[test]
    fn cert_subject_names_count_as_target_evidence() {
        let evidence = Evidence {
            cert: Some(CertEvidence {
                name: "mail.example.com".to_string(),
                vendor: None,
                names: vec!["mail.example.com".to_string()],
                issuer_cn: None,
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "mail.example.com");
        assert_eq!(infra.owner, InfraOwner::PossiblyOrganization);
        assert_eq!(infra.target_matches, 1);
        assert_eq!(infra.confidence, Confidence::Weak);
        assert!(
            termination_role(&evidence, "mail.example.com")
                .edge_classes
                .is_empty()
        );
    }

    #[test]
    fn cert_issuer_names_are_excluded_from_target_matching() {
        let evidence = Evidence {
            cert: Some(CertEvidence {
                name: "www.othername.org".to_string(),
                vendor: None,
                names: vec!["www.othername.org".to_string(), "ACME-CA".to_string()],
                issuer_cn: Some("ACME-CA".to_string()),
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "www.acme.org");
        assert_eq!(infra.owner, InfraOwner::Unknown);
        assert_eq!(infra.target_matches, 0);
        assert_eq!(infra.confidence, Confidence::None);
    }

    #[test]
    fn fixture_terminates_at_akamai_edge() {
        let report = fixture();
        assert_eq!(report.termination.role, TerminationRole::Edge);
        assert_eq!(report.termination.confidence, Confidence::Confirmed);
        assert!(!report.termination.edge_classes.is_empty());
        assert_eq!(report.verdict, Verdict::NoPqAtEdge);
        match &report.tls {
            TlsState::Tls(session) => assert!(!session.is_pq()),
            TlsState::Unavailable => panic!("fixture must have TLS"),
        }
    }

    #[test]
    fn tls_unavailable_verdict_is_independent_of_attribution() {
        let report = DomainReport::build(
            "gorlice.pinb.gov.pl".to_string(),
            None,
            TlsState::Unavailable,
            Evidence::default(),
            None,
            Local::now(),
        );
        assert_eq!(report.verdict, Verdict::TlsUnavailable);
        assert_eq!(report.verdict.as_str(), "tls_unavailable");
    }

    #[test]
    fn registrable_zone_handles_two_level_suffixes() {
        assert_eq!(
            registrable_zone("e-zamowienia.nbp.pl").as_deref(),
            Some("nbp.pl")
        );
        assert_eq!(
            registrable_zone("online.bankmillennium.pl.").as_deref(),
            Some("bankmillennium.pl")
        );
        assert_eq!(registrable_zone("nbp.pl").as_deref(), Some("nbp.pl"));
        assert_eq!(
            registrable_zone("www.foo.co.uk").as_deref(),
            Some("foo.co.uk")
        );
        assert_eq!(
            registrable_zone("pacjent.gov.pl").as_deref(),
            Some("pacjent.gov.pl")
        );
        assert_eq!(registrable_zone("pl").as_deref(), None);
        assert_eq!(registrable_zone("localhost").as_deref(), None);
    }
}
