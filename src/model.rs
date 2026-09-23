use std::net::IpAddr;

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

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
    Probable,
    None,
}

impl Confidence {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Confidence::Confirmed => "confirmed",
            Confidence::Probable => "probable",
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

/// Who owns the infrastructure the endpoint runs on, per the scoring
/// rules: the organization itself, an identifiable third party, or
/// unknown when the evidence is absent, weak or contested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfraOwner {
    Organization,
    ThirdParty,
    Unknown,
}

impl InfraOwner {
    pub const fn as_str(&self) -> &'static str {
        match self {
            InfraOwner::Organization => "organization",
            InfraOwner::ThirdParty => "third-party",
            InfraOwner::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Infrastructure {
    pub owner: InfraOwner,
    pub provider: Option<String>,
    pub org_score: u32,
    pub third_party_score: u32,
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

/// Infrastructure ownership per the scoring rules. Provider identity
/// never implies provider role: this answers only "whose infrastructure
/// is this?".
///
/// Weights (organization | third party):
///   final CNAME in org zone +1 | in a third-party zone +2
///   PTR in org zone +1         | in a third-party zone +1
///   RDAP netname names the org +3 | identified third party +3
///   AS name names the org +4   | identified third party +4
///   resolved IP in org ranges +4  | in provider ranges +4
///
/// A side scores only from 4 upward and must strictly beat the other;
/// anything weaker or tied stays unknown.
pub fn attribute_infrastructure(evidence: &Evidence, domain: &str) -> Infrastructure {
    let zone = registrable_zone(domain);
    let in_own_zone = |name: &str| zone.as_deref().is_some_and(|z| in_zone(name, z));
    let names_org = |text: &str| zone.as_deref().is_some_and(|z| names_operator(text, z));

    let mut org_score: u32 = 0;
    let mut third_party_score: u32 = 0;
    let mut provider: Option<String> = None;

    if let Some(cname) = &evidence.cname
        && let Some(hop) = cname.chain.last()
    {
        if in_own_zone(hop) {
            org_score += 1;
        } else {
            third_party_score += 2;
        }
    }

    if let Some(ptr) = &evidence.ptr {
        if in_own_zone(&ptr.record) {
            org_score += 1;
        } else {
            third_party_score += 1;
        }
    }

    let identity = named_third_party(evidence, &names_org);

    if let Some(range) = &evidence.range {
        third_party_score += 4;
        provider = Some(range.vendor.as_str().to_string());
    }

    if let Some(asn) = &evidence.asn {
        if names_org(&asn.asn) {
            org_score += 4;
        } else if let Some(vendor) = asn.vendor {
            third_party_score += 4;
            provider = Some(vendor.as_str().to_string());
        } else if identity.is_some() {
            third_party_score += 4;
            provider = identity.clone();
        }
    }

    if let Some(rdap) = &evidence.rdap {
        if names_org(&rdap.netname) {
            org_score += 3;
        } else if let Some(vendor) = rdap.vendor {
            third_party_score += 3;
            provider = Some(vendor.as_str().to_string());
        } else if identity.is_some() {
            third_party_score += 3;
            provider = identity;
        }
    }

    let owner = if org_score >= 4 && org_score > third_party_score {
        InfraOwner::Organization
    } else if third_party_score >= 4 && third_party_score > org_score {
        InfraOwner::ThirdParty
    } else {
        InfraOwner::Unknown
    };
    let confidence = match owner {
        InfraOwner::Unknown => Confidence::None,
        _ if org_score.abs_diff(third_party_score) >= 4 => Confidence::Confirmed,
        _ => Confidence::Probable,
    };

    Infrastructure {
        owner,
        provider,
        org_score,
        third_party_score,
        confidence,
    }
}

/// An AS name and an RDAP organization that agree on a shared
/// alphabetic token identify the network operator — without any
/// provider list. The identity must not be the scanned organization
/// itself, and both names must exist.
fn named_third_party(evidence: &Evidence, names_org: &impl Fn(&str) -> bool) -> Option<String> {
    let asn = evidence.asn.as_ref()?;
    let rdap = evidence.rdap.as_ref()?;
    if names_org(&asn.asn) || names_org(&rdap.netname) {
        return None;
    }
    if asn.vendor.is_some() || rdap.vendor.is_some() {
        return None;
    }
    let asn_tokens = identity_tokens(&asn.asn);
    identity_tokens(&rdap.netname)
        .into_iter()
        .find(|token| asn_tokens.contains(token))
        .map(|token| display_provider(&token))
}

fn identity_tokens(text: &str) -> Vec<String> {
    text.to_uppercase()
        .split(|c: char| !c.is_alphabetic())
        .filter(|token| token.len() >= 3)
        .map(String::from)
        .collect()
}

fn display_provider(token: &str) -> String {
    if token.len() <= 3 {
        token.to_uppercase()
    } else {
        let mut chars = token.chars();
        match chars.next() {
            Some(first) => {
                first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
            }
            None => token.to_string(),
        }
    }
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
        TerminationRole::LikelyEdge => Confidence::Probable,
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

/// True when `name` equals `zone` or lies inside it.
fn in_zone(name: &str, zone: &str) -> bool {
    let name = name.trim_end_matches('.').to_lowercase();
    name == zone || name.ends_with(&format!(".{zone}"))
}

/// True when a netname-style string ("PL-MBANKPL") contains the zone's
/// registrable label ("mbank") as a whole token.
fn names_operator(netname: &str, zone: &str) -> bool {
    let Some(label) = zone.split('.').next() else {
        return false;
    };
    let label = label.to_uppercase();
    netname
        .to_uppercase()
        .split(|c: char| !c.is_alphanumeric())
        .any(|token| token == label)
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
            InfraOwner::Organization => {
                if pq {
                    Verdict::PqOnOrgInfra
                } else {
                    Verdict::NoPqOnOrgInfra
                }
            }
            InfraOwner::ThirdParty => {
                if pq {
                    Verdict::PqOnThirdPartyInfra
                } else {
                    Verdict::NoPqOnThirdPartyInfra
                }
            }
            InfraOwner::Unknown => {
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
    fn range_evidence_identifies_the_provider_and_counts_third_party() {
        let evidence = Evidence {
            range: Some(RangeEvidence {
                cidr: "104.16.0.0/12".to_string(),
                vendor: Vendor::Cloudflare,
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "pqpulse.dev");
        assert_eq!(infra.owner, InfraOwner::ThirdParty);
        assert_eq!(infra.provider.as_deref(), Some("Cloudflare"));
        assert_eq!(infra.third_party_score, 4);
        assert_eq!(infra.confidence, Confidence::Confirmed);

        let termination = termination_role(&evidence, "pqpulse.dev");
        assert_eq!(termination.role, TerminationRole::LikelyEdge);
        assert_eq!(termination.edge_classes, vec![EdgeSignal::Range]);
        assert_eq!(
            verdict_of(&infra, &termination, true),
            Verdict::PqLikelyAtEdge
        );
    }

    #[test]
    fn ovh_network_is_third_party_infrastructure_never_an_edge() {
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
        assert_eq!(infra.owner, InfraOwner::ThirdParty);
        assert_eq!(infra.provider.as_deref(), Some("OVH"));
        assert_eq!(infra.org_score, 1);
        assert_eq!(infra.third_party_score, 7);

        let termination = termination_role(&evidence, "mail.krakowski.pinb.gov.pl");
        assert_eq!(termination.role, TerminationRole::Unproven);
        assert!(termination.edge_classes.is_empty());
        assert_eq!(
            verdict_of(&infra, &termination, false),
            Verdict::NoPqOnThirdPartyInfra
        );
        assert_eq!(
            verdict_of(&infra, &termination, true),
            Verdict::PqOnThirdPartyInfra
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
        assert_eq!(infra.owner, InfraOwner::ThirdParty);
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
        assert_eq!(termination.confidence, Confidence::Probable);
        let infra = attribute_infrastructure(&evidence, "www.example.com");
        assert_eq!(
            verdict_of(&infra, &termination, true),
            Verdict::PqLikelyAtEdge
        );
    }

    #[test]
    fn org_zone_dns_and_netname_attribute_to_the_organization() {
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
        assert_eq!(infra.owner, InfraOwner::Organization);
        assert_eq!(infra.provider, None);
        assert_eq!(infra.org_score, 4);
        assert_eq!(infra.third_party_score, 0);
        assert_eq!(infra.confidence, Confidence::Confirmed);
    }

    #[test]
    fn a_lone_own_zone_ptr_is_too_weak_to_attribute() {
        let evidence = Evidence {
            ptr: Some(PtrEvidence {
                record: "www.example.com".to_string(),
                vendor: None,
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "www.example.com");
        assert_eq!(infra.owner, InfraOwner::Unknown);
        assert_eq!(infra.confidence, Confidence::None);
        let termination = termination_role(&evidence, "www.example.com");
        assert_eq!(
            verdict_of(&infra, &termination, true),
            Verdict::PqUnattributed
        );
    }

    #[test]
    fn tied_scores_stay_unknown() {
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
        assert_eq!(infra.owner, InfraOwner::Unknown);
    }

    #[test]
    fn cname_delegation_counts_double_for_third_parties() {
        let evidence = Evidence {
            cname: Some(CnameEvidence {
                chain: vec!["cdn.vendor.example.net".to_string()],
                vendor: None,
            }),
            ..Default::default()
        };
        let infra = attribute_infrastructure(&evidence, "www.example.com");
        assert_eq!(infra.third_party_score, 2);

        let own = Evidence {
            cname: Some(CnameEvidence {
                chain: vec!["cdn.example.com".to_string()],
                vendor: None,
            }),
            ..Default::default()
        };
        assert_eq!(
            attribute_infrastructure(&own, "www.example.com").org_score,
            1
        );
    }

    #[test]
    fn cert_names_never_attribute_ownership_but_edge_namespace_is_role_evidence() {
        let evidence = Evidence {
            cert: Some(CertEvidence {
                name: "mail.example.com".to_string(),
                vendor: None,
                names: vec!["mail.example.com".to_string()],
            }),
            ..Default::default()
        };
        assert_eq!(
            attribute_infrastructure(&evidence, "mail.example.com").owner,
            InfraOwner::Unknown
        );
        assert!(
            termination_role(&evidence, "mail.example.com")
                .edge_classes
                .is_empty()
        );
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
