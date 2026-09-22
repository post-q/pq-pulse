use std::collections::{HashMap, HashSet};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operator {
    Own,
    Vendor(Vendor),
}

impl Operator {
    pub const fn short(&self) -> &'static str {
        match self {
            Operator::Own => "self",
            Operator::Vendor(vendor) => vendor.as_str(),
        }
    }

    pub fn label(&self, zone: &str) -> String {
        match self {
            Operator::Own => format!("self ({zone})"),
            Operator::Vendor(vendor) => vendor.as_str().to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalType {
    Cname,
    Range,
    Cert,
    Http,
    Ptr,
    Rdap,
    Asn,
}

impl SignalType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            SignalType::Cname => "CNAME",
            SignalType::Range => "RANGE",
            SignalType::Cert => "CERT",
            SignalType::Http => "HTTP",
            SignalType::Ptr => "PTR",
            SignalType::Rdap => "RDAP",
            SignalType::Asn => "ASN",
        }
    }

    /// Evidence class of this signal type.
    /// PTR, RDAP and ASN all derive from IP block ownership — counted
    /// as one class. HTTP shows the request was actually processed by
    /// the vendor edge — its own class.
    pub const fn class(&self) -> EvidenceClass {
        match self {
            SignalType::Cname => EvidenceClass::DnsDelegation,
            SignalType::Range => EvidenceClass::PublishedRange,
            SignalType::Cert => EvidenceClass::Certificate,
            SignalType::Http => EvidenceClass::EdgeProcessing,
            SignalType::Ptr | SignalType::Rdap | SignalType::Asn => EvidenceClass::IpInfra,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceClass {
    DnsDelegation,
    PublishedRange,
    Certificate,
    EdgeProcessing,
    IpInfra,
}

impl EvidenceClass {
    pub const fn as_str(&self) -> &'static str {
        match self {
            EvidenceClass::DnsDelegation => "dns_delegation",
            EvidenceClass::PublishedRange => "published_range",
            EvidenceClass::Certificate => "certificate",
            EvidenceClass::EdgeProcessing => "edge_processing",
            EvidenceClass::IpInfra => "ip_infra",
        }
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
            SymmetricAlg::Aes128 => "AES128",
            SymmetricAlg::Aes256 => "AES256",
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
    Undecided,
    None,
}

impl Confidence {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Confidence::Confirmed => "confirmed",
            Confidence::Probable => "probable",
            Confidence::Undecided => "undecided",
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
    PqCloudHosted,
    PqVendorHosted,
    PqOwnInfra,
    NoPqEdge,
    NoPqCloudHosted,
    NoPqVendorHosted,
    NoPqOwnInfra,
}

impl Verdict {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Verdict::PqAtEdge => "pq_at_edge",
            Verdict::PqCloudHosted => "pq_cloud_hosted",
            Verdict::PqVendorHosted => "pq_vendor_hosted",
            Verdict::PqOwnInfra => "pq_own_infra",
            Verdict::NoPqEdge => "no_pq_edge",
            Verdict::NoPqCloudHosted => "no_pq_cloud_hosted",
            Verdict::NoPqVendorHosted => "no_pq_vendor_hosted",
            Verdict::NoPqOwnInfra => "no_pq_own_infra",
        }
    }

    pub const fn explanation(&self) -> &'static str {
        match self {
            Verdict::PqAtEdge => {
                "The public connection terminates at an identified edge/CDN/security provider, where post-quantum or hybrid key exchange is enabled."
            }
            Verdict::PqCloudHosted => {
                "The service is hosted on infrastructure attributed to a public cloud provider, with post-quantum or hybrid key exchange enabled."
            }
            Verdict::PqVendorHosted => {
                "The service is hosted on infrastructure attributed to a third-party provider, with post-quantum or hybrid key exchange enabled."
            }
            Verdict::PqOwnInfra => {
                "The service appears to terminate on infrastructure operated by the organization, with post-quantum or hybrid key exchange enabled."
            }
            Verdict::NoPqEdge => {
                "The public connection terminates at an identified edge/CDN/security provider, but no post-quantum key exchange was observed."
            }
            Verdict::NoPqCloudHosted => {
                "The service is hosted on infrastructure attributed to a public cloud provider, but no post-quantum key exchange was observed."
            }
            Verdict::NoPqVendorHosted => {
                "The service is hosted on infrastructure attributed to a third-party provider, but no post-quantum key exchange was observed."
            }
            Verdict::NoPqOwnInfra => {
                "The service appears to terminate on infrastructure operated by the organization, but no post-quantum key exchange was observed."
            }
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.as_str(), self.explanation())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signal {
    pub kind: SignalType,
    pub operator: Operator,
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

/// Who operates the resolved infrastructure, as far as the raw evidence
/// says: `Own` when the CNAME/PTR stay inside the domain's registrable
/// zone or the RDAP netname names the same operator, `ThirdParty` when
/// they point into someone else's zone, `Unknown` when it cannot tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfraOwnership {
    Own,
    ThirdParty,
    Unknown,
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

impl Evidence {
    pub fn signals(&self, domain: &str) -> Vec<Signal> {
        let zone = registrable_zone(domain);
        let in_own_zone = |name: &str| zone.as_deref().is_some_and(|z| in_zone(name, z));
        let names_org = |text: &str| zone.as_deref().is_some_and(|z| names_operator(text, z));
        let mut signals = Vec::new();
        if let Some(cname) = &self.cname {
            let operator = match cname.vendor {
                Some(vendor) => Some(Operator::Vendor(vendor)),
                None if cname.chain.last().is_some_and(|hop| in_own_zone(hop)) => {
                    Some(Operator::Own)
                }
                None => None,
            };
            if let Some(operator) = operator {
                signals.push(Signal {
                    kind: SignalType::Cname,
                    operator,
                });
            }
        }
        if let Some(range) = &self.range {
            signals.push(Signal {
                kind: SignalType::Range,
                operator: Operator::Vendor(range.vendor),
            });
        }
        if let Some(cert) = &self.cert {
            if let Some(vendor) = cert.vendor {
                signals.push(Signal {
                    kind: SignalType::Cert,
                    operator: Operator::Vendor(vendor),
                });
            }
        }
        if let Some(http) = &self.http {
            signals.push(Signal {
                kind: SignalType::Http,
                operator: Operator::Vendor(http.vendor),
            });
        }
        if let Some(ptr) = &self.ptr {
            let operator = match ptr.vendor {
                Some(vendor) => Some(Operator::Vendor(vendor)),
                None if in_own_zone(&ptr.record) => Some(Operator::Own),
                None => None,
            };
            if let Some(operator) = operator {
                signals.push(Signal {
                    kind: SignalType::Ptr,
                    operator,
                });
            }
        }
        if let Some(rdap) = &self.rdap {
            let operator = match rdap.vendor {
                Some(vendor) => Some(Operator::Vendor(vendor)),
                None if names_org(&rdap.netname) => Some(Operator::Own),
                None => None,
            };
            if let Some(operator) = operator {
                signals.push(Signal {
                    kind: SignalType::Rdap,
                    operator,
                });
            }
        }
        if let Some(asn) = &self.asn {
            let operator = match asn.vendor {
                Some(vendor) => Some(Operator::Vendor(vendor)),
                None if names_org(&asn.asn) => Some(Operator::Own),
                None => None,
            };
            if let Some(operator) = operator {
                signals.push(Signal {
                    kind: SignalType::Asn,
                    operator,
                });
            }
        }
        signals
    }

    pub fn infra_ownership(&self, domain: &str) -> InfraOwnership {
        let Some(zone) = registrable_zone(domain) else {
            return InfraOwnership::Unknown;
        };
        let dns_refs = [
            // The terminal CNAME hop is where the name finally resolves.
            self.cname
                .as_ref()
                .and_then(|c| c.chain.last())
                .map(String::as_str),
            self.ptr.as_ref().map(|p| p.record.as_str()),
        ];
        if dns_refs.iter().flatten().any(|r| in_zone(r, &zone)) {
            return InfraOwnership::Own;
        }
        if self
            .rdap
            .as_ref()
            .is_some_and(|r| names_operator(&r.netname, &zone))
        {
            return InfraOwnership::Own;
        }
        if self
            .asn
            .as_ref()
            .is_some_and(|a| names_operator(&a.asn, &zone))
        {
            return InfraOwnership::Own;
        }
        if dns_refs
            .iter()
            .flatten()
            .any(|r| registrable_zone(r).is_some_and(|foreign| foreign != zone))
        {
            return InfraOwnership::ThirdParty;
        }
        InfraOwnership::Unknown
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

#[derive(Debug, Clone)]
pub struct TlsFacts {
    pub kx_group: String,
    pub symmetric_alg: SymmetricAlg,
}

impl TlsFacts {
    pub fn is_pq(&self) -> bool {
        self.kx_group == "X25519MLKEM768"
    }
}

#[derive(Debug, Clone)]
pub struct Signals {
    pub operator: Option<Operator>,
    pub candidates: Vec<Operator>,
    pub confidence: Confidence,
    pub signal_count: usize,
    pub class_count: usize,
}

impl Signals {
    pub fn aggregate(signals: &[Signal]) -> Self {
        let operator = determine_operator(signals);
        let candidates = if operator.is_none() {
            let mut seen: Vec<Operator> = Vec::new();
            for signal in signals {
                if !seen.contains(&signal.operator) {
                    seen.push(signal.operator);
                }
            }
            seen
        } else {
            Vec::new()
        };
        let attributed: Vec<&Signal> = match operator {
            Some(op) => signals.iter().filter(|s| s.operator == op).collect(),
            None => signals.iter().collect(),
        };
        let class_count = attributed
            .iter()
            .map(|s| s.kind.class())
            .collect::<HashSet<EvidenceClass>>()
            .len();
        Self {
            operator,
            candidates,
            confidence: confidence_of(operator, class_count),
            signal_count: attributed.len(),
            class_count,
        }
    }
}

/// The state produced by checking one domain: raw evidence,
/// per-scope signal aggregates and verdict. Presentation-free.
#[derive(Debug, Clone)]
pub struct DomainReport {
    pub domain: String,
    pub checked_at: DateTime<Local>,
    pub resolved_ip: Option<IpAddr>,
    pub tls: TlsFacts,
    pub evidence: Evidence,
    pub termination: Signals,
    pub verdict: Verdict,
}

impl DomainReport {
    pub fn build(
        domain: String,
        resolved_ip: Option<IpAddr>,
        tls: TlsFacts,
        evidence: Evidence,
        checked_at: DateTime<Local>,
    ) -> Self {
        let signals = evidence.signals(&domain);
        let termination = Signals::aggregate(&signals);
        let ownership = evidence.infra_ownership(&domain);
        let verdict = verdict_of(termination.operator, tls.is_pq(), ownership);
        Self {
            domain,
            checked_at,
            resolved_ip,
            tls,
            evidence,
            termination,
            verdict,
        }
    }
}

pub fn determine_operator(signals: &[Signal]) -> Option<Operator> {
    if signals.is_empty() {
        return None;
    }

    let mut operator_counts: HashMap<Operator, HashSet<EvidenceClass>> = HashMap::new();
    for signal in signals {
        operator_counts
            .entry(signal.operator)
            .or_default()
            .insert(signal.kind.class());
    }

    let max_classes = operator_counts.values().map(|s| s.len()).max().unwrap_or(0);
    let winners: Vec<Operator> = operator_counts
        .iter()
        .filter(|(_, classes)| classes.len() == max_classes)
        .map(|(operator, _)| *operator)
        .collect();

    if max_classes >= 2 {
        if winners.len() == 1 {
            Some(winners[0])
        } else {
            None
        }
    } else if signals.len() == 1 {
        Some(signals[0].operator)
    } else if operator_counts.len() == 1 {
        Some(winners[0])
    } else {
        None
    }
}

pub fn confidence_of(operator: Option<Operator>, class_count: usize) -> Confidence {
    match (operator, class_count) {
        (Some(_), n) if n >= 2 => Confidence::Confirmed,
        (Some(_), 1) => Confidence::Probable,
        (None, 0) => Confidence::None,
        _ => Confidence::Undecided,
    }
}

pub fn verdict_of(termination: Option<Operator>, pq: bool, ownership: InfraOwnership) -> Verdict {
    match (termination, pq, ownership) {
        (Some(Operator::Vendor(vendor)), true, _) if vendor.is_cloud() => Verdict::PqCloudHosted,
        (Some(Operator::Vendor(vendor)), false, _) if vendor.is_cloud() => Verdict::NoPqCloudHosted,
        (Some(Operator::Vendor(_)), true, _) => Verdict::PqAtEdge,
        (Some(Operator::Vendor(_)), false, _) => Verdict::NoPqEdge,
        (Some(Operator::Own), true, _) => Verdict::PqOwnInfra,
        (Some(Operator::Own), false, _) => Verdict::NoPqOwnInfra,
        (None, true, InfraOwnership::ThirdParty) => Verdict::PqVendorHosted,
        (None, false, InfraOwnership::ThirdParty) => Verdict::NoPqVendorHosted,
        (None, true, _) => Verdict::PqOwnInfra,
        (None, false, _) => Verdict::NoPqOwnInfra,
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
        TlsFacts {
            kx_group: "X25519".to_string(),
            symmetric_alg: SymmetricAlg::Aes256,
        },
        evidence,
        Local::now(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_slots_become_signals_only_when_attributed() {
        let evidence = Evidence {
            cname: Some(CnameEvidence {
                chain: vec!["cdn.example.net".to_string()],
                vendor: None,
            }),
            range: Some(RangeEvidence {
                cidr: "104.16.0.0/12".to_string(),
                vendor: Vendor::Cloudflare,
            }),
            cert: Some(CertEvidence {
                name: "www.example.com".to_string(),
                vendor: None,
            }),
            http: None,
            ptr: None,
            rdap: None,
            asn: Some(AsnEvidence {
                asn: "AS64512 EXAMPLE-CORP-AS".to_string(),
                vendor: None,
            }),
        };
        let signals = evidence.signals("pqpulse.dev");
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].kind, SignalType::Range);
        assert_eq!(signals[0].operator, Operator::Vendor(Vendor::Cloudflare));
    }

    #[test]
    fn ptr_and_rdap_are_one_evidence_class() {
        let signals = vec![
            Signal {
                kind: SignalType::Ptr,
                operator: Operator::Vendor(Vendor::Akamai),
            },
            Signal {
                kind: SignalType::Rdap,
                operator: Operator::Vendor(Vendor::Akamai),
            },
        ];
        let aggregate = Signals::aggregate(&signals);
        assert_eq!(aggregate.operator, Some(Operator::Vendor(Vendor::Akamai)));
        assert_eq!(aggregate.confidence, Confidence::Probable);
        assert_eq!(aggregate.signal_count, 2);
        assert_eq!(aggregate.class_count, 1);
    }

    #[test]
    fn conflicting_single_class_signals_are_undecided() {
        let signals = vec![
            Signal {
                kind: SignalType::Ptr,
                operator: Operator::Vendor(Vendor::Akamai),
            },
            Signal {
                kind: SignalType::Cname,
                operator: Operator::Vendor(Vendor::Cloudflare),
            },
        ];
        assert_eq!(determine_operator(&signals), None);
    }

    #[test]
    fn two_agreeing_classes_are_confirmed() {
        let signals = vec![
            Signal {
                kind: SignalType::Cname,
                operator: Operator::Vendor(Vendor::Cloudflare),
            },
            Signal {
                kind: SignalType::Range,
                operator: Operator::Vendor(Vendor::Cloudflare),
            },
        ];
        let aggregate = Signals::aggregate(&signals);
        assert_eq!(
            aggregate.operator,
            Some(Operator::Vendor(Vendor::Cloudflare))
        );
        assert_eq!(aggregate.confidence, Confidence::Confirmed);
    }

    #[test]
    fn asn_corroborates_rdap_without_a_new_evidence_class() {
        let ptr_rdap = vec![
            Signal {
                kind: SignalType::Ptr,
                operator: Operator::Vendor(Vendor::Akamai),
            },
            Signal {
                kind: SignalType::Rdap,
                operator: Operator::Vendor(Vendor::Akamai),
            },
        ];
        let with_asn = ptr_rdap
            .iter()
            .copied()
            .chain([Signal {
                kind: SignalType::Asn,
                operator: Operator::Vendor(Vendor::Akamai),
            }])
            .collect::<Vec<_>>();

        assert_eq!(SignalType::Asn.class(), SignalType::Ptr.class());
        let without = Signals::aggregate(&ptr_rdap);
        let with = Signals::aggregate(&with_asn);
        assert_eq!(without.class_count, 1);
        assert_eq!(with.class_count, 1, "ASN must not add a third-party class");
        assert_eq!(with.signal_count, 3);
        assert_eq!(with.operator, Some(Operator::Vendor(Vendor::Akamai)));
        assert_eq!(with.confidence, Confidence::Probable);
    }

    #[test]
    fn http_edge_processing_is_its_own_evidence_class() {
        assert_eq!(SignalType::Http.class(), EvidenceClass::EdgeProcessing);
        let signals = vec![
            Signal {
                kind: SignalType::Ptr,
                operator: Operator::Vendor(Vendor::Akamai),
            },
            Signal {
                kind: SignalType::Rdap,
                operator: Operator::Vendor(Vendor::Akamai),
            },
            Signal {
                kind: SignalType::Asn,
                operator: Operator::Vendor(Vendor::Akamai),
            },
            Signal {
                kind: SignalType::Http,
                operator: Operator::Vendor(Vendor::Akamai),
            },
        ];
        let aggregate = Signals::aggregate(&signals);
        assert_eq!(aggregate.class_count, 2);
        assert_eq!(aggregate.confidence, Confidence::Confirmed);
    }

    #[test]
    fn unresolved_evidence_is_neutral() {
        let evidence = Evidence {
            cname: None,
            range: None,
            cert: Some(CertEvidence {
                name: "www.example.com".to_string(),
                vendor: None,
            }),
            http: None,
            ptr: None,
            rdap: Some(RdapEvidence {
                netname: "XYZ-CORP".to_string(),
                vendor: None,
            }),
            asn: Some(AsnEvidence {
                asn: "AS64512 XYZ-CORP-AS".to_string(),
                vendor: None,
            }),
        };
        assert!(evidence.signals("pqpulse.dev").is_empty());

        let report = DomainReport::build(
            "pqpulse.dev".to_string(),
            Some("192.0.2.10".parse().unwrap()),
            TlsFacts {
                kx_group: "X25519".to_string(),
                symmetric_alg: SymmetricAlg::Aes256,
            },
            evidence,
            Local::now(),
        );
        assert_eq!(report.termination.operator, None);
        assert_eq!(report.termination.confidence, Confidence::None);
        assert_eq!(report.verdict, Verdict::NoPqOwnInfra);
    }

    #[test]
    fn own_zone_evidence_attributes_to_the_scanned_organization() {
        let evidence = Evidence {
            cname: Some(CnameEvidence {
                chain: vec!["upload.allegro.pl".to_string()],
                vendor: None,
            }),
            range: None,
            cert: Some(CertEvidence {
                name: "edge.business.allegro.pl".to_string(),
                vendor: None,
            }),
            http: None,
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
        };
        let signals = evidence.signals("upload.allegro.pl");
        assert_eq!(signals.len(), 2);
        assert!(signals.iter().all(|s| s.operator == Operator::Own));

        let report = DomainReport::build(
            "upload.allegro.pl".to_string(),
            Some("192.0.2.10".parse().unwrap()),
            TlsFacts {
                kx_group: "X25519".to_string(),
                symmetric_alg: SymmetricAlg::Aes256,
            },
            evidence,
            Local::now(),
        );
        assert_eq!(report.termination.operator, Some(Operator::Own));
        assert_eq!(report.termination.signal_count, 2);
        assert_eq!(report.termination.class_count, 2);
        assert_eq!(report.termination.confidence, Confidence::Confirmed);
        assert_eq!(report.verdict, Verdict::NoPqOwnInfra);
    }

    #[test]
    fn cert_names_do_not_attribute_own_infrastructure() {
        let evidence = Evidence {
            cert: Some(CertEvidence {
                name: "edge.business.allegro.pl".to_string(),
                vendor: None,
            }),
            ..Default::default()
        };
        assert!(evidence.signals("upload.allegro.pl").is_empty());
    }

    #[test]
    fn mixed_attribution_resolves_to_the_majority_operator() {
        let signals = vec![
            Signal {
                kind: SignalType::Cname,
                operator: Operator::Own,
            },
            Signal {
                kind: SignalType::Asn,
                operator: Operator::Own,
            },
            Signal {
                kind: SignalType::Http,
                operator: Operator::Vendor(Vendor::Akamai),
            },
        ];
        let aggregate = Signals::aggregate(&signals);
        assert_eq!(aggregate.operator, Some(Operator::Own));
        assert_eq!(aggregate.signal_count, 2);
        assert_eq!(aggregate.class_count, 2);
        assert_eq!(aggregate.confidence, Confidence::Confirmed);
    }

    #[test]
    fn cname_evidence_matches_vendor_anywhere_in_the_chain() {
        let evidence = Evidence {
            cname: Some(CnameEvidence {
                chain: vec![
                    "www.example.com.glb.example.org".to_string(),
                    "www.example.com.edgekey.net".to_string(),
                    "e970.dspg.akamaiedge.net".to_string(),
                ],
                vendor: Some(Vendor::Akamai),
            }),
            ..Default::default()
        };
        let signals = evidence.signals("www.example.com");
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].kind, SignalType::Cname);
        assert_eq!(signals[0].operator, Operator::Vendor(Vendor::Akamai));
    }

    #[test]
    fn tied_attribution_reports_candidates() {
        let signals = vec![
            Signal {
                kind: SignalType::Cname,
                operator: Operator::Vendor(Vendor::Cloudflare),
            },
            Signal {
                kind: SignalType::Range,
                operator: Operator::Vendor(Vendor::Cloudflare),
            },
            Signal {
                kind: SignalType::Ptr,
                operator: Operator::Vendor(Vendor::Akamai),
            },
            Signal {
                kind: SignalType::Http,
                operator: Operator::Vendor(Vendor::Akamai),
            },
        ];
        let aggregate = Signals::aggregate(&signals);
        assert_eq!(aggregate.operator, None);
        assert_eq!(
            aggregate.candidates,
            vec![
                Operator::Vendor(Vendor::Cloudflare),
                Operator::Vendor(Vendor::Akamai)
            ]
        );
        assert_eq!(aggregate.confidence, Confidence::Undecided);
    }

    #[test]
    fn verdicts_follow_termination_and_pq() {
        assert_eq!(
            verdict_of(
                Some(Operator::Vendor(Vendor::Akamai)),
                true,
                InfraOwnership::Unknown
            ),
            Verdict::PqAtEdge
        );
        assert_eq!(
            verdict_of(
                Some(Operator::Vendor(Vendor::Azure)),
                true,
                InfraOwnership::Unknown
            ),
            Verdict::PqCloudHosted
        );
        assert_eq!(
            verdict_of(None, true, InfraOwnership::ThirdParty),
            Verdict::PqVendorHosted
        );
        assert_eq!(
            verdict_of(None, true, InfraOwnership::Own),
            Verdict::PqOwnInfra
        );
        assert_eq!(
            verdict_of(Some(Operator::Own), true, InfraOwnership::Own),
            Verdict::PqOwnInfra
        );
        assert_eq!(
            verdict_of(
                Some(Operator::Vendor(Vendor::Azure)),
                false,
                InfraOwnership::Unknown
            ),
            Verdict::NoPqCloudHosted
        );
        assert_eq!(
            verdict_of(
                Some(Operator::Vendor(Vendor::Link11)),
                false,
                InfraOwnership::Unknown
            ),
            Verdict::NoPqEdge
        );
        assert_eq!(
            verdict_of(None, false, InfraOwnership::ThirdParty),
            Verdict::NoPqVendorHosted
        );
        assert_eq!(
            verdict_of(None, false, InfraOwnership::Unknown),
            Verdict::NoPqOwnInfra
        );
        assert_eq!(
            verdict_of(Some(Operator::Own), false, InfraOwnership::Own),
            Verdict::NoPqOwnInfra
        );
    }

    #[test]
    fn foreign_infra_is_vendor_hosted_not_own() {
        let evidence = Evidence {
            cert: Some(CertEvidence {
                name: "e-zamowienia.nbp.pl".to_string(),
                vendor: None,
            }),
            ptr: Some(PtrEvidence {
                record: "195.205.148.130.marketplanet.pl".to_string(),
                vendor: None,
            }),
            rdap: Some(RdapEvidence {
                netname: "OTWARTY-RYNEK-ELEKTRONICZNY".to_string(),
                vendor: None,
            }),
            ..Default::default()
        };
        let report = DomainReport::build(
            "e-zamowienia.nbp.pl".to_string(),
            Some("195.205.148.130".parse().unwrap()),
            TlsFacts {
                kx_group: "X25519".to_string(),
                symmetric_alg: SymmetricAlg::Aes128,
            },
            evidence,
            Local::now(),
        );
        assert_eq!(report.verdict, Verdict::NoPqVendorHosted);
    }

    #[test]
    fn same_zone_infra_stays_own() {
        let evidence = Evidence {
            ptr: Some(PtrEvidence {
                record: "online.bankmillennium.pl".to_string(),
                vendor: None,
            }),
            rdap: Some(RdapEvidence {
                netname: "BBG-PL".to_string(),
                vendor: None,
            }),
            ..Default::default()
        };
        let report = DomainReport::build(
            "online.bankmillennium.pl".to_string(),
            Some("193.201.167.52".parse().unwrap()),
            TlsFacts {
                kx_group: "X25519".to_string(),
                symmetric_alg: SymmetricAlg::Aes256,
            },
            evidence,
            Local::now(),
        );
        assert_eq!(report.verdict, Verdict::NoPqOwnInfra);
    }

    #[test]
    fn infra_ownership_tracks_zones_and_netnames() {
        let evidence = |cname: Option<&[&str]>, ptr: Option<&str>, rdap: Option<&str>| Evidence {
            cname: cname.map(|chain| CnameEvidence {
                chain: chain.iter().map(|t| t.to_string()).collect(),
                vendor: None,
            }),
            ptr: ptr.map(|r| PtrEvidence {
                record: r.to_string(),
                vendor: None,
            }),
            rdap: rdap.map(|n| RdapEvidence {
                netname: n.to_string(),
                vendor: None,
            }),
            ..Default::default()
        };
        // PTR inside the domain's own zone.
        assert_eq!(
            evidence(None, Some("online.bankmillennium.pl"), Some("BBG-PL"))
                .infra_ownership("online.bankmillennium.pl"),
            InfraOwnership::Own
        );
        // RDAP netname naming the registrable label.
        assert_eq!(
            evidence(None, None, Some("ZUS")).infra_ownership("www.zus.pl"),
            InfraOwnership::Own
        );
        // CNAME delegation to another zone of the same operator.
        assert_eq!(
            evidence(Some(&["online.global.mbank.pl"]), None, Some("PL-MBANKPL"))
                .infra_ownership("online.mbank.pl"),
            InfraOwnership::Own
        );
        // PTR in a foreign zone.
        assert_eq!(
            evidence(None, Some("195.205.148.130.marketplanet.pl"), None)
                .infra_ownership("e-zamowienia.nbp.pl"),
            InfraOwnership::ThirdParty
        );
        // CNAME into a foreign zone.
        assert_eq!(
            evidence(Some(&["fe.edelivery.sni.certum.pl"]), None, None)
                .infra_ownership("erds.envelo.pl"),
            InfraOwnership::ThirdParty
        );
        // PTR in a foreign zone, but RDAP names the operator: sibling
        // zones of the same organization are not third-party hosting.
        assert_eq!(
            evidence(None, Some("upload.allegro.com.cz"), Some("ALLEGRO-NET"))
                .infra_ownership("upload.allegro.pl"),
            InfraOwnership::Own
        );
        // Netname that does not echo the registrable label proves nothing.
        assert_eq!(
            evidence(None, None, Some("PL-PKOBP")).infra_ownership("ipko.pl"),
            InfraOwnership::Unknown
        );
        // No infra evidence at all.
        assert_eq!(
            evidence(None, None, None).infra_ownership("example.com"),
            InfraOwnership::Unknown
        );
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

    #[test]
    fn fixture_attributes_akamai() {
        let report = fixture();
        assert_eq!(
            report.termination.operator,
            Some(Operator::Vendor(Vendor::Akamai))
        );
        assert_eq!(report.termination.confidence, Confidence::Confirmed);
        assert_eq!(report.termination.signal_count, 4);
        assert_eq!(report.termination.class_count, 2);
        assert_eq!(report.verdict, Verdict::NoPqEdge);
        assert!(!report.tls.is_pq());
    }
}
