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
pub enum SignalType {
    Cname,
    Range,
    Cert,
    Ptr,
    Rdap,
}

impl SignalType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            SignalType::Cname => "CNAME",
            SignalType::Range => "RANGE",
            SignalType::Cert => "CERT",
            SignalType::Ptr => "PTR",
            SignalType::Rdap => "RDAP",
        }
    }

    /// Evidence class of this signal type.
    /// PTR and RDAP both derive from IP block ownership — counted as one class.
    pub const fn class(&self) -> EvidenceClass {
        match self {
            SignalType::Cname => EvidenceClass::DnsDelegation,
            SignalType::Range => EvidenceClass::PublishedRange,
            SignalType::Cert => EvidenceClass::Certificate,
            SignalType::Ptr | SignalType::Rdap => EvidenceClass::IpInfra,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceClass {
    DnsDelegation,
    PublishedRange,
    Certificate,
    IpInfra,
}

impl EvidenceClass {
    pub const fn as_str(&self) -> &'static str {
        match self {
            EvidenceClass::DnsDelegation => "dns_delegation",
            EvidenceClass::PublishedRange => "published_range",
            EvidenceClass::Certificate => "certificate",
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
    PqOwnInfra,
    NoPqEdge,
    NoPqCloudHosted,
    NoPqOwnInfra,
}

impl Verdict {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Verdict::PqAtEdge => "pq_at_edge",
            Verdict::PqCloudHosted => "pq_cloud_hosted",
            Verdict::PqOwnInfra => "pq_own_infra",
            Verdict::NoPqEdge => "no_pq_edge",
            Verdict::NoPqCloudHosted => "no_pq_cloud_hosted",
            Verdict::NoPqOwnInfra => "no_pq_own_infra",
        }
    }

    pub const fn explanation(&self) -> &'static str {
        match self {
            Verdict::PqAtEdge => {
                "post-quantum key exchange, TLS terminated by an identified edge vendor"
            }
            Verdict::PqCloudHosted => {
                "post-quantum key exchange, hosted on cloud infrastructure (no edge vendor)"
            }
            Verdict::PqOwnInfra => "post-quantum key exchange, own or unattributed infrastructure",
            Verdict::NoPqEdge => {
                "classical key exchange, TLS terminated by an identified edge vendor"
            }
            Verdict::NoPqCloudHosted => {
                "classical key exchange, hosted on cloud infrastructure (no edge vendor)"
            }
            Verdict::NoPqOwnInfra => "classical key exchange, own or unattributed infrastructure",
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.as_str(), self.explanation())
    }
}

/// A matched observation: evidence type plus the vendor it points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signal {
    pub kind: SignalType,
    pub vendor: Vendor,
}

#[derive(Debug, Clone)]
pub struct CnameEvidence {
    pub target: String,
    pub vendor: Option<Vendor>,
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

/// The five raw observation slots; a slot becomes a signal
/// only when it carries a vendor match.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    pub cname: Option<CnameEvidence>,
    pub range: Option<RangeEvidence>,
    pub cert: Option<CertEvidence>,
    pub ptr: Option<PtrEvidence>,
    pub rdap: Option<RdapEvidence>,
}

impl Evidence {
    pub fn signals(&self) -> Vec<Signal> {
        let mut signals = Vec::new();
        if let Some(vendor) = self.cname.as_ref().and_then(|c| c.vendor) {
            signals.push(Signal {
                kind: SignalType::Cname,
                vendor,
            });
        }
        if let Some(range) = &self.range {
            signals.push(Signal {
                kind: SignalType::Range,
                vendor: range.vendor,
            });
        }
        if let Some(vendor) = self.cert.as_ref().and_then(|c| c.vendor) {
            signals.push(Signal {
                kind: SignalType::Cert,
                vendor,
            });
        }
        if let Some(vendor) = self.ptr.as_ref().and_then(|p| p.vendor) {
            signals.push(Signal {
                kind: SignalType::Ptr,
                vendor,
            });
        }
        if let Some(vendor) = self.rdap.as_ref().and_then(|r| r.vendor) {
            signals.push(Signal {
                kind: SignalType::Rdap,
                vendor,
            });
        }
        signals
    }
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
pub struct Attribution {
    pub vendor: Option<Vendor>,
    pub confidence: Confidence,
    pub signal_count: usize,
    pub class_count: usize,
}

impl Attribution {
    pub fn from_signals(signals: &[Signal]) -> Self {
        let vendor = determine_vendor(signals);
        let class_count = signals
            .iter()
            .map(|s| s.kind.class())
            .collect::<HashSet<EvidenceClass>>()
            .len();
        Self {
            vendor,
            confidence: confidence_of(vendor, class_count),
            signal_count: signals.len(),
            class_count,
        }
    }
}

/// The state produced by checking one domain: raw evidence,
/// attribution and verdict. Presentation-free.
#[derive(Debug, Clone)]
pub struct DomainReport {
    pub domain: String,
    pub checked_at: DateTime<Local>,
    pub resolved_ip: Option<IpAddr>,
    pub tls: TlsFacts,
    pub evidence: Evidence,
    pub infra: Attribution,
    pub edge: Attribution,
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
        let signals = evidence.signals();
        let edge_signals = filter_edge_signals(&signals);
        let infra = Attribution::from_signals(&signals);
        let edge = Attribution::from_signals(&edge_signals);
        let verdict = verdict_of(edge.vendor, infra.vendor, tls.is_pq());
        Self {
            domain,
            checked_at,
            resolved_ip,
            tls,
            evidence,
            infra,
            edge,
            verdict,
        }
    }
}

/// Group signals into evidence classes per vendor, then count classes.
/// Returns the vendor with max agreeing classes, if attribution is possible.
pub fn determine_vendor(signals: &[Signal]) -> Option<Vendor> {
    if signals.is_empty() {
        return None;
    }

    let mut class_counts: HashMap<Vendor, HashSet<EvidenceClass>> = HashMap::new();
    for signal in signals {
        class_counts
            .entry(signal.vendor)
            .or_default()
            .insert(signal.kind.class());
    }

    let max_classes = class_counts.values().map(|s| s.len()).max().unwrap_or(0);

    if max_classes >= 2 {
        class_counts
            .into_iter()
            .find(|(_, classes)| classes.len() == max_classes)
            .map(|(vendor, _)| vendor)
    } else if signals.len() == 1 {
        Some(signals[0].vendor)
    } else if max_classes == 1 && class_counts.len() == 1 {
        class_counts.into_keys().next()
    } else {
        None
    }
}

/// For cloud providers, only CNAME and CERT signals qualify for edge attribution.
/// PTR and RDAP prove infrastructure ownership, not TLS termination.
pub fn filter_edge_signals(signals: &[Signal]) -> Vec<Signal> {
    signals
        .iter()
        .filter(|s| !s.vendor.is_cloud() || matches!(s.kind, SignalType::Cname | SignalType::Cert))
        .copied()
        .collect()
}

pub fn confidence_of(vendor: Option<Vendor>, class_count: usize) -> Confidence {
    match (vendor, class_count) {
        (Some(_), n) if n >= 2 => Confidence::Confirmed,
        (Some(_), 1) => Confidence::Probable,
        (None, 0) => Confidence::None,
        _ => Confidence::Undecided,
    }
}

pub fn verdict_of(edge: Option<Vendor>, infra: Option<Vendor>, pq: bool) -> Verdict {
    match (edge, infra, pq) {
        (Some(_), _, true) => Verdict::PqAtEdge,
        (None, Some(vendor), true) if vendor.is_cloud() => Verdict::PqCloudHosted,
        (None, _, true) => Verdict::PqOwnInfra,
        (Some(_), _, false) => Verdict::NoPqEdge,
        (None, Some(vendor), false) if vendor.is_cloud() => Verdict::NoPqCloudHosted,
        (None, _, false) => Verdict::NoPqOwnInfra,
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
        ptr: Some(PtrEvidence {
            record: "a104-96-178-165.deploy.static.akamaitechnologies.com".to_string(),
            vendor: Some(Vendor::Akamai),
        }),
        rdap: Some(RdapEvidence {
            netname: "AKAMAI".to_string(),
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
    fn evidence_slots_become_signals_only_when_vendor_matches() {
        let evidence = Evidence {
            cname: Some(CnameEvidence {
                target: "cdn.example.net".to_string(),
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
            ptr: None,
            rdap: None,
        };
        let signals = evidence.signals();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].kind, SignalType::Range);
        assert_eq!(signals[0].vendor, Vendor::Cloudflare);
    }

    #[test]
    fn ptr_and_rdap_are_one_evidence_class() {
        let signals = vec![
            Signal {
                kind: SignalType::Ptr,
                vendor: Vendor::Akamai,
            },
            Signal {
                kind: SignalType::Rdap,
                vendor: Vendor::Akamai,
            },
        ];
        let attribution = Attribution::from_signals(&signals);
        assert_eq!(attribution.vendor, Some(Vendor::Akamai));
        assert_eq!(attribution.confidence, Confidence::Probable);
        assert_eq!(attribution.signal_count, 2);
        assert_eq!(attribution.class_count, 1);
    }

    #[test]
    fn conflicting_single_class_signals_are_undecided() {
        let signals = vec![
            Signal {
                kind: SignalType::Ptr,
                vendor: Vendor::Akamai,
            },
            Signal {
                kind: SignalType::Cname,
                vendor: Vendor::Cloudflare,
            },
        ];
        assert_eq!(determine_vendor(&signals), None);
    }

    #[test]
    fn two_agreeing_classes_are_confirmed() {
        let signals = vec![
            Signal {
                kind: SignalType::Cname,
                vendor: Vendor::Cloudflare,
            },
            Signal {
                kind: SignalType::Range,
                vendor: Vendor::Cloudflare,
            },
        ];
        let attribution = Attribution::from_signals(&signals);
        assert_eq!(attribution.vendor, Some(Vendor::Cloudflare));
        assert_eq!(attribution.confidence, Confidence::Confirmed);
    }

    #[test]
    fn cloud_ip_infra_signals_are_not_edge_signals() {
        let signals = vec![
            Signal {
                kind: SignalType::Ptr,
                vendor: Vendor::Azure,
            },
            Signal {
                kind: SignalType::Cname,
                vendor: Vendor::Azure,
            },
        ];
        let edge = filter_edge_signals(&signals);
        assert_eq!(edge.len(), 1);
        assert_eq!(edge[0].kind, SignalType::Cname);
    }

    #[test]
    fn verdicts_follow_edge_and_pq() {
        assert_eq!(
            verdict_of(Some(Vendor::Akamai), None, true),
            Verdict::PqAtEdge
        );
        assert_eq!(
            verdict_of(None, Some(Vendor::Azure), true),
            Verdict::PqCloudHosted
        );
        assert_eq!(
            verdict_of(None, Some(Vendor::Akamai), true),
            Verdict::PqOwnInfra
        );
        assert_eq!(
            verdict_of(None, Some(Vendor::Azure), false),
            Verdict::NoPqCloudHosted
        );
        assert_eq!(verdict_of(None, None, false), Verdict::NoPqOwnInfra);
    }

    #[test]
    fn fixture_attributes_akamai_at_edge() {
        let report = fixture();
        assert_eq!(report.infra.vendor, Some(Vendor::Akamai));
        assert_eq!(report.edge.vendor, Some(Vendor::Akamai));
        assert_eq!(report.edge.confidence, Confidence::Probable);
        assert_eq!(report.verdict, Verdict::NoPqEdge);
        assert!(!report.tls.is_pq());
    }
}
