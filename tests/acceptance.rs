use pq_pulse::detect::decision::{API_KEY_ENV, Group, WEB_QUESTION, decide};

fn label(group: Group) -> &'static str {
    match group {
        Group::OwnInfra => "First-party (A)",
        Group::ThirdParty => "Third-party hosting (B)",
        Group::Edge => "Third-party edge (C)",
        Group::Unattributable => "Unknown (D)",
    }
}

fn assert_fixture(domain: &str, expected: Group, metadata: &str) {
    let key = std::env::var(API_KEY_ENV)
        .unwrap_or_else(|_| panic!("{API_KEY_ENV} must be set for the acceptance fixtures"));
    let key = key.trim();
    assert!(!key.is_empty(), "{API_KEY_ENV} is set but empty");

    let attribution = decide(key, domain, metadata, WEB_QUESTION, false)
        .unwrap_or_else(|err| panic!("{domain}: {err}"));
    assert_eq!(
        attribution.group,
        expected,
        "{domain}: model confidence {:.3} — expected {}",
        attribution.confidence,
        label(expected)
    );
}

#[test]
fn novexa_is_first_party() {
    let metadata = r#"novexa.test
checked: 2026-11-17 18:00 +01:00

WEB
  endpoint
    443/tcp      reachable
    TLS          TLS 1.3
    KX           X25519MLKEM768
    symmetric    AES-128
    PQ           yes

  network
    IP           192.0.2.10
    PTR          web01.novexa.test
    ASN          AS64496 NOVEXA-NET
    RDAP         NOVEXA-INFRASTRUCTURE"#;

    assert_fixture("novexa.test", Group::OwnInfra, metadata);
}

#[test]
fn veltrix_is_third_party_hosting() {
    let metadata = r#"veltrix.test
checked: 2026-11-17 18:01 +01:00

WEB
  endpoint
    443/tcp      reachable
    TLS          TLS 1.3
    KX           X25519MLKEM768
    symmetric    AES-256
    PQ           yes

  network
    IP           198.51.100.20
    PTR          server42.hostnova.test
    ASN          AS64497 HOSTNOVA-CLOUD
    RDAP         HOSTNOVA-HOSTING"#;

    assert_fixture("veltrix.test", Group::ThirdParty, metadata);
}

#[test]
fn meridian_is_third_party_edge() {
    let metadata = r#"meridian.test
checked: 2026-11-17 18:02 +01:00

WEB
  endpoint
    443/tcp      reachable
    TLS          TLS 1.3
    KX           X25519MLKEM768
    symmetric    AES-128
    PQ           yes

  termination
    provider     ShieldEdge

  network
    IP           203.0.113.30
    PTR          edge30.shieldedge.test
    ASN          AS64498 SHIELDEDGE-GLOBAL
    RDAP         SHIELDEDGE-CDN"#;

    assert_fixture("meridian.test", Group::Edge, metadata);
}

#[test]
fn quantara_is_unknown() {
    let metadata = r#"quantara.test
checked: 2026-11-17 18:03 +01:00

WEB
  endpoint
    443/tcp      reachable
    TLS          TLS 1.3
    KX           X25519MLKEM768
    symmetric    AES-256
    PQ           yes

  network
    IP           192.0.2.40
    PTR          -
    ASN          AS64499 UNKNOWN-NET
    RDAP         PRIVATE-NETWORK-SERVICES"#;

    assert_fixture("quantara.test", Group::Unattributable, metadata);
}

#[test]
fn aethernet_is_first_party() {
    let metadata = r#"aethernet.test
checked: 2026-11-17 18:04 +01:00

WEB
  endpoint
    443/tcp      reachable
    TLS          TLS 1.3
    KX           X25519MLKEM768
    symmetric    AES-128
    PQ           yes

  network
    IP           198.51.100.50
    PTR          edge01.aethernet.test
    ASN          AS64500 AETHERNET
    RDAP         AETHERNET-CDN"#;

    assert_fixture("aethernet.test", Group::OwnInfra, metadata);
}

#[test]
fn solarisbank_is_third_party_hosting() {
    let metadata = r#"solarisbank.test
checked: 2026-11-17 18:05 +01:00

WEB
  endpoint
    443/tcp      reachable
    TLS          TLS 1.3
    KX           X25519MLKEM768
    symmetric    AES-256
    PQ           yes

  network
    IP           203.0.113.60
    PTR          vm60.cloudvertex.test
    ASN          AS64501 CLOUDVERTEX
    RDAP         CLOUDVERTEX-COMPUTE"#;

    assert_fixture("solarisbank.test", Group::ThirdParty, metadata);
}

#[test]
fn fintrax_is_third_party_edge() {
    let metadata = r#"fintrax.test
checked: 2026-11-17 18:06 +01:00

WEB
  endpoint
    443/tcp      reachable
    TLS          TLS 1.3
    KX           X25519MLKEM768
    symmetric    AES-128
    PQ           yes

  termination
    provider     SecureFront

  network
    IP           192.0.2.70
    PTR          -
    ASN          AS64502 SECUREFRONT-EDGE
    RDAP         SECUREFRONT-WAF"#;

    assert_fixture("fintrax.test", Group::Edge, metadata);
}

#[test]
fn orbisdata_is_unknown() {
    let metadata = r#"orbisdata.test
checked: 2026-11-17 18:07 +01:00

WEB
  endpoint
    443/tcp      reachable
    TLS          TLS 1.3
    KX           X25519MLKEM768
    symmetric    AES-256
    PQ           yes

  network
    IP           198.51.100.80
    PTR          gateway.sharednet.test
    ASN          AS64503 SHAREDNET
    RDAP         SHARED-INFRASTRUCTURE"#;

    assert_fixture("orbisdata.test", Group::Unattributable, metadata);
}
