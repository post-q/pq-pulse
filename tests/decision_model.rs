use pq_pulse::detect::decision::{API_KEY_ENV, Group, WEB_QUESTION, decide, decide_sector};
use pq_pulse::model::Sector;

fn label(group: Group) -> &'static str {
    match group {
        Group::OwnInfra => "First-party (A)",
        Group::ThirdParty => "Third-party hosting (B)",
        Group::Edge => "Third-party edge (C)",
        Group::Unattributable => "Unknown (D)",
    }
}

/// `expected` is `None` for the `unknown` answer: no sector reported.
fn assert_sector_fixture(domain: &str, expected: Option<Sector>, context: &str) {
    let key = std::env::var(API_KEY_ENV)
        .unwrap_or_else(|_| panic!("{API_KEY_ENV} must be set for the acceptance fixtures"));
    let key = key.trim();
    assert!(!key.is_empty(), "{API_KEY_ENV} is set but empty");

    let sector =
        decide_sector(key, domain, context, false).unwrap_or_else(|err| panic!("{domain}: {err}"));
    assert_eq!(
        sector, expected,
        "{domain}: model classified {sector:?}, expected {expected:?}"
    );
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

#[test]
fn northbridge_is_finance() {
    let context = r#"Domain: northbridge.example
Page title: Northbridge | Personal and Business Banking
Meta description: Open savings accounts, apply for mortgages and manage investments.
Open Graph title: Northbridge Financial
Open Graph description: Banking solutions for individuals and businesses.
Headings (H1/H2): Banking made simple | Personal accounts | Business banking
Page content excerpt: Manage your money with current accounts, savings products, mortgage loans and investment services.
Organization name: Northbridge Financial
Organization description: Financial institution providing retail and commercial banking services.
Industry (JSON-LD): Financial Services"#;

    assert_sector_fixture("northbridge.example", Some(Sector::Finance), context);
}

#[test]
fn urbanbasket_is_retail() {
    let context = r#"Domain: urbanbasket.example
Page title: UrbanBasket | Shop Online
Meta description: Shop groceries, electronics and household essentials with home delivery.
Open Graph title: UrbanBasket Online Store
Open Graph description: Thousands of products at competitive prices.
Headings (H1/H2): Shop our latest offers | Popular categories
Page content excerpt: Browse electronics, groceries, clothing and home appliances. Add products to your basket and choose delivery or store pickup."#;

    assert_sector_fixture("urbanbasket.example", Some(Sector::Retail), context);
}

#[test]
fn cloudforge_is_technology() {
    let context = r#"Domain: cloudforge.example
Page title: CloudForge | Enterprise Software
Meta description: Cloud-native applications, cybersecurity solutions and infrastructure automation.
Open Graph title: CloudForge Technologies
Open Graph description: Software platforms for modern enterprises.
Headings (H1/H2): Build and scale your applications | Developer tools
Page content excerpt: Our platform provides application deployment, monitoring, identity management and automated infrastructure provisioning.
Organization name: CloudForge Technologies
Organization description: Developer of enterprise software and cloud infrastructure platforms."#;

    assert_sector_fixture("cloudforge.example", Some(Sector::Technology), context);
}

#[test]
fn novatel_is_telecommunications() {
    let context = r#"Domain: novatel.example
Page title: NovaTel | Mobile and Fiber Internet
Meta description: 5G mobile plans, fiber broadband and enterprise connectivity.
Open Graph title: NovaTel Communications
Headings (H1/H2): Mobile subscriptions | Fiber internet | Enterprise connectivity
Page content excerpt: Explore unlimited mobile data, 5G subscriptions, fiber broadband and dedicated network connectivity for businesses."#;

    assert_sector_fixture("novatel.example", Some(Sector::Telecommunications), context);
}

#[test]
fn cityservices_is_government() {
    let context = r#"Domain: cityservices.example
Page title: City Council | Public Services
Meta description: Municipal administration, local taxes, permits and citizen services.
Headings (H1/H2): Services for residents | Permits and applications
Page content excerpt: Apply for official documents, pay local taxes, report infrastructure issues and access municipal services."#;

    assert_sector_fixture("cityservices.example", Some(Sector::Government), context);
}

#[test]
fn medisphere_is_healthcare() {
    let context = r#"Domain: medisphere.example
Page title: MediSphere | Medical Care
Meta description: Specialist consultations, diagnostic laboratories and hospital services.
Open Graph title: MediSphere Healthcare
Open Graph description: Comprehensive medical services for patients.
Headings (H1/H2): Find a specialist | Book an appointment
Page content excerpt: Our medical centers offer cardiology, oncology, diagnostic imaging, laboratory testing and outpatient care."#;

    assert_sector_fixture("medisphere.example", Some(Sector::Healthcare), context);
}

#[test]
fn westbridge_is_education() {
    let context = r#"Domain: westbridge-university.example
Page title: Westbridge University
Meta description: Undergraduate and postgraduate programs, academic research and professional education.
Headings (H1/H2): Study at Westbridge | Research and innovation"#;

    assert_sector_fixture(
        "westbridge-university.example",
        Some(Sector::Education),
        context,
    );
}

#[test]
fn dailyobserver_is_media() {
    let context = r#"Domain: dailyobserver.example
Page title: The Daily Observer | Latest News
Meta description: Independent journalism covering politics, business, technology and international affairs.
Open Graph title: The Daily Observer"#;

    assert_sector_fixture("dailyobserver.example", Some(Sector::Media), context);
}

#[test]
fn steelworks_is_manufacturing() {
    let context = r#"Domain: steelworks.example
Page title: SteelWorks | Precision Engineering and Manufacturing
Headings (H1/H2): Industrial components | CNC machining | Production facilities"#;

    assert_sector_fixture("steelworks.example", Some(Sector::Manufacturing), context);
}

#[test]
fn greenpower_is_energy() {
    let context = r#"Domain: greenpower.example
Page title: GreenPower | Renewable Energy
Meta description: Electricity generation, wind farms, solar installations and energy distribution."#;

    assert_sector_fixture("greenpower.example", Some(Sector::Energy), context);
}

#[test]
fn harvestfields_is_other() {
    let context = r#"Domain: harvestfields.example
Page title: HarvestFields | Agricultural Production
Meta description: Crop cultivation, livestock farming and agricultural land management.
Organization name: HarvestFields Agriculture"#;

    assert_sector_fixture("harvestfields.example", Some(Sector::Other), context);
}

#[test]
fn qxportal_is_unknown() {
    let context = "Domain: qxportal.example";

    assert_sector_fixture("qxportal.example", None, context);
}
