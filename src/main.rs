use std::collections::HashMap;
use std::env;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Local;
use ipnet::IpNet;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme, StreamOwned,
};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Vendor alias table — token-exact matching (case-insensitive)
// "THALES-IMPERVA-NA4-AGG" splits into tokens, "IMPERVA" matches Imperva
// "PALMYRA" is a single token, does NOT match "MYRA"
// ---------------------------------------------------------------------------

const VENDOR_ALIASES: &[(&[&str], &str)] = &[
    (&["CLOUDFLARE", "CLOUDFLARENET"], "Cloudflare"),
    (
        &["AKAMAI", "AKAMAITECHNOLOGIES", "AKAMAIEDGE", "AKAMAIHD"],
        "Akamai",
    ),
    (&["INCAPSULA", "THALES-IMPERVA", "IMPERVA"], "Imperva"),
    (&["FASTLY"], "Fastly"),
    (&["CLOUDFRONT", "AMAZON", "AMAZONAWS"], "CloudFront"),
    (&["MYRA"], "Myra"),
    (&["LINK11"], "Link11"),
    (
        &["GOOGLE", "GOOGL", "GOOGLEUSERCONTENT", "GCLOUD"],
        "Google Cloud",
    ),
    (&["MSFT", "MICROSOFT", "AZURE", "AZUREFD"], "Azure"),
];

// Cloud providers: PTR + RDAP prove hosting, NOT edge TLS termination.
// Only CNAME or cert evidence counts for edge attribution.
// CDN/WAF vendors: any signal counts for edge attribution.
const CLOUD_VENDORS: &[&str] = &["Google Cloud", "Azure"];

// Known vendor DNS zones for CNAME delegation check
const VENDOR_ZONES: &[(&str, &str)] = &[
    ("cloudflare.com", "Cloudflare"),
    ("cloudflare.net", "Cloudflare"),
    ("akamai.net", "Akamai"),
    ("akamaiedge.net", "Akamai"),
    ("akamaihd.net", "Akamai"),
    ("edgekey.net", "Akamai"),
    ("imperva.com", "Imperva"),
    ("incapsula.com", "Imperva"),
    ("impervadns.net", "Imperva"),
    ("fastly.net", "Fastly"),
    ("fastly.com", "Fastly"),
    ("myra.cloud", "Myra"),
    ("link11.com", "Link11"),
    ("link11.net", "Link11"),
    ("cloudfront.net", "CloudFront"),
    ("amazonaws.com", "CloudFront"),
    ("googleusercontent.com", "Google Cloud"),
    ("gc.googleusercontent.com", "Google Cloud"),
    ("azurefd.net", "Azure"),
    ("azureedge.net", "Azure"),
    ("cloudapp.net", "Azure"),
];

fn match_vendor(text: &str) -> Option<&'static str> {
    let text_upper = text.to_uppercase();
    for (tokens, vendor) in VENDOR_ALIASES {
        for token in text_upper.split(|c: char| !c.is_alphanumeric()) {
            if tokens.contains(&token) {
                return Some(vendor);
            }
        }
    }
    None
}

fn match_cname_vendor(cname: &str) -> Option<&'static str> {
    let cname_lower = cname.to_lowercase();
    for (zone, vendor) in VENDOR_ZONES {
        if cname_lower.ends_with(&format!(".{zone}")) || cname_lower == *zone {
            return Some(vendor);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Certificate-capturing verifier — same as NoCertificateVerification
// but stores the end-entity cert for vendor name extraction
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct CertCapturingVerifier {
    cert: Mutex<Option<Vec<u8>>>,
}

impl CertCapturingVerifier {
    fn new() -> Self {
        Self {
            cert: Mutex::new(None),
        }
    }
}

impl ServerCertVerifier for CertCapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        *self.cert.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

// ---------------------------------------------------------------------------
// DNS helpers — shell out to dig for CNAME and PTR lookups
// ---------------------------------------------------------------------------

fn dig_cname(domain: &str) -> Option<String> {
    let output = Command::new("dig")
        .args(["+short", domain, "CNAME"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.trim_end_matches('.').to_string())
    }
}

fn dig_ptr(ip: &str) -> Option<String> {
    let output = Command::new("dig")
        .args(["+short", "-x", ip])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.trim_end_matches('.').to_string())
    }
}

// ---------------------------------------------------------------------------
// Vendor IP range fetching with 24h file cache
// ---------------------------------------------------------------------------

fn cache_path() -> PathBuf {
    std::env::temp_dir().join("pq-edge-ranges.json")
}

type VendorRanges = Vec<(String, Vec<String>)>;

fn fetch_vendor_ranges() -> VendorRanges {
    let mut ranges: VendorRanges = Vec::new();

    if let Ok(resp) = ureq::get("https://www.cloudflare.com/ips-v4")
        .timeout(Duration::from_secs(10))
        .call()
    {
        if let Ok(body) = resp.into_string() {
            let cf: Vec<String> = body
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            if !cf.is_empty() {
                ranges.push(("Cloudflare".to_string(), cf));
            }
        }
    }

    if let Ok(resp) = ureq::get("https://api.fastly.com/public-ip-list")
        .timeout(Duration::from_secs(10))
        .call()
    {
        if let Ok(json) = resp.into_json::<Value>() {
            let fastly: Vec<String> = json["addresses"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if !fastly.is_empty() {
                ranges.push(("Fastly".to_string(), fastly));
            }
        }
    }

    if let Ok(resp) = ureq::get("https://ip-ranges.amazonaws.com/ip-ranges.json")
        .timeout(Duration::from_secs(15))
        .call()
    {
        if let Ok(json) = resp.into_json::<Value>() {
            let cf: Vec<String> = json["prefixes"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter(|v| v["service"].as_str() == Some("CLOUDFRONT"))
                        .filter_map(|v| v["ip_prefix"].as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if !cf.is_empty() {
                ranges.push(("CloudFront".to_string(), cf));
            }
        }
    }

    let cache = serde_json::json!({
        "cached_at": Local::now().timestamp(),
        "ranges": serde_json::to_string(&ranges).unwrap_or_default(),
    });
    let _ = std::fs::write(cache_path(), cache.to_string());

    ranges
}

fn load_cached_ranges() -> Option<VendorRanges> {
    let content = std::fs::read_to_string(cache_path()).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;
    let cached_at = json["cached_at"].as_i64()?;
    let now = Local::now().timestamp();
    if now - cached_at > 86400 {
        return None;
    }
    let ranges_str = json["ranges"].as_str()?;
    serde_json::from_str(ranges_str).ok()
}

fn get_vendor_ranges() -> VendorRanges {
    load_cached_ranges().unwrap_or_else(fetch_vendor_ranges)
}

fn ip_in_ranges(ip: &IpAddr, ranges: &VendorRanges) -> Option<String> {
    for (vendor, cidrs) in ranges {
        for cidr in cidrs {
            if let Ok(net) = cidr.parse::<IpNet>() {
                if net.contains(ip) {
                    return Some(vendor.clone());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// RDAP lookup — try each RIR endpoint until one returns data
// ---------------------------------------------------------------------------

fn rdap_lookup(ip: &str) -> Option<(String, Option<String>)> {
    let rdap_urls = [
        format!("https://rdap.arin.net/registry/ip/{ip}"),
        format!("https://rdap.db.ripe.net/ip/{ip}"),
        format!("https://rdap.apnic.net/ip/{ip}"),
        format!("https://rdap.lacnic.net/rdap/ip/{ip}"),
        format!("https://rdap.afrinic.net/rdap/ip/{ip}"),
    ];

    for url in &rdap_urls {
        match ureq::get(url).timeout(Duration::from_secs(10)).call() {
            Ok(resp) => {
                if let Ok(json) = resp.into_json::<Value>() {
                    let netname = json["name"].as_str().unwrap_or("").to_string();

                    let mut org_name = String::new();
                    if let Some(entities) = json["entities"].as_array() {
                        for entity in entities {
                            if let Some(vcard) = entity["vcardArray"].as_array() {
                                if vcard.len() > 1 {
                                    if let Some(items) = vcard[1].as_array() {
                                        for item in items {
                                            if let Some(arr) = item.as_array() {
                                                if arr.first().and_then(|f| f.as_str())
                                                    == Some("fn")
                                                {
                                                    if let Some(name) =
                                                        arr.get(2).and_then(|v| v.as_str())
                                                    {
                                                        org_name = name.to_string();
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let combined = format!("{netname} {org_name}");
                    let vendor = match_vendor(&combined).map(String::from);
                    return Some((netname, vendor));
                }
            }
            Err(_) => continue,
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Certificate parsing — extract CN, issuer CN, and SANs for vendor matching
// ---------------------------------------------------------------------------

fn parse_cert_vendor(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;

    let subject = cert.subject();
    if let Some(cn) = subject.iter_common_name().next() {
        if let Ok(cn_str) = cn.attr_value().as_str() {
            if let Some(vendor) = match_vendor(cn_str) {
                return Some(vendor.to_string());
            }
        }
    }

    let issuer = cert.issuer();
    if let Some(cn) = issuer.iter_common_name().next() {
        if let Ok(cn_str) = cn.attr_value().as_str() {
            if let Some(vendor) = match_vendor(cn_str) {
                return Some(vendor.to_string());
            }
        }
    }

    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for gn in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(s) = gn {
                    if let Some(vendor) = match_vendor(s) {
                        return Some(vendor.to_string());
                    }
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Signal aggregation — count agreeing evidence classes, determine vendor
// ---------------------------------------------------------------------------

/// Evidence class for a signal type.
/// PTR and RDAP both derive from IP block ownership — counted as one class.
fn evidence_class(signal_type: &str) -> &str {
    match signal_type {
        "CNAME" => "dns_delegation",
        "CERT" => "certificate",
        "RANGE" => "published_range",
        "PTR" | "RDAP" => "ip_infra",
        _ => "other",
    }
}

/// Group signals into evidence classes per vendor, then count classes.
/// Returns vendor with max agreeing classes, or None.
fn determine_vendor(signals: &[(String, String)]) -> Option<String> {
    if signals.is_empty() {
        return None;
    }

    // vendor -> set of evidence classes
    let mut class_counts: HashMap<String, std::collections::HashSet<&str>> = HashMap::new();
    for (kind, vendor) in signals {
        let cls = evidence_class(kind);
        class_counts
            .entry(vendor.clone())
            .or_default()
            .insert(cls);
    }

    // Find vendor with max agreeing classes
    let max_classes = class_counts.values().map(|s| s.len()).max().unwrap_or(0);

    if max_classes >= 2 {
        class_counts
            .into_iter()
            .find(|(_, s)| s.len() == max_classes)
            .map(|(v, _)| v)
    } else if signals.len() == 1 {
        Some(signals[0].1.clone())
    } else if max_classes == 1 && class_counts.len() == 1 {
        // All signals point to same vendor, but only one evidence class
        class_counts.into_keys().next()
    } else {
        None
    }
}

/// For cloud providers, only CNAME and CERT signals qualify for edge attribution.
/// PTR and RDAP prove infrastructure ownership, not TLS termination.
/// For CDN/WAF vendors, all signals qualify.
fn filter_edge_signals(signals: &[(String, String)]) -> Vec<(String, String)> {
    signals
        .iter()
        .filter(|(kind, vendor)| {
            if CLOUD_VENDORS.contains(&vendor.as_str()) {
                kind == "CNAME" || kind == "CERT"
            } else {
                true
            }
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------

fn date_stamp() -> String {
    Local::now().format("%m%d%Y").to_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::args().nth(1).expect("usage: pq-tls-kx-check <domain>");
    let port = 443;

    if let Err(_existing) = rustls::crypto::aws_lc_rs::default_provider().install_default() {}

    // --- Step 1: DNS resolution (A record) ---
    let resolved_ip: Option<IpAddr> = (host.as_str(), port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(|a| a.ip());
    let ip_str = resolved_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "UNKNOWN".to_string());

    // --- Step 2: CNAME delegation ---
    let cname_target = dig_cname(&host).unwrap_or_default();
    let cname_vendor = if !cname_target.is_empty() {
        match_cname_vendor(&cname_target).map(String::from)
    } else {
        None
    };

    // --- Step 3: Published vendor IP ranges ---
    let vendor_ranges = get_vendor_ranges();
    let range_vendor = resolved_ip
        .as_ref()
        .and_then(|ip| ip_in_ranges(ip, &vendor_ranges));

    // --- Step 4: TLS handshake with cert capture ---
    let verifier = Arc::new(CertCapturingVerifier::new());

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();

    let server_name = ServerName::try_from(host.as_str())?.to_owned();
    let conn = ClientConnection::new(Arc::new(config), server_name)?;
    let sock = TcpStream::connect((host.as_str(), port))?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    sock.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut tls = StreamOwned::new(conn, sock);

    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }

    let kx = tls
        .conn
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()))
        .unwrap_or_else(|| "<none>".to_string());

    let cs = tls
        .conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "<none>".to_string());

    let aes = if cs.contains("AES_128") {
        "AES128"
    } else if cs.contains("AES_256") {
        "AES256"
    } else {
        "OTHER"
    };

    // --- Step 5: Parse captured certificate ---
    let cert_der = verifier.cert.lock().unwrap().take();
    let cert_vendor = cert_der.as_ref().and_then(|der| parse_cert_vendor(der));

    // --- Step 6: Reverse DNS (PTR) ---
    let ptr_record = dig_ptr(&ip_str).unwrap_or_default();
    let ptr_vendor = if !ptr_record.is_empty() {
        match_vendor(&ptr_record).map(String::from)
    } else {
        None
    };

    // --- Step 7: RDAP registry lookup ---
    let (rdap_netname, rdap_vendor) = if resolved_ip.is_some() {
        rdap_lookup(&ip_str).unwrap_or((String::new(), None))
    } else {
        (String::new(), None)
    };

    // --- Step 8: Determine infra vendor (all signals) and edge vendor (filtered) ---
    let mut signals: Vec<(String, String)> = Vec::new();
    if let Some(v) = &cname_vendor {
        signals.push(("CNAME".to_string(), v.clone()));
    }
    if let Some(v) = &range_vendor {
        signals.push(("RANGE".to_string(), v.clone()));
    }
    if let Some(v) = &cert_vendor {
        signals.push(("CERT".to_string(), v.clone()));
    }
    if let Some(v) = &ptr_vendor {
        signals.push(("PTR".to_string(), v.clone()));
    }
    if let Some(v) = &rdap_vendor {
        signals.push(("RDAP".to_string(), v.clone()));
    }

    let infra_vendor = determine_vendor(&signals);
    let infra_signal_count = signals.len();
    let edge_signals = filter_edge_signals(&signals);
    let edge_vendor = determine_vendor(&edge_signals);
    let edge_signal_count = edge_signals.len();

    // Count evidence classes (PTR + RDAP = 1 class) for confidence
    let infra_class_count: usize = signals
        .iter()
        .map(|(k, _)| evidence_class(k))
        .collect::<std::collections::HashSet<_>>()
        .len();
    let edge_class_count: usize = edge_signals
        .iter()
        .map(|(k, _)| evidence_class(k))
        .collect::<std::collections::HashSet<_>>()
        .len();

    let infra_vendor_str = infra_vendor.as_deref().unwrap_or("");
    let edge_vendor_str = edge_vendor.as_deref().unwrap_or("");
    let infra_confidence = match (&infra_vendor, infra_class_count) {
        (Some(_), n) if n >= 2 => "confirmed",
        (Some(_), 1) => "probable",
        (None, 0) => "none",
        _ => "undecided",
    };
    let edge_confidence = match (&edge_vendor, edge_class_count) {
        (Some(_), n) if n >= 2 => "confirmed",
        (Some(_), 1) => "probable",
        (None, 0) => "none",
        _ => "undecided",
    };

    let is_pq = kx == "X25519MLKEM768";
    let verdict = match (&edge_vendor, &infra_vendor, is_pq) {
        (Some(_), _, true) => "pq_at_edge",
        (None, Some(iv), true) if CLOUD_VENDORS.contains(&iv.as_str()) => "pq_cloud_hosted",
        (None, _, true) => "pq_own_infra",
        (Some(_), _, false) => "no_pq_edge",
        (None, Some(iv), false) if CLOUD_VENDORS.contains(&iv.as_str()) => "no_pq_cloud_hosted",
        (None, _, false) => "no_pq_own_infra",
    };

    // --- CSV output ---
    let filename = format!("kx-results-{}.csv", date_stamp());
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&filename)?;

    let cname_vendor_str = cname_vendor.as_deref().unwrap_or("");
    let range_vendor_str = range_vendor.as_deref().unwrap_or("");
    let cert_vendor_str = cert_vendor.as_deref().unwrap_or("");
    let ptr_vendor_str = ptr_vendor.as_deref().unwrap_or("");
    let rdap_vendor_str = rdap_vendor.as_deref().unwrap_or("");

    writeln!(
        file,
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        host,
        kx,
        aes,
        ip_str,
        cname_target,
        range_vendor_str,
        cert_vendor_str,
        ptr_vendor_str,
        rdap_netname,
        rdap_vendor_str,
        infra_vendor_str,
        infra_confidence,
        edge_vendor_str,
        edge_signal_count,
        edge_confidence,
        verdict
    )?;

    // --- stdout summary ---
    println!("TLD: {}", host);
    println!("IP: {}", ip_str);
    println!("KX group: {}", kx);
    println!("AES: {}", aes);
    println!(
        "CNAME: {} -> vendor: {}",
        if cname_target.is_empty() {
            "(none)"
        } else {
            &cname_target
        },
        if cname_vendor_str.is_empty() {
            "(none)"
        } else {
            cname_vendor_str
        }
    );
    println!(
        "Range match: {}",
        if range_vendor_str.is_empty() {
            "(none)"
        } else {
            range_vendor_str
        }
    );
    println!(
        "Cert vendor: {}",
        if cert_vendor_str.is_empty() {
            "(none)"
        } else {
            cert_vendor_str
        }
    );
    println!(
        "PTR: {} -> vendor: {}",
        if ptr_record.is_empty() {
            "(none)"
        } else {
            &ptr_record
        },
        if ptr_vendor_str.is_empty() {
            "(none)"
        } else {
            ptr_vendor_str
        }
    );
    println!(
        "RDAP: {} -> vendor: {}",
        if rdap_netname.is_empty() {
            "(none)"
        } else {
            &rdap_netname
        },
        if rdap_vendor_str.is_empty() {
            "(none)"
        } else {
            rdap_vendor_str
        }
    );
    println!(
        "Infra vendor: {} (signals: {}, classes: {}, confidence: {})",
        if infra_vendor_str.is_empty() {
            "(none)"
        } else {
            infra_vendor_str
        },
        infra_signal_count,
        infra_class_count,
        infra_confidence
    );
    println!(
        "Edge vendor: {} (signals: {}, classes: {}, confidence: {})",
        if edge_vendor_str.is_empty() {
            "(none)"
        } else {
            edge_vendor_str
        },
        edge_signal_count,
        edge_class_count,
        edge_confidence
    );
    println!("Verdict: {}", verdict);
    println!("---------------");

    // --- Optional HTTP proof (same as before) ---
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host
    );
    tls.write_all(req.as_bytes())?;

    let mut buf = [0u8; 8192];
    let mut resp = Vec::new();
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                resp.extend_from_slice(&buf[..n]);
                if resp.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if resp.len() > 64 * 1024 {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}
