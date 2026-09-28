use crate::model::CertEvidence;

use crate::providers::match_vendor;

/// Vendor match plus the observed name (subject CN, then issuer CN, then
/// SANs; when nothing matches, the first available name is the observation).
/// Every observed name is kept for edge-namespace role checks.
pub(crate) fn parse_cert_evidence(cert_der: &[u8]) -> Option<CertEvidence> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.attr_value().as_str().ok());
    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.attr_value().as_str().ok());

    let mut names: Vec<String> = Vec::new();
    for name in [subject_cn, issuer_cn].into_iter().flatten() {
        if !names.contains(&name.to_string()) {
            names.push(name.to_string());
        }
    }
    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for gn in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(s) = gn
                    && !names.contains(&s.to_string())
                {
                    names.push(s.to_string());
                }
            }
        }
    }

    let vendor = names.iter().find_map(|name| match_vendor(name));
    let name = names.first().cloned()?;
    Some(CertEvidence {
        name,
        vendor,
        names,
        issuer_cn: issuer_cn.map(String::from),
    })
}
