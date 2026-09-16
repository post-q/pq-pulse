use crate::model::Vendor;

use super::vendors::match_vendor;

/// Vendor match plus the observed name, trying subject CN, then issuer CN,
/// then SANs; when nothing matches, the first available name is the observation.
pub(crate) fn parse_cert_evidence(cert_der: &[u8]) -> Option<(Option<Vendor>, String)> {
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

    let mut sans: Vec<String> = Vec::new();
    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for gn in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(s) = gn {
                    sans.push(s.to_string());
                }
            }
        }
    }

    if let Some(cn) = subject_cn
        && let Some(vendor) = match_vendor(cn)
    {
        return Some((Some(vendor), cn.to_string()));
    }
    if let Some(cn) = issuer_cn
        && let Some(vendor) = match_vendor(cn)
    {
        return Some((Some(vendor), cn.to_string()));
    }
    for san in &sans {
        if let Some(vendor) = match_vendor(san) {
            return Some((Some(vendor), san.clone()));
        }
    }

    let observed = subject_cn
        .map(String::from)
        .or_else(|| issuer_cn.map(String::from))
        .or_else(|| sans.first().cloned())?;
    Some((None, observed))
}
