mod cert;
mod dns;
mod ranges;
mod rdap;
mod tls;
mod vendors;

use chrono::Local;
use thiserror::Error;

use crate::model::{
    CertEvidence, CnameEvidence, DomainReport, Evidence, PtrEvidence, RangeEvidence,
};

use dns::{dig_cname, dig_ptr, resolve};
use ranges::{get_vendor_ranges, ip_in_ranges};
use rdap::rdap_lookup;
use tls::probe;
use vendors::{match_cname_vendor, match_vendor};

/// Detection failures; `Display` forwards the upstream message unchanged.
#[derive(Debug, Error)]
pub(crate) enum DetectError {
    #[error("{0}")]
    InvalidServerName(#[from] rustls::pki_types::InvalidDnsNameError),
    #[error("{0}")]
    Tls(#[from] rustls::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

pub(crate) fn check_domain(host: &str) -> Result<DomainReport, DetectError> {
    let resolved_ip = resolve(host);

    let cname = dig_cname(host).map(|target| CnameEvidence {
        vendor: match_cname_vendor(&target),
        target,
    });

    let vendor_ranges = get_vendor_ranges();
    let range = resolved_ip
        .as_ref()
        .and_then(|ip| ip_in_ranges(ip, &vendor_ranges))
        .map(|(vendor, cidr)| RangeEvidence { cidr, vendor });

    let (tls, cert_der) = probe(host)?;

    let cert = cert_der
        .as_deref()
        .and_then(cert::parse_cert_evidence)
        .map(|(vendor, name)| CertEvidence { vendor, name });

    let ptr = resolved_ip
        .and_then(|ip| dig_ptr(&ip.to_string()))
        .map(|record| PtrEvidence {
            vendor: match_vendor(&record),
            record,
        });

    let rdap = resolved_ip
        .map(|ip| ip.to_string())
        .as_deref()
        .and_then(rdap_lookup);

    Ok(DomainReport::build(
        host.to_string(),
        resolved_ip,
        tls,
        Evidence {
            cname,
            range,
            cert,
            ptr,
            rdap,
        },
        Local::now(),
    ))
}
