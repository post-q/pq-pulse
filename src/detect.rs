mod asn;
mod cert;
mod dns;
mod http;
mod mail;
mod ranges;
mod rdap;
mod tls;

use crate::providers::{match_cname_chain_vendor, match_vendor};

use chrono::Local;
use thiserror::Error;

use crate::model::{CnameEvidence, DomainReport, Evidence, PtrEvidence, RangeEvidence, TlsState};

use asn::asn_lookup;
use dns::{dig_cname_chain, dig_ptr, resolve};
use http::probe_http;
use mail::probe_mail_with_ranges;
use ranges::{get_vendor_ranges, ip_in_ranges};
use rdap::rdap_lookup;
use tls::probe;

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

    let cname_chain = dig_cname_chain(host);
    let cname = (!cname_chain.is_empty()).then(|| CnameEvidence {
        vendor: match_cname_chain_vendor(&cname_chain),
        chain: cname_chain,
    });

    let vendor_ranges = get_vendor_ranges();
    let range = resolved_ip
        .as_ref()
        .and_then(|ip| ip_in_ranges(ip, &vendor_ranges))
        .map(|(vendor, cidr)| RangeEvidence { cidr, vendor });

    let (tls, cert, http, email, ptr, rdap, asn) = std::thread::scope(|scope| {
        let mail = scope.spawn(|| probe_mail_with_ranges(host, &vendor_ranges));

        let (tls, cert_der) = match probe(host) {
            Ok((facts, cert)) => (TlsState::Tls(facts), cert),
            Err(_) => (TlsState::Unavailable, None),
        };

        let cert = cert_der.as_deref().and_then(cert::parse_cert_evidence);

        let http = probe_http(host);

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

        let asn = resolved_ip.and_then(asn_lookup);

        let email = mail.join().unwrap_or_default();

        (tls, cert, http, email, ptr, rdap, asn)
    });

    Ok(DomainReport::build(
        host.to_string(),
        resolved_ip,
        tls,
        Evidence {
            cname,
            range,
            cert,
            http,
            ptr,
            rdap,
            asn,
        },
        email,
        Local::now(),
    ))
}
