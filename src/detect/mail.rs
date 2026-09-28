use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::asn::asn_lookup;
use super::cert::parse_cert_evidence;
use super::dns::{dig_mx, dig_ptr, resolve_all};
use super::limits::{Limits, RateLimiter, jitter_sleep};
use super::ranges::{VendorRanges, ip_in_ranges};
use super::rdap::rdap_lookup;
use super::tls;
use crate::model::{
    EmailReport, Evidence, MxProbe, MxRecord, Port, PortProbe, PtrEvidence, RangeEvidence,
    SmtpState,
};
use crate::providers::match_vendor;

use crate::model::attribute_infrastructure;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const EHLO_NAME: &str = "pq-pulse";

pub(crate) fn probe_mail_with_ranges(
    domain: &str,
    vendor_ranges: &VendorRanges,
    limits: Option<&Limits>,
) -> Option<EmailReport> {
    mail_report_with(domain, dig_mx(domain), resolve_all, vendor_ranges, limits)
}

fn mail_report_with(
    domain: &str,
    records: Vec<MxRecord>,
    resolve: impl Fn(&str) -> Vec<IpAddr> + Sync,
    vendor_ranges: &VendorRanges,
    limits: Option<&Limits>,
) -> Option<EmailReport> {
    if records.is_empty() {
        return None;
    }
    let mx = thread::scope(|scope| {
        let handles: Vec<_> = records
            .iter()
            .map(|record| scope.spawn(|| probe_mx(domain, record, vendor_ranges, &resolve, limits)))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("mx probe thread"))
            .collect()
    });
    Some(EmailReport { mx })
}

fn probe_mx(
    domain: &str,
    record: &MxRecord,
    vendor_ranges: &VendorRanges,
    resolve: &(impl Fn(&str) -> Vec<IpAddr> + Sync),
    limits: Option<&Limits>,
) -> MxProbe {
    let addresses = resolve(&record.host);
    let outcomes = match limits {
        Some(limits) => limits.host_locks.with_host(&record.host, || {
            let mut outcomes = Vec::new();
            for (attempt, port) in Port::ALL.iter().enumerate() {
                if attempt > 0 {
                    jitter_sleep();
                }
                outcomes.push(probe_port(
                    *port,
                    record.host.as_str(),
                    &addresses,
                    Some(&limits.limiter),
                ));
            }
            outcomes
        }),
        None => thread::scope(|scope| {
            let handles: Vec<_> = Port::ALL
                .iter()
                .map(|port| {
                    let host = record.host.as_str();
                    let addrs: &[IpAddr] = &addresses;
                    scope.spawn(move || probe_port(*port, host, addrs, None))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle.join().unwrap_or(ProbeOutcome {
                        state: SmtpState::Unreachable,
                        peer: None,
                        cert: None,
                    })
                })
                .collect()
        }),
    };

    let attribution_ip = outcomes
        .iter()
        .find_map(|outcome| outcome.peer)
        .or_else(|| addresses.first().copied());
    let range = attribution_ip
        .as_ref()
        .and_then(|ip| ip_in_ranges(ip, vendor_ranges))
        .map(|(vendor, cidr)| RangeEvidence { cidr, vendor });
    let ptr = attribution_ip
        .and_then(|ip| dig_ptr(&ip.to_string()))
        .map(|name| PtrEvidence {
            vendor: match_vendor(&name),
            record: name,
        });
    let rdap = attribution_ip
        .map(|ip| ip.to_string())
        .as_deref()
        .and_then(rdap_lookup);
    let asn = attribution_ip.and_then(asn_lookup);
    let cert = outcomes
        .iter()
        .find_map(|outcome| outcome.cert.clone())
        .as_deref()
        .and_then(parse_cert_evidence);

    let evidence = Evidence {
        range,
        cert,
        ptr,
        rdap,
        asn,
        ..Default::default()
    };
    let infrastructure = attribute_infrastructure(&evidence, domain);

    MxProbe {
        priority: record.priority,
        host: record.host.clone(),
        addresses,
        ip: attribution_ip,
        ports: Port::ALL
            .iter()
            .zip(outcomes)
            .map(|(port, outcome)| PortProbe {
                port: *port,
                state: outcome.state,
            })
            .collect(),
        evidence,
        infrastructure,
    }
}

struct ProbeOutcome {
    state: SmtpState,
    peer: Option<IpAddr>,
    cert: Option<Vec<u8>>,
}

fn probe_port(
    port: Port,
    host: &str,
    addresses: &[IpAddr],
    limiter: Option<&RateLimiter>,
) -> ProbeOutcome {
    match port {
        Port::Smtps465 => smtps_probe(host, addresses, limiter),
        _ => smtp_probe(host, addresses, port.number(), limiter),
    }
}

fn smtp_probe(
    host: &str,
    addresses: &[IpAddr],
    port: u16,
    limiter: Option<&RateLimiter>,
) -> ProbeOutcome {
    let Some((mut conn, peer)) = connect_any(addresses, port, limiter) else {
        return ProbeOutcome {
            state: SmtpState::Unreachable,
            peer: None,
            cert: None,
        };
    };

    let banner_ok = conn
        .read_response()
        .is_ok_and(|lines| lines.first().is_some_and(|line| line.starts_with("220")));
    if !banner_ok {
        return ProbeOutcome {
            state: SmtpState::NoStarttls,
            peer: Some(peer),
            cert: None,
        };
    }

    let capabilities = match conn.send(&format!("EHLO {EHLO_NAME}")) {
        Ok(()) => match conn.read_response() {
            Ok(lines) if is_code(&lines, "250") => lines,
            _ => {
                return ProbeOutcome {
                    state: SmtpState::NoStarttls,
                    peer: Some(peer),
                    cert: None,
                };
            }
        },
        Err(_) => {
            return ProbeOutcome {
                state: SmtpState::NoStarttls,
                peer: Some(peer),
                cert: None,
            };
        }
    };

    if !has_starttls(&capabilities) {
        return ProbeOutcome {
            state: SmtpState::NoStarttls,
            peer: Some(peer),
            cert: None,
        };
    }

    if conn.send("STARTTLS").is_err() {
        return ProbeOutcome {
            state: SmtpState::TlsFailed,
            peer: Some(peer),
            cert: None,
        };
    }
    let accepted = conn
        .read_response()
        .is_ok_and(|lines| is_code(&lines, "220"));

    if !accepted {
        return ProbeOutcome {
            state: SmtpState::TlsFailed,
            peer: Some(peer),
            cert: None,
        };
    }

    let sock = conn.into_inner();
    match tls::upgrade(sock, host) {
        Ok((session, cert)) => ProbeOutcome {
            state: SmtpState::Tls(session),
            peer: Some(peer),
            cert,
        },
        Err(_) => ProbeOutcome {
            state: SmtpState::TlsFailed,
            peer: Some(peer),
            cert: None,
        },
    }
}

fn connect_any(
    addresses: &[IpAddr],
    port: u16,
    limiter: Option<&RateLimiter>,
) -> Option<(SmtpConn, IpAddr)> {
    if let Some(limiter) = limiter {
        for ip in addresses {
            limiter.acquire();
            if let Ok(stream) =
                TcpStream::connect_timeout(&SocketAddr::new(*ip, port), CONNECT_TIMEOUT)
            {
                return Some((SmtpConn::new(stream), *ip));
            }
        }
        return None;
    }

    let (sender, receiver) = mpsc::channel();
    let mut handles = Vec::new();
    for ip in addresses.iter().copied() {
        let sender = sender.clone();
        handles.push(thread::spawn(move || {
            let addr = SocketAddr::new(ip, port);
            let _ = sender.send(
                TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
                    .ok()
                    .map(|stream| (SmtpConn::new(stream), ip)),
            );
        }));
    }
    drop(sender);

    let mut failures = 0;
    for received in receiver {
        match received {
            Some(conn) => return Some(conn),
            None => {
                failures += 1;
                if failures == handles.len() {
                    return None;
                }
            }
        }
    }
    None
}

fn smtps_probe(host: &str, addresses: &[IpAddr], limiter: Option<&RateLimiter>) -> ProbeOutcome {
    let Some((conn, peer)) = connect_any(addresses, Port::Smtps465.number(), limiter) else {
        return ProbeOutcome {
            state: SmtpState::Unreachable,
            peer: None,
            cert: None,
        };
    };
    match tls::upgrade(conn.into_inner(), host) {
        Ok((session, cert)) => ProbeOutcome {
            state: SmtpState::Tls(session),
            peer: Some(peer),
            cert,
        },
        Err(_) => ProbeOutcome {
            state: SmtpState::TlsFailed,
            peer: Some(peer),
            cert: None,
        },
    }
}

fn is_code(lines: &[String], code: &str) -> bool {
    lines
        .last()
        .and_then(|line| line.split_once(' '))
        .is_some_and(|(prefix, _)| prefix == code)
}

fn has_starttls(capabilities: &[String]) -> bool {
    capabilities
        .iter()
        .filter_map(|line| line.get(4..))
        .any(|capability| capability.split_whitespace().next() == Some("STARTTLS"))
}

fn complete_reply(buffer: &[u8]) -> Option<Vec<String>> {
    let text = std::str::from_utf8(buffer).ok()?;
    let mut lines: Vec<String> = Vec::new();
    for chunk in text.split('\n') {
        let line = chunk.strip_suffix('\r').unwrap_or(chunk);
        match line.split_at_checked(3) {
            Some((code, rest)) if code.bytes().all(|b| b.is_ascii_digit()) => {
                if rest.starts_with(' ') {
                    lines.push(line.to_string());
                    return Some(lines);
                }
                if rest.starts_with('-') {
                    lines.push(line.to_string());
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}

struct SmtpConn {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl SmtpConn {
    fn new(stream: TcpStream) -> Self {
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    fn send(&mut self, command: &str) -> std::io::Result<()> {
        self.stream.write_all(command.as_bytes())?;
        self.stream.write_all(b"\r\n")?;
        self.stream.flush()
    }

    fn read_response(&mut self) -> std::io::Result<Vec<String>> {
        let mut chunk = [0u8; 1024];
        loop {
            if let Some(lines) = complete_reply(&self.buffer) {
                self.buffer.clear();
                return Ok(lines);
            }
            let read = self.stream.read(&mut chunk)?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed mid-reply",
                ));
            }
            self.buffer.extend_from_slice(&chunk[..read]);
            if self.buffer.len() > 64 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "oversized SMTP reply",
                ));
            }
        }
    }

    fn into_inner(self) -> TcpStream {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::dns::parse_mx_lines;
    use crate::model::{TlsFacts, TlsSession};

    #[test]
    fn ehlo_capabilities_are_detected_exactly() {
        let lines = vec![
            "250-mail.example.com".to_string(),
            "250-PIPELINING".to_string(),
            "250-STARTTLS".to_string(),
            "250 SIZE 104857600".to_string(),
        ];
        assert!(has_starttls(&lines));

        let lines = vec!["250-STARTTLSFUZZ".to_string(), "250 OK".to_string()];
        assert!(!has_starttls(&lines));

        assert!(!has_starttls(&["250 PIPELINING".to_string()]));
        assert!(!has_starttls(&[]));
    }

    #[test]
    fn replies_parse_including_multiline() {
        let single = b"220 mail.example.com ESMTP ready\r\n";
        assert_eq!(
            complete_reply(single),
            Some(vec!["220 mail.example.com ESMTP ready".to_string()])
        );

        let multi =
            b"250-mail.example.com\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 SIZE 104857600\r\n";
        assert_eq!(
            complete_reply(multi),
            Some(vec![
                "250-mail.example.com".to_string(),
                "250-PIPELINING".to_string(),
                "250-STARTTLS".to_string(),
                "250 SIZE 104857600".to_string(),
            ])
        );

        assert_eq!(
            complete_reply(b"250-STARTTLS\n250 OK\n"),
            Some(vec!["250-STARTTLS".to_string(), "250 OK".to_string()])
        );

        assert_eq!(complete_reply(b"250-STARTTLS\r\n"), None);
        assert_eq!(complete_reply(b"250-STARTTL"), None);
        assert_eq!(complete_reply(b"250-ST"), None);
        assert_eq!(complete_reply(b"garbage\r\n"), None);
    }

    #[test]
    fn reply_codes_are_read_from_the_final_line() {
        let lines = vec!["250-STARTTLS".to_string(), "250 OK".to_string()];
        assert!(is_code(&lines, "250"));
        assert!(!is_code(&lines, "220"));

        let lines = vec!["220 go ahead".to_string()];
        assert!(is_code(&lines, "220"));
        assert!(!is_code(&lines, "250"));

        let lines = vec!["220 ".to_string()];
        assert!(is_code(&lines, "220"));
        assert!(!is_code(&[], "220"));
    }

    #[test]
    fn starttls_states_are_distinct_observations() {
        assert_ne!(SmtpState::NoStarttls, SmtpState::TlsFailed);
        assert_ne!(
            SmtpState::NoStarttls,
            SmtpState::Tls(TlsSession {
                version: "TLS 1.3".to_string(),
                facts: TlsFacts {
                    kx_group: "X25519".to_string(),
                    symmetric_alg: crate::model::SymmetricAlg::Aes256,
                },
            })
        );
        assert_ne!(
            SmtpState::TlsFailed,
            SmtpState::Tls(TlsSession {
                version: "TLS 1.3".to_string(),
                facts: TlsFacts {
                    kx_group: "X25519MLKEM768".to_string(),
                    symmetric_alg: crate::model::SymmetricAlg::Aes256,
                },
            })
        );
    }

    #[test]
    fn no_mx_records_mean_no_probes_and_no_report() {
        let ranges = VendorRanges::new();
        assert!(
            mail_report_with("example.com", Vec::new(), |_host| vec![], &ranges, None).is_none()
        );
    }

    #[test]
    fn multiple_mx_records_are_all_reported_independently() {
        let records = parse_mx_lines("20 mx2.example.com\n10 mx1.example.com\n");
        assert_eq!(records.len(), 2);
        let report = mail_report_with(
            "example.com",
            records,
            |_host| vec![],
            &VendorRanges::new(),
            None,
        )
        .unwrap();
        assert_eq!(report.mx.len(), 2);
        assert_eq!(report.mx[0].priority, 10);
        assert_eq!(report.mx[0].host, "mx1.example.com");
        assert_eq!(report.mx[1].priority, 20);
        assert_eq!(report.mx[1].host, "mx2.example.com");
        for probe in &report.mx {
            assert!(probe.addresses.is_empty());
            assert_eq!(probe.ports.len(), 3);
            for port_probe in &probe.ports {
                assert_eq!(port_probe.state, SmtpState::Unreachable);
            }
        }
    }

    #[test]
    fn ports_are_probed_in_a_fixed_order() {
        let records = parse_mx_lines("10 mx.example.com\n");
        let report = mail_report_with(
            "example.com",
            records,
            |_host| vec![],
            &VendorRanges::new(),
            None,
        )
        .unwrap();
        let ports: Vec<Port> = report.mx[0].ports.iter().map(|p| p.port).collect();
        assert_eq!(
            ports,
            vec![Port::Smtp25, Port::Submission587, Port::Smtps465]
        );
        for port in &ports {
            assert_eq!(
                port.number(),
                match port {
                    Port::Smtp25 => 25,
                    Port::Submission587 => 587,
                    Port::Smtps465 => 465,
                }
            );
        }
        assert!(Port::Smtp25.has_starttls());
        assert!(Port::Submission587.has_starttls());
        assert!(!Port::Smtps465.has_starttls());
    }
}
