use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, ProtocolVersion, SignatureScheme,
    StreamOwned,
};

use crate::model::{SymmetricAlg, TlsFacts, TlsSession};

use super::DetectError;
use super::limits::RateLimiter;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// Like NoCertificateVerification, but stores the end-entity cert
// for vendor name extraction.
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

struct TlsProbe {
    stream: StreamOwned<ClientConnection, TcpStream>,
    verifier: Arc<CertCapturingVerifier>,
}

impl TlsProbe {
    fn new(sock: TcpStream, host: &str) -> Result<Self, DetectError> {
        let verifier = Arc::new(CertCapturingVerifier::new());

        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();

        let server_name = ServerName::try_from(host)?.to_owned();
        let conn = ClientConnection::new(Arc::new(config), server_name)?;
        Ok(Self {
            stream: StreamOwned::new(conn, sock),
            verifier,
        })
    }

    fn complete_handshake(&mut self) -> Result<(), DetectError> {
        while self.stream.conn.is_handshaking() {
            self.stream.conn.complete_io(&mut self.stream.sock)?;
        }
        Ok(())
    }

    fn outcome(&self) -> (TlsSession, Option<Vec<u8>>) {
        let kx_group = self
            .stream
            .conn
            .negotiated_key_exchange_group()
            .map(|g| format!("{:?}", g.name()))
            .unwrap_or_else(|| "<none>".to_string());

        let cs = self
            .stream
            .conn
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()))
            .unwrap_or_else(|| "<none>".to_string());

        let session = TlsSession {
            version: tls_version_name(self.stream.conn.protocol_version()).to_string(),
            facts: TlsFacts {
                kx_group,
                symmetric_alg: SymmetricAlg::from_suite_name(&cs),
            },
        };
        (session, self.verifier.cert.lock().unwrap().take())
    }
}

fn tls_version_name(version: Option<ProtocolVersion>) -> &'static str {
    match version {
        Some(ProtocolVersion::TLSv1_3) => "TLS 1.3",
        Some(ProtocolVersion::TLSv1_2) => "TLS 1.2",
        Some(ProtocolVersion::TLSv1_1) => "TLS 1.1",
        Some(ProtocolVersion::TLSv1_0) => "TLS 1.0",
        Some(_) => "other",
        None => "<none>",
    }
}

fn with_timeouts(sock: TcpStream) -> Result<TcpStream, DetectError> {
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    sock.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(sock)
}

pub(crate) fn upgrade(
    sock: TcpStream,
    host: &str,
) -> Result<(TlsSession, Option<Vec<u8>>), DetectError> {
    let mut probe = TlsProbe::new(with_timeouts(sock)?, host)?;
    probe.complete_handshake()?;
    Ok(probe.outcome())
}

fn connect_host(
    host: &str,
    port: u16,
    limiter: Option<&RateLimiter>,
) -> Result<TcpStream, DetectError> {
    let mut last_err: Option<io::Error> = None;
    for addr in (host, port).to_socket_addrs()? {
        if let Some(limiter) = limiter {
            limiter.acquire();
        }
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(sock) => return Ok(sock),
            Err(err) => last_err = Some(err),
        }
    }
    Err(DetectError::Io(last_err.unwrap_or_else(|| {
        io::Error::other(format!("no addresses for {host}"))
    })))
}

pub(crate) fn probe(
    host: &str,
    limiter: Option<&RateLimiter>,
) -> Result<(TlsSession, Option<Vec<u8>>), DetectError> {
    let sock = connect_host(host, 443, limiter)?;
    let mut probe = TlsProbe::new(with_timeouts(sock)?, host)?;
    probe.complete_handshake()?;

    let (session, cert) = probe.outcome();

    let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    probe.stream.write_all(req.as_bytes())?;

    let mut buf = [0u8; 8192];
    let mut resp = Vec::new();
    loop {
        match probe.stream.read(&mut buf) {
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

    Ok((session, cert))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_versions_get_stable_display_names() {
        assert_eq!(tls_version_name(Some(ProtocolVersion::TLSv1_3)), "TLS 1.3");
        assert_eq!(tls_version_name(Some(ProtocolVersion::TLSv1_2)), "TLS 1.2");
        assert_eq!(tls_version_name(Some(ProtocolVersion::TLSv1_0)), "TLS 1.0");
        assert_eq!(tls_version_name(None), "<none>");
    }
}
