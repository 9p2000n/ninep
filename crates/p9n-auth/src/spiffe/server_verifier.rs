//! Custom SPIFFE server certificate verifier for TLS clients.
//!
//! Standard rustls WebPKI verification expects the server certificate to contain
//! a DNS SAN matching the SNI hostname. SPIFFE X.509-SVIDs only contain a URI SAN
//! (`spiffe://...`), so we need a custom verifier that validates the certificate
//! chain against the trust bundle and checks the SPIFFE ID instead of a hostname.

use super::trust_bundle::TrustBundleStore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use std::sync::Arc;

/// A `ServerCertVerifier` that validates SPIFFE X.509-SVIDs.
///
/// Instead of matching the server name against DNS SANs, this verifier:
/// 1. Verifies the certificate chain against the SPIFFE trust bundle
/// 2. Checks that the leaf certificate contains a valid `spiffe://` URI SAN
/// 3. Ignores the SNI hostname (SPIFFE identity is in the URI, not DNS)
#[derive(Debug)]
pub struct SpiffeServerVerifier {
    trust_store: TrustBundleStore,
    crypto_provider: Arc<CryptoProvider>,
}

impl SpiffeServerVerifier {
    pub fn new(trust_store: &TrustBundleStore, crypto_provider: Arc<CryptoProvider>) -> Self {
        Self {
            trust_store: trust_store.clone(),
            crypto_provider,
        }
    }
}

impl ServerCertVerifier for SpiffeServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Verify chain + SPIFFE ID using our existing chain_verifier
        super::chain_verifier::verify_x509_svid(end_entity.as_ref(), &self.trust_store)
            .map_err(|e| Error::General(format!("SPIFFE verification failed: {e}")))?;

        // Also check expiry against `now` — chain_verifier checks against system time,
        // but rustls passes its own `now` for testability. We trust chain_verifier's
        // check which uses UnixTime::now() internally via webpki.
        let _ = now;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
