//! Quinn endpoint configuration.

use crate::error::TransportError;
use p9n_auth::spiffe::tls_config;
use p9n_auth::SpiffeAuth;
use std::net::SocketAddr;
use std::sync::Arc;

/// Create a quinn server endpoint with SPIFFE mTLS.
pub fn server_endpoint(
    bind: SocketAddr,
    auth: &SpiffeAuth,
) -> Result<quinn::Endpoint, TransportError> {
    let tls = tls_config::server_config(&auth.identity, &auth.trust_store)
        .map_err(|e| TransportError::Other(format!("TLS config: {e}")))?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| TransportError::Other(format!("QUIC crypto: {e}")))?,
    ));

    // Enable datagram support
    let transport = Arc::get_mut(&mut server_config.transport).unwrap();
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(16u32.into());
    transport.datagram_receive_buffer_size(Some(65536));

    let endpoint =
        quinn::Endpoint::server(server_config, bind).map_err(TransportError::Io)?;

    Ok(endpoint)
}

/// Create a quinn client endpoint with SPIFFE mTLS.
pub fn client_endpoint(auth: &SpiffeAuth) -> Result<quinn::Endpoint, TransportError> {
    let tls = tls_config::client_config(&auth.identity, &auth.trust_store)
        .map_err(|e| TransportError::Other(format!("TLS config: {e}")))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| TransportError::Other(format!("QUIC crypto: {e}")))?,
    ));

    // Transport tuning (stream concurrency, datagram buffer).
    // 0-RTT itself is enabled via rustls ClientConfig (enable_early_data + session store).
    client_config.transport_config(Arc::new({
        let mut tc = quinn::TransportConfig::default();
        tc.max_concurrent_bidi_streams(256u32.into());
        tc.max_concurrent_uni_streams(16u32.into());
        tc.datagram_receive_buffer_size(Some(65536));
        tc
    }));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(TransportError::Io)?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}
