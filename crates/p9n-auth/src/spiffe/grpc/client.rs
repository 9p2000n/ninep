//! gRPC client for the SPIFFE Workload API over Unix socket.
//!
//! Connects to the SPIRE Agent at `SPIFFE_ENDPOINT_SOCKET` and calls
//! `FetchX509SVID` (server-streaming RPC) to receive SVIDs.

use super::frame;
use super::proto::{self, X509SvidResponse};
use crate::error::AuthError;
use bytes::Bytes;
use h2::client;
use http::Request;
use tokio::net::UnixStream;

/// Stream of X509SVIDResponse messages from a FetchX509SVID call.
pub struct X509SvidStream {
    body: h2::RecvStream,
    decoder: frame::Decoder,
}

impl X509SvidStream {
    /// Read the next X509SVIDResponse pushed by the server.
    ///
    /// Returns `Ok(None)` when the stream is closed by the server.
    pub async fn next(&mut self) -> Result<Option<X509SvidResponse>, AuthError> {
        loop {
            // Try to decode a complete message from the buffer first.
            if let Some(payload) = self.decoder.next_message() {
                return proto::decode_x509_svid_response(&payload).map(Some);
            }
            // Need more data from the HTTP/2 stream.
            match self.body.data().await {
                Some(Ok(chunk)) => {
                    // Flow-control: release capacity so the sender can continue.
                    let len = chunk.len();
                    let _ = self.body.flow_control().release_capacity(len);
                    self.decoder.push(chunk);
                }
                Some(Err(e)) => {
                    return Err(AuthError::WorkloadApi(format!("h2 stream error: {e}")));
                }
                None => {
                    // Stream ended. Check if there's a final buffered message.
                    if let Some(payload) = self.decoder.next_message() {
                        return proto::decode_x509_svid_response(&payload).map(Some);
                    }
                    return Ok(None);
                }
            }
        }
    }
}

/// Initiate a FetchX509SVID streaming RPC over an existing HTTP/2 connection.
pub async fn fetch_x509_svid(
    mut sender: client::SendRequest<Bytes>,
) -> Result<X509SvidStream, AuthError> {
    let request = Request::builder()
        .method("POST")
        .uri("http://localhost/SpiffeWorkloadAPI/FetchX509SVID")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .map_err(|e| AuthError::WorkloadApi(format!("build request: {e}")))?;

    let (response_future, mut send_stream) = sender
        .send_request(request, false)
        .map_err(|e| AuthError::WorkloadApi(format!("send request: {e}")))?;

    // Send the empty X509SVIDRequest as a gRPC frame and close the send side.
    let grpc_payload = frame::encode(&[]);
    send_stream
        .send_data(Bytes::from(grpc_payload), true)
        .map_err(|e| AuthError::WorkloadApi(format!("send data: {e}")))?;

    let response = response_future
        .await
        .map_err(|e| AuthError::WorkloadApi(format!("response: {e}")))?;

    let status = response.status();
    if status != http::StatusCode::OK {
        return Err(AuthError::WorkloadApi(format!(
            "server returned HTTP {status}"
        )));
    }

    let body = response.into_body();
    Ok(X509SvidStream {
        body,
        decoder: frame::Decoder::new(),
    })
}

/// Connect to the SPIRE Agent via Unix socket and return an HTTP/2 sender.
pub async fn connect(socket_path: &str) -> Result<client::SendRequest<Bytes>, AuthError> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| AuthError::WorkloadApi(format!("connect {socket_path}: {e}")))?;

    let (sender, conn) = client::handshake(stream)
        .await
        .map_err(|e| AuthError::WorkloadApi(format!("h2 handshake: {e}")))?;

    // Drive the HTTP/2 connection in the background.
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("workload API h2 connection closed: {e}");
        }
    });

    Ok(sender)
}
