//! Hand-written protobuf codec for the SPIFFE Workload API.
//!
//! Only the messages needed for `FetchX509SVID` are implemented:
//!   - X509SVIDRequest  (empty, encoded as zero bytes)
//!   - X509SVIDResponse { repeated X509SVID svids = 1; }
//!   - X509SVID { string spiffe_id=1; bytes x509_svid=2; bytes x509_svid_key=3; bytes bundle=4; }

use crate::error::AuthError;

const WIRE_VARINT: u8 = 0;
const WIRE_64BIT: u8 = 1;
const WIRE_LEN: u8 = 2;
const WIRE_32BIT: u8 = 5;

/// A single X.509-SVID returned by the Workload API.
#[derive(Debug, Clone, Default)]
pub struct X509Svid {
    pub spiffe_id: String,
    /// DER-encoded certificate chain (multiple certs concatenated).
    pub cert_chain_der: Vec<u8>,
    /// DER-encoded private key (PKCS8).
    pub private_key_der: Vec<u8>,
    /// DER-encoded CA bundle (multiple certs concatenated).
    pub bundle_der: Vec<u8>,
}

/// Response from FetchX509SVID streaming RPC.
#[derive(Debug, Clone, Default)]
pub struct X509SvidResponse {
    pub svids: Vec<X509Svid>,
}

pub fn decode_x509_svid_response(data: &[u8]) -> Result<X509SvidResponse, AuthError> {
    let mut resp = X509SvidResponse::default();
    let mut pos = 0;
    while pos < data.len() {
        let tag = decode_varint(data, &mut pos)?;
        let field = (tag >> 3) as u32;
        let wt = (tag & 0x7) as u8;
        match (field, wt) {
            (1, WIRE_LEN) => {
                let sub = decode_len_field(data, &mut pos)?;
                resp.svids.push(decode_x509_svid(sub)?);
            }
            _ => skip_field(data, &mut pos, wt)?,
        }
    }
    Ok(resp)
}

fn decode_x509_svid(data: &[u8]) -> Result<X509Svid, AuthError> {
    let mut svid = X509Svid::default();
    let mut pos = 0;
    while pos < data.len() {
        let tag = decode_varint(data, &mut pos)?;
        let field = (tag >> 3) as u32;
        let wt = (tag & 0x7) as u8;
        match (field, wt) {
            (1, WIRE_LEN) => {
                svid.spiffe_id = String::from_utf8(decode_len_field(data, &mut pos)?.to_vec())
                    .map_err(|e| AuthError::WorkloadApi(format!("invalid spiffe_id: {e}")))?;
            }
            (2, WIRE_LEN) => svid.cert_chain_der = decode_len_field(data, &mut pos)?.to_vec(),
            (3, WIRE_LEN) => svid.private_key_der = decode_len_field(data, &mut pos)?.to_vec(),
            (4, WIRE_LEN) => svid.bundle_der = decode_len_field(data, &mut pos)?.to_vec(),
            _ => skip_field(data, &mut pos, wt)?,
        }
    }
    Ok(svid)
}

// ── Protobuf primitives ──

fn decode_varint(data: &[u8], pos: &mut usize) -> Result<u64, AuthError> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            return Err(AuthError::WorkloadApi("truncated varint".into()));
        }
        let b = data[*pos];
        *pos += 1;
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err(AuthError::WorkloadApi("varint too long".into()));
        }
    }
}

fn decode_len_field<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], AuthError> {
    let len = decode_varint(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(AuthError::WorkloadApi("truncated length-delimited field".into()));
    }
    let slice = &data[*pos..*pos + len];
    *pos += len;
    Ok(slice)
}

fn skip_field(data: &[u8], pos: &mut usize, wire_type: u8) -> Result<(), AuthError> {
    match wire_type {
        WIRE_VARINT => { decode_varint(data, pos)?; }
        WIRE_64BIT => {
            if *pos + 8 > data.len() {
                return Err(AuthError::WorkloadApi("truncated fixed64".into()));
            }
            *pos += 8;
        }
        WIRE_LEN => { decode_len_field(data, pos)?; }
        WIRE_32BIT => {
            if *pos + 4 > data.len() {
                return Err(AuthError::WorkloadApi("truncated fixed32".into()));
            }
            *pos += 4;
        }
        _ => return Err(AuthError::WorkloadApi(format!("unknown wire type {wire_type}"))),
    }
    Ok(())
}

/// Split concatenated DER-encoded certificates into individual certs.
///
/// The Workload API returns multiple DER certificates concatenated in a single
/// bytes field. Each DER certificate starts with a SEQUENCE tag (0x30).
pub fn split_der_certs(data: &[u8]) -> Vec<Vec<u8>> {
    let mut certs = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if data[pos] != 0x30 {
            break;
        }
        match der_element_len(data, pos) {
            Some(total) if pos + total <= data.len() => {
                certs.push(data[pos..pos + total].to_vec());
                pos += total;
            }
            _ => break,
        }
    }
    certs
}

/// Compute the total length of a DER element (tag + length + content) starting at `pos`.
fn der_element_len(data: &[u8], pos: usize) -> Option<usize> {
    if pos + 2 > data.len() {
        return None;
    }
    // Skip tag byte
    let len_start = pos + 1;
    let first = data[len_start];
    if first & 0x80 == 0 {
        // Short form: length is first byte itself
        Some(2 + first as usize)
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || len_start + 1 + num_bytes > data.len() {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | data[len_start + 1 + i] as usize;
        }
        Some(1 + 1 + num_bytes + len) // tag + first_len_byte + len_bytes + content
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varint(buf: &mut Vec<u8>, mut val: u64) {
        loop {
            let mut byte = (val & 0x7F) as u8;
            val >>= 7;
            if val != 0 { byte |= 0x80; }
            buf.push(byte);
            if val == 0 { break; }
        }
    }

    fn encode_tag(buf: &mut Vec<u8>, field: u32, wire_type: u8) {
        encode_varint(buf, ((field as u64) << 3) | wire_type as u64);
    }

    fn encode_bytes_field(buf: &mut Vec<u8>, field: u32, data: &[u8]) {
        encode_tag(buf, field, 2);
        encode_varint(buf, data.len() as u64);
        buf.extend_from_slice(data);
    }

    fn encode_string_field(buf: &mut Vec<u8>, field: u32, s: &str) {
        encode_bytes_field(buf, field, s.as_bytes());
    }

    fn build_x509_svid(spiffe_id: &str, cert: &[u8], key: &[u8], bundle: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_string_field(&mut buf, 1, spiffe_id);
        encode_bytes_field(&mut buf, 2, cert);
        encode_bytes_field(&mut buf, 3, key);
        encode_bytes_field(&mut buf, 4, bundle);
        buf
    }

    fn build_response(svids: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = Vec::new();
        for svid in svids {
            encode_bytes_field(&mut buf, 1, svid);
        }
        buf
    }

    #[test]
    fn test_decode_single_svid() {
        let svid = build_x509_svid(
            "spiffe://example.com/app",
            b"\x30\x03\x01\x01\xff",
            b"\x30\x03private",
            b"\x30\x03\x01\x01\x00",
        );
        let resp_bytes = build_response(&[svid]);
        let resp = decode_x509_svid_response(&resp_bytes).unwrap();

        assert_eq!(resp.svids.len(), 1);
        assert_eq!(resp.svids[0].spiffe_id, "spiffe://example.com/app");
        assert_eq!(resp.svids[0].cert_chain_der, b"\x30\x03\x01\x01\xff");
        assert_eq!(resp.svids[0].private_key_der, b"\x30\x03private");
        assert_eq!(resp.svids[0].bundle_der, b"\x30\x03\x01\x01\x00");
    }

    #[test]
    fn test_decode_multiple_svids() {
        let s1 = build_x509_svid("spiffe://a.com/x", b"cert1", b"key1", b"ca1");
        let s2 = build_x509_svid("spiffe://b.com/y", b"cert2", b"key2", b"ca2");
        let resp_bytes = build_response(&[s1, s2]);
        let resp = decode_x509_svid_response(&resp_bytes).unwrap();
        assert_eq!(resp.svids.len(), 2);
        assert_eq!(resp.svids[0].spiffe_id, "spiffe://a.com/x");
        assert_eq!(resp.svids[1].spiffe_id, "spiffe://b.com/y");
    }

    #[test]
    fn test_unknown_fields_skipped() {
        let mut svid = build_x509_svid("spiffe://x.com/w", b"c", b"k", b"b");
        // Add unknown field 99 (varint)
        encode_tag(&mut svid, 99, 0);
        encode_varint(&mut svid, 42);
        // Add unknown field 100 (length-delimited)
        encode_bytes_field(&mut svid, 100, b"unknown data");

        let resp_bytes = build_response(&[svid]);
        let resp = decode_x509_svid_response(&resp_bytes).unwrap();
        assert_eq!(resp.svids[0].spiffe_id, "spiffe://x.com/w");
    }

    #[test]
    fn test_empty_response() {
        let resp = decode_x509_svid_response(&[]).unwrap();
        assert!(resp.svids.is_empty());
    }

    #[test]
    fn test_split_der_certs_single() {
        // Short-form length: 0x30 0x03 [3 bytes content]
        let cert = vec![0x30, 0x03, 0x01, 0x02, 0x03];
        let certs = split_der_certs(&cert);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], cert);
    }

    #[test]
    fn test_split_der_certs_multiple() {
        let c1 = vec![0x30, 0x02, 0xAA, 0xBB];
        let c2 = vec![0x30, 0x03, 0xCC, 0xDD, 0xEE];
        let mut concat = c1.clone();
        concat.extend_from_slice(&c2);
        let certs = split_der_certs(&concat);
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0], c1);
        assert_eq!(certs[1], c2);
    }

    #[test]
    fn test_split_der_certs_long_form_length() {
        // Long-form: 0x30 0x81 0x80 [128 bytes content]
        let mut cert = vec![0x30, 0x81, 0x80];
        cert.extend_from_slice(&[0xAA; 128]);
        let certs = split_der_certs(&cert);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].len(), 3 + 128);
    }

    #[test]
    fn test_split_der_certs_empty() {
        assert!(split_der_certs(&[]).is_empty());
    }
}
