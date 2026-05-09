//! `p9nPosixIdentity` X.509 extension parser.
//!
//! Defined in `docs/POSIX_IDENTITY.md` §3. The extension embeds a POSIX
//! `(uid, gid, groups)` mapping into a SPIFFE X.509-SVID so that both ends
//! of a 9P2000.N connection can derive a shared POSIX identity from the
//! same authenticated artifact.
//!
//! The OID `1.3.6.1.4.1.65588.1.1` is allocated under IANA Private
//! Enterprise Number 65588 (the 9P2000.N project).

use crate::error::AuthError;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};

/// Dotted form of the assigned OID.
pub const P9N_POSIX_IDENTITY_OID: &str = "1.3.6.1.4.1.65588.1.1";

/// DER body of the OID (no tag/length prefix). Used for byte comparison
/// against [`x509_parser::extensions::X509Extension::oid`].
const P9N_POSIX_IDENTITY_OID_DER: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x84, 0x80, 0x34, 0x01, 0x01];

/// Lower bound of the SPIFFE-reserved POSIX uid/gid range, inclusive.
pub const SPIFFE_UID_MIN: u32 = 1_048_576; // 2^20
/// Upper bound of the SPIFFE-reserved range, inclusive.
pub const SPIFFE_UID_MAX: u32 = 2_147_483_647;

/// `NGROUPS_MAX` on common Linux distributions.
pub const MAX_SUPPLEMENTARY_GROUPS: usize = 64;

/// Hard cap on the DER-encoded extension value; rejects pathological certs
/// without having to allocate first.
const MAX_EXTENSION_SIZE: usize = 2048;

const CURRENT_VERSION: u32 = 1;

/// Parsed contents of a `p9nPosixIdentity` extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixIdentity {
    pub version: u8,
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub trust_domain: Option<String>,
}

/// Parse the `p9nPosixIdentity` extension from a DER X.509 certificate.
///
/// Returns `Ok(None)` if no such extension is present. Returns `Err` if the
/// extension is malformed, carries out-of-range values, exceeds the size
/// cap, or names a trust domain that disagrees with the cert's SPIFFE URI
/// SAN.
pub fn extract_posix_identity(cert_der: &[u8]) -> Result<Option<PosixIdentity>, AuthError> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| AuthError::InvalidSpiffeId(format!("x509 parse: {e}")))?;
    extract_from_parsed(&cert)
}

fn extract_from_parsed(
    cert: &X509Certificate<'_>,
) -> Result<Option<PosixIdentity>, AuthError> {
    let mut value: Option<&[u8]> = None;
    for ext in cert.extensions() {
        if ext.oid.as_bytes() == P9N_POSIX_IDENTITY_OID_DER {
            if value.is_some() {
                return Err(invalid("duplicate p9nPosixIdentity extension"));
            }
            value = Some(ext.value);
        }
    }
    let value = match value {
        Some(v) => v,
        None => return Ok(None),
    };

    if value.len() > MAX_EXTENSION_SIZE {
        return Err(invalid(&format!(
            "extension exceeds {MAX_EXTENSION_SIZE}-byte cap ({} bytes)",
            value.len()
        )));
    }

    let identity = parse_extension_value(value)?;

    if let Some(td) = identity.trust_domain.as_deref() {
        let san_td = spiffe_trust_domain_from(cert)
            .ok_or_else(|| invalid("trustDomain present but SVID has no spiffe:// SAN"))?;
        if td != san_td {
            return Err(invalid(&format!(
                "trustDomain {td} disagrees with SPIFFE URI SAN {san_td}"
            )));
        }
    }

    Ok(Some(identity))
}

fn spiffe_trust_domain_from(cert: &X509Certificate<'_>) -> Option<String> {
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name {
                    if let Some(rest) = uri.strip_prefix("spiffe://") {
                        return rest.split('/').next().map(|s| s.to_string());
                    }
                }
            }
        }
    }
    None
}

fn parse_extension_value(der: &[u8]) -> Result<PosixIdentity, AuthError> {
    let (tag, contents, rest) = read_tlv(der)?;
    if tag != 0x30 {
        return Err(invalid("expected outer SEQUENCE"));
    }
    if !rest.is_empty() {
        return Err(invalid("trailing bytes after p9nPosixIdentity SEQUENCE"));
    }

    let mut cur = contents;

    // The schema permits version 1..127 but only v1 is currently defined,
    // and §3.1 says future revisions must use a different OID. Reject
    // anything else here so unknown versions never leak into ownership_for.
    let (version, c) = read_uint(cur, "version", CURRENT_VERSION, CURRENT_VERSION)?;
    cur = c;
    let (uid, c) = read_uint(cur, "uid", SPIFFE_UID_MIN, SPIFFE_UID_MAX)?;
    cur = c;
    let (gid, c) = read_uint(cur, "gid", SPIFFE_UID_MIN, SPIFFE_UID_MAX)?;
    cur = c;

    let mut groups: Vec<u32> = Vec::new();
    let mut groups_seen = false;
    let mut trust_domain: Option<String> = None;

    while !cur.is_empty() {
        let (tag, contents, after) = read_tlv(cur)?;
        match tag {
            0x30 => {
                if groups_seen {
                    return Err(invalid("duplicate groups SEQUENCE"));
                }
                groups_seen = true;
                let mut gcur = contents;
                while !gcur.is_empty() {
                    if groups.len() >= MAX_SUPPLEMENTARY_GROUPS {
                        return Err(invalid(&format!(
                            "more than {MAX_SUPPLEMENTARY_GROUPS} supplementary groups"
                        )));
                    }
                    let (g, gnext) = read_uint(gcur, "group", SPIFFE_UID_MIN, SPIFFE_UID_MAX)?;
                    groups.push(g);
                    gcur = gnext;
                }
            }
            0x0C => {
                if trust_domain.is_some() {
                    return Err(invalid("duplicate trustDomain"));
                }
                let s = std::str::from_utf8(contents)
                    .map_err(|_| invalid("trustDomain is not valid UTF-8"))?;
                trust_domain = Some(s.to_string());
            }
            other => {
                return Err(invalid(&format!("unexpected tag 0x{other:02X}")));
            }
        }
        cur = after;
    }

    Ok(PosixIdentity {
        version: version as u8,
        uid,
        gid,
        groups,
        trust_domain,
    })
}

fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), AuthError> {
    if input.is_empty() {
        return Err(invalid("unexpected end of DER"));
    }
    let tag = input[0];
    if tag & 0x1F == 0x1F {
        return Err(invalid("multi-byte tags not supported"));
    }
    if input.len() < 2 {
        return Err(invalid("truncated length"));
    }
    let first = input[1] as usize;
    let (length, header_len) = if first & 0x80 == 0 {
        (first, 2)
    } else {
        let n = first & 0x7F;
        if n == 0 || n > 4 {
            return Err(invalid("invalid length encoding"));
        }
        if input.len() < 2 + n {
            return Err(invalid("truncated length"));
        }
        let mut v = 0usize;
        for &b in &input[2..2 + n] {
            v = (v << 8) | b as usize;
        }
        (v, 2 + n)
    };
    if input.len() < header_len + length {
        return Err(invalid("truncated content"));
    }
    let contents = &input[header_len..header_len + length];
    let rest = &input[header_len + length..];
    Ok((tag, contents, rest))
}

fn read_uint<'a>(
    input: &'a [u8],
    field: &str,
    min: u32,
    max: u32,
) -> Result<(u32, &'a [u8]), AuthError> {
    let (tag, contents, rest) = read_tlv(input)?;
    if tag != 0x02 {
        return Err(invalid(&format!("{field}: expected INTEGER")));
    }
    if contents.is_empty() {
        return Err(invalid(&format!("{field}: empty INTEGER")));
    }
    if contents[0] & 0x80 != 0 {
        return Err(invalid(&format!("{field}: negative INTEGER not allowed")));
    }
    if contents.len() > 5 || (contents.len() == 5 && contents[0] != 0) {
        return Err(invalid(&format!("{field}: INTEGER does not fit in u32")));
    }
    let mut v = 0u32;
    for &b in contents {
        v = (v << 8) | b as u32;
    }
    if v < min || v > max {
        return Err(invalid(&format!(
            "{field}: value {v} out of range [{min}, {max}]"
        )));
    }
    Ok((v, rest))
}

fn invalid(msg: &str) -> AuthError {
    AuthError::InvalidSpiffeId(format!("p9nPosixIdentity: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der_uint(v: u32) -> Vec<u8> {
        let bytes = v.to_be_bytes();
        let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        let mut content: Vec<u8> = bytes[first_nonzero..].to_vec();
        if content[0] & 0x80 != 0 {
            content.insert(0, 0);
        }
        let mut out = vec![0x02, content.len() as u8];
        out.extend_from_slice(&content);
        out
    }

    fn encode_length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len <= 0xFF {
            vec![0x81, len as u8]
        } else if len <= 0xFFFF {
            vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
        } else {
            panic!("test helper: length {len} not supported");
        }
    }

    fn der_seq(inner: &[u8]) -> Vec<u8> {
        let mut out = vec![0x30];
        out.extend(encode_length(inner.len()));
        out.extend_from_slice(inner);
        out
    }

    fn der_utf8(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut out = vec![0x0C, bytes.len() as u8];
        out.extend_from_slice(bytes);
        out
    }

    fn build_value(
        version: u32,
        uid: u32,
        gid: u32,
        groups: Option<&[u32]>,
        trust_domain: Option<&str>,
    ) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend(der_uint(version));
        inner.extend(der_uint(uid));
        inner.extend(der_uint(gid));
        if let Some(gs) = groups {
            let mut g_inner = Vec::new();
            for g in gs {
                g_inner.extend(der_uint(*g));
            }
            inner.extend(der_seq(&g_inner));
        }
        if let Some(td) = trust_domain {
            inner.extend(der_utf8(td));
        }
        der_seq(&inner)
    }

    #[test]
    fn parses_full_extension() {
        let value = build_value(1, 1_048_577, 1_048_577, Some(&[1_048_577, 2_097_152]), Some("example.com"));
        let parsed = parse_extension_value(&value).unwrap();
        assert_eq!(parsed, PosixIdentity {
            version: 1,
            uid: 1_048_577,
            gid: 1_048_577,
            groups: vec![1_048_577, 2_097_152],
            trust_domain: Some("example.com".to_string()),
        });
    }

    #[test]
    fn parses_minimal_extension() {
        let value = build_value(1, 1_048_576, 1_048_576, None, None);
        let parsed = parse_extension_value(&value).unwrap();
        assert_eq!(parsed.uid, 1_048_576);
        assert_eq!(parsed.gid, 1_048_576);
        assert!(parsed.groups.is_empty());
        assert!(parsed.trust_domain.is_none());
    }

    #[test]
    fn rejects_uid_below_range() {
        let value = build_value(1, 1000, 1_048_577, None, None);
        let err = parse_extension_value(&value).unwrap_err();
        assert!(matches!(err, AuthError::InvalidSpiffeId(_)));
    }

    #[test]
    fn rejects_uid_above_range() {
        // 2^31 = 2147483648 — one above SPIFFE_UID_MAX
        let value = build_value(1, 2_147_483_648, 1_048_577, None, None);
        let err = parse_extension_value(&value).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("out of range"), "expected range error, got {msg}");
    }

    #[test]
    fn rejects_gid_above_range() {
        let value = build_value(1, 1_048_577, 2_147_483_648, None, None);
        assert!(parse_extension_value(&value).is_err());
    }

    #[test]
    fn rejects_unknown_version() {
        let value = build_value(2, 1_048_577, 1_048_577, None, None);
        let err = parse_extension_value(&value).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("version"), "expected version error, got {msg}");
    }

    #[test]
    fn rejects_supplementary_group_out_of_range() {
        let value = build_value(1, 1_048_577, 1_048_577, Some(&[100]), None);
        assert!(parse_extension_value(&value).is_err());
    }

    #[test]
    fn rejects_too_many_groups() {
        let many: Vec<u32> = (0..(MAX_SUPPLEMENTARY_GROUPS as u32 + 1))
            .map(|i| 1_048_576 + i)
            .collect();
        let value = build_value(1, 1_048_577, 1_048_577, Some(&many), None);
        let err = parse_extension_value(&value).unwrap_err();
        assert!(format!("{err}").contains("supplementary groups"));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut value = build_value(1, 1_048_577, 1_048_577, None, None);
        value.push(0xAA);
        assert!(parse_extension_value(&value).is_err());
    }

    #[test]
    fn rejects_truncated_sequence() {
        let mut value = build_value(1, 1_048_577, 1_048_577, None, None);
        value.truncate(value.len() - 1);
        assert!(parse_extension_value(&value).is_err());
    }

    #[test]
    fn rejects_negative_integer() {
        // Hand-rolled SEQUENCE { INTEGER -1, ... } — first content byte 0xFF
        // signals negative under DER's two's complement INTEGER.
        let inner: Vec<u8> = vec![
            0x02, 0x01, 0xFF,                   // version = -1
            0x02, 0x03, 0x10, 0x00, 0x01,       // uid
            0x02, 0x03, 0x10, 0x00, 0x01,       // gid
        ];
        let value = der_seq(&inner);
        let err = parse_extension_value(&value).unwrap_err();
        assert!(format!("{err}").contains("negative"));
    }

    #[test]
    fn accepts_padded_uint_form_from_doc() {
        // Doc shows uid 1048577 encoded as `02 04 00 10 00 01` (BER allows the
        // unnecessary leading zero). Verify the parser accepts that form.
        let inner: Vec<u8> = vec![
            0x02, 0x01, 0x01,                            // version = 1
            0x02, 0x04, 0x00, 0x10, 0x00, 0x01,          // uid = 1048577 (4-byte)
            0x02, 0x04, 0x00, 0x10, 0x00, 0x01,          // gid = 1048577 (4-byte)
        ];
        let value = der_seq(&inner);
        let parsed = parse_extension_value(&value).unwrap();
        assert_eq!(parsed.uid, 1_048_577);
        assert_eq!(parsed.gid, 1_048_577);
    }

    #[test]
    fn oid_der_matches_dotted_form() {
        // Sanity: 1.3.6.1.4.1.65588.1.1 → 2B 06 01 04 01 84 80 34 01 01
        // (arc 65588 = 4*16384 + 0*128 + 52 → 0x84 0x80 0x34 with continuation
        // bits set on all but the last subidentifier byte.)
        assert_eq!(
            P9N_POSIX_IDENTITY_OID_DER,
            &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x84, 0x80, 0x34, 0x01, 0x01]
        );
    }
}
