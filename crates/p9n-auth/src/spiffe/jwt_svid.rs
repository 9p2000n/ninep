//! JWT-SVID verification using jsonwebtoken.

use crate::error::AuthError;
use serde::{Deserialize, Serialize};

/// JWT `aud` claim can be a single string or an array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl Default for OneOrMany {
    fn default() -> Self {
        Self::Many(vec![])
    }
}

impl OneOrMany {
    pub fn contains(&self, val: &str) -> bool {
        match self {
            Self::One(s) => s == val,
            Self::Many(v) => v.iter().any(|s| s == val),
        }
    }
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::One(s) => vec![s.clone()],
            Self::Many(v) => v.clone(),
        }
    }
}

/// Standard + custom claims in a SPIFFE JWT-SVID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtSvidClaims {
    /// SPIFFE ID (e.g., "spiffe://example.com/workload")
    pub sub: String,
    /// Audience list
    #[serde(default)]
    pub aud: OneOrMany,
    /// Expiry (Unix timestamp)
    pub exp: u64,
    /// Issued at
    #[serde(default)]
    pub iat: u64,
    /// Issuer (typically the trust domain URI)
    #[serde(default)]
    pub iss: String,
    // ── 9P2000.N custom claims ──
    /// Rights bitmask (read/write/walk/create/remove/setattr)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p9n_rights: Option<u64>,
    /// Walk depth limit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p9n_depth: Option<u16>,
}

/// JWT-SVID verification result.
#[derive(Debug, Clone)]
pub struct JwtVerifyResult {
    pub spiffe_id: String,
    pub audience: Vec<String>,
    pub expiry: u64,
    pub p9n_rights: Option<u64>,
    pub p9n_depth: Option<u16>,
}

/// A JWK Set for JWT-SVID verification (from Rfetchbundle format=1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// Minimal JWK representation (RSA or EC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: String,
    #[serde(default)]
    pub alg: Option<String>,
    // RSA
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    // EC
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

impl JwkSet {
    /// Parse from JSON bytes (e.g., from Rfetchbundle bundle data).
    pub fn from_json(data: &[u8]) -> Result<Self, AuthError> {
        serde_json::from_slice(data).map_err(|e| AuthError::Jwt(format!("JWK parse: {e}")))
    }

    /// Find a JWK by key ID. If kid is empty, returns the first key.
    pub fn find_key(&self, kid: &str) -> Option<&Jwk> {
        if kid.is_empty() {
            self.keys.first()
        } else {
            self.keys.iter().find(|k| k.kid == kid)
        }
    }
}

fn decoding_key_from_jwk(jwk: &Jwk) -> Result<jsonwebtoken::DecodingKey, AuthError> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk
                .n
                .as_ref()
                .ok_or_else(|| AuthError::Jwt("RSA JWK missing 'n'".into()))?;
            let e = jwk
                .e
                .as_ref()
                .ok_or_else(|| AuthError::Jwt("RSA JWK missing 'e'".into()))?;
            jsonwebtoken::DecodingKey::from_rsa_components(n, e)
                .map_err(|e| AuthError::Jwt(format!("RSA key: {e}")))
        }
        "EC" => {
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| AuthError::Jwt("EC JWK missing 'x'".into()))?;
            let y = jwk
                .y
                .as_ref()
                .ok_or_else(|| AuthError::Jwt("EC JWK missing 'y'".into()))?;
            jsonwebtoken::DecodingKey::from_ec_components(x, y)
                .map_err(|e| AuthError::Jwt(format!("EC key: {e}")))
        }
        other => Err(AuthError::Jwt(format!("unsupported key type: {other}"))),
    }
}

fn algorithm_from_jwk(jwk: &Jwk) -> Result<jsonwebtoken::Algorithm, AuthError> {
    if let Some(alg) = &jwk.alg {
        match alg.as_str() {
            "RS256" => Ok(jsonwebtoken::Algorithm::RS256),
            "RS384" => Ok(jsonwebtoken::Algorithm::RS384),
            "RS512" => Ok(jsonwebtoken::Algorithm::RS512),
            "ES256" => Ok(jsonwebtoken::Algorithm::ES256),
            "ES384" => Ok(jsonwebtoken::Algorithm::ES384),
            other => Err(AuthError::Jwt(format!("unsupported algorithm: {other}"))),
        }
    } else {
        match jwk.kty.as_str() {
            "RSA" => Ok(jsonwebtoken::Algorithm::RS256),
            "EC" => Ok(jsonwebtoken::Algorithm::ES256),
            _ => Err(AuthError::Jwt("cannot infer algorithm".into())),
        }
    }
}

/// Verify a JWT-SVID token against a JWK Set.
///
/// Validates signature, expiry, and audience. Returns the verified claims.
pub fn verify_jwt_svid(
    token: &str,
    jwk_set: &JwkSet,
    expected_audience: &str,
) -> Result<JwtVerifyResult, AuthError> {
    let header = jsonwebtoken::decode_header(token)
        .map_err(|e| AuthError::Jwt(format!("header: {e}")))?;

    let kid = header.kid.as_deref().unwrap_or("");
    let jwk = jwk_set
        .find_key(kid)
        .ok_or_else(|| AuthError::Jwt(format!("no JWK for kid={kid}")))?;

    let key = decoding_key_from_jwk(jwk)?;
    let alg = algorithm_from_jwk(jwk)?;

    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.set_audience(&[expected_audience]);
    validation.set_required_spec_claims(&["sub", "exp", "aud"]);

    let data = jsonwebtoken::decode::<JwtSvidClaims>(token, &key, &validation)
        .map_err(|e| AuthError::Jwt(format!("verification: {e}")))?;

    let claims = data.claims;

    if !claims.sub.starts_with("spiffe://") {
        return Err(AuthError::InvalidSpiffeId(format!(
            "JWT sub is not a SPIFFE ID: {}",
            claims.sub
        )));
    }

    Ok(JwtVerifyResult {
        spiffe_id: claims.sub,
        audience: claims.aud.to_vec(),
        expiry: claims.exp,
        p9n_rights: claims.p9n_rights,
        p9n_depth: claims.p9n_depth,
    })
}

/// Extract the SPIFFE ID from a JWT-SVID without full verification.
///
/// Useful for logging/routing but NOT for authentication decisions.
pub fn extract_spiffe_id_from_jwt(token: &str) -> Result<String, AuthError> {
    let mut validation = jsonwebtoken::Validation::default();
    validation.insecure_disable_signature_validation();
    validation.set_required_spec_claims::<&str>(&[]);
    validation.validate_aud = false;
    validation.validate_exp = false;

    let key = jsonwebtoken::DecodingKey::from_secret(b"unused");
    let data = jsonwebtoken::decode::<JwtSvidClaims>(token, &key, &validation)
        .map_err(|e| AuthError::Jwt(format!("decode: {e}")))?;

    Ok(data.claims.sub)
}

// ── Capability token signing/verification (HMAC-SHA256) ──

/// Encode a capability token using HMAC-SHA256.
///
/// Used by Tcapgrant to sign a token containing granted rights and depth.
pub fn encode_cap_token(
    hmac_key: &[u8; 32],
    subject: &str,
    audience: &str,
    rights: u64,
    depth: u16,
    expiry: u64,
) -> Result<String, AuthError> {
    let claims = JwtSvidClaims {
        sub: subject.to_string(),
        aud: OneOrMany::One(audience.to_string()),
        exp: expiry,
        iat: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        iss: audience.to_string(),
        p9n_rights: Some(rights),
        p9n_depth: Some(depth),
    };

    let key = jsonwebtoken::EncodingKey::from_secret(hmac_key);
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| AuthError::Jwt(format!("encode: {e}")))
}

/// Verify a capability token using HMAC-SHA256.
///
/// Used by Tcapuse to validate a previously granted token.
/// Returns the verified claims including p9n_rights and p9n_depth.
pub fn verify_cap_token(
    hmac_key: &[u8; 32],
    token: &str,
    expected_subject: &str,
    expected_audience: &str,
) -> Result<JwtVerifyResult, AuthError> {
    let key = jsonwebtoken::DecodingKey::from_secret(hmac_key);
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[expected_audience]);
    validation.set_required_spec_claims(&["sub", "exp"]);

    let data = jsonwebtoken::decode::<JwtSvidClaims>(token, &key, &validation)
        .map_err(|e| AuthError::Jwt(format!("cap verify: {e}")))?;

    let claims = data.claims;

    // Verify subject matches (prevent token transfer between identities)
    if claims.sub != expected_subject {
        return Err(AuthError::Jwt(format!(
            "cap token subject mismatch: expected {expected_subject}, got {}",
            claims.sub
        )));
    }

    Ok(JwtVerifyResult {
        spiffe_id: claims.sub,
        audience: claims.aud.to_vec(),
        expiry: claims.exp,
        p9n_rights: claims.p9n_rights,
        p9n_depth: claims.p9n_depth,
    })
}
