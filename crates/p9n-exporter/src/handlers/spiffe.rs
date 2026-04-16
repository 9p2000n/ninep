//! SPIFFE security handlers: Tfetchbundle, Tspiffeverify, TstartlsSpiffe.

use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_auth::spiffe::{chain_verifier, x509_svid};
use p9n_auth::spiffe::jwt_svid;
use p9n_auth::error::AuthError;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use std::sync::Arc;

/// Handle Tfetchbundle: return trust bundle for a trust domain.
pub fn handle_fetchbundle<B: Backend>(
    _session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Fetchbundle {
        trust_domain,
        format,
    } = fc.msg
    else {
        return Err("expected Fetchbundle message".into());
    };
    let tag = fc.tag;

    match format {
        BUNDLE_X509_CAS => {
            // Return PEM-encoded CA certificates
            match ctx.trust_store.to_pem(&trust_domain) {
                Some(pem) => Ok(Fcall {
                    size: 0,
                    msg_type: MsgType::Rfetchbundle,
                    tag,
                    msg: Msg::Rfetchbundle {
                        trust_domain,
                        format,
                        bundle: pem,
                    },
                }),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no trust bundle for domain: {trust_domain}"),
                )
                .into()),
            }
        }
        BUNDLE_JWT_KEYS => {
            // Return JSON-encoded JWK Set
            match ctx.trust_store.to_jwk_json(&trust_domain) {
                Some(json) => Ok(Fcall {
                    size: 0,
                    msg_type: MsgType::Rfetchbundle,
                    tag,
                    msg: Msg::Rfetchbundle {
                        trust_domain,
                        format,
                        bundle: json,
                    },
                }),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no JWT keys for domain: {trust_domain}"),
                )
                .into()),
            }
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown bundle format: {format}"),
        )
        .into()),
    }
}

/// Handle Tspiffeverify: verify a peer's SVID.
pub fn handle_spiffeverify<B: Backend>(
    _session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Spiffeverify {
        svid_type,
        spiffe_id,
        svid,
    } = fc.msg
    else {
        return Err("expected Spiffeverify message".into());
    };
    let tag = fc.tag;

    match svid_type {
        SVID_X509 => {
            // Verify X.509 certificate chain against trust bundle
            match chain_verifier::verify_x509_svid(&svid, &ctx.trust_store) {
                Ok(result) => {
                    // Check if verified SPIFFE ID matches the declared one
                    if result.spiffe_id != spiffe_id {
                        return Ok(Fcall {
                            size: 0,
                            msg_type: MsgType::Rspiffeverify,
                            tag,
                            msg: Msg::Rspiffeverify {
                                status: SPIFFE_MISMATCH,
                                spiffe_id,
                                expiry: 0,
                            },
                        });
                    }

                    Ok(Fcall {
                        size: 0,
                        msg_type: MsgType::Rspiffeverify,
                        tag,
                        msg: Msg::Rspiffeverify {
                            status: SPIFFE_OK,
                            spiffe_id: result.spiffe_id,
                            expiry: result.not_after,
                        },
                    })
                }
                Err(AuthError::CertificateExpired) => Ok(Fcall {
                    size: 0,
                    msg_type: MsgType::Rspiffeverify,
                    tag,
                    msg: Msg::Rspiffeverify {
                        status: SPIFFE_EXPIRED,
                        spiffe_id,
                        expiry: 0,
                    },
                }),
                Err(AuthError::InvalidSpiffeId(_)) => Ok(Fcall {
                    size: 0,
                    msg_type: MsgType::Rspiffeverify,
                    tag,
                    msg: Msg::Rspiffeverify {
                        status: SPIFFE_MISMATCH,
                        spiffe_id,
                        expiry: 0,
                    },
                }),
                Err(_) => Ok(Fcall {
                    size: 0,
                    msg_type: MsgType::Rspiffeverify,
                    tag,
                    msg: Msg::Rspiffeverify {
                        status: SPIFFE_UNTRUSTED,
                        spiffe_id,
                        expiry: 0,
                    },
                }),
            }
        }
        SVID_JWT => {
            // Verify JWT-SVID against trust bundle's JWK Set
            let token = match std::str::from_utf8(&svid) {
                Ok(t) => t,
                Err(_) => {
                    return Ok(Fcall {
                        size: 0,
                        msg_type: MsgType::Rspiffeverify,
                        tag,
                        msg: Msg::Rspiffeverify {
                            status: SPIFFE_UNTRUSTED,
                            spiffe_id,
                            expiry: 0,
                        },
                    });
                }
            };

            // Extract trust domain from JWT claims (without signature verification)
            let claimed_id = match jwt_svid::extract_spiffe_id_from_jwt_unverified(token) {
                Ok(id) => id,
                Err(_) => {
                    return Ok(Fcall {
                        size: 0,
                        msg_type: MsgType::Rspiffeverify,
                        tag,
                        msg: Msg::Rspiffeverify {
                            status: SPIFFE_UNTRUSTED,
                            spiffe_id,
                            expiry: 0,
                        },
                    });
                }
            };

            let domain = x509_svid::extract_trust_domain(&claimed_id).unwrap_or_default();

            // Look up JWK Set for this trust domain
            let jwk_set = match ctx.trust_store.get_jwt_keys(&domain) {
                Some(keys) => keys,
                None => {
                    return Ok(Fcall {
                        size: 0,
                        msg_type: MsgType::Rspiffeverify,
                        tag,
                        msg: Msg::Rspiffeverify {
                            status: SPIFFE_UNTRUSTED,
                            spiffe_id,
                            expiry: 0,
                        },
                    });
                }
            };

            // Verify JWT signature, expiry, and audience
            match jwt_svid::verify_jwt_svid(token, &jwk_set, &ctx.server_spiffe_id) {
                Ok(result) => {
                    if result.spiffe_id != spiffe_id {
                        return Ok(Fcall {
                            size: 0,
                            msg_type: MsgType::Rspiffeverify,
                            tag,
                            msg: Msg::Rspiffeverify {
                                status: SPIFFE_MISMATCH,
                                spiffe_id,
                                expiry: 0,
                            },
                        });
                    }
                    Ok(Fcall {
                        size: 0,
                        msg_type: MsgType::Rspiffeverify,
                        tag,
                        msg: Msg::Rspiffeverify {
                            status: SPIFFE_OK,
                            spiffe_id: result.spiffe_id,
                            expiry: result.expiry,
                        },
                    })
                }
                Err(ref e) if e.is_expired() => Ok(Fcall {
                    size: 0,
                    msg_type: MsgType::Rspiffeverify,
                    tag,
                    msg: Msg::Rspiffeverify {
                        status: SPIFFE_EXPIRED,
                        spiffe_id,
                        expiry: 0,
                    },
                }),
                Err(_) => Ok(Fcall {
                    size: 0,
                    msg_type: MsgType::Rspiffeverify,
                    tag,
                    msg: Msg::Rspiffeverify {
                        status: SPIFFE_UNTRUSTED,
                        spiffe_id,
                        expiry: 0,
                    },
                }),
            }
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown SVID type: {svid_type}"),
        )
        .into()),
    }
}

/// Handle TstartlsSpiffe: SPIFFE identity exchange confirmation.
///
/// In QUIC mode, mTLS is already complete. This message confirms the declared
/// SPIFFE ID matches the TLS certificate and establishes mutual identity awareness.
pub fn handle_startls_spiffe<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::StartlsSpiffe {
        spiffe_id,
        trust_domain,
    } = fc.msg
    else {
        return Err("expected StartlsSpiffe message".into());
    };
    let tag = fc.tag;

    // Verify the declared SPIFFE ID matches what we extracted from TLS
    match &session.spiffe_id {
        Some(tls_id) => {
            if *tls_id != spiffe_id {
                tracing::warn!(
                    "SPIFFE ID mismatch: TLS={tls_id}, declared={spiffe_id}"
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("SPIFFE ID mismatch: TLS={tls_id}, declared={spiffe_id}"),
                )
                .into());
            }
        }
        None => {
            tracing::warn!("no SPIFFE ID in TLS certificate");
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "no SPIFFE ID in peer TLS certificate",
            )
            .into());
        }
    }

    session.set_spiffe_verified(true);

    tracing::info!(
        "SPIFFE identity verified: {spiffe_id} (domain: {trust_domain})"
    );

    // Respond with our own identity
    Ok(Fcall {
        size: 0,
        msg_type: MsgType::RstartlsSpiffe,
        tag,
        msg: Msg::StartlsSpiffe {
            spiffe_id: ctx.server_spiffe_id.clone(),
            trust_domain: ctx.server_trust_domain.clone(),
        },
    })
}

