//! The low-level representation of a JWT: claims, headers, assembly and parsing.
//!
//! The key types:
//! - [`TokenClaims`] — the payload (`iss`, `sub`, `aud`, `exp`, ...);
//! - [`TokenHeaders`] — the JOSE header (`alg`, `kid`, `typ`, an optional `jku`);
//! - [`JsonWebToken`] — a wrapper over the header, the claims and the key;
//!   parameterised by the key type: `JsonWebToken<Private>` can sign
//!   ([`JsonWebToken::to_string`]) and `JsonWebToken<Public>` can parse and
//!   verify ([`JsonWebToken::from_string`]);
//! - [`JtiStore`] — the trait of the token identifier store (implemented in
//!   `redis.rs`).
//!
//! The segments are encoded as base64url without padding, as JWS requires.

use crate::key::{KeyManager, SUPPORTED_ALGORITHMS};
use actix_web::web::Data;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::env;
use thiserror::Error;
use tracing::{debug, error, warn};
use uuid::Uuid;

/// Reads a `u64` from an environment variable, falling back to `default` when it
/// is missing or unparsable.
fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

#[derive(Error, Debug)]
pub enum JtiError {
    #[error("Bad connection")]
    BadConnection,
    #[error("Wrong operation")]
    WrongOperation,
}

/// The token identifier (`jti`) store.
///
/// It abstracts the backend (Redis in this project) away from the domain logic.
/// The presence of a `jti` in the store means the token is "active": on issue
/// the `jti` is written with a TTL, on revocation it is deleted, and on
/// verification its existence is checked.
///
/// The trait covers **everything** the HTTP layer needs from the store, the
/// readiness probe included ([`JtiStore::ping`]): otherwise `/readyz` would talk
/// to a concrete backend directly and the seam would leak in exactly the place
/// where it is easiest to miss.
///
/// `where Self: Sized` is not needed here: an `async fn` in a trait already
/// makes the trait non-object-safe, and the store is always taken by static type
/// (`web::Data<S>`), never through `dyn`.
pub trait JtiStore {
    /// Checks that the store is available (the `GET /readyz` readiness probe).
    ///
    /// An error means "we cannot serve requests": without the store the `jti`
    /// cannot be checked, so a revoked token would become valid.
    async fn ping(&self) -> Result<(), JtiError>;
    /// Stores a `jti` with a lifetime of `ttl` (in seconds).
    async fn store_jti(&self, jti: &str, ttl: u64) -> Result<(), JtiError>;
    /// Returns `true` when the `jti` is present (the token is neither revoked nor expired).
    async fn check_jti(&self, jti: &str) -> Result<bool, JtiError>;
    /// Deletes the `jti` (revoking a token). Idempotent.
    async fn delete_jti(&self, jti: &str) -> Result<(), JtiError>;
    /// Binds a `jti` to a group; `expires_at` is the Unix time the token expires.
    ///
    /// The group exists so that tokens can be killed in batches. The group key
    /// is formed by the caller (see [`subject_group`]) — the store itself knows
    /// nothing about its meaning.
    async fn add_to_group(&self, group: &str, jti: &str, expires_at: i64) -> Result<(), JtiError>;
    /// Revokes every token of a group and the group itself. Returns the number revoked.
    ///
    /// Idempotent: for a group that does not exist it returns `0`.
    async fn revoke_group(&self, group: &str) -> Result<u64, JtiError>;
    /// Stores a refresh token record with a lifetime of `ttl` (in seconds).
    async fn store_refresh(
        &self,
        id: &str,
        record: &RefreshRecord,
        ttl: u64,
    ) -> Result<(), JtiError>;
    /// Reads a refresh token record. `None` means there is no record (it expired or was revoked).
    async fn get_refresh(&self, id: &str) -> Result<Option<RefreshRecord>, JtiError>;
    /// Marks a refresh token as used.
    ///
    /// Returns `true` when the mark was set by this very call and `false` when
    /// the token had already been used. The operation must be **atomic**: both
    /// the reuse detector and the protection against a race between two
    /// simultaneous exchanges of one token rest on it.
    async fn mark_refresh_used(&self, id: &str) -> Result<bool, JtiError>;
    /// Reserves a one-time TOTP code for `ttl` (in seconds).
    ///
    /// Returns `true` when the code was reserved by this very call and `false`
    /// when it had been presented already — that is, this is a replay.
    ///
    /// Like [`JtiStore::mark_refresh_used`], the operation must be **atomic**
    /// (`SET NX`): replay protection rests on it.
    async fn claim_totp_code(&self, hash: &str, ttl: u64) -> Result<bool, JtiError>;
}

/// The store key of a reserved TOTP code.
pub fn totp_code_key(hash: &str) -> String {
    format!("totp:used:{hash}")
}

/// The key of the group of tokens issued for a subject.
///
/// Extracted into a function for a reason: the same group mechanism is reused by
/// the revocation of a refresh token family ([`family_group`]), so the store
/// operates on an abstract key while the caller supplies the meaning of the
/// group. The prefix separates groups from flat `jti` keys.
pub fn subject_group(subject: &str) -> String {
    format!("group:sub:{subject}")
}

/// The key of the group of one refresh token family.
///
/// The group holds both the `jti` values of the issued access tokens and the
/// keys of the refresh records themselves — which is why a single `revoke_group`
/// kills the whole chain.
pub fn family_group(family: &str) -> String {
    format!("group:family:{family}")
}

/// The store key of a refresh token record.
pub fn refresh_key(id: &str) -> String {
    format!("refresh:{id}")
}

/// A refresh token record: everything needed to issue a new access token from it.
///
/// The refresh token itself is an opaque random string rather than a JWT: nobody
/// parses it or checks its signature, it is merely a key to this record. That
/// also means a leaked token is useless without the store and revocation is
/// instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRecord {
    /// The subject the token was issued to.
    pub subject: String,
    /// The audience the access tokens of the chain are issued with.
    pub audience: Vec<String>,
    /// The family identifier — shared by the whole rotation chain.
    pub family: String,
}

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("Unprocessable entity")]
    UnprocessableEntity,
    #[error("Store error")]
    StoreError,
    #[error("Bad signature")]
    BadSignature,
    #[error("Not valid")]
    NotValid,
    #[error("Broken")]
    Broken,
    #[error("Key error")]
    KeyError,
    #[error("Serialization failed")]
    Serialization,
}

/// The token payload (the registered claims of RFC 7519).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Issuer — who issued the token (from the `Host` header).
    pub iss: String,
    /// Subject — whom the token was issued about.
    pub sub: String,
    /// Audience — the list of recipients.
    pub aud: Vec<String>,
    /// Expiration — the moment it expires (Unix time, seconds).
    pub exp: usize,
    /// Issued At — the moment of issue.
    pub iat: usize,
    /// Not Before — the moment from which the token is valid.
    pub nbf: usize,
    /// JWT ID — the unique identifier (a UUID v4), the key in [`JtiStore`].
    pub jti: String,
    /// Arbitrary claims supplied by the client (roles, scope, tenant and so on).
    ///
    /// `flatten` because in a JWT they must sit **alongside** the registered
    /// ones rather than in a nested object: the consumer of the token looks for
    /// `role`, not `extra.role`.
    ///
    /// Reserved names cannot get in here — [`validate_custom_claims`] rejects
    /// them, or a client could substitute `exp` or `iss`.
    #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,
}

/// The claim names the service forms itself. A client may not override them.
///
/// Substituting `exp` would allow bypassing the `TOKEN_TTL_MIN/MAX_SECONDS`
/// bounds, and substituting `iss` or `sub` would allow issuing a token under
/// someone else's name.
pub const RESERVED_CLAIMS: &[&str] = &["iss", "sub", "aud", "exp", "iat", "nbf", "jti"];

/// Validates the set of custom claims before a token is issued.
///
/// # Errors
/// [`JwtError::UnprocessableEntity`] when the claims:
/// - override a reserved name (see [`RESERVED_CLAIMS`]);
/// - exceed the limit on the number of keys (`TOKEN_CLAIMS_MAX_COUNT`);
/// - exceed the size limit in bytes (`TOKEN_CLAIMS_MAX_BYTES`).
///
/// The limits are not there out of spite: a token travels in HTTP headers, and a
/// bloated payload breaks proxies with their header size limits.
///
/// The contents of the claims are **never logged** — they may contain personal
/// data; only the name of the conflicting key or the fact that a limit was
/// exceeded reaches the log.
pub fn validate_custom_claims(claims: &Map<String, Value>) -> Result<(), JwtError> {
    if claims.is_empty() {
        return Ok(());
    }

    let max_count = env_u64("TOKEN_CLAIMS_MAX_COUNT", 32) as usize;
    if claims.len() > max_count {
        debug!("Too many custom claims: {} > {}", claims.len(), max_count);
        return Err(JwtError::UnprocessableEntity);
    }

    for name in claims.keys() {
        if RESERVED_CLAIMS.contains(&name.as_str()) {
            // Logging the key name is safe, the value is not.
            debug!("Attempt to override a reserved claim: {}", name);
            return Err(JwtError::UnprocessableEntity);
        }
    }

    let max_bytes = env_u64("TOKEN_CLAIMS_MAX_BYTES", 4096) as usize;
    let size = serde_json::to_vec(claims)
        .map_err(|_| JwtError::Serialization)?
        .len();

    if size > max_bytes {
        debug!(
            "Custom claims are too large: {} > {} bytes",
            size, max_bytes
        );
        return Err(JwtError::UnprocessableEntity);
    }

    Ok(())
}

impl TokenClaims {
    /// Forms a new set of claims and registers the `jti` in the store.
    ///
    /// The lifetime is decided by the `ttl` argument (seconds): when it is set,
    /// it is used (after a bounds check), otherwise `TOKEN_EXPIRATION_SECONDS`
    /// (`3600` by default). `exp` and the TTL of the store record are computed
    /// from it and always match. The `jti` is generated as a UUID v4.
    ///
    /// The bounds of a custom `ttl` come from `TOKEN_TTL_MIN_SECONDS` (`1` by
    /// default) and `TOKEN_TTL_MAX_SECONDS` (`86400` by default).
    ///
    /// # Errors
    /// - [`JwtError::UnprocessableEntity`] — an empty `audience`, an invalid
    ///   `TOKEN_EXPIRATION_SECONDS` value or a custom `ttl` outside
    ///   `[TOKEN_TTL_MIN_SECONDS, TOKEN_TTL_MAX_SECONDS]`;
    /// - [`JwtError::StoreError`] — the `jti` could not be written to the store,
    ///   or the resulting claims failed their own [`TokenClaims::is_verify`]
    ///   check.
    ///
    /// # Note
    /// Issuing is fail-fast: when the `jti` could not be stored, the token is
    /// **not** handed out ([`JwtError::StoreError`]) — that is what guarantees
    /// consistency with the later verification (`is_verify` requires the `jti`
    /// to be present).
    pub async fn create_new<T: JtiStore>(
        issuer: &str,
        subject: &str,
        audience: &[String],
        ttl: Option<u64>,
        extra: Map<String, Value>,
        store: Data<T>,
    ) -> Result<Self, JwtError> {
        // Checked before any work: there is no point going to the store for a
        // `jti` if the claims will be rejected anyway.
        validate_custom_claims(&extra)?;

        let expiration_seconds = match ttl {
            Some(requested) => {
                let min = env_u64("TOKEN_TTL_MIN_SECONDS", 1);
                let max = env_u64("TOKEN_TTL_MAX_SECONDS", 86400);

                if requested < min || requested > max {
                    // The client's fault (we return 422) — no reason for an ERROR in production.
                    debug!(
                        "Requested ttl {} out of bounds [{}, {}]",
                        requested, min, max
                    );
                    return Err(JwtError::UnprocessableEntity);
                }

                requested
            }
            None => match env::var("TOKEN_EXPIRATION_SECONDS")
                .unwrap_or("3600".into())
                .parse::<u64>()
            {
                Ok(v) => v,
                Err(e) => {
                    // Invalid service configuration — degradation, not a
                    // dependency failure.
                    warn!("TOKEN_EXPIRATION_SECONDS: {}", e);
                    return Err(JwtError::UnprocessableEntity);
                }
            },
        };

        let Some(first_audience) = audience.first() else {
            return Err(JwtError::UnprocessableEntity);
        };

        let now = Utc::now();
        let exp = now + Duration::seconds(expiration_seconds as i64);

        let jti = Uuid::new_v4().to_string();

        // Fail-fast: when the `jti` was not written to the store the token must
        // not be issued — its later verification would fail (a missing jti means
        // revoked). We propagate the error and the handler returns 500.
        store
            .store_jti(&jti, expiration_seconds)
            .await
            .map_err(|e| {
                error!("JTI Store: {}", e);
                JwtError::StoreError
            })?;

        // The index for bulk revocation is fail-fast too, for the same reason as
        // the `jti` itself: a token that did not reach the index would survive a
        // revocation of all of the subject's tokens. Issuing such a token
        // silently is more dangerous than not issuing one at all.
        store
            .add_to_group(&subject_group(subject), &jti, exp.timestamp())
            .await
            .map_err(|e| {
                error!("JTI Store (subject index): {}", e);
                JwtError::StoreError
            })?;

        let jwt = Self {
            iss: issuer.to_string(),
            sub: subject.to_string(),
            aud: audience.to_vec(),
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
            nbf: now.timestamp() as usize,
            jti,
            extra,
        };

        if !jwt.is_verify(issuer, first_audience, store).await {
            return Err(JwtError::StoreError);
        }

        Ok(jwt)
    }

    /// Decodes claims from a base64url token segment.
    ///
    /// # Errors
    /// [`JwtError::Broken`] — the segment is not valid base64url, does not
    /// decode as UTF-8 or does not parse as JSON claims.
    pub fn from_base64(str: String) -> Result<Self, JwtError> {
        // A corrupt token comes from the client — that is DEBUG, not ERROR: in
        // production such events are normal and must not raise alerts.
        let bytes = match BASE64_URL_SAFE_NO_PAD.decode(str) {
            Ok(bytes) => bytes,
            Err(e) => {
                debug!("Claims: base64url does not decode: {}", e);
                return Err(JwtError::Broken);
            }
        };

        let json = match String::from_utf8(bytes) {
            Ok(string) => string,
            Err(e) => {
                debug!("Claims: not UTF-8: {}", e);
                return Err(JwtError::Broken);
            }
        };

        match serde_json::from_str(&json) {
            Ok(jwt) => Ok(jwt),
            Err(e) => {
                debug!("Claims: does not parse as JSON: {}", e);
                Err(JwtError::Broken)
            }
        }
    }

    /// Validates the claims against the expected `issuer`/`audience` and the
    /// current time, and checks that the `jti` is in the store.
    ///
    /// Returns `true` only when `iss` matched, `audience` is in `aud`, the time
    /// bounds hold (`nbf <= now`, `iat <= now`, `exp > now`) and the `jti` was
    /// found in the [`JtiStore`].
    ///
    /// A store error is logged and treated as "not valid" (`false` is returned).
    pub async fn is_verify<T: JtiStore>(
        &self,
        issuer: &str,
        audience: &str,
        store: Data<T>,
    ) -> bool {
        let now = Utc::now().timestamp() as usize;

        let claims_valid = self.iss == issuer
            && self.aud.contains(&audience.to_owned())
            && self.nbf <= now
            && self.iat <= now
            && self.exp > now;

        if !claims_valid {
            return false;
        }

        match store.check_jti(&self.jti).await {
            Ok(exists) => exists,
            Err(e) => {
                error!("JTI check: {}", e);
                false
            }
        }
    }

    /// Serialises the claims into a JSON string.
    ///
    /// # Errors
    /// [`JwtError::Serialization`] — serialisation failed (practically
    /// unreachable for this type).
    pub fn to_json(&self) -> Result<String, JwtError> {
        serde_json::to_string(self).map_err(|e| {
            error!("{}", e);
            JwtError::Serialization
        })
    }

    /// Encodes the claims into a base64url segment (JSON → base64url without padding).
    ///
    /// # Errors
    /// [`JwtError::Serialization`] — the claims could not be serialised to JSON.
    pub fn to_base64(&self) -> Result<String, JwtError> {
        Ok(BASE64_URL_SAFE_NO_PAD.encode(self.to_json()?))
    }
}

/// The token header (the JOSE header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenHeaders {
    /// The signature algorithm (`RS256`, `ES256`, `EdDSA`, ...).
    alg: String,
    /// The identifier of the key the token is signed with.
    kid: String,
    /// The token type; always `"JWT"`.
    typ: String,
    /// The JWK Set URL — not serialised when unset (`TOKEN_JKU`).
    #[serde(skip_serializing_if = "Option::is_none")]
    jku: Option<String>,
}

impl TokenHeaders {
    /// Builds the header for a new token.
    ///
    /// `alg` comes from `TOKEN_ALGORITHM` (`RS256` by default), `jku` from the
    /// optional `TOKEN_JKU`, and `kid` is passed in by the key manager.
    pub fn create_new(kid: String) -> Self {
        let jku = env::var("TOKEN_JKU").ok();

        let alg = env::var("TOKEN_ALGORITHM").unwrap_or("RS256".into());

        Self {
            alg,
            kid,
            typ: "JWT".to_string(),
            jku,
        }
    }

    /// Decodes the header from a base64url token segment.
    ///
    /// # Errors
    /// [`JwtError::Broken`] — the segment is not valid base64url, does not
    /// decode as UTF-8 or does not parse as a JSON header.
    pub fn from_base64(str: String) -> Result<Self, JwtError> {
        // As with the claims: a corrupt header is the client's fault, DEBUG level.
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(str).map_err(|e| {
            debug!("Header: base64url does not decode: {}", e);
            JwtError::Broken
        })?;

        let json = String::from_utf8(bytes).map_err(|e| {
            debug!("Header: not UTF-8: {}", e);
            JwtError::Broken
        })?;

        serde_json::from_str(&json).map_err(|e| {
            debug!("Header: does not parse as JSON: {}", e);
            JwtError::Broken
        })
    }

    /// Validates the header while verifying a token.
    ///
    /// It requires `alg` to be one of [`SUPPORTED_ALGORITHMS`], `typ` to be
    /// `"JWT"` and `jku` to match the current configuration (`TOKEN_JKU`).
    pub fn is_verify(&self) -> bool {
        let jku = env::var("TOKEN_JKU").ok();

        SUPPORTED_ALGORITHMS.contains(&self.alg.as_str()) && self.jku == jku && self.typ == "JWT"
    }

    /// Serialises the header into a JSON string.
    ///
    /// # Errors
    /// [`JwtError::Serialization`] — serialisation failed (practically
    /// unreachable for this type).
    pub fn to_json(&self) -> Result<String, JwtError> {
        serde_json::to_string(self).map_err(|e| {
            error!("{}", e);
            JwtError::Serialization
        })
    }

    /// Encodes the header into a base64url segment.
    ///
    /// # Errors
    /// [`JwtError::Serialization`] — the header could not be serialised to JSON.
    pub fn to_base64(&self) -> Result<String, JwtError> {
        Ok(BASE64_URL_SAFE_NO_PAD.encode(self.to_json()?))
    }
}

/// The whole token: the header, the claims and the key.
///
/// The `T` parameter is the OpenSSL key type: [`Private`] for issuing (signing)
/// and [`Public`] for verification. The corresponding operations are implemented
/// in separate `impl` blocks.
#[derive(Debug, Clone)]
pub struct JsonWebToken<T> {
    pub headers: TokenHeaders,
    pub claims: TokenClaims,
    key: PKey<T>,
}

impl JsonWebToken<Private> {
    /// Assembles a token from a ready header, claims and a private key.
    pub fn create_new(headers: TokenHeaders, claims: TokenClaims, key: PKey<Private>) -> Self {
        Self {
            headers,
            claims,
            key,
        }
    }

    /// Serialises and signs the token into the `header.payload.signature` form.
    ///
    /// The header and the claims are encoded as base64url, and the signature is
    /// computed over the `header.payload` string with the private key and
    /// encoded as base64url too.
    ///
    /// The digest is chosen by `alg` **exactly as it is during verification**
    /// ([`JsonWebToken::from_string`]): `RS*`/`ES*` are signed over the
    /// corresponding SHA-2 (256/384/512) and `EdDSA` without an explicit digest
    /// (the algorithm is determined by the key itself). The signing and
    /// verification schemes must match, or an issued token would fail its own
    /// verification.
    ///
    /// # Errors
    /// - [`JwtError::Serialization`] — the header or claims could not be serialised;
    /// - [`JwtError::BadSignature`] — the `Signer` could not be initialised or
    ///   the signature could not be computed.
    pub fn to_string(&self) -> Result<String, JwtError> {
        let headers = self.headers.to_base64()?;
        let claims = self.claims.to_base64()?;

        let mut signer = match self.headers.alg.as_str() {
            "RS256" | "ES256" => Signer::new(MessageDigest::sha256(), &self.key),
            "RS384" | "ES384" => Signer::new(MessageDigest::sha384(), &self.key),
            "RS512" | "ES512" => Signer::new(MessageDigest::sha512(), &self.key),
            _ => Signer::new_without_digest(&self.key),
        }
        .map_err(|e| {
            error!("{}", e);
            JwtError::BadSignature
        })?;
        let signature_bytes = signer
            .sign_oneshot_to_vec(format!("{}.{}", headers, claims).as_bytes())
            .map_err(|e| {
                error!("{}", e);
                JwtError::BadSignature
            })?;

        let signature = URL_SAFE_NO_PAD.encode(signature_bytes);

        Ok(format!("{}.{}.{}", headers, claims, signature))
    }
}

impl JsonWebToken<Public> {
    /// Parses a token string and verifies it fully.
    ///
    /// The steps:
    /// 1. Split the token into the `header.payload.signature` segments.
    /// 2. Fetch the public key by the `kid` from the header through
    ///    [`KeyManager`].
    /// 3. Choose the digest by `alg` and verify the signature over
    ///    `header.payload`.
    /// 4. Validate the header ([`TokenHeaders::is_verify`]) and the claims
    ///    ([`TokenClaims::is_verify`]) against `issuer`/`audience`.
    ///
    /// # Errors
    /// - [`JwtError::Broken`] — an invalid base64url signature;
    /// - [`JwtError::BadSignature`] — the signature did not match or the verifier could not be built;
    /// - [`JwtError::NotValid`] — the header or the claims failed validation.
    pub async fn from_string<T: JtiStore>(
        token: &str,
        issuer: &str,
        audience: &str,
        key_manager: &KeyManager,
        store: Data<T>,
    ) -> Result<Self, JwtError> {
        let mut parts = token.split('.');
        let (headers_segment, claims_segment, signature_segment) =
            match (parts.next(), parts.next(), parts.next()) {
                (Some(h), Some(c), Some(s)) => (h, c, s),
                _ => return Err(JwtError::Broken),
            };

        let headers = TokenHeaders::from_base64(headers_segment.to_string())?;

        let key = match key_manager.get_public_key(headers.kid.as_str()).await {
            Ok(key) => key,
            Err(e) => {
                // The cause (an unavailable JWKS and so on) was already logged by
                // `key.rs` at its own level — here only the outcome of the check,
                // without a duplicate ERROR.
                debug!("Public key by kid not obtained: {}", e);
                return Err(JwtError::BadSignature);
            }
        };

        let signature_decoded = match URL_SAFE_NO_PAD.decode(signature_segment) {
            Ok(decoded) => decoded,
            Err(e) => {
                debug!("Signature: base64url does not decode: {}", e);
                return Err(JwtError::Broken);
            }
        };

        // The verifier borrows `key`, so we keep it in a separate scope —
        // otherwise `key` could not be moved into the returned token.
        let is_success = {
            let mut verifier = match headers.alg.as_str() {
                "RS256" | "ES256" => Verifier::new(MessageDigest::sha256(), &key),
                "RS384" | "ES384" => Verifier::new(MessageDigest::sha384(), &key),
                "RS512" | "ES512" => Verifier::new(MessageDigest::sha512(), &key),
                _ => Verifier::new_without_digest(&key),
            }
            .map_err(|e| {
                error!("{}", e);
                JwtError::BadSignature
            })?;

            verifier
                .verify_oneshot(
                    &signature_decoded,
                    format!("{}.{}", headers_segment, claims_segment).as_bytes(),
                )
                .map_err(|e| {
                    // Most often these are invalid signature bytes from the client.
                    debug!("Signature verification did not run: {}", e);
                    JwtError::BadSignature
                })?
        };

        if !is_success {
            return Err(JwtError::BadSignature);
        }

        let claims = TokenClaims::from_base64(claims_segment.to_string())?;

        if !headers.is_verify() || !claims.is_verify(issuer, audience, store).await {
            return Err(JwtError::NotValid);
        }

        Ok(Self {
            headers,
            claims,
            key,
        })
    }
}

#[cfg(test)]
mod tests {
    //! Tests of JWT assembly, parsing and claim validation.
    //!
    //! The `jti` store is replaced by the in-memory [`MockStore`] — neither
    //! Redis nor the network is needed. A full round trip of token verification
    //! (`from_string`) requires a public key from `jwks-service-app`, so what is
    //! checked here is everything that does not depend on the network: the life
    //! cycle of the claims, the encoding of the segments and the correctness of
    //! the signature [`JsonWebToken::to_string`] produces.

    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::Id;
    use openssl::rsa::Rsa;
    use parking_lot::Mutex;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex as StdMutex;

    /// An environment lock: the claim limits are read from process variables
    /// while the tests run in parallel.
    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// An in-memory implementation of [`JtiStore`] for the tests.
    struct MockStore {
        jtis: Mutex<HashSet<String>>,
        groups: Mutex<HashMap<String, HashSet<String>>>,
        refreshes: Mutex<HashMap<String, (RefreshRecord, bool)>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                jtis: Mutex::new(HashSet::new()),
                groups: Mutex::new(HashMap::new()),
                refreshes: Mutex::new(HashMap::new()),
            }
        }

        fn insert(&self, jti: &str) {
            self.jtis.lock().insert(jti.to_string());
        }
    }

    impl JtiStore for MockStore {
        async fn ping(&self) -> Result<(), JtiError> {
            Ok(())
        }

        async fn store_jti(&self, jti: &str, _ttl: u64) -> Result<(), JtiError> {
            self.jtis.lock().insert(jti.to_string());
            Ok(())
        }

        async fn check_jti(&self, jti: &str) -> Result<bool, JtiError> {
            Ok(self.jtis.lock().contains(jti))
        }

        async fn delete_jti(&self, jti: &str) -> Result<(), JtiError> {
            self.jtis.lock().remove(jti);
            Ok(())
        }

        async fn add_to_group(
            &self,
            group: &str,
            jti: &str,
            _expires_at: i64,
        ) -> Result<(), JtiError> {
            self.groups
                .lock()
                .entry(group.to_string())
                .or_default()
                .insert(jti.to_string());
            Ok(())
        }

        async fn revoke_group(&self, group: &str) -> Result<u64, JtiError> {
            let members = self.groups.lock().remove(group).unwrap_or_default();

            let mut jtis = self.jtis.lock();
            let revoked = members.iter().filter(|jti| jtis.remove(*jti)).count();

            Ok(revoked as u64)
        }

        async fn store_refresh(
            &self,
            id: &str,
            record: &RefreshRecord,
            _ttl: u64,
        ) -> Result<(), JtiError> {
            self.refreshes
                .lock()
                .insert(id.to_string(), (record.clone(), false));
            Ok(())
        }

        async fn get_refresh(&self, id: &str) -> Result<Option<RefreshRecord>, JtiError> {
            Ok(self
                .refreshes
                .lock()
                .get(id)
                .map(|(record, _)| record.clone()))
        }

        async fn mark_refresh_used(&self, id: &str) -> Result<bool, JtiError> {
            let mut refreshes = self.refreshes.lock();

            match refreshes.get_mut(id) {
                Some((_, true)) => Ok(false),
                Some((_, used)) => {
                    *used = true;
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        async fn claim_totp_code(&self, _hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            Ok(true)
        }
    }

    /// A [`JtiStore`] whose `jti` write always fails — it simulates an
    /// unavailable Redis to check fail-fast on issue.
    struct FailingStore;

    impl JtiStore for FailingStore {
        async fn ping(&self) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn store_jti(&self, _jti: &str, _ttl: u64) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn check_jti(&self, _jti: &str) -> Result<bool, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn delete_jti(&self, _jti: &str) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn add_to_group(
            &self,
            _group: &str,
            _jti: &str,
            _expires_at: i64,
        ) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn revoke_group(&self, _group: &str) -> Result<u64, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn store_refresh(
            &self,
            _id: &str,
            _record: &RefreshRecord,
            _ttl: u64,
        ) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn get_refresh(&self, _id: &str) -> Result<Option<RefreshRecord>, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn mark_refresh_used(&self, _id: &str) -> Result<bool, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn claim_totp_code(&self, _hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            Err(JtiError::BadConnection)
        }
    }

    /// A [`JtiStore`] where ONLY the write into the group index fails.
    ///
    /// It exists to check fail-fast separately: the `jti` itself was written
    /// while the index for bulk revocation was not. Such a token would survive a
    /// revocation of all of the subject's tokens, so it must not be issued.
    struct FailingGroupStore {
        jtis: Mutex<HashSet<String>>,
    }

    impl FailingGroupStore {
        fn new() -> Self {
            Self {
                jtis: Mutex::new(HashSet::new()),
            }
        }
    }

    impl JtiStore for FailingGroupStore {
        async fn ping(&self) -> Result<(), JtiError> {
            Ok(())
        }

        async fn store_jti(&self, jti: &str, _ttl: u64) -> Result<(), JtiError> {
            self.jtis.lock().insert(jti.to_string());
            Ok(())
        }

        async fn check_jti(&self, jti: &str) -> Result<bool, JtiError> {
            Ok(self.jtis.lock().contains(jti))
        }

        async fn delete_jti(&self, jti: &str) -> Result<(), JtiError> {
            self.jtis.lock().remove(jti);
            Ok(())
        }

        async fn add_to_group(
            &self,
            _group: &str,
            _jti: &str,
            _expires_at: i64,
        ) -> Result<(), JtiError> {
            Err(JtiError::WrongOperation)
        }

        async fn revoke_group(&self, _group: &str) -> Result<u64, JtiError> {
            Err(JtiError::WrongOperation)
        }

        async fn store_refresh(
            &self,
            _id: &str,
            _record: &RefreshRecord,
            _ttl: u64,
        ) -> Result<(), JtiError> {
            Err(JtiError::WrongOperation)
        }

        async fn get_refresh(&self, _id: &str) -> Result<Option<RefreshRecord>, JtiError> {
            Err(JtiError::WrongOperation)
        }

        async fn mark_refresh_used(&self, _id: &str) -> Result<bool, JtiError> {
            Err(JtiError::WrongOperation)
        }

        async fn claim_totp_code(&self, _hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            Err(JtiError::WrongOperation)
        }
    }

    /// Deliberately valid claims: issued "now", alive for another hour.
    fn sample_claims() -> TokenClaims {
        let now = Utc::now().timestamp() as usize;
        TokenClaims {
            iss: "issuer".to_string(),
            sub: "subject".to_string(),
            aud: vec!["api1".to_string(), "api2".to_string()],
            exp: now + 3600,
            iat: now,
            nbf: now,
            jti: "jti-1".to_string(),
            extra: Default::default(),
        }
    }

    // --- Encoding and decoding the segments ---

    #[test]
    fn claims_base64_roundtrip() {
        let claims = sample_claims();
        let decoded = TokenClaims::from_base64(claims.to_base64().unwrap()).unwrap();

        assert_eq!(decoded.iss, claims.iss);
        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.aud, claims.aud);
        assert_eq!(decoded.exp, claims.exp);
        assert_eq!(decoded.iat, claims.iat);
        assert_eq!(decoded.nbf, claims.nbf);
        assert_eq!(decoded.jti, claims.jti);
    }

    #[test]
    fn claims_from_base64_rejects_invalid_base64() {
        // '!' is not in the base64url alphabet — a decoding error.
        assert!(matches!(
            TokenClaims::from_base64("!!!not-base64!!!".to_string()),
            Err(JwtError::Broken)
        ));
    }

    #[test]
    fn claims_from_base64_rejects_non_json() {
        // Valid base64url, but what follows is not JSON claims.
        let payload = BASE64_URL_SAFE_NO_PAD.encode("just a string");
        assert!(matches!(
            TokenClaims::from_base64(payload),
            Err(JwtError::Broken)
        ));
    }

    #[test]
    fn header_from_base64_rejects_invalid() {
        // Corrupt base64url — this used to panic, now it is Err(Broken).
        assert!(matches!(
            TokenHeaders::from_base64("!!!not-base64!!!".to_string()),
            Err(JwtError::Broken)
        ));
    }

    #[actix_web::test]
    async fn from_string_rejects_malformed_token() {
        // Fewer than three segments — this used to panic on
        // `parts.next().unwrap()`. The token is rejected during parsing, before
        // the keys are touched, so the manager is only needed here for the
        // signature — it never goes to the network.
        let store = Data::new(MockStore::new());
        let keys = KeyManager::new("RS256".to_string());
        let result =
            JsonWebToken::<Public>::from_string("not-a-jwt", "issuer", "api1", &keys, store).await;
        assert!(matches!(result, Err(JwtError::Broken)));
    }

    #[test]
    fn header_roundtrip_and_verify() {
        let header = TokenHeaders::create_new("kid-1".to_string());
        let decoded = TokenHeaders::from_base64(header.to_base64().unwrap()).unwrap();

        assert_eq!(decoded.kid, "kid-1");
        assert_eq!(decoded.typ, "JWT");
        // alg defaults to RS256 (which is in SUPPORTED_ALGORITHMS) and jku is unset.
        assert!(decoded.is_verify());
    }

    // --- Claim validation (iss/aud/nbf/iat/exp, jti) ---

    #[actix_web::test]
    async fn is_verify_accepts_valid_claims() {
        let store = Data::new(MockStore::new());
        store.insert("jti-1");

        let claims = sample_claims();
        assert!(claims.is_verify("issuer", "api2", store).await);
    }

    #[actix_web::test]
    async fn is_verify_rejects_wrong_issuer() {
        let store = Data::new(MockStore::new());
        store.insert("jti-1");

        let claims = sample_claims();
        assert!(!claims.is_verify("other-issuer", "api1", store).await);
    }

    #[actix_web::test]
    async fn is_verify_rejects_wrong_audience() {
        let store = Data::new(MockStore::new());
        store.insert("jti-1");

        let claims = sample_claims();
        assert!(!claims.is_verify("issuer", "unknown-aud", store).await);
    }

    #[actix_web::test]
    async fn is_verify_rejects_expired_token() {
        let store = Data::new(MockStore::new());
        store.insert("jti-1");

        let now = Utc::now().timestamp() as usize;
        let mut claims = sample_claims();
        claims.iat = now - 7200;
        claims.nbf = now - 7200;
        claims.exp = now - 3600; // expired an hour ago

        assert!(!claims.is_verify("issuer", "api1", store).await);
    }

    #[actix_web::test]
    async fn is_verify_rejects_not_yet_valid_token() {
        let store = Data::new(MockStore::new());
        store.insert("jti-1");

        let now = Utc::now().timestamp() as usize;
        let mut claims = sample_claims();
        claims.nbf = now + 3600; // becomes valid only in an hour

        assert!(!claims.is_verify("issuer", "api1", store).await);
    }

    #[actix_web::test]
    async fn is_verify_rejects_missing_jti() {
        // The store is empty: the `jti` was revoked or expired.
        let store = Data::new(MockStore::new());

        let claims = sample_claims();
        assert!(!claims.is_verify("issuer", "api1", store).await);
    }

    // --- Issuing claims (create_new) ---

    #[actix_web::test]
    async fn create_new_builds_valid_claims_and_stores_jti() {
        let store = Data::new(MockStore::new());
        let audience = vec!["api1".to_string()];

        let claims = TokenClaims::create_new(
            "issuer",
            "subject",
            &audience,
            None,
            Map::new(),
            store.clone(),
        )
        .await
        .unwrap();

        assert_eq!(claims.iss, "issuer");
        assert_eq!(claims.sub, "subject");
        assert_eq!(claims.aud, audience);
        assert_eq!(claims.iat, claims.nbf);
        assert!(claims.exp > claims.iat);
        assert!(Uuid::parse_str(&claims.jti).is_ok());
        // The jti must be registered in the store.
        assert!(store.check_jti(&claims.jti).await.unwrap());
    }

    #[actix_web::test]
    async fn create_new_rejects_empty_audience() {
        let store = Data::new(MockStore::new());
        let result =
            TokenClaims::create_new("issuer", "subject", &[], None, Map::new(), store).await;
        assert!(matches!(result, Err(JwtError::UnprocessableEntity)));
    }

    #[actix_web::test]
    async fn create_new_honors_custom_ttl() {
        let store = Data::new(MockStore::new());
        let audience = vec!["api1".to_string()];

        let before = Utc::now().timestamp() as usize;
        let claims = TokenClaims::create_new(
            "issuer",
            "subject",
            &audience,
            Some(120),
            Map::new(),
            store.clone(),
        )
        .await
        .unwrap();
        let after = Utc::now().timestamp() as usize;

        // exp = iat + ttl, allowing for a possible one-second shift while measuring.
        assert!(claims.exp >= before + 120 && claims.exp <= after + 120);
        assert_eq!(claims.exp, claims.iat + 120);
    }

    #[actix_web::test]
    async fn create_new_rejects_ttl_below_min() {
        // The default lower bound is 1 second, so 0 is not allowed.
        let store = Data::new(MockStore::new());
        let audience = vec!["api1".to_string()];

        let result =
            TokenClaims::create_new("issuer", "subject", &audience, Some(0), Map::new(), store)
                .await;
        assert!(matches!(result, Err(JwtError::UnprocessableEntity)));
    }

    #[actix_web::test]
    async fn create_new_rejects_ttl_above_max() {
        // The default upper bound is 86400 seconds.
        let store = Data::new(MockStore::new());
        let audience = vec!["api1".to_string()];

        let result = TokenClaims::create_new(
            "issuer",
            "subject",
            &audience,
            Some(86401),
            Map::new(),
            store,
        )
        .await;
        assert!(matches!(result, Err(JwtError::UnprocessableEntity)));
    }

    #[actix_web::test]
    async fn create_new_fails_when_store_unavailable() {
        // Redis is unavailable: the `jti` write fails and the token must not be issued (fail-fast).
        let store = Data::new(FailingStore);
        let audience = vec!["api1".to_string()];

        let result =
            TokenClaims::create_new("issuer", "subject", &audience, None, Map::new(), store).await;
        assert!(matches!(result, Err(JwtError::StoreError)));
    }

    #[actix_web::test]
    async fn create_new_fails_when_group_index_unavailable() {
        // The `jti` itself was written but the subject index was not. Such a
        // token would survive a bulk revocation, so it must not be issued:
        // fail-fast, exactly as with an unavailable `jti` write.
        let store = Data::new(FailingGroupStore::new());
        let audience = vec!["api1".to_string()];

        let result =
            TokenClaims::create_new("issuer", "subject", &audience, None, Map::new(), store).await;
        assert!(matches!(result, Err(JwtError::StoreError)));
    }

    #[test]
    fn subject_group_is_namespaced() {
        // The prefix separates groups from flat `jti` keys, or a subject named
        // like a UUID could collide with someone else's token identifier.
        assert_eq!(subject_group("user1"), "group:sub:user1");
    }

    // --- Token signing (JsonWebToken::to_string) ---

    #[test]
    fn to_string_produces_verifiable_signature() {
        // An Ed25519 key: signing and verification without an explicit digest — as in `to_string`.
        let private = PKey::generate_ed25519().unwrap();
        let public =
            PKey::public_key_from_raw_bytes(&private.raw_public_key().unwrap(), Id::ED25519)
                .unwrap();

        // `alg` is set explicitly rather than through `TokenHeaders::create_new`:
        // that one reads `TOKEN_ALGORITHM` from the environment, and the test
        // used to pass only because the neighbours managed to set `EdDSA` there.
        // On its own it failed — an Ed25519 key was signed with the digest of the
        // default `RS256`.
        let headers = headers_with_alg("EdDSA");
        let claims = sample_claims();
        let jwt = JsonWebToken::create_new(headers, claims, private);

        let token = jwt.to_string().unwrap();

        // Exactly three segments: header.payload.signature.
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // The signature really does cover "header.payload".
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let mut verifier = Verifier::new_without_digest(&public).unwrap();
        let signed_data = format!("{}.{}", parts[0], parts[1]);
        assert!(verifier
            .verify_oneshot(&signature, signed_data.as_bytes())
            .unwrap());

        // The claims segment decodes back without loss.
        let decoded_claims = TokenClaims::from_base64(parts[1].to_string()).unwrap();
        assert_eq!(decoded_claims.jti, "jti-1");
        assert_eq!(decoded_claims.iss, "issuer");
    }

    // --- Consistency of signing and verification for every algorithm (JWT-13) ---

    /// Generates a (private, public) key pair suitable for `alg`.
    fn keypair_for(alg: &str) -> (PKey<Private>, PKey<Public>) {
        match alg {
            "RS256" | "RS384" | "RS512" => {
                let rsa = Rsa::generate(2048).unwrap();
                let public = PKey::from_rsa(
                    Rsa::from_public_components(
                        rsa.n().to_owned().unwrap(),
                        rsa.e().to_owned().unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap();
                (PKey::from_rsa(rsa).unwrap(), public)
            }
            "ES256" | "ES384" | "ES512" => {
                let nid = match alg {
                    "ES256" => Nid::X9_62_PRIME256V1,
                    "ES384" => Nid::SECP384R1,
                    _ => Nid::SECP521R1,
                };
                let group = EcGroup::from_curve_name(nid).unwrap();
                let ec = EcKey::generate(&group).unwrap();
                let public =
                    PKey::from_ec_key(EcKey::from_public_key(&group, ec.public_key()).unwrap())
                        .unwrap();
                (PKey::from_ec_key(ec).unwrap(), public)
            }
            "EdDSA" => {
                let private = PKey::generate_ed25519().unwrap();
                let public = PKey::public_key_from_raw_bytes(
                    &private.raw_public_key().unwrap(),
                    Id::ED25519,
                )
                .unwrap();
                (private, public)
            }
            other => panic!("no key generator for alg {other} in the test"),
        }
    }

    /// A header with an explicit `alg` — it bypasses the dependency of
    /// `create_new` on the `TOKEN_ALGORITHM` env var (which matters for a
    /// parallel test run).
    fn headers_with_alg(alg: &str) -> TokenHeaders {
        TokenHeaders {
            alg: alg.to_string(),
            kid: "kid-1".to_string(),
            typ: "JWT".to_string(),
            jku: None,
        }
    }

    /// Verifies a token signature exactly the way
    /// [`JsonWebToken::from_string`] does: the digest is chosen by `alg`. That is
    /// the same verification path as on the production `POST /tokens/verify`, so
    /// a successful check here is equivalent to passing an issue→verify round
    /// trip.
    fn verify_signature(token: &str, alg: &str, public: &PKey<Public>) -> bool {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "a token must consist of three segments");

        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let signed = format!("{}.{}", parts[0], parts[1]);

        let mut verifier = match alg {
            "RS256" | "ES256" => Verifier::new(MessageDigest::sha256(), public),
            "RS384" | "ES384" => Verifier::new(MessageDigest::sha384(), public),
            "RS512" | "ES512" => Verifier::new(MessageDigest::sha512(), public),
            _ => Verifier::new_without_digest(public),
        }
        .unwrap();

        verifier
            .verify_oneshot(&signature, signed.as_bytes())
            .unwrap()
    }

    /// An issue→verify round trip for the default `RS256` (a regression test for
    /// JWT-13: the signature used to be produced without a digest and failed its
    /// own verification).
    #[test]
    fn sign_verify_roundtrip_rs256() {
        let (private, public) = keypair_for("RS256");
        let jwt = JsonWebToken::create_new(headers_with_alg("RS256"), sample_claims(), private);
        let token = jwt.to_string().unwrap();

        assert!(verify_signature(&token, "RS256", &public));
    }

    /// An issue→verify round trip for `ES256` (a representative of the `ES*` family).
    #[test]
    fn sign_verify_roundtrip_es256() {
        let (private, public) = keypair_for("ES256");
        let jwt = JsonWebToken::create_new(headers_with_alg("ES256"), sample_claims(), private);
        let token = jwt.to_string().unwrap();

        assert!(verify_signature(&token, "ES256", &public));
    }

    /// A round trip for **every** algorithm in [`SUPPORTED_ALGORITHMS`]: the
    /// signature produced by `to_string` must agree with the verification in
    /// `from_string`. A digest mismatch was exactly the bug of JWT-13.
    #[test]
    fn sign_verify_roundtrip_all_supported_algorithms() {
        for &alg in SUPPORTED_ALGORITHMS {
            let (private, public) = keypair_for(alg);
            let jwt = JsonWebToken::create_new(headers_with_alg(alg), sample_claims(), private);
            let token = jwt.to_string().unwrap();

            assert!(
                verify_signature(&token, alg, &public),
                "the {alg} signature failed verification with the same digest (a sign/verify mismatch)"
            );
        }
    }

    #[test]
    fn custom_claims_reject_reserved_names() {
        // Substituting `exp` would bypass the TTL bounds, and substituting `iss`
        // or `sub` would allow issuing a token under someone else's name.
        for name in RESERVED_CLAIMS {
            let mut claims = Map::new();
            claims.insert((*name).to_string(), Value::from("substituted"));

            assert!(
                matches!(
                    validate_custom_claims(&claims),
                    Err(JwtError::UnprocessableEntity)
                ),
                "the reserved claim {name} must be rejected"
            );
        }
    }

    #[test]
    fn custom_claims_accept_ordinary_names() {
        let mut claims = Map::new();
        claims.insert("role".to_string(), Value::from("admin"));
        claims.insert("scope".to_string(), Value::from(vec!["read", "write"]));
        claims.insert("tenant_id".to_string(), Value::from(42));

        assert!(validate_custom_claims(&claims).is_ok());
    }

    #[test]
    fn empty_custom_claims_are_allowed() {
        // An empty set is the most common case: the client knows nothing about claims.
        assert!(validate_custom_claims(&Map::new()).is_ok());
    }

    #[test]
    fn custom_claims_respect_count_limit() {
        let _guard = env_guard();
        env::set_var("TOKEN_CLAIMS_MAX_COUNT", "3");

        let mut claims = Map::new();
        for i in 0..4 {
            claims.insert(format!("claim_{i}"), Value::from(i));
        }

        assert!(matches!(
            validate_custom_claims(&claims),
            Err(JwtError::UnprocessableEntity)
        ));

        env::remove_var("TOKEN_CLAIMS_MAX_COUNT");
    }

    #[test]
    fn custom_claims_respect_size_limit() {
        let _guard = env_guard();
        env::set_var("TOKEN_CLAIMS_MAX_BYTES", "64");

        let mut claims = Map::new();
        // One key, but a value deliberately larger than the limit: a token
        // travels in headers and a bloated payload breaks proxies.
        claims.insert("blob".to_string(), Value::from("x".repeat(128)));

        assert!(matches!(
            validate_custom_claims(&claims),
            Err(JwtError::UnprocessableEntity)
        ));

        env::remove_var("TOKEN_CLAIMS_MAX_BYTES");
    }

    #[actix_web::test]
    async fn create_new_puts_custom_claims_alongside_registered() {
        let store = Data::new(MockStore::new());
        let audience = vec!["api1".to_string()];

        let mut extra = Map::new();
        extra.insert("role".to_string(), Value::from("admin"));

        let claims = TokenClaims::create_new("issuer", "subject", &audience, None, extra, store)
            .await
            .expect("the claims are formed");

        // In serialised form the custom claims sit alongside the registered ones
        // rather than in a nested object: the consumer looks for `role`, not
        // `extra.role`.
        let value = serde_json::to_value(&claims).unwrap();
        assert_eq!(value["role"], "admin");
        assert_eq!(value["sub"], "subject");
        assert!(value.get("extra").is_none());
    }

    #[actix_web::test]
    async fn create_new_rejects_reserved_custom_claim() {
        let store = Data::new(MockStore::new());
        let audience = vec!["api1".to_string()];

        let mut extra = Map::new();
        extra.insert("exp".to_string(), Value::from(9_999_999_999_u64));

        let result =
            TokenClaims::create_new("issuer", "subject", &audience, None, extra, store).await;

        assert!(matches!(result, Err(JwtError::UnprocessableEntity)));
    }
}
