//! Technician authentication: Entra ID OIDC access tokens plus an optional,
//! explicitly enabled development issuer.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};

use crate::ApiError;
use crate::state::AppState;

/// Issuer string of development tokens.
pub const DEV_ISSUER: &str = "rmm-dev";
/// App role that grants administrative access.
pub const ROLE_ADMIN: &str = "RMM.Admin";

/// Decode the first PEM block; returns its label and DER bytes.
fn pem_block(pem: &[u8]) -> Result<(String, Vec<u8>), String> {
    let text = std::str::from_utf8(pem).map_err(|_| "PEM is not UTF-8".to_string())?;
    let start = text.find("-----BEGIN ").ok_or("no PEM header")?;
    let rest = &text[start + 11..];
    let label_end = rest.find("-----").ok_or("bad PEM header")?;
    let label = rest[..label_end].to_owned();
    let body = &rest[label_end + 5..];
    let end = body.find("-----END ").ok_or("no PEM footer")?;
    let b64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
    let der = data_encoding::BASE64
        .decode(b64.as_bytes())
        .map_err(|e| format!("bad PEM base64: {e}"))?;
    Ok((label, der))
}

/// One DER element: `(tag, content, rest)`.
fn der_next(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |a, b| (a << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// PKCS#1 `RSAPublicKey` DER from a PEM `RSA PUBLIC KEY` or `PUBLIC KEY` block.
pub fn rsa_public_der_from_pem(pem: &[u8]) -> Result<Vec<u8>, String> {
    let (label, der) = pem_block(pem)?;
    match label.as_str() {
        "RSA PUBLIC KEY" => Ok(der),
        "PUBLIC KEY" => {
            let (_, seq, _) = der_next(&der).ok_or("bad SPKI")?;
            let (_, _alg, rest) = der_next(seq).ok_or("bad SPKI")?;
            let (tag, bits, _) = der_next(rest).ok_or("bad SPKI")?;
            if tag != 0x03 || bits.first() != Some(&0) {
                return Err("bad SPKI bit string".into());
            }
            Ok(bits[1..].to_vec())
        }
        other => Err(format!("unsupported PEM label {other}")),
    }
}

/// PKCS#1 `RSAPrivateKey` DER from a PEM `RSA PRIVATE KEY` or `PRIVATE KEY` block.
pub fn rsa_private_der_from_pem(pem: &[u8]) -> Result<Vec<u8>, String> {
    let (label, der) = pem_block(pem)?;
    match label.as_str() {
        "RSA PRIVATE KEY" => Ok(der),
        "PRIVATE KEY" => {
            let (_, seq, _) = der_next(&der).ok_or("bad PKCS#8")?;
            let (_, _version, rest) = der_next(seq).ok_or("bad PKCS#8")?;
            let (_, _alg, rest) = der_next(rest).ok_or("bad PKCS#8")?;
            let (tag, key, _) = der_next(rest).ok_or("bad PKCS#8")?;
            if tag != 0x04 {
                return Err("bad PKCS#8 key".into());
            }
            Ok(key.to_vec())
        }
        other => Err(format!("unsupported PEM label {other}")),
    }
}

const JWKS_TTL: Duration = Duration::from_secs(3600);
const JWKS_MIN_REFETCH: Duration = Duration::from_secs(60);
const LEEWAY_SECS: u64 = 60;

/// Identity extracted from a validated token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Claims {
    /// Token subject.
    pub sub: String,
    /// Entra object id.
    #[serde(default)]
    pub oid: String,
    /// Display name.
    #[serde(default)]
    pub name: String,
    /// App roles granted to the caller.
    #[serde(default)]
    pub roles: Vec<String>,
}

impl Claims {
    /// The caller's one stable identity: the Entra object id when present
    /// (the same for every application in the tenant), else the subject
    /// (development tokens). Audit rows and technician ids both use it, so a
    /// technician-list entry can be matched to the audit trail.
    pub fn identity(&self) -> &str {
        if self.oid.is_empty() {
            &self.sub
        } else {
            &self.oid
        }
    }

    /// Stable actor string for audit rows.
    pub fn actor(&self) -> String {
        self.identity().to_owned()
    }

    /// Technician id of the caller (401 when the token names nobody).
    pub fn tech_id(&self) -> Result<&str, ApiError> {
        match self.identity() {
            "" => Err(ApiError::Unauthorized),
            id => Ok(id),
        }
    }

    /// Whether the caller holds `role`.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// Fail with 403 unless `claims` holds `role`.
pub fn require_role(claims: &Claims, role: &str) -> Result<(), ApiError> {
    if claims.has_role(role) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Settings for [`Authenticator::from_config`].
#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    /// Entra tenant id; Entra validation is disabled when `None`.
    pub tenant_id: Option<String>,
    /// Expected `aud` claim.
    pub audience: String,
    /// Accept development tokens (only with `RMM_AUTH_ALLOW_DEV=1`).
    pub allow_dev: bool,
    /// PEM public key that verifies development tokens.
    pub dev_pubkey_pem: Option<Vec<u8>>,
}

#[derive(Default)]
struct EntraState {
    issuer: Option<String>,
    jwks_uri: Option<String>,
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
}

struct Entra {
    discovery_url: String,
    state: tokio::sync::Mutex<EntraState>,
}

struct Inner {
    audience: String,
    entra: Option<Entra>,
    dev: Option<DecodingKey>,
    refetch_interval: Duration,
    http: reqwest::Client,
}

/// Validates technician bearer tokens.
#[derive(Clone)]
pub struct Authenticator {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("entra", &self.inner.entra.is_some())
            .field("dev", &self.inner.dev.is_some())
            .finish()
    }
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct IssOnly {
    iss: Option<String>,
}

impl Authenticator {
    /// Build from explicit settings. Development keys are ignored unless
    /// `allow_dev` is set.
    pub fn from_config(cfg: AuthConfig) -> Result<Self, String> {
        let discovery = cfg.tenant_id.as_deref().map(|tid| {
            format!("https://login.microsoftonline.com/{tid}/v2.0/.well-known/openid-configuration")
        });
        Self::build(cfg, discovery)
    }

    /// Like [`Authenticator::from_config`] but with an explicit discovery URL
    /// (tests and sovereign clouds).
    pub fn with_discovery_url(cfg: AuthConfig, discovery_url: &str) -> Result<Self, String> {
        Self::build(cfg, Some(discovery_url.to_owned()))
    }

    fn build(cfg: AuthConfig, discovery_url: Option<String>) -> Result<Self, String> {
        let dev = if cfg.allow_dev {
            match &cfg.dev_pubkey_pem {
                Some(pem) => {
                    tracing::warn!("RMM_AUTH_ALLOW_DEV is set: development tokens are accepted");
                    Some(DecodingKey::from_rsa_der(&rsa_public_der_from_pem(pem)?))
                }
                None => None,
            }
        } else {
            None
        };
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(Self {
            inner: Arc::new(Inner {
                audience: cfg.audience,
                entra: discovery_url.map(|discovery_url| Entra {
                    discovery_url,
                    state: tokio::sync::Mutex::new(EntraState::default()),
                }),
                dev,
                refetch_interval: JWKS_MIN_REFETCH,
                http,
            }),
        })
    }

    /// Override the minimum time between JWKS refetches on an unknown key id.
    /// Only effective before the authenticator is cloned.
    #[must_use]
    pub fn with_refetch_interval(mut self, interval: Duration) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.refetch_interval = interval;
        }
        self
    }

    /// Build from the process environment.
    pub fn from_env() -> Result<Self, String> {
        let tenant_id = std::env::var("RMM_ENTRA_TENANT_ID")
            .ok()
            .filter(|s| !s.is_empty());
        let audience = std::env::var("RMM_ENTRA_AUDIENCE").unwrap_or_default();
        let allow_dev = std::env::var("RMM_AUTH_ALLOW_DEV").as_deref() == Ok("1");
        let dev_pubkey_pem = match std::env::var("RMM_AUTH_DEV_PUBKEY_FILE") {
            Ok(path) if allow_dev => {
                Some(std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?)
            }
            _ => None,
        };
        if audience.is_empty() {
            return Err("RMM_ENTRA_AUDIENCE is not set".into());
        }
        Self::from_config(AuthConfig {
            tenant_id,
            audience,
            allow_dev,
            dev_pubkey_pem,
        })
    }

    fn validation(&self, issuer: &str) -> Validation {
        let mut v = Validation::new(Algorithm::RS256);
        v.leeway = LEEWAY_SECS;
        v.validate_nbf = true;
        v.set_audience(&[&self.inner.audience]);
        v.set_issuer(&[issuer]);
        v.set_required_spec_claims(&["exp", "aud", "iss"]);
        v
    }

    /// Validate a bearer token and return its claims.
    pub async fn verify(&self, token: &str) -> Result<Claims, ApiError> {
        let header = decode_header(token).map_err(|_| ApiError::Unauthorized)?;
        if header.alg != Algorithm::RS256 {
            return Err(ApiError::Unauthorized);
        }
        let iss = jsonwebtoken::dangerous::insecure_decode::<IssOnly>(token)
            .map_err(|_| ApiError::Unauthorized)?
            .claims
            .iss
            .unwrap_or_default();

        if iss == DEV_ISSUER {
            let key = self.inner.dev.as_ref().ok_or(ApiError::Unauthorized)?;
            return decode::<Claims>(token, key, &self.validation(DEV_ISSUER))
                .map(|d| d.claims)
                .map_err(|_| ApiError::Unauthorized);
        }

        let kid = header.kid.ok_or(ApiError::Unauthorized)?;
        let (key, issuer) = self.entra_key(&kid).await?;
        decode::<Claims>(token, &key, &self.validation(&issuer))
            .map(|d| d.claims)
            .map_err(|_| ApiError::Unauthorized)
    }

    async fn entra_key(&self, kid: &str) -> Result<(DecodingKey, String), ApiError> {
        let entra = self.inner.entra.as_ref().ok_or(ApiError::Unauthorized)?;
        let mut st = entra.state.lock().await;
        let age = st.fetched_at.map(|t| t.elapsed());
        let expired = age.is_none_or(|a| a >= JWKS_TTL);
        let unknown = !st.keys.contains_key(kid);
        let may_refetch = age.is_none_or(|a| a >= self.inner.refetch_interval);
        if expired || (unknown && may_refetch) {
            self.refresh(entra, &mut st).await.map_err(|err| {
                tracing::warn!(%err, "jwks refresh failed");
                ApiError::Unauthorized
            })?;
        }
        let key = st.keys.get(kid).cloned().ok_or(ApiError::Unauthorized)?;
        let issuer = st.issuer.clone().ok_or(ApiError::Unauthorized)?;
        Ok((key, issuer))
    }

    async fn refresh(&self, entra: &Entra, st: &mut EntraState) -> Result<(), String> {
        if st.jwks_uri.is_none() {
            let d: Discovery = self
                .inner
                .http
                .get(&entra.discovery_url)
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|e| format!("discovery: {e}"))?
                .json()
                .await
                .map_err(|e| format!("discovery body: {e}"))?;
            st.issuer = Some(d.issuer);
            st.jwks_uri = Some(d.jwks_uri);
        }
        let uri = st.jwks_uri.clone().unwrap_or_default();
        let set: JwkSet = self
            .inner
            .http
            .get(&uri)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| format!("jwks: {e}"))?
            .json()
            .await
            .map_err(|e| format!("jwks body: {e}"))?;
        let mut keys = HashMap::new();
        for jwk in &set.keys {
            let Some(kid) = jwk.common.key_id.clone() else {
                continue;
            };
            if !matches!(jwk.algorithm, AlgorithmParameters::RSA(_)) {
                continue;
            }
            if let Ok(k) = DecodingKey::from_jwk(jwk) {
                keys.insert(kid, k);
            }
        }
        st.keys = keys;
        st.fetched_at = Some(Instant::now());
        Ok(())
    }
}

fn bearer(parts: &Parts) -> Option<&str> {
    let value = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
        .filter(|t| !t.is_empty())
}

impl FromRequestParts<AppState> for Claims {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or(ApiError::Unauthorized)?;
        state.authenticator.verify(token).await
    }
}

/// Names the app role a [`RequireRole`] extractor demands.
pub trait RoleName {
    /// The required role.
    const ROLE: &'static str;
}

/// Marker for `RMM.Admin`.
#[derive(Debug, Clone, Copy)]
pub struct Admin;

impl RoleName for Admin {
    const ROLE: &'static str = ROLE_ADMIN;
}

/// Extractor: authenticated caller holding the role named by `R` (401/403).
#[derive(Debug)]
pub struct RequireRole<R>(pub Claims, pub PhantomData<R>);

impl<R: RoleName + Send + Sync> FromRequestParts<AppState> for RequireRole<R> {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let claims = Claims::from_request_parts(parts, state).await?;
        require_role(&claims, R::ROLE)?;
        Ok(Self(claims, PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_prefers_the_object_id() {
        let entra = Claims {
            sub: "pairwise-sub".into(),
            oid: "object-id".into(),
            ..Claims::default()
        };
        assert_eq!(entra.identity(), "object-id");
        assert_eq!(entra.actor(), "object-id");
        assert_eq!(entra.tech_id().ok(), Some("object-id"));

        let dev = Claims {
            sub: "dev-user".into(),
            ..Claims::default()
        };
        assert_eq!(dev.tech_id().ok(), Some("dev-user"));
        assert!(Claims::default().tech_id().is_err());
    }
}
