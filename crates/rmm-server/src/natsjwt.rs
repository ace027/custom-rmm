//! NATS JWTs for the auth callout: encoding, request decoding and the
//! claims authd issues to agents.
//!
//! Format (nats-io/jwt v2): `base64url(header).base64url(claims).base64url(sig)`
//! without padding, header `{"typ":"JWT","alg":"ed25519-nkey"}`, signature
//! Ed25519 over the first two parts with the issuer's nkey.
//!
//! This file is self-contained (no `crate::` paths) because
//! `tests/natsjwt.rs` includes it with `#[path]`; the package has no library
//! target.

use std::fmt;

use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use ed25519_dalek::{Signature, VerifyingKey};
use nkeys::KeyPair;
use rmm_db::repo::AgentAuthRow;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Account the agent users are placed in (user JWT audience).
pub const AGENT_ACCOUNT: &str = "RMM";
/// Lifetime of an issued agent user JWT.
pub const USER_JWT_TTL_SECS: u64 = 3600;
/// Largest JWT authd will try to decode.
const MAX_JWT_LEN: usize = 64 * 1024;

const HEADER: &str = r#"{"typ":"JWT","alg":"ed25519-nkey"}"#;

/// Account key prefix byte (first byte of a decoded nkey, see the nkeys spec).
pub const PREFIX_ACCOUNT: u8 = 0;
/// Server key prefix byte.
pub const PREFIX_SERVER: u8 = 13 << 3;
/// User key prefix byte.
pub const PREFIX_USER: u8 = 20 << 3;

/// Why a JWT or callout request was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtError(pub String);

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for JwtError {}

fn err(msg: impl Into<String>) -> JwtError {
    JwtError(msg.into())
}

/// Result alias for this module.
pub type Result<T> = std::result::Result<T, JwtError>;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Sign `claims` as a NATS JWT. `iss` and `jti` are always set; `iat` is set
/// to now unless the claims already carry one. `jti` is the unpadded base32
/// SHA-256 of the claims serialised without it.
pub fn encode_jwt(claims: &Value, issuer: &KeyPair) -> String {
    let mut c = match claims {
        Value::Object(m) => m.clone(),
        _ => serde_json::Map::new(),
    };
    c.remove("jti");
    c.insert("iss".into(), Value::String(issuer.public_key()));
    if !c.contains_key("iat") {
        c.insert("iat".into(), json!(unix_now()));
    }
    let unsigned = Value::Object(c.clone()).to_string();
    let jti: [u8; 32] = Sha256::digest(unsigned.as_bytes()).into();
    c.insert("jti".into(), Value::String(BASE32_NOPAD.encode(&jti)));
    let body = Value::Object(c).to_string();
    let signing_input = format!(
        "{}.{}",
        BASE64URL_NOPAD.encode(HEADER.as_bytes()),
        BASE64URL_NOPAD.encode(body.as_bytes())
    );
    // Signing only fails for a public-only key pair, which callers never pass.
    let sig = issuer.sign(signing_input.as_bytes()).unwrap_or_default();
    format!("{signing_input}.{}", BASE64URL_NOPAD.encode(&sig))
}

/// Decode a base64url field, accepting optional padding.
fn b64url(s: &str) -> Result<Vec<u8>> {
    BASE64URL_NOPAD
        .decode(s.trim_end_matches('=').as_bytes())
        .map_err(|_| err("bad base64url"))
}

/// Split and verify a JWT signed by the nkey in its `iss` claim; return the
/// claims. `expected_prefix` restricts the issuer key type.
pub fn decode_verified(jwt: &str, expected_prefix: u8) -> Result<Value> {
    if jwt.len() > MAX_JWT_LEN {
        return Err(err("jwt too large"));
    }
    let mut parts = jwt.trim().split('.');
    let (Some(h), Some(c), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(err("jwt must have three parts"));
    };
    let header: Value =
        serde_json::from_slice(&b64url(h)?).map_err(|_| err("bad jwt header json"))?;
    if header.get("alg").and_then(Value::as_str) != Some("ed25519-nkey") {
        return Err(err("unsupported jwt alg"));
    }
    let claims: Value =
        serde_json::from_slice(&b64url(c)?).map_err(|_| err("bad jwt claims json"))?;
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| err("jwt has no issuer"))?;
    let key = public_key_bytes(iss, expected_prefix)?;
    let sig = b64url(s)?;
    verify_ed25519(&key, format!("{h}.{c}").as_bytes(), &sig)?;
    Ok(claims)
}

/// Raw Ed25519 key from an nkey public string of the given type.
pub fn public_key_bytes(nkey: &str, expected_prefix: u8) -> Result<[u8; 32]> {
    let (prefix, key) = nkeys::from_public_key(nkey).map_err(|_| err("invalid nkey"))?;
    if prefix != expected_prefix {
        return Err(err("nkey has the wrong type"));
    }
    Ok(key)
}

fn verify_ed25519(key: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(key).map_err(|_| err("invalid public key"))?;
    let sig = Signature::from_slice(sig).map_err(|_| err("invalid signature encoding"))?;
    vk.verify_strict(msg, &sig)
        .map_err(|_| err("signature verification failed"))
}

/// Client details from an authorization request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientInfo {
    /// Remote address as seen by the server.
    pub host: String,
    /// Nonce the server sent the client in INFO.
    pub nonce: String,
    /// Server-side connection id.
    pub cid: u64,
    /// Client kind (`Client`, `Leafnode`, ...).
    pub kind: String,
    /// Connection type (`nats`, `websocket`, `mqtt`, ...).
    pub conn_type: String,
}

/// The client's CONNECT options from an authorization request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectOpts {
    /// Public user nkey the client claims.
    pub nkey: String,
    /// Signature over the nonce (base64url).
    pub sig: String,
    /// Client-chosen connection name.
    pub name: String,
}

/// A decoded `authorization_request`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthRequest {
    /// Per-connection user nkey the response and user JWT must be issued to.
    pub user_nkey: String,
    /// Public key of the requesting server (response audience).
    pub server_id: String,
    /// Client details.
    pub client_info: ClientInfo,
    /// CONNECT options.
    pub connect_opts: ConnectOpts,
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    path.iter()
        .try_fold(v, |v, k| v.get(*k))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// Decode and verify an `authorization_request` JWT from the server.
pub fn decode_authorization_request(jwt: &str) -> Result<AuthRequest> {
    let claims = decode_verified(jwt, PREFIX_SERVER)?;
    let nats = claims
        .get("nats")
        .ok_or_else(|| err("missing nats claims"))?;
    if str_at(nats, &["type"]) != "authorization_request" {
        return Err(err("not an authorization request"));
    }
    let server_id = str_at(nats, &["server_id", "id"]).to_owned();
    if server_id != str_at(&claims, &["iss"]) {
        return Err(err("request issuer is not the requesting server"));
    }
    let user_nkey = str_at(nats, &["user_nkey"]).to_owned();
    public_key_bytes(&user_nkey, PREFIX_USER)?;
    let ci = nats.get("client_info").cloned().unwrap_or(Value::Null);
    let co = nats.get("connect_opts").cloned().unwrap_or(Value::Null);
    Ok(AuthRequest {
        user_nkey,
        server_id,
        client_info: ClientInfo {
            host: str_at(&ci, &["host"]).to_owned(),
            nonce: str_at(&ci, &["nonce"]).to_owned(),
            cid: ci.get("id").and_then(Value::as_u64).unwrap_or(0),
            kind: str_at(&ci, &["kind"]).to_owned(),
            conn_type: str_at(&ci, &["type"]).to_owned(),
        },
        connect_opts: ConnectOpts {
            nkey: str_at(&co, &["nkey"]).to_owned(),
            sig: str_at(&co, &["sig"]).to_owned(),
            name: str_at(&co, &["name"]).to_owned(),
        },
    })
}

/// Check the client's proof of key possession: `connect_opts.sig` must be an
/// Ed25519 signature over `client_info.nonce` by the key in
/// `connect_opts.nkey`. Returns the raw public key.
pub fn verify_nonce_signature(req: &AuthRequest) -> Result<[u8; 32]> {
    if req.client_info.nonce.is_empty() {
        return Err(err("server sent no nonce"));
    }
    if req.connect_opts.nkey.is_empty() || req.connect_opts.sig.is_empty() {
        return Err(err("client did not present an nkey signature"));
    }
    let key = public_key_bytes(&req.connect_opts.nkey, PREFIX_USER)?;
    // Clients send RawURLEncoding; the server also accepts RawStdEncoding.
    let sig = b64url(&req.connect_opts.sig).or_else(|_| {
        data_encoding::BASE64_NOPAD
            .decode(req.connect_opts.sig.trim_end_matches('=').as_bytes())
            .map_err(|_| err("bad signature encoding"))
    })?;
    verify_ed25519(&key, req.client_info.nonce.as_bytes(), &sig)?;
    Ok(key)
}

/// NATS user name of an agent's connection (the user JWT `name`). The
/// server reports it as the connection's authorized user, so authd finds an
/// agent's connections in connz by this name.
pub fn agent_user_name(agent_id: uuid::Uuid) -> String {
    format!("agent:{agent_id}")
}

/// Subjects an agent may publish to.
pub fn agent_pub_allow(agent: &AgentAuthRow) -> Vec<String> {
    let (c, a) = (agent.client_id, agent.agent_id);
    vec![
        format!("telemetry.{c}.{a}.>"),
        format!("result.{c}.{a}"),
        format!("shell.{a}.*.out"),
        "svc.trust.latest".to_owned(),
        "svc.release.latest".to_owned(),
        format!("$JS.API.CONSUMER.INFO.CMD.agent_{a}"),
        format!("$JS.API.CONSUMER.MSG.NEXT.CMD.agent_{a}"),
        format!("$JS.ACK.CMD.agent_{a}.>"),
    ]
}

/// Subjects an agent may subscribe to.
pub fn agent_sub_allow(agent: &AgentAuthRow) -> Vec<String> {
    let a = agent.agent_id;
    vec![
        format!("_INBOX_{a}.>"),
        format!("shell.{a}.*.in"),
        format!("shell.{a}.*.ctl"),
    ]
}

/// Unsigned user claims for an agent: account RMM, WebSocket only, expires
/// after [`USER_JWT_TTL_SECS`].
pub fn user_claims(user_nkey: &str, agent: &AgentAuthRow, now: u64) -> Value {
    json!({
        "sub": user_nkey,
        "aud": AGENT_ACCOUNT,
        "name": agent_user_name(agent.agent_id),
        "iat": now,
        "exp": now + USER_JWT_TTL_SECS,
        "nats": {
            "pub": {"allow": agent_pub_allow(agent)},
            "sub": {"allow": agent_sub_allow(agent)},
            // -1 is "no limit"; an omitted limit decodes as 0 (nothing allowed).
            "subs": -1,
            "data": -1,
            "payload": -1,
            "allowed_connection_types": ["WEBSOCKET"],
            "type": "user",
            "version": 2
        }
    })
}

/// Unsigned `authorization_response` claims. Exactly one of `user_jwt` and
/// `error` should be set; an error response never carries a JWT.
pub fn authorization_response(
    user_nkey: &str,
    server_id: &str,
    user_jwt: Option<String>,
    error: Option<String>,
) -> Value {
    let mut nats = serde_json::Map::new();
    match (user_jwt, error) {
        (_, Some(e)) => {
            nats.insert("error".into(), Value::String(e));
        }
        (Some(j), None) => {
            nats.insert("jwt".into(), Value::String(j));
        }
        (None, None) => {
            nats.insert("error".into(), Value::String("not authorized".into()));
        }
    }
    nats.insert("type".into(), json!("authorization_response"));
    nats.insert("version".into(), json!(2));
    json!({"sub": user_nkey, "aud": server_id, "nats": Value::Object(nats)})
}
