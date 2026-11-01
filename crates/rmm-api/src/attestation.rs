//! Hardware-only WebAuthn registration: verify a `packed` attestation whose
//! x5c chain leads to a configured attestation root and whose AAGUID is
//! allowlisted.
//!
//! Every other attestation format, including `none` and self attestation
//! (packed without x5c), is rejected, so only authenticators whose vendor
//! certified the key can register. Chain signatures are checked with
//! aws-lc-rs and may be ECDSA P-256/SHA-256, ECDSA P-384/SHA-384 or RSA
//! PKCS#1 v1.5 SHA-256 (2048-8192 bit); any other algorithm is rejected.
//! The attestation signature itself must be ES256 from a P-256 leaf.

use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature;
use ciborium::Value;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use rmm_trust::webauthn::{CoseKey, parse_cose_key};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::Version;
use x509_cert::der::asn1::OctetString;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

/// `id-fido-gen-ce-aaguid`: the AAGUID in a FIDO attestation certificate.
pub const OID_FIDO_GEN_CE_AAGUID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_SHA256_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

/// COSE algorithm id of ES256.
const COSE_ES256: i64 = -7;
/// Longest x5c chain accepted.
const MAX_X5C: usize = 4;
/// Longest credential id (WebAuthn §5.8.3 limit).
const MAX_CRED_ID: usize = 1023;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

/// A credential that passed attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCredential {
    /// Credential id.
    pub cred_id: Vec<u8>,
    /// COSE algorithm of the credential key: -7 or -8.
    pub alg: i32,
    /// COSE_Key bytes exactly as the authenticator sent them.
    pub cose_pubkey: Vec<u8>,
    /// Authenticator AAGUID.
    pub aaguid: [u8; 16],
    /// Signature counter at registration.
    pub sign_count: u32,
}

/// Why a registration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// The attestation object, authenticator data or a certificate could not be parsed.
    Malformed(String),
    /// The attestation format is not `packed` with an x5c chain.
    Format(String),
    /// clientDataJSON type is not `webauthn.create`.
    ClientDataType,
    /// The challenge does not match.
    Challenge,
    /// The origin is not an allowed console origin.
    Origin,
    /// rpIdHash does not match the relying party.
    RpIdHash,
    /// User presence flag not set.
    UserPresence,
    /// User verification flag not set.
    UserVerification,
    /// The credential is backup eligible (a synced passkey, not hardware-bound).
    BackupEligible,
    /// The attestation signature does not verify.
    Signature,
    /// The certificate chain does not verify to a configured root.
    Chain(String),
    /// A certificate in the chain is outside its validity period.
    CertificateValidity,
    /// The certificate's AAGUID extension disagrees with authenticator data.
    AaguidMismatch,
    /// The AAGUID is not allowlisted.
    AaguidNotAllowed(String),
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed attestation: {m}"),
            Self::Format(m) => write!(f, "unsupported attestation: {m}"),
            Self::ClientDataType => f.write_str("clientDataJSON type is not webauthn.create"),
            Self::Challenge => f.write_str("challenge mismatch"),
            Self::Origin => f.write_str("origin not allowed"),
            Self::RpIdHash => f.write_str("rpIdHash mismatch"),
            Self::UserPresence => f.write_str("user presence flag not set"),
            Self::UserVerification => f.write_str("user verification flag not set"),
            Self::BackupEligible => {
                f.write_str("credential is backup eligible; only device-bound keys are accepted")
            }
            Self::Signature => f.write_str("attestation signature does not verify"),
            Self::Chain(m) => write!(f, "attestation chain rejected: {m}"),
            Self::CertificateValidity => {
                f.write_str("attestation certificate is expired or not yet valid")
            }
            Self::AaguidMismatch => f.write_str("certificate AAGUID does not match authenticator"),
            Self::AaguidNotAllowed(a) => write!(f, "authenticator AAGUID {a} is not allowlisted"),
        }
    }
}

impl std::error::Error for AttestationError {}

fn malformed(m: impl Into<String>) -> AttestationError {
    AttestationError::Malformed(m.into())
}

fn chain_err(m: impl Into<String>) -> AttestationError {
    AttestationError::Chain(m.into())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Decode exactly one CBOR item from `bytes` (no trailing data).
fn cbor_exact(bytes: &[u8], what: &str) -> Result<Value, AttestationError> {
    let mut cur = Cursor::new(bytes);
    let v: Value =
        ciborium::de::from_reader(&mut cur).map_err(|e| malformed(format!("{what}: {e}")))?;
    if cur.position() != bytes.len() as u64 {
        return Err(malformed(format!("{what}: trailing data")));
    }
    Ok(v)
}

/// Text-keyed map entries, rejecting non-text and duplicate keys.
fn text_map(v: Value, what: &str) -> Result<Vec<(String, Value)>, AttestationError> {
    let Value::Map(entries) = v else {
        return Err(malformed(format!("{what} is not a map")));
    };
    let mut out: Vec<(String, Value)> = Vec::with_capacity(entries.len());
    for (k, v) in entries {
        let Value::Text(k) = k else {
            return Err(malformed(format!("{what} has a non-text key")));
        };
        if out.iter().any(|(e, _)| *e == k) {
            return Err(malformed(format!("{what} has duplicate key {k}")));
        }
        out.push((k, v));
    }
    Ok(out)
}

fn take(map: &mut Vec<(String, Value)>, key: &str) -> Option<Value> {
    let i = map.iter().position(|(k, _)| k == key)?;
    Some(map.swap_remove(i).1)
}

struct PackedStmt {
    alg: i64,
    sig: Vec<u8>,
    x5c: Vec<Vec<u8>>,
}

struct ParsedObject {
    auth_data: Vec<u8>,
    stmt: PackedStmt,
}

fn parse_attestation_object(att_obj: &[u8]) -> Result<ParsedObject, AttestationError> {
    let mut top = text_map(
        cbor_exact(att_obj, "attestationObject")?,
        "attestationObject",
    )?;
    let fmt = match take(&mut top, "fmt") {
        Some(Value::Text(f)) => f,
        _ => return Err(malformed("fmt missing")),
    };
    if fmt != "packed" {
        return Err(AttestationError::Format(format!(
            "format {fmt:?}; only packed attestation with x5c is accepted"
        )));
    }
    let auth_data = match take(&mut top, "authData") {
        Some(Value::Bytes(b)) => b,
        _ => return Err(malformed("authData missing")),
    };
    let stmt = match take(&mut top, "attStmt") {
        Some(v) => text_map(v, "attStmt")?,
        None => return Err(malformed("attStmt missing")),
    };
    if !top.is_empty() {
        return Err(malformed("attestationObject has unknown keys"));
    }
    let mut stmt = stmt;
    let alg = match take(&mut stmt, "alg") {
        Some(Value::Integer(i)) => i64::try_from(i).map_err(|_| malformed("attStmt.alg range"))?,
        _ => return Err(malformed("attStmt.alg missing")),
    };
    let sig = match take(&mut stmt, "sig") {
        Some(Value::Bytes(b)) => b,
        _ => return Err(malformed("attStmt.sig missing")),
    };
    let x5c = match take(&mut stmt, "x5c") {
        Some(Value::Array(items)) => items
            .into_iter()
            .map(|v| match v {
                Value::Bytes(b) => Ok(b),
                _ => Err(malformed("x5c entry is not a byte string")),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(malformed("x5c is not an array")),
        None => {
            return Err(AttestationError::Format(
                "self attestation (packed without x5c) is not accepted".into(),
            ));
        }
    };
    if !stmt.is_empty() {
        // ecdaaKeyId or anything else.
        return Err(AttestationError::Format(
            "attStmt has unsupported fields".into(),
        ));
    }
    if x5c.is_empty() || x5c.len() > MAX_X5C {
        return Err(AttestationError::Format(format!(
            "x5c must hold 1 to {MAX_X5C} certificates"
        )));
    }
    Ok(ParsedObject {
        auth_data,
        stmt: PackedStmt { alg, sig, x5c },
    })
}

struct AuthData {
    sign_count: u32,
    aaguid: [u8; 16],
    cred_id: Vec<u8>,
    cose_pubkey: Vec<u8>,
    key: CoseKey,
}

fn parse_auth_data(ad: &[u8], rp_id: &str) -> Result<AuthData, AttestationError> {
    if ad.len() < 37 {
        return Err(malformed("authenticator data shorter than 37 bytes"));
    }
    if !ct_eq(&ad[..32], &Sha256::digest(rp_id.as_bytes())) {
        return Err(AttestationError::RpIdHash);
    }
    let flags = ad[32];
    if flags & FLAG_UP == 0 {
        return Err(AttestationError::UserPresence);
    }
    if flags & FLAG_UV == 0 {
        return Err(AttestationError::UserVerification);
    }
    if flags & FLAG_BE != 0 {
        return Err(AttestationError::BackupEligible);
    }
    if flags & FLAG_AT == 0 {
        return Err(malformed("attested credential data flag not set"));
    }
    let sign_count = u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]);
    let rest = &ad[37..];
    if rest.len() < 18 {
        return Err(malformed("attested credential data truncated"));
    }
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&rest[..16]);
    let id_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
    let rest = &rest[18..];
    if id_len == 0 || id_len > MAX_CRED_ID || rest.len() < id_len {
        return Err(malformed("credential id length"));
    }
    let cred_id = rest[..id_len].to_vec();
    let rest = &rest[id_len..];

    // The COSE key is one CBOR item; find where it ends.
    let mut cur = Cursor::new(rest);
    let _: Value =
        ciborium::de::from_reader(&mut cur).map_err(|e| malformed(format!("COSE key: {e}")))?;
    let key_len = usize::try_from(cur.position()).map_err(|_| malformed("COSE key length"))?;
    let cose_pubkey = rest[..key_len].to_vec();
    let key = parse_cose_key(&cose_pubkey).map_err(|e| malformed(e.to_string()))?;
    let ext = &rest[key_len..];
    if flags & FLAG_ED != 0 {
        if !matches!(cbor_exact(ext, "extensions")?, Value::Map(_)) {
            return Err(malformed("extensions is not a map"));
        }
    } else if !ext.is_empty() {
        return Err(malformed("trailing data after credential public key"));
    }
    Ok(AuthData {
        sign_count,
        aaguid,
        cred_id,
        cose_pubkey,
        key,
    })
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    ty: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

fn check_client_data(
    client_data_json: &[u8],
    expected_challenge: &[u8],
    origins: &[String],
) -> Result<(), AttestationError> {
    let cd: ClientData = serde_json::from_slice(client_data_json)
        .map_err(|e| malformed(format!("clientDataJSON: {e}")))?;
    if cd.ty != "webauthn.create" {
        return Err(AttestationError::ClientDataType);
    }
    let got = data_encoding::BASE64URL_NOPAD
        .decode(cd.challenge.as_bytes())
        .map_err(|_| AttestationError::Challenge)?;
    if !ct_eq(&got, expected_challenge) {
        return Err(AttestationError::Challenge);
    }
    if cd.cross_origin == Some(true) || !origins.contains(&cd.origin) {
        return Err(AttestationError::Origin);
    }
    Ok(())
}

/// The P-256 key of an SPKI, or an error for any other key type.
fn p256_key(spki: &SubjectPublicKeyInfoOwned) -> Result<P256VerifyingKey, AttestationError> {
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(chain_err("certificate key is not an EC key"));
    }
    let curve: ObjectIdentifier = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| chain_err("EC key without curve"))?
        .decode_as()
        .map_err(|_| chain_err("EC key curve is not a named curve"))?;
    if curve != OID_SECP256R1 {
        return Err(chain_err("certificate key is not P-256"));
    }
    let bits = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| chain_err("public key bit string"))?;
    P256VerifyingKey::from_sec1_bytes(bits).map_err(|_| chain_err("invalid P-256 point"))
}

/// A certificate-signing key this verifier accepts for chain links.
enum IssuerKey<'a> {
    /// Uncompressed SEC1 point on P-256.
    P256(&'a [u8]),
    /// Uncompressed SEC1 point on P-384.
    P384(&'a [u8]),
    /// PKCS#1 `RSAPublicKey` DER.
    Rsa(&'a [u8]),
}

/// Classify an issuer SPKI; any key other than P-256, P-384 or RSA is
/// rejected. RSA modulus size (2048-8192 bits) is enforced at verification.
fn issuer_key(spki: &SubjectPublicKeyInfoOwned) -> Result<IssuerKey<'_>, AttestationError> {
    let bits = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| chain_err("public key bit string"))?;
    if spki.algorithm.oid == OID_RSA_ENCRYPTION {
        // RFC 4055: parameters MUST be NULL (tolerate absent).
        match &spki.algorithm.parameters {
            None => {}
            Some(p) if p.is_null() => {}
            Some(_) => return Err(chain_err("RSA key with parameters")),
        }
        return Ok(IssuerKey::Rsa(bits));
    }
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(chain_err("certificate key is not an EC or RSA key"));
    }
    let curve: ObjectIdentifier = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| chain_err("EC key without curve"))?
        .decode_as()
        .map_err(|_| chain_err("EC key curve is not a named curve"))?;
    let (len, key) = if curve == OID_SECP256R1 {
        (65, IssuerKey::P256(bits))
    } else if curve == OID_SECP384R1 {
        (97, IssuerKey::P384(bits))
    } else {
        return Err(chain_err("EC key is not on P-256 or P-384"));
    };
    if bits.len() != len || bits.first() != Some(&0x04) {
        return Err(chain_err("EC key is not an uncompressed point"));
    }
    Ok(key)
}

/// Verify that `issuer` signed `cert`.
///
/// Accepted (signature algorithm, issuer key) pairs, matching what FIDO
/// vendors use for attestation CAs: ecdsa-with-SHA256 with P-256,
/// ecdsa-with-SHA384 with P-384, sha256WithRSAEncryption with RSA
/// 2048-8192 bits. Every other combination is rejected.
fn verify_signed_by(cert: &Certificate, issuer: &Certificate) -> Result<(), AttestationError> {
    let tbs = cert.tbs_certificate();
    if tbs.issuer() != issuer.tbs_certificate().subject() {
        return Err(chain_err("issuer name does not match"));
    }
    let sig_alg = cert.signature_algorithm();
    if tbs.signature() != sig_alg {
        return Err(chain_err("signature algorithm mismatch inside certificate"));
    }
    let key = issuer_key(issuer.tbs_certificate().subject_public_key_info())?;
    let (alg, key_bytes): (&'static dyn signature::VerificationAlgorithm, &[u8]) =
        match (sig_alg.oid, key) {
            // RFC 5758: ECDSA signature algorithm parameters MUST be absent.
            (o, IssuerKey::P256(k)) if o == OID_ECDSA_SHA256 && sig_alg.parameters.is_none() => {
                (&signature::ECDSA_P256_SHA256_ASN1, k)
            }
            (o, IssuerKey::P384(k)) if o == OID_ECDSA_SHA384 && sig_alg.parameters.is_none() => {
                (&signature::ECDSA_P384_SHA384_ASN1, k)
            }
            (o, IssuerKey::Rsa(k))
                if o == OID_SHA256_WITH_RSA
                    && sig_alg.parameters.as_ref().is_none_or(|p| p.is_null()) =>
            {
                (&signature::RSA_PKCS1_2048_8192_SHA256, k)
            }
            (o, _) => {
                return Err(chain_err(format!(
                    "unsupported certificate signature algorithm {o} for the issuer key"
                )));
            }
        };
    let msg = tbs.to_der().map_err(|e| chain_err(format!("tbs: {e}")))?;
    let raw = cert
        .signature()
        .as_bytes()
        .ok_or_else(|| chain_err("signature bit string"))?;
    signature::UnparsedPublicKey::new(alg, key_bytes)
        .verify(&msg, raw)
        .map_err(|_| chain_err("certificate signature does not verify"))
}

fn check_validity(cert: &Certificate, now: u64) -> Result<(), AttestationError> {
    let v = cert.tbs_certificate().validity();
    let nb = v.not_before.to_unix_duration().as_secs();
    let na = v.not_after.to_unix_duration().as_secs();
    if now < nb || now > na {
        return Err(AttestationError::CertificateValidity);
    }
    Ok(())
}

/// `(critical, BasicConstraints)` if present.
fn basic_constraints(cert: &Certificate) -> Result<Option<BasicConstraints>, AttestationError> {
    cert.tbs_certificate()
        .get_extension::<BasicConstraints>()
        .map(|o| o.map(|(_, bc)| bc))
        .map_err(|_| chain_err("bad basicConstraints"))
}

/// Reject critical extensions this verifier does not understand.
fn check_critical(cert: &Certificate) -> Result<(), AttestationError> {
    for ext in cert
        .tbs_certificate()
        .extensions()
        .map_or(&[][..], Vec::as_slice)
    {
        if ext.critical && ext.extn_id != OID_BASIC_CONSTRAINTS && ext.extn_id != OID_KEY_USAGE {
            return Err(chain_err(format!(
                "unsupported critical extension {}",
                ext.extn_id
            )));
        }
    }
    Ok(())
}

/// Packed attestation certificate requirements (WebAuthn §8.2.1).
fn check_leaf(leaf: &Certificate, aaguid: &[u8; 16]) -> Result<(), AttestationError> {
    let tbs = leaf.tbs_certificate();
    if tbs.version() != Version::V3 {
        return Err(chain_err("attestation certificate is not X.509 v3"));
    }
    let ou = tbs
        .subject()
        .organization_unit()
        .map_err(|_| chain_err("bad subject OU"))?;
    if ou.as_ref().map(|o| o.value()).as_deref() != Some("Authenticator Attestation") {
        return Err(chain_err(
            "attestation certificate OU is not 'Authenticator Attestation'",
        ));
    }
    if basic_constraints(leaf)?.is_some_and(|bc| bc.ca) {
        return Err(chain_err("attestation certificate is a CA"));
    }
    let mut found = tbs
        .extensions()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter(|e| e.extn_id == OID_FIDO_GEN_CE_AAGUID);
    if let Some(ext) = found.next() {
        if found.next().is_some() || ext.critical {
            return Err(AttestationError::AaguidMismatch);
        }
        let inner = OctetString::from_der(ext.extn_value.as_bytes())
            .map_err(|_| AttestationError::AaguidMismatch)?;
        if inner.as_bytes() != aaguid {
            return Err(AttestationError::AaguidMismatch);
        }
    }
    Ok(())
}

/// Verify `x5c` (leaf first) up to one of `roots`, all valid at `now`.
fn verify_chain(
    x5c: &[Certificate],
    x5c_der: &[Vec<u8>],
    roots: &[Certificate],
    now: u64,
) -> Result<(), AttestationError> {
    for (i, cert) in x5c.iter().enumerate() {
        check_validity(cert, now)?;
        check_critical(cert)?;
        if i > 0 {
            // An intermediate (or the root itself) must be a CA whose path
            // length allows the certificates below it.
            let bc = basic_constraints(cert)?
                .ok_or_else(|| chain_err("intermediate without basicConstraints"))?;
            if !bc.ca {
                return Err(chain_err("intermediate is not a CA"));
            }
            if let Some(max) = bc.path_len_constraint
                && i - 1 > usize::from(max)
            {
                return Err(chain_err("path length exceeded"));
            }
        }
    }
    for pair in x5c.windows(2) {
        verify_signed_by(&pair[0], &pair[1])?;
    }
    let (Some(last), Some(last_der)) = (x5c.last(), x5c_der.last()) else {
        return Err(chain_err("empty chain"));
    };
    // The authenticator may include the root itself as the last element.
    for root in roots {
        if root.to_der().is_ok_and(|d| d == *last_der) {
            return Ok(());
        }
    }
    let mut last_err = chain_err("no configured root issued this chain");
    for root in roots
        .iter()
        .filter(|r| r.tbs_certificate().subject() == last.tbs_certificate().issuer())
    {
        match verify_signed_by(last, root).and_then(|()| check_validity(root, now)) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Verify a registration response; see the module docs for the policy.
pub fn verify_registration(
    att_obj: &[u8],
    client_data_json: &[u8],
    expected_challenge: &[u8],
    rp_id: &str,
    origins: &[String],
    roots: &[Certificate],
    aaguids: &[[u8; 16]],
) -> Result<RegisteredCredential, AttestationError> {
    verify_registration_at(
        att_obj,
        client_data_json,
        expected_challenge,
        rp_id,
        origins,
        roots,
        aaguids,
        unix_now(),
    )
}

/// [`verify_registration`] at an explicit Unix time.
#[allow(clippy::too_many_arguments)]
pub fn verify_registration_at(
    att_obj: &[u8],
    client_data_json: &[u8],
    expected_challenge: &[u8],
    rp_id: &str,
    origins: &[String],
    roots: &[Certificate],
    aaguids: &[[u8; 16]],
    now: u64,
) -> Result<RegisteredCredential, AttestationError> {
    let obj = parse_attestation_object(att_obj)?;
    check_client_data(client_data_json, expected_challenge, origins)?;
    let ad = parse_auth_data(&obj.auth_data, rp_id)?;

    if obj.stmt.alg != COSE_ES256 {
        return Err(AttestationError::Format(
            "attestation signature must be ES256".into(),
        ));
    }
    let x5c = obj
        .stmt
        .x5c
        .iter()
        .map(|der| Certificate::from_der(der).map_err(|e| malformed(format!("x5c: {e}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = &x5c[0];
    let leaf_key = p256_key(leaf.tbs_certificate().subject_public_key_info())
        .map_err(|_| AttestationError::Signature)?;
    let mut msg = Vec::with_capacity(obj.auth_data.len() + 32);
    msg.extend_from_slice(&obj.auth_data);
    msg.extend_from_slice(&Sha256::digest(client_data_json));
    let sig = P256Signature::from_der(&obj.stmt.sig).map_err(|_| AttestationError::Signature)?;
    leaf_key
        .verify(&msg, &sig)
        .map_err(|_| AttestationError::Signature)?;

    verify_chain(&x5c, &obj.stmt.x5c, roots, now)?;
    check_leaf(leaf, &ad.aaguid)?;

    if ad.aaguid == [0u8; 16] || !aaguids.contains(&ad.aaguid) {
        return Err(AttestationError::AaguidNotAllowed(
            data_encoding::HEXLOWER.encode(&ad.aaguid),
        ));
    }
    let alg = match ad.key {
        CoseKey::Es256(_) => -7,
        CoseKey::Ed25519(_) => -8,
    };
    Ok(RegisteredCredential {
        cred_id: ad.cred_id,
        alg,
        cose_pubkey: ad.cose_pubkey,
        aaguid: ad.aaguid,
        sign_count: ad.sign_count,
    })
}

/// Attestation trust configuration: roots and the AAGUID allowlist.
#[derive(Debug, Clone)]
pub struct AttestationConfig {
    /// Attestation root certificates.
    pub roots: Vec<Certificate>,
    /// Allowlisted AAGUIDs.
    pub aaguids: Vec<[u8; 16]>,
}

/// Parse a comma-separated list of 16-byte hex AAGUIDs (dashes allowed).
pub fn parse_aaguids(list: &str) -> Result<Vec<[u8; 16]>, String> {
    let mut out = Vec::new();
    for part in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let hex: String = part.chars().filter(|c| *c != '-').collect();
        let raw = data_encoding::HEXLOWER_PERMISSIVE
            .decode(hex.as_bytes())
            .map_err(|e| format!("bad AAGUID {part:?}: {e}"))?;
        let a = <[u8; 16]>::try_from(raw.as_slice())
            .map_err(|_| format!("AAGUID {part:?} must be 16 bytes"))?;
        if a == [0u8; 16] {
            return Err("the all-zero AAGUID cannot be allowlisted".into());
        }
        out.push(a);
    }
    Ok(out)
}

impl AttestationConfig {
    /// Build from a PEM bundle and an AAGUID list; both must be non-empty.
    pub fn from_parts(pem: &[u8], aaguids: &str) -> Result<Self, String> {
        let roots =
            Certificate::load_pem_chain(pem).map_err(|e| format!("bad attestation roots: {e}"))?;
        if roots.is_empty() {
            return Err("attestation root bundle holds no certificates".into());
        }
        for r in &roots {
            issuer_key(r.tbs_certificate().subject_public_key_info())
                .map_err(|e| format!("attestation root: {e}"))?;
        }
        let aaguids = parse_aaguids(aaguids)?;
        if aaguids.is_empty() {
            return Err("AAGUID allowlist is empty".into());
        }
        Ok(Self { roots, aaguids })
    }

    /// Load from `RMM_WEBAUTHN_ATTESTATION_ROOTS` (PEM bundle path) and
    /// `RMM_WEBAUTHN_AAGUIDS`. `Ok(None)` when either is unset or empty.
    pub fn from_env() -> Result<Option<Self>, String> {
        let path = std::env::var("RMM_WEBAUTHN_ATTESTATION_ROOTS").unwrap_or_default();
        let list = std::env::var("RMM_WEBAUTHN_AAGUIDS").unwrap_or_default();
        if path.trim().is_empty() || list.trim().is_empty() {
            return Ok(None);
        }
        let pem = std::fs::read(path.trim()).map_err(|e| format!("read {path}: {e}"))?;
        Self::from_parts(&pem, &list).map(Some)
    }
}
