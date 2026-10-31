//! Shared enrollment wire types and the device fingerprint.
//!
//! Agent and server both compute [`fingerprint`] from [`HwFacts`], so the
//! normalization here is the single source of truth. HTTP bodies are JSON with
//! byte fields encoded as standard (padded) base64 strings.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::canonical;

/// Domain-separation prefix of the fingerprint hash.
const FP_PREFIX: &[u8] = b"RMMFP1";
/// Domain-separation prefix of the enrollment proof-of-possession message.
const ENROLL_PREFIX: &[u8; 10] = b"RMMENROLL1";

/// Hardware identifiers as read from firmware; any field may be unavailable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwFacts {
    /// SMBIOS system UUID.
    pub smbios_uuid: Option<String>,
    /// SMBIOS system serial number.
    pub system_serial: Option<String>,
    /// SMBIOS baseboard serial number.
    pub board_serial: Option<String>,
    /// System manufacturer.
    pub manufacturer: Option<String>,
    /// System product name.
    pub model: Option<String>,
}

/// How reliable a fingerprint is for recognising the same machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FpStrength {
    /// UUID and at least one serial are present and not placeholders.
    Strong,
    /// Not enough genuine identifiers; must never be used to reattach.
    Weak,
}

const JUNK_STRINGS: &[&str] = &[
    "to be filled by o.e.m.",
    "default string",
    "system serial number",
    "not specified",
    "0",
];

const JUNK_UUID: &str = "03000200-0400-0500-0006-000700080009";

/// Normalize an SMBIOS UUID to lowercase hyphenated form; junk becomes empty.
fn normalize_uuid(raw: Option<&str>) -> String {
    let t = raw.unwrap_or("").trim().to_ascii_lowercase();
    let hex: String = t.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return String::new();
    }
    if hex.bytes().all(|b| b == b'0') || hex.bytes().all(|b| b == b'f') {
        return String::new();
    }
    let out = format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    );
    if out == JUNK_UUID {
        return String::new();
    }
    out
}

/// Normalize a serial number (trimmed, uppercased); junk becomes empty.
fn normalize_serial(raw: Option<&str>) -> String {
    let t = raw.unwrap_or("").trim();
    if t.is_empty() || JUNK_STRINGS.iter().any(|j| t.eq_ignore_ascii_case(j)) {
        return String::new();
    }
    t.to_uppercase()
}

/// Compute the device fingerprint: SHA-256 over `RMMFP1` followed by the
/// length-prefixed (u32 big endian) normalized UUID, system serial and
/// baseboard serial.
pub fn fingerprint(hw: &HwFacts) -> ([u8; 32], FpStrength) {
    let uuid = normalize_uuid(hw.smbios_uuid.as_deref());
    let sys = normalize_serial(hw.system_serial.as_deref());
    let board = normalize_serial(hw.board_serial.as_deref());
    let mut h = Sha256::new();
    h.update(FP_PREFIX);
    for part in [&uuid, &sys, &board] {
        // Serials are short firmware strings; saturating keeps this infallible.
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        h.update(len.to_be_bytes());
        h.update(part.as_bytes());
    }
    let strength = if uuid.is_empty() || (sys.is_empty() && board.is_empty()) {
        FpStrength::Weak
    } else {
        FpStrength::Strong
    };
    (h.finalize().into(), strength)
}

/// Standard padded base64 for byte fields in JSON.
mod b64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub(super) fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    pub(super) fn decode(s: &str) -> Result<Vec<u8>, String> {
        let bytes = s.as_bytes();
        if !bytes.len().is_multiple_of(4) {
            return Err("base64 length is not a multiple of 4".into());
        }
        let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
        for (ci, chunk) in bytes.chunks(4).enumerate() {
            let last = (ci + 1) * 4 == bytes.len();
            let mut n: u32 = 0;
            let mut pad = 0;
            for &c in chunk {
                let v = match c {
                    b'A'..=b'Z' => c - b'A',
                    b'a'..=b'z' => c - b'a' + 26,
                    b'0'..=b'9' => c - b'0' + 52,
                    b'+' => 62,
                    b'/' => 63,
                    b'=' if last => {
                        pad += 1;
                        0
                    }
                    _ => return Err("invalid base64 character".into()),
                };
                if pad > 0 && c != b'=' {
                    return Err("data after base64 padding".into());
                }
                n = (n << 6) | u32::from(v);
            }
            if pad > 2 {
                return Err("too much base64 padding".into());
            }
            let triple = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
            out.extend_from_slice(&triple[..3 - pad]);
        }
        Ok(out)
    }

    pub(super) mod bytes32 {
        use super::*;
        pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&encode(v))
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
            let raw = decode(&String::deserialize(d)?).map_err(D::Error::custom)?;
            raw.try_into()
                .map_err(|_| D::Error::custom("expected 32 bytes"))
        }
    }

    pub(super) mod vec {
        use super::*;
        pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&encode(v))
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            decode(&String::deserialize(d)?).map_err(D::Error::custom)
        }
    }

    pub(super) mod opt_vec {
        use super::*;
        pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            match v {
                Some(b) => s.serialize_str(&encode(b)),
                None => s.serialize_none(),
            }
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
            Option::<String>::deserialize(d)?
                .map(|s| decode(&s).map_err(D::Error::custom))
                .transpose()
        }
    }
}

/// Enrollment request sent by a new agent, signed with its own key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// One-time enrollment token (`rmmenr_...`).
    pub token: String,
    /// The agent's Ed25519 public key.
    #[serde(with = "b64::bytes32")]
    pub agent_pubkey: [u8; 32],
    /// Hardware facts used for the fingerprint.
    pub hw: HwFacts,
    /// OS family, e.g. `windows`.
    pub os_family: String,
    /// OS version string.
    pub os_version: String,
    /// Host name.
    pub hostname: String,
    /// Agent version.
    pub agent_version: String,
    /// Unix time in seconds when the request was made.
    pub ts: u64,
    /// Ed25519 signature over [`EnrollRequest::signing_bytes`].
    #[serde(with = "b64::vec")]
    pub proof: Vec<u8>,
}

fn text(s: &str) -> ciborium::Value {
    ciborium::Value::Text(s.to_owned())
}

fn opt_text(s: &Option<String>) -> ciborium::Value {
    s.as_deref().map_or(ciborium::Value::Null, text)
}

impl EnrollRequest {
    /// Message the agent signs: `RMMENROLL1` followed by the SHA-256 of the
    /// canonical CBOR encoding of the request with the `proof` field omitted.
    pub fn signing_bytes(&self) -> [u8; 42] {
        use ciborium::Value;
        let hw = Value::Map(vec![
            (text("smbios_uuid"), opt_text(&self.hw.smbios_uuid)),
            (text("system_serial"), opt_text(&self.hw.system_serial)),
            (text("board_serial"), opt_text(&self.hw.board_serial)),
            (text("manufacturer"), opt_text(&self.hw.manufacturer)),
            (text("model"), opt_text(&self.hw.model)),
        ]);
        let value = Value::Map(vec![
            (text("token"), text(&self.token)),
            (
                text("agent_pubkey"),
                Value::Bytes(self.agent_pubkey.to_vec()),
            ),
            (text("hw"), hw),
            (text("os_family"), text(&self.os_family)),
            (text("os_version"), text(&self.os_version)),
            (text("hostname"), text(&self.hostname)),
            (text("agent_version"), text(&self.agent_version)),
            (text("ts"), Value::Integer(self.ts.into())),
        ]);
        // Only text, bytes, null and integers are used, which always encode.
        let cbor = canonical::encode_value(&value).expect("plain CBOR value is encodable");
        let digest = Sha256::digest(&cbor);
        let mut out = [0u8; 42];
        out[..10].copy_from_slice(ENROLL_PREFIX);
        out[10..].copy_from_slice(&digest);
        out
    }
}

/// Signed trust artifacts handed to a freshly enrolled agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustBundle {
    /// Signed manifest envelope.
    #[serde(with = "b64::opt_vec")]
    pub manifest: Option<Vec<u8>>,
    /// Signed revocations envelope.
    #[serde(with = "b64::opt_vec")]
    pub revocations: Option<Vec<u8>>,
    /// Signed technician list envelope.
    #[serde(with = "b64::opt_vec")]
    pub techlist: Option<Vec<u8>>,
}

/// Server reply to a successful enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    /// Assigned agent id.
    pub agent_id: Uuid,
    /// Device id (stable across reattach).
    pub device_id: Uuid,
    /// Owning client id.
    pub client_id: Uuid,
    /// NATS URL to connect to.
    pub nats_url: String,
    /// Trust artifacts known to the server.
    pub trust: TrustBundle,
    /// Device status, e.g. `active` or `pending_review`.
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> HwFacts {
        HwFacts {
            smbios_uuid: Some("4C4C4544-0042-3510-8051-B7C04F4C4C32".into()),
            system_serial: Some(" abc123 ".into()),
            board_serial: Some("/BRD/9/".into()),
            manufacturer: Some("Dell Inc.".into()),
            model: Some("OptiPlex".into()),
        }
    }

    #[test]
    fn fingerprint_fixed_vector() {
        let (fp, s) = fingerprint(&good());
        assert_eq!(s, FpStrength::Strong);
        let hex: String = fp.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "2695bcb2933469688e579f1a0f8a2bde36b529bda27e7a9036ceb13840a0fb8c"
        );
    }

    #[test]
    fn fingerprint_normalizes_case_and_whitespace() {
        let mut b = good();
        b.smbios_uuid = Some("4c4c4544-0042-3510-8051-b7c04f4c4c32".into());
        b.system_serial = Some("ABC123".into());
        assert_eq!(fingerprint(&good()), fingerprint(&b));
        // Model and manufacturer do not affect the fingerprint.
        b.model = None;
        assert_eq!(fingerprint(&good()), fingerprint(&b));
    }

    #[test]
    fn every_junk_value_normalizes_to_empty() {
        for j in [
            "",
            "  ",
            "0",
            "To be filled by O.E.M.",
            "default string",
            "SYSTEM SERIAL NUMBER",
            "Not Specified",
        ] {
            assert_eq!(normalize_serial(Some(j)), "", "{j:?}");
        }
        assert_eq!(normalize_serial(None), "");
        for j in [
            "00000000-0000-0000-0000-000000000000",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
            "ffffffffffffffffffffffffffffffff",
            "03000200-0400-0500-0006-000700080009",
            "03000200-0400-0500-0006-000700080009 ",
            "not-a-uuid",
            "",
        ] {
            assert_eq!(normalize_uuid(Some(j)), "", "{j:?}");
        }
        assert_eq!(normalize_uuid(None), "");
        assert_eq!(
            normalize_uuid(Some("4C4C4544004235108051B7C04F4C4C32")),
            "4c4c4544-0042-3510-8051-b7c04f4c4c32"
        );
    }

    #[test]
    fn strength_rules() {
        let mut h = good();
        assert_eq!(fingerprint(&h).1, FpStrength::Strong);
        h.board_serial = Some("Default string".into());
        assert_eq!(fingerprint(&h).1, FpStrength::Strong, "one serial suffices");
        h.system_serial = Some("0".into());
        assert_eq!(fingerprint(&h).1, FpStrength::Weak, "no serials");
        let mut h = good();
        h.smbios_uuid = Some("00000000-0000-0000-0000-000000000000".into());
        assert_eq!(fingerprint(&h).1, FpStrength::Weak, "junk uuid");
        assert_eq!(fingerprint(&HwFacts::default()).1, FpStrength::Weak);
    }

    #[test]
    fn fingerprint_parts_are_length_prefixed() {
        let mut a = good();
        let mut b = good();
        a.system_serial = Some("AB".into());
        a.board_serial = Some("C".into());
        b.system_serial = Some("A".into());
        b.board_serial = Some("BC".into());
        assert_ne!(fingerprint(&a).0, fingerprint(&b).0);
    }

    fn req() -> EnrollRequest {
        EnrollRequest {
            token: "rmmenr_AAAA".into(),
            agent_pubkey: [7; 32],
            hw: good(),
            os_family: "windows".into(),
            os_version: "Windows 11 Pro 24H2 (build 26100)".into(),
            hostname: "pc1".into(),
            agent_version: "0.1.0".into(),
            ts: 1_700_000_000,
            proof: vec![1, 2, 3],
        }
    }

    #[test]
    fn signing_bytes_shape_and_proof_exclusion() {
        let r = req();
        let sb = r.signing_bytes();
        assert_eq!(sb.len(), 42);
        assert_eq!(&sb[..10], b"RMMENROLL1");
        let mut other = r.clone();
        other.proof = vec![9; 64];
        assert_eq!(other.signing_bytes(), sb);
        other.ts += 1;
        assert_ne!(other.signing_bytes(), sb);
        let mut other = r.clone();
        other.hw.model = None;
        assert_ne!(other.signing_bytes(), sb);
    }

    #[test]
    fn request_json_round_trip_with_base64() {
        let r = req();
        let json = serde_json::to_value(&r).expect("serialize");
        assert_eq!(
            json["agent_pubkey"],
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
        );
        assert_eq!(json["proof"], "AQID");
        let back: EnrollRequest = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, r);
    }

    #[test]
    fn response_json_round_trip() {
        let resp = EnrollResponse {
            agent_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            client_id: Uuid::from_u128(3),
            nats_url: "wss://rmm.example/nats".into(),
            trust: TrustBundle {
                manifest: Some(vec![0, 255, 128, 1]),
                revocations: None,
                techlist: Some(vec![]),
            },
            status: "active".into(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: EnrollResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    #[test]
    fn base64_matches_rfc4648_and_rejects_bad_input() {
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64::encode(raw.as_bytes()), enc);
            assert_eq!(b64::decode(enc).expect("decode"), raw.as_bytes());
        }
        for bad in ["Zg=", "Z", "Zm9v!", "Zg=a", "=Zg=", "Zg==Zm9v"] {
            assert!(b64::decode(bad).is_err(), "{bad}");
        }
        let short = serde_json::json!({"agent_pubkey": "AQID"});
        assert!(serde_json::from_value::<EnrollRequest>(short).is_err());
    }
}
