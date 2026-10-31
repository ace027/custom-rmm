//! Golden envelope vectors, checked in both directions.
//!
//! Regenerate with
//! `RMM_REGEN_VECTORS=1 cargo test -p rmm-trust --features sign --test envelope_vectors -- --ignored regen`.

use rmm_trust::envelope::Envelope;
use rmm_trust::keys::PublicKey;
use serde::{Deserialize, Serialize};

const VECTORS: &str = include_str!("vectors/envelope.json");

#[derive(Debug, Serialize, Deserialize)]
struct Case {
    name: String,
    #[serde(rename = "type")]
    type_: String,
    payload_hex: String,
    pubkeys_hex: Vec<String>,
    key_ids_hex: Vec<String>,
    signing_message_hex: String,
    envelope_hex: String,
}

fn load() -> Vec<Case> {
    serde_json::from_str(VECTORS).expect("vectors parse")
}

fn pubkeys(case: &Case) -> Vec<PublicKey> {
    case.pubkeys_hex
        .iter()
        .map(|h| {
            let raw: [u8; 32] = hex::decode(h).expect("hex").try_into().expect("32 bytes");
            PublicKey::from_bytes(&raw).expect("key")
        })
        .collect()
}

fn verify_all(env: &Envelope, keys: &[PublicKey]) -> Result<(), rmm_trust::error::TrustError> {
    for entry in &env.sigs {
        let key = keys
            .iter()
            .find(|k| k.key_id() == entry.key_id)
            .ok_or(rmm_trust::error::TrustError::UnknownKey)?;
        env.verify_sig(entry, key)?;
    }
    Ok(())
}

#[test]
fn vectors_decode_encode_verify() {
    let cases = load();
    assert!(cases.len() >= 4);
    for case in &cases {
        let bytes = hex::decode(&case.envelope_hex).expect("hex");
        let env = Envelope::from_bytes(&bytes).expect("decode");
        assert_eq!(env.r#type, case.type_, "{}", case.name);
        assert_eq!(
            hex::encode(&env.payload.0),
            case.payload_hex,
            "{}",
            case.name
        );
        let ids: Vec<String> = env.sigs.iter().map(|s| hex::encode(s.key_id.0)).collect();
        assert_eq!(ids, case.key_ids_hex, "{}", case.name);
        assert_eq!(
            hex::encode(env.signing_message()),
            case.signing_message_hex,
            "{}",
            case.name
        );
        assert_eq!(
            hex::encode(env.to_bytes().expect("encode")),
            case.envelope_hex
        );
        let keys = pubkeys(case);
        for (k, id) in keys.iter().zip(&case.key_ids_hex) {
            assert_eq!(&hex::encode(k.key_id().0), id, "{}", case.name);
        }
        verify_all(&env, &keys).expect("all signatures verify");
    }
}

#[test]
fn single_bit_flips_never_pass() {
    for case in load() {
        let bytes = hex::decode(&case.envelope_hex).expect("hex");
        let keys = pubkeys(&case);
        for i in 0..bytes.len() {
            for bit in 0..8 {
                let mut m = bytes.clone();
                m[i] ^= 1 << bit;
                if let Ok(env) = Envelope::from_bytes(&m) {
                    assert!(
                        verify_all(&env, &keys).is_err(),
                        "{}: flip byte {i} bit {bit} still verifies",
                        case.name
                    );
                }
            }
        }
    }
}

#[cfg(feature = "sign")]
mod regen {
    use super::*;
    use ciborium::Value;
    use rmm_proto::canonical::encode_value;
    use rmm_trust::envelope::TYPE_COMMAND;
    use rmm_trust::sign::{Ed25519Signer, Signer, sign_envelope};

    fn case(name: &str, type_: &str, payload: Vec<u8>, signers: &[&Ed25519Signer]) -> Case {
        let dyn_signers: Vec<&dyn Signer> = signers.iter().map(|s| *s as &dyn Signer).collect();
        let env = sign_envelope(type_, payload.clone(), &dyn_signers).expect("sign");
        let mut keys: Vec<_> = signers.iter().map(|s| s.public_key()).collect();
        keys.sort_by_key(|k| k.key_id());
        Case {
            name: name.into(),
            type_: type_.into(),
            payload_hex: hex::encode(&payload),
            pubkeys_hex: keys.iter().map(|k| hex::encode(k.to_bytes())).collect(),
            key_ids_hex: env.sigs.iter().map(|s| hex::encode(s.key_id.0)).collect(),
            signing_message_hex: hex::encode(env.signing_message()),
            envelope_hex: hex::encode(env.to_bytes().expect("encode")),
        }
    }

    #[test]
    #[ignore]
    fn regen() {
        if std::env::var("RMM_REGEN_VECTORS").as_deref() != Ok("1") {
            return;
        }
        let a = Ed25519Signer::from_seed(&[1; 32]);
        let b = Ed25519Signer::from_seed(&[2; 32]);
        let doc = encode_value(&Value::Map(vec![
            (Value::Text("a".into()), Value::Integer(1.into())),
            (
                Value::Text("b".into()),
                Value::Array(vec![
                    Value::Bool(true),
                    Value::Null,
                    Value::Bytes(vec![0x00, 0xff]),
                ]),
            ),
        ]))
        .expect("doc");
        let long: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let cases = vec![
            case("empty-payload-single-sig", "rmm.manifest/1", vec![], &[&a]),
            case(
                "cbor-payload-single-sig",
                "rmm.manifest/1",
                doc.clone(),
                &[&a],
            ),
            case("cbor-payload-two-sigs", "rmm.manifest/1", doc, &[&a, &b]),
            case("command-300-byte-payload", TYPE_COMMAND, long, &[&a]),
        ];
        let mut json = serde_json::to_string_pretty(&cases).expect("json");
        json.push('\n');
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/envelope.json");
        std::fs::write(path, json).expect("write vectors");
    }
}
