//! Golden trust-document vectors, checked in both directions.
//!
//! Each case stores the document as JSON (human-readable, hex bytes), its
//! canonical CBOR encoding and, for signed document types, a signed envelope.
//!
//! Regenerate with
//! `RMM_REGEN_VECTORS=1 cargo test -p rmm-trust --features sign --test docs_vectors -- --ignored regen`.

use std::fmt::Debug;

use rmm_proto::canonical::to_canonical_vec;
use rmm_trust::docs::{
    ArtifactRevocations, Command, CommandBody, ShellGrant, TechnicianList, TrustManifest,
    decode_doc,
};
use rmm_trust::envelope::Envelope;
use rmm_trust::error::TrustError;
use rmm_trust::keys::PublicKey;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const VECTORS: &str = include_str!("vectors/docs.json");

#[derive(Debug, Serialize, Deserialize)]
struct Case {
    name: String,
    doc: String,
    #[serde(rename = "type")]
    type_: Option<String>,
    json: serde_json::Value,
    cbor_hex: String,
    pubkeys_hex: Vec<String>,
    envelope_hex: Option<String>,
}

fn load() -> Vec<Case> {
    serde_json::from_str(VECTORS).expect("vectors parse")
}

fn check<T>(case: &Case, validate: fn(&T) -> Result<(), TrustError>)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let name = &case.name;
    let doc: T = serde_json::from_value(case.json.clone()).expect("json decode");
    assert_eq!(
        serde_json::to_value(&doc).expect("json encode"),
        case.json,
        "{name}: json round trip"
    );
    let cbor = hex::decode(&case.cbor_hex).expect("hex");
    assert_eq!(
        to_canonical_vec(&doc).expect("encode"),
        cbor,
        "{name}: encode"
    );
    assert_eq!(
        decode_doc::<T>(&cbor).expect("decode"),
        doc,
        "{name}: decode"
    );
    validate(&doc).expect("valid");

    if let Some(env_hex) = &case.envelope_hex {
        let env = Envelope::from_bytes(&hex::decode(env_hex).expect("hex")).expect("envelope");
        assert_eq!(env.payload.0, cbor, "{name}: envelope payload");
        assert_eq!(Some(&env.r#type), case.type_.as_ref(), "{name}: type");
        assert!(!env.sigs.is_empty());
        for entry in &env.sigs {
            let key = case
                .pubkeys_hex
                .iter()
                .map(|h| {
                    let raw: [u8; 32] = hex::decode(h).expect("hex").try_into().expect("32");
                    PublicKey::from_bytes(&raw).expect("key")
                })
                .find(|k| k.key_id() == entry.key_id)
                .expect("signer key in vector");
            env.verify_sig(entry, &key).expect("signature verifies");
        }
    }
}

#[test]
fn vectors_both_directions() {
    let cases = load();
    let mut kinds: Vec<&str> = cases.iter().map(|c| c.doc.as_str()).collect();
    kinds.sort_unstable();
    kinds.dedup();
    assert_eq!(
        kinds,
        [
            "command",
            "manifest",
            "revocations",
            "shell-grant",
            "techlist"
        ]
    );
    for case in &cases {
        match case.doc.as_str() {
            "manifest" => check::<TrustManifest>(case, TrustManifest::validate),
            "revocations" => check::<ArtifactRevocations>(case, ArtifactRevocations::validate),
            "command" => check::<Command>(case, Command::validate),
            "shell-grant" => check::<ShellGrant>(case, ShellGrant::validate),
            "techlist" => check::<TechnicianList>(case, TechnicianList::validate),
            other => panic!("unknown doc kind {other}"),
        }
    }
}

#[test]
fn json_uses_hex_and_role_strings() {
    let cases = load();
    let m = &cases
        .iter()
        .find(|c| c.doc == "manifest")
        .expect("manifest")
        .json;
    let root = m["root_keys"][0].as_str().expect("hex string");
    assert_eq!(root.len(), 64);
    assert!(
        root.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert!(m["thresholds"]["artifact-revoke"].is_u64());
    assert_eq!(m["certs"][0]["roles"][0], "catalog");
}

#[test]
fn every_command_body_variant_present() {
    let mut seen = [false; 4];
    for case in load().iter().filter(|c| c.doc == "command") {
        let cmd: Command = serde_json::from_value(case.json.clone()).expect("cmd");
        let i = match cmd.body {
            CommandBody::Invoke { .. } => 0,
            CommandBody::ShellOpen { .. } => 1,
            CommandBody::TrustUpdate { .. } => 2,
            CommandBody::Collect { .. } => 3,
        };
        seen[i] = true;
    }
    assert_eq!(seen, [true; 4]);
}

#[test]
fn command_body_tag_is_kind() {
    for case in load().iter().filter(|c| c.doc == "command") {
        let kind = case.json["body"]["kind"].as_str().expect("kind tag");
        assert!(["invoke", "shell-open", "trust-update", "collect"].contains(&kind));
        if kind == "collect" {
            assert!(case.json["body"]["collect_kind"].is_string());
        }
    }
}

fn manifest_value() -> ciborium::Value {
    let case = load()
        .into_iter()
        .find(|c| c.doc == "manifest")
        .expect("manifest");
    let cbor = hex::decode(case.cbor_hex).expect("hex");
    rmm_proto::canonical::check_canonical(&cbor).expect("canonical")
}

#[test]
fn unknown_field_rejected() {
    let ciborium::Value::Map(mut entries) = manifest_value() else {
        panic!("map");
    };
    entries.push((ciborium::Value::Text("extra".into()), ciborium::Value::Null));
    let bytes = rmm_proto::canonical::encode_value(&ciborium::Value::Map(entries)).expect("enc");
    assert!(decode_doc::<TrustManifest>(&bytes).is_err());
}

#[test]
fn missing_field_rejected() {
    let ciborium::Value::Map(mut entries) = manifest_value() else {
        panic!("map");
    };
    entries.retain(|(k, _)| k.as_text() != Some("revocation_mirrors"));
    let bytes = rmm_proto::canonical::encode_value(&ciborium::Value::Map(entries)).expect("enc");
    assert!(decode_doc::<TrustManifest>(&bytes).is_err());
}

#[test]
fn text_where_bytes_expected_rejected() {
    // A hex text string in place of a byte string is not the canonical
    // encoding of the document and must not decode.
    let ciborium::Value::Map(mut entries) = manifest_value() else {
        panic!("map");
    };
    for (k, v) in &mut entries {
        if k.as_text() == Some("root_keys") {
            *v = ciborium::Value::Array(vec![ciborium::Value::Text("ab".repeat(32))]);
        }
    }
    let bytes = rmm_proto::canonical::encode_value(&ciborium::Value::Map(entries)).expect("enc");
    assert!(decode_doc::<TrustManifest>(&bytes).is_err());
}

#[cfg(feature = "sign")]
mod regen {
    use std::collections::BTreeMap;

    use super::*;
    use rmm_trust::docs::{Cert, Credential, Role, Technician};
    use rmm_trust::envelope::{TYPE_COMMAND, TYPE_MANIFEST, TYPE_REVOCATIONS, TYPE_TECHLIST};
    use rmm_trust::keys::{Bytes, KeyId};
    use rmm_trust::sign::{Ed25519Signer, Signer, sign_envelope};

    const T0: u64 = 1_800_000_000;
    const DAY: u64 = 86_400;

    fn case<T: Serialize>(
        name: &str,
        doc: &str,
        value: &T,
        signed: Option<(&str, &Ed25519Signer)>,
    ) -> Case {
        let cbor = to_canonical_vec(value).expect("encode");
        let (type_, pubkeys_hex, envelope_hex) = match signed {
            Some((t, s)) => {
                let env = sign_envelope(t, cbor.clone(), &[s as &dyn Signer]).expect("sign");
                (
                    Some(t.to_owned()),
                    vec![hex::encode(s.public_key().to_bytes())],
                    Some(hex::encode(env.to_bytes().expect("env"))),
                )
            }
            None => (None, vec![], None),
        };
        Case {
            name: name.into(),
            doc: doc.into(),
            type_,
            json: serde_json::to_value(value).expect("json"),
            cbor_hex: hex::encode(cbor),
            pubkeys_hex,
            envelope_hex,
        }
    }

    fn cert(s: &Ed25519Signer, roles: Vec<Role>, label: &str) -> Cert {
        let pk = s.public_key();
        Cert {
            key_id: pk.key_id(),
            pubkey: Bytes(pk.to_bytes().to_vec()),
            alg: "ed25519".into(),
            roles,
            not_before: T0 - DAY,
            not_after: T0 + 730 * DAY,
            label: label.into(),
        }
    }

    fn command(n: u8, body: CommandBody) -> Command {
        Command {
            cmd_id: Bytes(vec![n; 16]),
            agent_id: "agent-1".into(),
            client_id: "client-1".into(),
            issued_at: T0,
            expires_at: T0 + 600,
            policy_hash: Bytes(vec![0x5a; 32]),
            body,
        }
    }

    #[test]
    #[ignore]
    fn regen() {
        if std::env::var("RMM_REGEN_VECTORS").as_deref() != Ok("1") {
            return;
        }
        let root = Ed25519Signer::from_seed(&[0xa1; 32]);
        let s1 = Ed25519Signer::from_seed(&[0x51; 32]);
        let c = Ed25519Signer::from_seed(&[0xc0; 32]);

        let manifest = TrustManifest {
            seq: 1,
            issued_at: T0,
            expires_at: T0 + 365 * DAY,
            root_keys: vec![Bytes(root.public_key().to_bytes().to_vec())],
            root_threshold: 1,
            certs: vec![
                cert(
                    &s1,
                    vec![
                        Role::Catalog,
                        Role::Release,
                        Role::Techlist,
                        Role::ArtifactRevoke,
                    ],
                    "signing-daily",
                ),
                cert(&c, vec![Role::Command], "server-command"),
            ],
            thresholds: BTreeMap::from([
                (Role::Catalog, 1),
                (Role::Release, 1),
                (Role::Techlist, 1),
                (Role::ArtifactRevoke, 1),
                (Role::Command, 1),
            ]),
            revoked_keys: vec![KeyId([0xee; 32])],
            console_rp_id: "rmm.example.com".into(),
            console_origins: vec!["https://rmm.example.com".into()],
            capability_ceiling: vec!["inventory".into(), "services".into()],
            revocation_mirrors: vec![],
        };
        let revocations = ArtifactRevocations {
            seq: 7,
            issued_at: T0,
            expires_at: T0 + 45 * DAY,
            revoked_hashes: vec![KeyId([0x11; 32]), KeyId([0x22; 32])],
        };
        let techlist = TechnicianList {
            seq: 3,
            issued_at: T0,
            expires_at: T0 + 90 * DAY,
            techs: vec![Technician {
                tech_id: "tech-alice".into(),
                client_scope: vec!["*".into()],
                perms: vec!["shell".into(), "invoke".into()],
                creds: vec![
                    Credential {
                        cred_id: Bytes(vec![0xc1; 20]),
                        alg: -7,
                        cose_pubkey: Bytes(vec![0xa5, 0x01, 0x02]),
                        aaguid: Bytes(vec![0xaa; 16]),
                    },
                    Credential {
                        cred_id: Bytes(vec![0xc2; 20]),
                        alg: -8,
                        cose_pubkey: Bytes(vec![0xa4, 0x01, 0x01]),
                        aaguid: Bytes(vec![0xab; 16]),
                    },
                ],
            }],
        };
        let grant = ShellGrant {
            grant_id: Bytes(vec![0x67; 16]),
            agent_id: "agent-1".into(),
            client_id: "client-1".into(),
            tech_id: "tech-alice".into(),
            cred_id: Bytes(vec![0xc1; 20]),
            issued_at: T0,
            open_by: T0 + 60,
            max_duration: 3600,
            shell: "powershell".into(),
            record: true,
            e2e_pubkey: None,
        };
        let invoke = command(
            1,
            CommandBody::Invoke {
                definition: Bytes(vec![0xde, 0xf0]),
                params: BTreeMap::from([
                    ("count".to_owned(), ciborium::Value::Integer(3.into())),
                    ("delta".to_owned(), ciborium::Value::Integer((-2).into())),
                    ("force".to_owned(), ciborium::Value::Bool(false)),
                    (
                        "service".to_owned(),
                        ciborium::Value::Text("Spooler".into()),
                    ),
                ]),
            },
        );
        let shell = command(
            2,
            CommandBody::ShellOpen {
                grant: Bytes(to_canonical_vec(&grant).expect("grant")),
                assertion: Bytes(vec![0x01, 0x02, 0x03]),
            },
        );
        let update = command(
            3,
            CommandBody::TrustUpdate {
                manifest: Some(Bytes(vec![0x0a])),
                revocations: None,
                techlist: Some(Bytes(vec![0x0b])),
            },
        );
        let collect = command(
            4,
            CommandBody::Collect {
                kind: "inventory".into(),
            },
        );

        let cases = vec![
            case(
                "manifest",
                "manifest",
                &manifest,
                Some((TYPE_MANIFEST, &root)),
            ),
            case(
                "revocations",
                "revocations",
                &revocations,
                Some((TYPE_REVOCATIONS, &s1)),
            ),
            case(
                "techlist",
                "techlist",
                &techlist,
                Some((TYPE_TECHLIST, &s1)),
            ),
            case("shell-grant", "shell-grant", &grant, None),
            case(
                "command-invoke",
                "command",
                &invoke,
                Some((TYPE_COMMAND, &c)),
            ),
            case(
                "command-shell-open",
                "command",
                &shell,
                Some((TYPE_COMMAND, &c)),
            ),
            case(
                "command-trust-update",
                "command",
                &update,
                Some((TYPE_COMMAND, &c)),
            ),
            case(
                "command-collect",
                "command",
                &collect,
                Some((TYPE_COMMAND, &c)),
            ),
        ];
        let mut json = serde_json::to_string_pretty(&cases).expect("json");
        json.push('\n');
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/docs.json");
        std::fs::write(path, json).expect("write vectors");
    }
}
