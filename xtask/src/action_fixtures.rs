//! `xtask action-fixtures [--out DIR]`: deterministic golden files for the
//! agent's command-rejection and shell-verification tests. Uses rmm-trust's
//! `sign` feature, which is fine here because xtask is not an agent-side crate.
//!
//! xtask has no general-purpose signer (rmm-trust's signer only signs the
//! 39-byte envelope message), so WebAuthn assertions made with a technician
//! credential are produced by the agent tests themselves from the documented
//! credential seeds; the fixtures carry the signed trust documents and a
//! `ShellOpen` that the server command key alone can produce.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ciborium::Value;
use rmm_proto::canonical::to_canonical_vec;
use rmm_recipe::definition::{Arg, Definition, ParamKind, ParamSpec, Step};
use rmm_trust::docs::{
    ArtifactRevocations, COSE_EDDSA, Cert, Command, CommandBody, Credential, Role, ShellGrant,
    Technician, TechnicianList, TrustManifest,
};
use rmm_trust::envelope::{Envelope, TYPE_COMMAND, TYPE_MANIFEST, TYPE_REVOCATIONS, TYPE_TECHLIST};
use rmm_trust::keys::{Bytes, KeyId};
use rmm_trust::sign::{Ed25519Signer, Signer, sign_envelope};
use rmm_trust::webauthn::{Assertion, shell_challenge};

/// The fixed "current time" all fixtures are relative to (2027-01-15 08:00 UTC).
pub const NOW: u64 = 1_800_000_000;
/// Agent the valid commands are addressed to.
pub const AGENT_ID: &str = "agent_0000000000000001";
/// Another agent, for the wrong-agent fixture.
pub const OTHER_AGENT_ID: &str = "agent_0000000000000002";
/// Client (tenant) of the agent.
pub const CLIENT_ID: &str = "client_0000000000000001";

const DAY: u64 = 86_400;
const SPOOLER_JSON: &str = include_str!("../../catalog/printing.spooler-restart.json");

const ROOT_SEED: [u8; 32] = [0x11; 32];
const CATALOG_SEED: [u8; 32] = [0x22; 32];
const COMMAND_SEED: [u8; 32] = [0x33; 32];
const ROGUE_SEED: [u8; 32] = [0x44; 32];
/// Software Ed25519 credential seeds of the fixture technicians.
const ALICE_CRED_SEED: [u8; 32] = [0x66; 32];
const BOB_CRED_SEED: [u8; 32] = [0x67; 32];
const CAROL_CRED_SEED: [u8; 32] = [0x68; 32];
/// Technician in scope of the fixture client.
pub const ALICE: &str = "tech_alice";
/// Technician scoped to another client only.
pub const BOB: &str = "tech_bob";
/// Technician with scope `*`.
pub const CAROL: &str = "tech_carol";
const OTHER_CLIENT_ID: &str = "client_0000000000000099";
const RP_ID: &str = "console.example.test";
const ORIGIN: &str = "https://console.example.test";

type Res<T> = Result<T, String>;

fn e<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> String {
    move |err| format!("{what}: {err}")
}

fn sign(type_: &str, payload: Vec<u8>, key: &Ed25519Signer) -> Res<Envelope> {
    sign_envelope(type_, payload, &[key]).map_err(e("sign"))
}

fn env_bytes(env: &Envelope) -> Res<Vec<u8>> {
    env.to_bytes().map_err(e("encode envelope"))
}

fn cert(key: &Ed25519Signer, roles: Vec<Role>, label: &str) -> Cert {
    Cert {
        key_id: key.key_id(),
        pubkey: Bytes(key.public_key().to_bytes().to_vec()),
        alg: "ed25519".into(),
        roles,
        not_before: NOW - 2 * DAY,
        not_after: NOW + 365 * DAY,
        label: label.into(),
    }
}

fn definition(id: &str, steps: Vec<Step>, params: Vec<ParamSpec>) -> Res<Definition> {
    let mut def: Definition = serde_json::from_str(SPOOLER_JSON).map_err(e("spooler json"))?;
    def.id = id.into();
    def.params = params;
    def.steps = steps;
    Ok(def)
}

fn step(block: &str, args: Vec<(&str, Arg)>) -> Step {
    Step {
        block: block.into(),
        args: args.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        retries: 0,
        on_fail: rmm_recipe::definition::OnFail::Abort,
    }
}

struct Ctx {
    command: Ed25519Signer,
}

impl Ctx {
    fn command(
        &self,
        n: u8,
        agent: &str,
        issued_at: u64,
        expires_at: u64,
        definition: &Envelope,
        params: BTreeMap<String, Value>,
    ) -> Res<Envelope> {
        let cmd = Command {
            cmd_id: Bytes(vec![n; 16]),
            agent_id: agent.into(),
            client_id: CLIENT_ID.into(),
            issued_at,
            expires_at,
            policy_hash: Bytes(vec![0; 32]),
            body: CommandBody::Invoke {
                definition: Bytes(env_bytes(definition)?),
                params,
            },
        };
        let payload = to_canonical_vec(&cmd).map_err(e("encode command"))?;
        sign(TYPE_COMMAND, payload, &self.command)
    }
}

/// SHA-256 via the envelope content id (SHA-256 of the payload), so xtask
/// needs no hash crate of its own.
fn sha256(data: &[u8]) -> [u8; 32] {
    Envelope {
        v: 1,
        r#type: String::new(),
        payload: Bytes(data.to_vec()),
        sigs: Vec::new(),
    }
    .content_id()
}

fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for ch in data.chunks(3) {
        let n = ch
            .iter()
            .enumerate()
            .fold(0u32, |a, (i, b)| a | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=ch.len() {
            out.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// COSE_Key of an Ed25519 (OKP, alg -8, crv 6) credential.
fn ed25519_cose(key: &Ed25519Signer) -> Res<Vec<u8>> {
    let map = Value::Map(vec![
        (Value::from(1), Value::from(1)),
        (Value::from(3), Value::from(-8)),
        (Value::from(-1), Value::from(6)),
        (
            Value::from(-2),
            Value::Bytes(key.public_key().to_bytes().to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&map, &mut out).map_err(e("encode cose key"))?;
    Ok(out)
}

fn tech(id: &str, scope: &[&str], cred_n: u8, seed: &[u8; 32]) -> Res<Technician> {
    Ok(Technician {
        tech_id: id.into(),
        client_scope: scope.iter().map(|s| (*s).to_owned()).collect(),
        perms: vec!["shell".into()],
        creds: vec![Credential {
            cred_id: Bytes(vec![cred_n; 16]),
            alg: COSE_EDDSA,
            cose_pubkey: Bytes(ed25519_cose(&Ed25519Signer::from_seed(seed))?),
            aaguid: Bytes(vec![0xAA; 16]),
        }],
    })
}

fn readme() -> String {
    format!(
        "# Action golden fixtures\n\n\
Generated by `cargo run -p xtask -- action-fixtures`. Do not edit by hand;\n\
the output is deterministic and CI checks it with `git diff --exit-code`.\n\n\
All times are relative to `NOW = {NOW}` (2027-01-15 08:00 UTC). Tests must use a\n\
fixed clock at `NOW`. Agent `{AGENT_ID}`, client `{CLIENT_ID}`.\n\
Key seeds: root 0x11, catalog 0x22, command 0x33, rogue 0x44 (repeated 32 times).\n\n\
## Trust documents\n\n\
- `root.pub.hex`: the root public key (compile it in as the single root, threshold 1).\n\
- `manifest.env`: root-signed manifest (seq 1). Catalog key holds catalog, artifact-revoke and\n\
  techlist; command key holds command. Thresholds 1. capability_ceiling [service, files.write].\n\
- `revocations.env`: catalog-signed revocations (seq 1) listing the content id of\n\
  `definition-revoked.env`.\n\n\
## Definitions (envelopes, type rmm.definition/1)\n\n\
- `definition-valid.env`: the spooler definition signed by the catalog key.\n\
- `definition-revoked.env`: a spooler variant (id printing.spooler-revoked) signed by the catalog key; revoked.\n\
- `definition-rogue.env`: the spooler definition signed by a key that is not certified.\n\
- `definition-unknown-block.env`: catalog-signed; contains block `shell.exec`.\n\
- `definition-param.env`: catalog-signed; declares int param `wait_s` (1..=120, required).\n\n\
## Commands (envelopes, type rmm.command/1, signed by the command key)\n\n\
- `cmd-valid.env`: valid spooler invocation (issued NOW-10, expires NOW+590).\n\
- `cmd-expired.env`: expires at NOW-400 (outside the 300 s skew).\n\
- `cmd-replay.env`: valid; feed the same bytes twice, the second must be a replay.\n\
- `cmd-tampered.env`: `cmd-valid.env` with one payload bit flipped (bad signature).\n\
- `cmd-revoked.env`: invokes `definition-revoked.env`.\n\
- `cmd-rogue-definition.env`: invokes `definition-rogue.env` (definition not catalog-signed).\n\
- `cmd-wrong-agent.env`: addressed to `{OTHER_AGENT_ID}`.\n\
- `cmd-unknown-block.env`: invokes `definition-unknown-block.env` (fails static validation).\n\
- `cmd-bad-param.env`: invokes `definition-param.env` with `wait_s = 9999` (fails param validation).\n\
- `cmd-good-param.env`: invokes `definition-param.env` with `wait_s = 30` (passes).\n\n\
## Shell (technician list signed by the catalog key, which holds the techlist role)\n\n\
Manifest console RP id `{RP_ID}`, origin `{ORIGIN}`. Credentials are software Ed25519\n\
(COSE alg -8, crv 6) with AAGUID 0xAA x16; the tests sign assertions with these seeds.\n\n\
- `techlist.env`: seq 1 (issued NOW-86400, expires NOW+30 days). `{ALICE}` scope [`{CLIENT_ID}`],\n\
  cred id 0xA1 x16, seed 0x66; `{BOB}` scope [`{OTHER_CLIENT_ID}`], cred id 0xB1 x16, seed 0x67;\n\
  `{CAROL}` scope [`*`], cred id 0xC1 x16, seed 0x68.\n\
- `techlist-removed.env`: seq 2, the same list without `{ALICE}`. Applying `techlist.env` after it\n\
  is a rollback.\n\
- `cmd-shell-server-only.env`: ShellOpen (cmd id 0x20 x16, issued NOW-10, expires NOW+590) with a\n\
  valid grant for `{ALICE}` (grant id 0x21 x16, cred 0xA1 x16, issued NOW-5, open_by NOW+60,\n\
  max_duration 3600, shell `sh`) and an assertion with correct authenticator and client data\n\
  but a signature the server cannot make (64 zero bytes): what the command key alone produces.\n"
    )
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> Res<()> {
    std::fs::write(dir.join(name), bytes).map_err(|err| format!("write {name}: {err}"))
}

/// Generate all fixtures into `out`.
pub fn run(out: &Path) -> Res<()> {
    std::fs::create_dir_all(out).map_err(e("create out dir"))?;
    let root = Ed25519Signer::from_seed(&ROOT_SEED);
    let catalog = Ed25519Signer::from_seed(&CATALOG_SEED);
    let command = Ed25519Signer::from_seed(&COMMAND_SEED);
    let rogue = Ed25519Signer::from_seed(&ROGUE_SEED);

    let manifest = TrustManifest {
        seq: 1,
        issued_at: NOW - DAY,
        expires_at: NOW + 300 * DAY,
        root_keys: vec![Bytes(root.public_key().to_bytes().to_vec())],
        root_threshold: 1,
        certs: vec![
            cert(
                &catalog,
                vec![Role::Catalog, Role::ArtifactRevoke, Role::Techlist],
                "fixture catalog",
            ),
            cert(&command, vec![Role::Command], "fixture command"),
        ],
        thresholds: BTreeMap::from([
            (Role::Catalog, 1),
            (Role::ArtifactRevoke, 1),
            (Role::Techlist, 1),
            (Role::Command, 1),
        ]),
        revoked_keys: vec![],
        console_rp_id: RP_ID.into(),
        console_origins: vec![ORIGIN.into()],
        capability_ceiling: vec!["service".into(), "files.write".into()],
        revocation_mirrors: vec![],
    };
    let manifest_env = sign(
        TYPE_MANIFEST,
        to_canonical_vec(&manifest).map_err(e("encode manifest"))?,
        &root,
    )?;

    // Definitions.
    let spooler: Definition = serde_json::from_str(SPOOLER_JSON).map_err(e("spooler json"))?;
    let def_env = |d: &Definition, key: &Ed25519Signer| -> Res<Envelope> {
        sign(
            rmm_recipe::definition::TYPE_DEFINITION,
            d.to_canonical().map_err(e("encode definition"))?,
            key,
        )
    };
    let valid_def = def_env(&spooler, &catalog)?;
    let mut revoked = spooler.clone();
    revoked.id = "printing.spooler-revoked".into();
    let revoked_def = def_env(&revoked, &catalog)?;
    let rogue_def = def_env(&spooler, &rogue)?;
    let unknown = definition(
        "test.unknown-block",
        vec![step("shell.exec", vec![])],
        vec![],
    )?;
    let unknown_def = def_env(
        &Definition {
            precheck: vec![],
            verify: vec![],
            rollback: vec![],
            ..unknown
        },
        &catalog,
    )?;
    let wait_s = ParamSpec {
        name: "wait_s".into(),
        kind: ParamKind::Int,
        required: true,
        enum_values: vec![],
        max_len: None,
        min: Some(1),
        max: Some(120),
    };
    let param = definition(
        "test.param-wait",
        vec![step(
            "service.wait",
            vec![
                ("name", Arg::Lit(Value::Text("Spooler".into()))),
                ("state", Arg::Lit(Value::Text("running".into()))),
                ("timeout_s", Arg::Param("wait_s".into())),
            ],
        )],
        vec![wait_s],
    )?;
    let param_def = def_env(
        &Definition {
            precheck: vec![],
            verify: vec![],
            rollback: vec![],
            ..param
        },
        &catalog,
    )?;

    let revocations = ArtifactRevocations {
        seq: 1,
        issued_at: NOW - 3600,
        expires_at: NOW + 30 * DAY,
        revoked_hashes: vec![KeyId(revoked_def.content_id())],
    };
    let revocations_env = sign(
        TYPE_REVOCATIONS,
        to_canonical_vec(&revocations).map_err(e("encode revocations"))?,
        &catalog,
    )?;

    // Commands.
    let ctx = Ctx { command };
    let none = BTreeMap::new;
    let (ok_from, ok_to) = (NOW - 10, NOW + 590);
    let valid = ctx.command(1, AGENT_ID, ok_from, ok_to, &valid_def, none())?;
    let expired = ctx.command(2, AGENT_ID, NOW - 1000, NOW - 400, &valid_def, none())?;
    let replay = ctx.command(3, AGENT_ID, ok_from, ok_to, &valid_def, none())?;
    let mut tampered = valid.clone();
    if let Some(b) = tampered.payload.0.last_mut() {
        *b ^= 1;
    }
    let revoked_cmd = ctx.command(4, AGENT_ID, ok_from, ok_to, &revoked_def, none())?;
    let rogue_cmd = ctx.command(5, AGENT_ID, ok_from, ok_to, &rogue_def, none())?;
    let wrong_agent = ctx.command(6, OTHER_AGENT_ID, ok_from, ok_to, &valid_def, none())?;
    let unknown_cmd = ctx.command(7, AGENT_ID, ok_from, ok_to, &unknown_def, none())?;
    let wait = |n: i64| BTreeMap::from([("wait_s".to_owned(), Value::Integer(n.into()))]);
    let bad_param = ctx.command(8, AGENT_ID, ok_from, ok_to, &param_def, wait(9999))?;
    let good_param = ctx.command(9, AGENT_ID, ok_from, ok_to, &param_def, wait(30))?;

    // Shell: technician lists and a ShellOpen the command key alone can make.
    let techs = vec![
        tech(ALICE, &[CLIENT_ID], 0xA1, &ALICE_CRED_SEED)?,
        tech(BOB, &[OTHER_CLIENT_ID], 0xB1, &BOB_CRED_SEED)?,
        tech(CAROL, &["*"], 0xC1, &CAROL_CRED_SEED)?,
    ];
    let techlist_env = |seq: u64, techs: Vec<Technician>| -> Res<Envelope> {
        let list = TechnicianList {
            seq,
            issued_at: NOW - DAY,
            expires_at: NOW + 30 * DAY,
            techs,
        };
        sign(
            TYPE_TECHLIST,
            to_canonical_vec(&list).map_err(e("encode techlist"))?,
            &catalog,
        )
    };
    let techlist = techlist_env(1, techs.clone())?;
    let techlist_removed = techlist_env(2, techs[1..].to_vec())?;
    let grant = ShellGrant {
        grant_id: Bytes(vec![0x21; 16]),
        agent_id: AGENT_ID.into(),
        client_id: CLIENT_ID.into(),
        tech_id: ALICE.into(),
        cred_id: Bytes(vec![0xA1; 16]),
        issued_at: NOW - 5,
        open_by: NOW + 60,
        max_duration: 3600,
        shell: "sh".into(),
        record: true,
        e2e_pubkey: None,
    };
    let grant_bytes = to_canonical_vec(&grant).map_err(e("encode grant"))?;
    let mut auth_data = sha256(RP_ID.as_bytes()).to_vec();
    auth_data.push(0x05); // UP | UV
    auth_data.extend_from_slice(&1u32.to_be_bytes());
    let client_data = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{ORIGIN}\"}}",
        b64url(&shell_challenge(&grant_bytes))
    );
    let forged = Assertion {
        authenticator_data: auth_data,
        client_data_json: client_data.into_bytes(),
        signature: vec![0; 64],
    };
    let shell_cmd = Command {
        cmd_id: Bytes(vec![0x20; 16]),
        agent_id: AGENT_ID.into(),
        client_id: CLIENT_ID.into(),
        issued_at: ok_from,
        expires_at: ok_to,
        policy_hash: Bytes(vec![0; 32]),
        body: CommandBody::ShellOpen {
            grant: Bytes(grant_bytes),
            assertion: Bytes(to_canonical_vec(&forged).map_err(e("encode assertion"))?),
        },
    };
    let shell_server_only = sign(
        TYPE_COMMAND,
        to_canonical_vec(&shell_cmd).map_err(e("encode command"))?,
        &ctx.command,
    )?;

    let files: Vec<(&str, Vec<u8>)> = vec![
        (
            "root.pub.hex",
            format!("{}\n", hex::encode(root.public_key().to_bytes())).into_bytes(),
        ),
        ("manifest.env", env_bytes(&manifest_env)?),
        ("revocations.env", env_bytes(&revocations_env)?),
        ("definition-valid.env", env_bytes(&valid_def)?),
        ("definition-revoked.env", env_bytes(&revoked_def)?),
        ("definition-rogue.env", env_bytes(&rogue_def)?),
        ("definition-unknown-block.env", env_bytes(&unknown_def)?),
        ("definition-param.env", env_bytes(&param_def)?),
        ("cmd-valid.env", env_bytes(&valid)?),
        ("cmd-expired.env", env_bytes(&expired)?),
        ("cmd-replay.env", env_bytes(&replay)?),
        ("cmd-tampered.env", env_bytes(&tampered)?),
        ("cmd-revoked.env", env_bytes(&revoked_cmd)?),
        ("cmd-rogue-definition.env", env_bytes(&rogue_cmd)?),
        ("cmd-wrong-agent.env", env_bytes(&wrong_agent)?),
        ("cmd-unknown-block.env", env_bytes(&unknown_cmd)?),
        ("cmd-bad-param.env", env_bytes(&bad_param)?),
        ("cmd-good-param.env", env_bytes(&good_param)?),
        ("techlist.env", env_bytes(&techlist)?),
        ("techlist-removed.env", env_bytes(&techlist_removed)?),
        ("cmd-shell-server-only.env", env_bytes(&shell_server_only)?),
        ("README.md", readme().into_bytes()),
    ];
    for (name, bytes) in &files {
        write(out, name, bytes)?;
    }
    Ok(())
}

/// Default output directory.
pub fn default_out(root: &Path) -> PathBuf {
    root.join("crates/rmm-agent-core/tests/fixtures")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmm_trust::error::TrustError;
    use rmm_trust::keys::PublicKey;
    use rmm_trust::store::{Clock, TrustStore};
    use rmm_trust::verify::{FixedClock, MemoryReplayCache, MemorySeqStore};

    fn read(dir: &Path, name: &str) -> Vec<u8> {
        std::fs::read(dir.join(name)).expect("fixture")
    }

    #[test]
    fn fixtures_behave_as_documented() {
        let dir = std::env::temp_dir().join(format!("rmm-fixtures-{}", std::process::id()));
        run(&dir).expect("generate");
        let root_hex = String::from_utf8(read(&dir, "root.pub.hex")).expect("utf8");
        let raw: [u8; 32] = hex::decode(root_hex.trim())
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let clock = FixedClock(NOW);
        let mut store = TrustStore::new(vec![PublicKey::from_bytes(&raw).expect("key")], 1);
        let mut seq = MemorySeqStore::new();
        store
            .apply_manifest(&read(&dir, "manifest.env"), &clock, &mut seq)
            .expect("manifest");
        store
            .apply_revocations(&read(&dir, "revocations.env"), &clock, &mut seq)
            .expect("revocations");
        assert_eq!(clock.now(), NOW);

        let verify = |name: &str, agent: &str, replay: &mut MemoryReplayCache| {
            store.verify_command(&read(&dir, name), agent, CLIENT_ID, &clock, replay)
        };
        let mut replay = MemoryReplayCache::new(FixedClock(NOW));
        assert!(verify("cmd-valid.env", AGENT_ID, &mut replay).is_ok());
        assert_eq!(
            verify("cmd-valid.env", AGENT_ID, &mut replay).err(),
            Some(TrustError::Replay)
        );
        let mut fresh = MemoryReplayCache::new(FixedClock(NOW));
        assert_eq!(
            verify("cmd-expired.env", AGENT_ID, &mut fresh).err(),
            Some(TrustError::Expired)
        );
        assert_eq!(
            verify("cmd-tampered.env", AGENT_ID, &mut fresh).err(),
            Some(TrustError::BadSignature)
        );
        assert_eq!(
            verify("cmd-revoked.env", AGENT_ID, &mut fresh).err(),
            Some(TrustError::ArtifactRevoked)
        );
        assert_eq!(
            verify("cmd-wrong-agent.env", AGENT_ID, &mut fresh).err(),
            Some(TrustError::WrongAgent)
        );
        for ok in [
            "cmd-replay.env",
            "cmd-rogue-definition.env",
            "cmd-unknown-block.env",
            "cmd-bad-param.env",
        ] {
            assert!(verify(ok, AGENT_ID, &mut fresh).is_ok(), "{ok}");
        }
        // The rogue definition is not catalog-signed.
        let rogue = Envelope::from_bytes(&read(&dir, "definition-rogue.env")).expect("env");
        assert!(store.verify_role(&rogue, Role::Catalog, NOW).is_err());
        let good = Envelope::from_bytes(&read(&dir, "definition-valid.env")).expect("env");
        assert!(store.verify_role(&good, Role::Catalog, NOW).is_ok());
        // The server-only ShellOpen is a validly signed command.
        assert!(verify("cmd-shell-server-only.env", AGENT_ID, &mut fresh).is_ok());

        // Technician lists: seq 2 replaces seq 1; going back is a rollback.
        store
            .apply_techlist(&read(&dir, "techlist.env"), &clock, &mut seq)
            .expect("techlist");
        assert!(store.techlist().and_then(|l| l.tech(ALICE)).is_some());
        store
            .apply_techlist(&read(&dir, "techlist-removed.env"), &clock, &mut seq)
            .expect("techlist-removed");
        assert!(store.techlist().and_then(|l| l.tech(ALICE)).is_none());
        assert!(matches!(
            store.apply_techlist(&read(&dir, "techlist.env"), &clock, &mut seq),
            Err(TrustError::Rollback { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}
