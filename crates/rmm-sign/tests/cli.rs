//! End-to-end tests of the rmm-sign binary. Non-interactive: the passphrase
//! comes from RMM_SIGN_PASSPHRASE and signing uses --yes.
#![allow(clippy::unwrap_used)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const PASS: &str = "correct horse battery staple";
const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

fn tmp() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "rmm-sign-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_with<S: AsRef<OsStr>>(pass: &str, args: &[S]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rmm-sign"))
        .args(args)
        .env("RMM_SIGN_PASSPHRASE", pass)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn run<S: AsRef<OsStr>>(args: &[S]) -> Output {
    run_with(PASS, args)
}

fn ok<S: AsRef<OsStr> + std::fmt::Debug>(args: &[S]) -> String {
    let out = run(args);
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn line_value(text: &str, key: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")))
        .unwrap_or_else(|| panic!("no {key} in {text}"))
        .trim()
        .to_owned()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

struct Key {
    path: PathBuf,
    public_key: String,
    key_id: String,
}

fn keygen(dir: &Path, name: &str) -> Key {
    let path = dir.join(name);
    let out = ok(&["keygen-root", "--out", s(&path)]);
    Key {
        path,
        public_key: line_value(&out, "public_key"),
        key_id: line_value(&out, "key_id"),
    }
}

fn backend(k: &Key) -> String {
    format!("file:{}", s(&k.path))
}

fn manifest_json(roots: &[&Key], threshold: u8, tech: &Key) -> String {
    let roots: Vec<String> = roots
        .iter()
        .map(|k| format!("\"{}\"", k.public_key))
        .collect();
    format!(
        r#"{{
  "seq": 1,
  "issued_at": {NOW},
  "expires_at": {exp},
  "root_keys": [{roots}],
  "root_threshold": {threshold},
  "certs": [{{
    "key_id": "{kid}",
    "pubkey": "{pk}",
    "alg": "ed25519",
    "roles": ["techlist"],
    "not_before": {NOW},
    "not_after": {exp},
    "label": "techlist key"
  }}],
  "thresholds": {{"techlist": 1}},
  "revoked_keys": [],
  "console_rp_id": "rmm.example",
  "console_origins": ["https://rmm.example"],
  "capability_ceiling": [],
  "revocation_mirrors": []
}}"#,
        exp = NOW + 100 * DAY,
        roots = roots.join(", "),
        kid = tech.key_id,
        pk = tech.public_key,
    )
}

/// AAGUID of a YubiKey 5 (firmware 5.2/5.4).
const YUBIKEY_5_AAGUID: &str = "ee882879721c491397753dfcce97072a";
/// An AAGUID that is not a YubiKey 5.
const OTHER_AAGUID: &str = "42424242424242424242424242424242";

fn techlist_with_aaguid(seq: u64, perms: &str, aaguid: &str) -> String {
    format!(
        r#"{{
  "seq": {seq},
  "issued_at": {NOW},
  "expires_at": {exp},
  "techs": [{{"tech_id": "alice", "client_scope": ["*"], "perms": ["{perms}"], "creds": [
    {{"cred_id": "c1c1c1c1", "alg": -7, "cose_pubkey": "a50102", "aaguid": "{aaguid}"}}
  ]}}]
}}"#,
        exp = NOW + 30 * DAY
    )
}

fn techlist_json(seq: u64, perms: &str) -> String {
    techlist_with_aaguid(seq, perms, YUBIKEY_5_AAGUID)
}

fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

fn sign_args(ty: &str, input: &str, backend: &str, out: &str) -> Vec<String> {
    [
        "sign",
        "--type",
        ty,
        "--in",
        input,
        "--backend",
        backend,
        "--out",
        out,
        "--yes",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

fn add(args: &mut Vec<String>, extra: &[&str]) {
    args.extend(extra.iter().map(|s| (*s).to_owned()));
}

#[test]
fn keygen_then_pubkey_prints_same_key_id() {
    let dir = tmp();
    let k = keygen(&dir, "root.age");
    let out = ok(&["pubkey", "--backend", &backend(&k)]);
    assert_eq!(line_value(&out, "key_id"), k.key_id);
    assert_eq!(line_value(&out, "public_key"), k.public_key);
    assert_eq!(k.key_id.len(), 64);
}

#[test]
fn keygen_refuses_to_overwrite() {
    let dir = tmp();
    let k = keygen(&dir, "root.age");
    let before = std::fs::read(&k.path).unwrap();
    let out = run(&["keygen-root", "--out", s(&k.path)]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("refusing to overwrite"));
    assert_eq!(std::fs::read(&k.path).unwrap(), before);
}

#[test]
fn full_chain_root_certifies_techlist_key() {
    let dir = tmp();
    let root = keygen(&dir, "root.age");
    let tech = keygen(&dir, "tech.age");

    let draft = write(&dir, "m.json", &manifest_json(&[&root], 1, &tech));
    let menv = dir.join("m.env");
    let out = ok(&sign_args("manifest", s(&draft), &backend(&root), s(&menv)));
    assert!(out.contains(&root.key_id));

    let tl = write(&dir, "t.json", &techlist_json(1, "shell"));
    let tenv = dir.join("t.env");
    ok(&sign_args("techlist", s(&tl), &backend(&tech), s(&tenv)));

    let now = NOW.to_string();
    let verify_m = ok(&[
        "verify",
        "--roots",
        &root.public_key,
        "--root-threshold",
        "1",
        "--now",
        &now,
        s(&menv),
    ]);
    assert!(verify_m.contains(&format!("signer: {}", root.key_id)));
    assert!(verify_m.contains("\"console_rp_id\": \"rmm.example\""));

    let verify_t = ok(&[
        "verify",
        "--roots",
        &root.public_key,
        "--root-threshold",
        "1",
        "--manifest",
        s(&menv),
        "--now",
        &now,
        s(&tenv),
    ]);
    assert!(verify_t.contains(&format!("signer: {}", tech.key_id)));
    assert!(verify_t.contains("\"tech_id\": \"alice\""));

    let inspected = ok(&["inspect", s(&tenv)]);
    assert!(inspected.contains("type: rmm.techlist/1"));
    assert!(inspected.contains(&tech.key_id));
    assert!(inspected.contains("\"perms\""));

    // The root key is not certified for techlist: verification must fail.
    let bad = dir.join("bad.env");
    ok(&sign_args("techlist", s(&tl), &backend(&root), s(&bad)));
    let out = run(&[
        "verify",
        "--roots",
        &root.public_key,
        "--root-threshold",
        "1",
        "--manifest",
        s(&menv),
        "--now",
        &now,
        s(&bad),
    ]);
    assert!(!out.status.success());
}

#[test]
fn two_of_two_root_multisig_with_add_to() {
    let dir = tmp();
    let r1 = keygen(&dir, "r1.age");
    let r2 = keygen(&dir, "r2.age");
    let tech = keygen(&dir, "tech.age");
    let draft = write(&dir, "m.json", &manifest_json(&[&r1, &r2], 2, &tech));
    let partial = dir.join("partial.env");
    let full = dir.join("full.env");
    ok(&sign_args(
        "manifest",
        s(&draft),
        &backend(&r1),
        s(&partial),
    ));

    let roots = format!("{},{}", r1.public_key, r2.public_key);
    let now = NOW.to_string();
    // One signature is not enough.
    let out = run(&[
        "verify",
        "--roots",
        &roots,
        "--root-threshold",
        "2",
        "--now",
        &now,
        s(&partial),
    ]);
    assert!(!out.status.success());

    let mut args = sign_args("manifest", s(&draft), &backend(&r2), s(&full));
    add(&mut args, &["--add-to", s(&partial)]);
    ok(&args);
    let v = ok(&[
        "verify",
        "--roots",
        &roots,
        "--root-threshold",
        "2",
        "--now",
        &now,
        s(&full),
    ]);
    assert!(v.contains(&r1.key_id) && v.contains(&r2.key_id));

    // Signing again with the same key is refused.
    let again = dir.join("again.env");
    let mut args = sign_args("manifest", s(&draft), &backend(&r2), s(&again));
    add(&mut args, &["--add-to", s(&full)]);
    assert!(!run(&args).status.success());
}

#[test]
fn add_to_with_different_payload_is_refused() {
    let dir = tmp();
    let root = keygen(&dir, "root.age");
    let tech = keygen(&dir, "tech.age");
    let a = write(&dir, "a.json", &manifest_json(&[&root], 1, &tech));
    let other = manifest_json(&[&root], 1, &tech).replace("\"seq\": 1", "\"seq\": 2");
    let b = write(&dir, "b.json", &other);
    let first = dir.join("first.env");
    let out = dir.join("out.env");
    ok(&sign_args("manifest", s(&a), &backend(&root), s(&first)));
    let mut args = sign_args("manifest", s(&b), &backend(&root), s(&out));
    add(&mut args, &["--add-to", s(&first)]);
    let res = run(&args);
    assert!(!res.status.success());
    assert!(String::from_utf8_lossy(&res.stderr).contains("different document"));
    assert!(!out.exists());
}

#[test]
fn tampered_envelope_fails_verify() {
    let dir = tmp();
    let root = keygen(&dir, "root.age");
    let tech = keygen(&dir, "tech.age");
    let draft = write(&dir, "m.json", &manifest_json(&[&root], 1, &tech));
    let menv = dir.join("m.env");
    ok(&sign_args("manifest", s(&draft), &backend(&root), s(&menv)));
    let mut bytes = std::fs::read(&menv).unwrap();
    // Flip a bit inside the signature (the tail of the canonical envelope).
    let i = bytes.len() - 5;
    bytes[i] ^= 1;
    let bad = dir.join("bad.env");
    std::fs::write(&bad, bytes).unwrap();
    let now = NOW.to_string();
    let out = run(&[
        "verify",
        "--roots",
        &root.public_key,
        "--root-threshold",
        "1",
        "--now",
        &now,
        s(&bad),
    ]);
    assert!(!out.status.success());
}

#[test]
fn wrong_passphrase_exits_2_and_writes_nothing() {
    let dir = tmp();
    let root = keygen(&dir, "root.age");
    let tech = keygen(&dir, "tech.age");
    let draft = write(&dir, "m.json", &manifest_json(&[&root], 1, &tech));
    let out_path = dir.join("m.env");
    let args = sign_args("manifest", s(&draft), &backend(&root), s(&out_path));
    let res = run_with("not the passphrase", &args);
    assert_eq!(res.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&res.stderr).contains("wrong passphrase"));
    assert!(!out_path.exists());

    let res = run_with("nope", &["pubkey", "--backend", &backend(&root)]);
    assert_eq!(res.status.code(), Some(2));
}

#[test]
fn existing_out_is_refused_unless_force() {
    let dir = tmp();
    let root = keygen(&dir, "root.age");
    let tech = keygen(&dir, "tech.age");
    let draft = write(&dir, "m.json", &manifest_json(&[&root], 1, &tech));
    let menv = dir.join("m.env");
    ok(&sign_args("manifest", s(&draft), &backend(&root), s(&menv)));
    let before = std::fs::read(&menv).unwrap();

    let args = sign_args("manifest", s(&draft), &backend(&root), s(&menv));
    let res = run(&args);
    assert!(!res.status.success());
    assert!(String::from_utf8_lossy(&res.stderr).contains("refusing to overwrite"));
    assert_eq!(std::fs::read(&menv).unwrap(), before);

    let mut forced = args.clone();
    forced.push("--force".to_owned());
    ok(&forced);
}

#[test]
fn diff_against_prev_shows_changed_field() {
    let dir = tmp();
    let tech = keygen(&dir, "tech.age");
    let v1 = write(&dir, "t1.json", &techlist_json(1, "shell"));
    let v2 = write(&dir, "t2.json", &techlist_json(2, "inventory"));
    let e1 = dir.join("t1.env");
    let e2 = dir.join("t2.env");
    ok(&sign_args("techlist", s(&v1), &backend(&tech), s(&e1)));
    let mut args = sign_args("techlist", s(&v2), &backend(&tech), s(&e2));
    add(&mut args, &["--prev", s(&e1)]);
    let res = run(&args);
    assert!(res.status.success());
    let err = String::from_utf8_lossy(&res.stderr);
    assert!(err.contains("-  \"seq\": 1"), "{err}");
    assert!(err.contains("+  \"seq\": 2"), "{err}");
    assert!(
        err.contains("-        \"shell\"") && err.contains("+        \"inventory\""),
        "{err}"
    );
}

#[test]
fn unknown_draft_field_is_named() {
    let dir = tmp();
    let tech = keygen(&dir, "tech.age");
    let bad = techlist_json(1, "shell").replace("\"seq\": 1,", "\"seq\": 1, \"bogus_field\": 7,");
    let draft = write(&dir, "t.json", &bad);
    let out = dir.join("t.env");
    let res = run(&sign_args("techlist", s(&draft), &backend(&tech), s(&out)));
    assert!(!res.status.success());
    assert!(String::from_utf8_lossy(&res.stderr).contains("bogus_field"));
    assert!(!out.exists());
}

#[test]
fn confirmation_must_be_yes() {
    let dir = tmp();
    let tech = keygen(&dir, "tech.age");
    let draft = write(&dir, "t.json", &techlist_json(1, "shell"));
    let out = dir.join("t.env");
    let res = run(&[
        "sign",
        "--type",
        "techlist",
        "--in",
        s(&draft),
        "--backend",
        &backend(&tech),
        "--out",
        s(&out),
    ]);
    // stdin is /dev/null: no confirmation, no signature.
    assert!(!res.status.success());
    assert!(!out.exists());
}

#[test]
fn card_backend_without_card_reports_clearly() {
    let out = run(&["pubkey", "--backend", "card:0006:00000000"]);
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).is_empty());
}

#[test]
fn bad_backend_is_rejected() {
    let out = run(&["pubkey", "--backend", "usb"]);
    assert!(!out.status.success());
}

/// Sign a manifest and a techlist, returning (dir, root, manifest env, techlist env).
fn signed_chain() -> (PathBuf, Key, PathBuf, PathBuf) {
    let dir = tmp();
    let root = keygen(&dir, "root.age");
    let tech = keygen(&dir, "tech.age");
    let draft = write(&dir, "m.json", &manifest_json(&[&root], 1, &tech));
    let menv = dir.join("m.env");
    ok(&sign_args("manifest", s(&draft), &backend(&root), s(&menv)));
    let tl = write(&dir, "t.json", &techlist_json(1, "shell"));
    let tenv = dir.join("t.env");
    ok(&sign_args("techlist", s(&tl), &backend(&tech), s(&tenv)));
    (dir, root, menv, tenv)
}

fn assert_expired(out: &Output) {
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("expired"), "stderr: {err}");
}

#[test]
fn expired_manifest_fails_verify() {
    let (_dir, root, menv, _) = signed_chain();
    let now = (NOW + 101 * DAY).to_string();
    let out = run(&[
        "verify",
        "--roots",
        &root.public_key,
        "--root-threshold",
        "1",
        "--now",
        &now,
        s(&menv),
    ]);
    assert_expired(&out);
}

#[test]
fn expired_techlist_fails_verify() {
    let (_dir, root, menv, tenv) = signed_chain();
    // Techlist expires at NOW + 30d; the manifest is still valid then.
    let now = (NOW + 31 * DAY).to_string();
    let out = run(&[
        "verify",
        "--roots",
        &root.public_key,
        "--root-threshold",
        "1",
        "--manifest",
        s(&menv),
        "--now",
        &now,
        s(&tenv),
    ]);
    assert_expired(&out);
}

#[test]
fn expired_command_fails_verify() {
    let dir = tmp();
    let root = keygen(&dir, "root.age");
    let cmdkey = keygen(&dir, "cmd.age");
    let manifest = manifest_json(&[&root], 1, &cmdkey)
        .replace("\"roles\": [\"techlist\"]", "\"roles\": [\"command\"]")
        .replace(
            "\"thresholds\": {\"techlist\": 1}",
            "\"thresholds\": {\"command\": 1}",
        );
    let draft = write(&dir, "m.json", &manifest);
    let menv = dir.join("m.env");
    ok(&sign_args("manifest", s(&draft), &backend(&root), s(&menv)));

    let cmd = format!(
        r#"{{
  "cmd_id": "{id}",
  "agent_id": "agent-1",
  "client_id": "client-1",
  "issued_at": {NOW},
  "expires_at": {exp},
  "policy_hash": "{ph}",
  "body": {{"kind": "collect", "collect_kind": "inventory"}}
}}"#,
        id = "11".repeat(16),
        ph = "22".repeat(32),
        exp = NOW + 600,
    );
    let cdraft = write(&dir, "c.json", &cmd);
    let cenv = dir.join("c.env");
    ok(&sign_args(
        "command",
        s(&cdraft),
        &backend(&cmdkey),
        s(&cenv),
    ));

    let verify_at = |now: u64| {
        let now = now.to_string();
        run(&[
            "verify",
            "--roots",
            &root.public_key,
            "--root-threshold",
            "1",
            "--manifest",
            s(&menv),
            "--now",
            &now,
            s(&cenv),
        ])
    };
    let fresh = verify_at(NOW + 1);
    assert!(
        fresh.status.success(),
        "{}",
        String::from_utf8_lossy(&fresh.stderr)
    );
    assert_expired(&verify_at(NOW + 600));
}

fn catalog_manifest_json(root: &Key, cat: &Key) -> String {
    format!(
        r#"{{
  "seq": 1,
  "issued_at": {NOW},
  "expires_at": {exp},
  "root_keys": ["{rpk}"],
  "root_threshold": 1,
  "certs": [{{
    "key_id": "{kid}",
    "pubkey": "{pk}",
    "alg": "ed25519",
    "roles": ["catalog"],
    "not_before": {NOW},
    "not_after": {exp},
    "label": "catalog key"
  }}],
  "thresholds": {{"catalog": 1}},
  "revoked_keys": [],
  "console_rp_id": "rmm.example",
  "console_origins": ["https://rmm.example"],
  "capability_ceiling": [],
  "revocation_mirrors": []
}}"#,
        exp = NOW + 100 * DAY,
        rpk = root.public_key,
        kid = cat.key_id,
        pk = cat.public_key,
    )
}

fn catalog_definition() -> String {
    let p =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/printing.spooler-restart.json");
    std::fs::read_to_string(p).unwrap()
}

#[test]
fn definition_signed_by_catalog_key_verifies() {
    let dir = tmp();
    let root = keygen(&dir, "root.age");
    let cat = keygen(&dir, "cat.age");
    let draft = write(&dir, "m.json", &catalog_manifest_json(&root, &cat));
    let menv = dir.join("m.env");
    ok(&sign_args("manifest", s(&draft), &backend(&root), s(&menv)));

    let def = write(&dir, "d.json", &catalog_definition());
    let denv = dir.join("d.env");
    ok(&sign_args("definition", s(&def), &backend(&cat), s(&denv)));

    let now = NOW.to_string();
    let v = ok(&[
        "verify",
        "--roots",
        &root.public_key,
        "--root-threshold",
        "1",
        "--manifest",
        s(&menv),
        "--now",
        &now,
        s(&denv),
    ]);
    assert!(v.contains(&format!("signer: {}", cat.key_id)));
    assert!(v.contains("printing.spooler-restart"));
    let i = ok(&["inspect", s(&denv)]);
    assert!(i.contains("type: rmm.definition/1"));

    // The root key is not certified for the catalog role.
    let bad = dir.join("bad.env");
    ok(&sign_args("definition", s(&def), &backend(&root), s(&bad)));
    let out = run(&[
        "verify",
        "--roots",
        &root.public_key,
        "--root-threshold",
        "1",
        "--manifest",
        s(&menv),
        "--now",
        &now,
        s(&bad),
    ]);
    assert!(!out.status.success());
}

#[test]
fn definition_with_unknown_block_is_refused() {
    let dir = tmp();
    let cat = keygen(&dir, "cat.age");
    let json = catalog_definition().replace("service.stop", "no.such-block");
    assert_ne!(json, catalog_definition());
    let def = write(&dir, "d.json", &json);
    let denv = dir.join("d.env");
    let out = run(&sign_args("definition", s(&def), &backend(&cat), s(&denv)));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("validation"));
    assert!(!denv.exists());
}

#[test]
fn definition_with_unknown_field_is_refused() {
    let dir = tmp();
    let cat = keygen(&dir, "cat.age");
    let json = catalog_definition().replacen("\"version\": 1,", "\"version\": 1, \"bogus\": 1,", 1);
    let def = write(&dir, "d.json", &json);
    let denv = dir.join("d.env");
    let out = run(&sign_args("definition", s(&def), &backend(&cat), s(&denv)));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("bogus"));
    assert!(!denv.exists());
}

#[test]
fn keygen_command_writes_0600_hex_seed_matching_public_key() {
    let dir = tmp();
    let path = dir.join("command.key");
    let out = ok(&["keygen-command", "--out", s(&path)]);
    let eq = |k: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap()
            .trim()
            .to_owned()
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Load it the way rmm_api::load_command_key does: hex text, 32 bytes.
    let text = std::fs::read_to_string(&path).unwrap();
    let raw = hex::decode(text.trim()).unwrap();
    let seed: [u8; 32] = raw.as_slice().try_into().unwrap();
    let signer = rmm_trust::sign::Ed25519Signer::from_seed(&seed);
    use rmm_trust::sign::Signer;
    assert_eq!(hex::encode(signer.public_key().to_bytes()), eq("public"));
    assert_eq!(hex::encode(signer.key_id().0), eq("key_id"));
    assert!(!dir.join("command.key.tmp").exists());
}

#[test]
fn keygen_command_refuses_to_overwrite_without_force() {
    let dir = tmp();
    let path = dir.join("command.key");
    ok(&["keygen-command", "--out", s(&path)]);
    let before = std::fs::read(&path).unwrap();
    let out = run(&["keygen-command", "--out", s(&path)]);
    assert!(!out.status.success());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    ok(&["keygen-command", "--out", s(&path), "--force"]);
    assert_ne!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn techlist_with_unknown_aaguid_is_refused() {
    let dir = tmp();
    let tech = keygen(&dir, "tech.age");
    let draft = write(
        &dir,
        "t.json",
        &techlist_with_aaguid(1, "shell", OTHER_AAGUID),
    );
    let out_path = dir.join("t.env");
    let out = run(&sign_args(
        "techlist",
        s(&draft),
        &backend(&tech),
        s(&out_path),
    ));
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("\"alice\""), "{err}");
    assert!(
        err.contains("42424242-4242-4242-4242-424242424242"),
        "{err}"
    );
    assert!(!out_path.exists(), "nothing is written");

    // The operator explicitly admits the authenticator.
    let mut args = sign_args("techlist", s(&draft), &backend(&tech), s(&out_path));
    add(&mut args, &["--allow-aaguid", OTHER_AAGUID]);
    ok(&args);
    assert!(out_path.exists());
    // Dashed form and repeated flags work too.
    let out2 = dir.join("t2.env");
    let mut args = sign_args("techlist", s(&draft), &backend(&tech), s(&out2));
    add(
        &mut args,
        &[
            "--allow-aaguid",
            "11111111-1111-1111-1111-111111111111",
            "--allow-aaguid",
            "42424242-4242-4242-4242-424242424242",
        ],
    );
    ok(&args);
}

#[test]
fn malformed_allow_aaguid_is_refused() {
    let dir = tmp();
    let tech = keygen(&dir, "tech.age");
    let draft = write(&dir, "t.json", &techlist_json(1, "shell"));
    for bad in [
        "zz",
        "4242",
        "4242424242424242424242424242424242",
        "g2424242424242424242424242424242",
    ] {
        let out_path = dir.join("t.env");
        let mut args = sign_args("techlist", s(&draft), &backend(&tech), s(&out_path));
        add(&mut args, &["--allow-aaguid", bad]);
        let out = run(&args);
        assert!(!out.status.success(), "{bad}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("--allow-aaguid"),
            "{bad}"
        );
        assert!(!out_path.exists());
    }
}

#[test]
fn techlist_needs_hardware_credentials() {
    let dir = tmp();
    let tech = keygen(&dir, "tech.age");
    let empty = techlist_json(1, "shell").replace(
        &format!(
            r#"[
    {{"cred_id": "c1c1c1c1", "alg": -7, "cose_pubkey": "a50102", "aaguid": "{YUBIKEY_5_AAGUID}"}}
  ]"#
        ),
        "[]",
    );
    assert!(empty.contains("\"creds\": []"), "{empty}");
    let draft = write(&dir, "t.json", &empty);
    let out = run(&sign_args(
        "techlist",
        s(&draft),
        &backend(&tech),
        s(&dir.join("a.env")),
    ));
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("\"alice\" has no credentials"), "{err}");

    // A truncated AAGUID is named with its technician.
    let short = write(&dir, "s.json", &techlist_with_aaguid(1, "shell", "ee8828"));
    let out = run(&sign_args(
        "techlist",
        s(&short),
        &backend(&tech),
        s(&dir.join("b.env")),
    ));
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("\"alice\"") && err.contains("ee8828") && err.contains("16 bytes"),
        "{err}"
    );

    // --allow-aaguid makes no sense for other document types.
    let m = write(&dir, "m.json", &manifest_json(&[&tech], 1, &tech));
    let mut args = sign_args("manifest", s(&m), &backend(&tech), s(&dir.join("m.env")));
    add(&mut args, &["--allow-aaguid", OTHER_AAGUID]);
    let out = run(&args);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("only applies to --type techlist"));
}

fn release_manifest_json(root: &Key, rel: &Key, cat: &Key) -> String {
    format!(
        r#"{{
  "seq": 1,
  "issued_at": {NOW},
  "expires_at": {exp},
  "root_keys": ["{rpk}"],
  "root_threshold": 1,
  "certs": [
    {{"key_id": "{rid}", "pubkey": "{rp}", "alg": "ed25519", "roles": ["release"],
      "not_before": {NOW}, "not_after": {exp}, "label": "release key"}},
    {{"key_id": "{cid}", "pubkey": "{cp}", "alg": "ed25519", "roles": ["catalog"],
      "not_before": {NOW}, "not_after": {exp}, "label": "catalog key"}}
  ],
  "thresholds": {{"release": 1, "catalog": 1}},
  "revoked_keys": [],
  "console_rp_id": "rmm.example",
  "console_origins": ["https://rmm.example"],
  "capability_ceiling": [],
  "revocation_mirrors": []
}}"#,
        exp = NOW + 100 * DAY,
        rpk = root.public_key,
        rid = rel.key_id,
        rp = rel.public_key,
        cid = cat.key_id,
        cp = cat.public_key,
    )
}

fn release_json(sha_hex: &str) -> String {
    format!(
        r#"{{
  "seq": 1,
  "version": "1.2.3",
  "issued_at": {NOW},
  "expires_at": {exp},
  "artifacts": [
    {{"platform": "linux-x86_64", "sha256": "{sha_hex}", "size": 4096, "name": "rmm-agent"}}
  ]
}}"#,
        exp = NOW + 30 * DAY
    )
}

#[test]
fn release_signed_by_release_key_verifies_and_other_roles_fail() {
    let dir = tmp();
    let root = keygen(&dir, "root.age");
    let rel = keygen(&dir, "rel.age");
    let cat = keygen(&dir, "cat.age");
    let draft = write(&dir, "m.json", &release_manifest_json(&root, &rel, &cat));
    let menv = dir.join("m.env");
    ok(&sign_args("manifest", s(&draft), &backend(&root), s(&menv)));

    let sha = "ab".repeat(32);
    let rdraft = write(&dir, "r.json", &release_json(&sha));
    let renv = dir.join("r.env");
    ok(&sign_args("release", s(&rdraft), &backend(&rel), s(&renv)));

    let now = NOW.to_string();
    let verify_args = |file: &Path| {
        run(&[
            "verify",
            "--roots",
            &root.public_key,
            "--root-threshold",
            "1",
            "--manifest",
            s(&menv),
            "--now",
            &now,
            s(file),
        ])
    };
    let out = verify_args(&renv);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = String::from_utf8(out.stdout).unwrap();
    assert!(v.contains(&format!("signer: {}", rel.key_id)));
    assert!(v.contains(&sha));
    let i = ok(&["inspect", s(&renv)]);
    assert!(i.contains("type: rmm.release/1"));

    // A catalog-role key signs successfully but does not verify as a release.
    let bad = dir.join("bad.env");
    ok(&sign_args("release", s(&rdraft), &backend(&cat), s(&bad)));
    assert!(!verify_args(&bad).status.success());
}

#[test]
fn release_draft_with_bad_hash_is_refused() {
    let dir = tmp();
    let rel = keygen(&dir, "rel.age");
    let short = write(&dir, "r.json", &release_json(&"ab".repeat(31)));
    let out = run(&sign_args(
        "release",
        s(&short),
        &backend(&rel),
        s(&dir.join("r.env")),
    ));
    assert!(!out.status.success());
    assert!(!dir.join("r.env").exists());
}
