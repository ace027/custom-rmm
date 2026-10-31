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

fn techlist_json(seq: u64, perms: &str) -> String {
    format!(
        r#"{{
  "seq": {seq},
  "issued_at": {NOW},
  "expires_at": {exp},
  "techs": [{{"tech_id": "alice", "client_scope": ["*"], "perms": ["{perms}"], "creds": []}}]
}}"#,
        exp = NOW + 30 * DAY
    )
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
