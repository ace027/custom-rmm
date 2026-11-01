//! `xtask fake-authn`: a software FIDO2 authenticator for development and CI.
//!
//! It stands in for a YubiKey so the end-to-end shell test can run without
//! hardware. It owns a dev attestation CA and a dev AAGUID (`rmm-dev-fake-key`),
//! registers credentials with `packed` attestations chained to that CA and
//! signs assertions with user presence and user verification.
//!
//! NEVER FOR PRODUCTION. Production servers list only the vendor's attestation
//! roots and the AAGUIDs of the keys you issue (`RMM_WEBAUTHN_ATTESTATION_ROOTS`,
//! `RMM_WEBAUTHN_AAGUIDS`), neither of which contains the dev root or the dev
//! AAGUID, so a credential made here is refused at registration. A techlist
//! holding one can be signed only with `rmm-sign --allow-aaguid`, which a
//! production signing ceremony never passes. The API additionally disables
//! registration when the dev AAGUID is listed outside dev mode.
//!
//! Subcommands:
//!   ca --out DIR [--force]
//!       Create DIR/attestation-root.pem (the dev attestation root),
//!       DIR/attestation-root.key (its key, hex, 0600) and DIR/aaguid.hex.
//!       Keeps existing files unless --force.
//!   register --api URL --token JWT --dir DIR [--ca DIR] [--cacert FILE] [--origin ORIGIN]
//!       Register a new credential for the token's technician and store it in
//!       DIR/credential.json. The attestation root key is read from `--ca`
//!       (default DIR). Prints the server's reply.
//!   assert --grant-response FILE --dir DIR [--origin ORIGIN]
//!       Sign the challenge of a grant response with the stored credential and
//!       print the JSON body for `POST /api/v1/shell-sessions/{grant_id}/open`.

use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use ciborium::Value as Cbor;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use rand::TryRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::der::asn1::OctetString;
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::der::pem::LineEnding;
use x509_cert::der::{Encode, EncodePem};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::time::{Time, Validity};

/// AAGUID of the dev authenticator: "rmm-dev-fake-key" in ASCII. Not a real device.
pub const DEV_AAGUID: [u8; 16] = *b"rmm-dev-fake-key";
/// Origin of the dev console (matches `console_origins` from scripts/dev-trust.sh).
const DEFAULT_ORIGIN: &str = "https://localhost";

const OID_FIDO_GEN_CE_AAGUID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");
const ROOT_DN: &str = "CN=RMM Dev Fake FIDO Root CA,O=RMM Dev,C=US";
const LEAF_DN: &str = "CN=RMM Dev Fake Key,OU=Authenticator Attestation,O=RMM Dev,C=SE";
const DAY: u64 = 86_400;

fn err<E: std::fmt::Display>(what: &str) -> impl Fn(E) -> String + '_ {
    move |e| format!("{what}: {e}")
}

fn b64(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

fn unb64(field: &str, s: &str) -> Result<Vec<u8>, String> {
    data_encoding::BASE64URL_NOPAD
        .decode(s.as_bytes())
        .map_err(|e| format!("{field}: {e}"))
}

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn req(args: &[String], name: &str) -> Result<String, String> {
    opt(args, name).ok_or_else(|| format!("{name} is required"))
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    rand::rngs::SysRng
        .try_fill_bytes(&mut b)
        .map_err(err("random bytes"))?;
    Ok(b)
}

fn random_key() -> Result<SigningKey, String> {
    loop {
        if let Ok(k) = SigningKey::from_slice(&random::<32>()?) {
            return Ok(k);
        }
    }
}

fn key_from_hex(hex: &str) -> Result<SigningKey, String> {
    let raw = data_encoding::HEXLOWER_PERMISSIVE
        .decode(hex.trim().as_bytes())
        .map_err(err("key hex"))?;
    SigningKey::from_slice(&raw).map_err(err("key"))
}

fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    f.write_all(data)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    // `mode` only applies to new files.
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))
}

// ---------------------------------------------------------------- X.509

struct Profile {
    subject: Name,
    issuer: Name,
    ca: bool,
    aaguid: Option<[u8; 16]>,
}

impl BuilderProfile for Profile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let bc = BasicConstraints {
            ca: self.ca,
            path_len_constraint: None,
        };
        let mut exts = vec![Extension {
            extn_id: BasicConstraints::OID,
            critical: true,
            extn_value: OctetString::new(bc.to_der()?)?,
        }];
        if let Some(a) = &self.aaguid {
            exts.push(Extension {
                extn_id: OID_FIDO_GEN_CE_AAGUID,
                critical: false,
                extn_value: OctetString::new(OctetString::new(a.to_vec())?.to_der()?)?,
            });
        }
        Ok(exts)
    }
}

fn validity(from_days_ago: u64, for_days: u64) -> Result<Validity, String> {
    let now = SystemTime::now();
    let t = |at: SystemTime| Time::try_from(at).map_err(err("validity"));
    Ok(Validity::new(
        t(now - Duration::from_secs(from_days_ago * DAY))?,
        t(now + Duration::from_secs(for_days * DAY))?,
    ))
}

fn make_cert(
    subject: &str,
    issuer: &str,
    key: &SigningKey,
    issuer_key: &SigningKey,
    ca: bool,
    aaguid: Option<[u8; 16]>,
    validity: Validity,
) -> Result<Certificate, String> {
    let profile = Profile {
        subject: Name::from_str(subject).map_err(err("subject"))?,
        issuer: Name::from_str(issuer).map_err(err("issuer"))?,
        ca,
        aaguid,
    };
    let spki = SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).map_err(err("spki"))?;
    let serial = SerialNumber::from(u32::from_be_bytes(random::<4>()?) >> 1);
    CertificateBuilder::new(profile, serial, validity, spki)
        .map_err(err("certificate"))?
        .build::<_, DerSignature>(issuer_key)
        .map_err(err("sign certificate"))
}

// ---------------------------------------------------------------- ca

fn ca(args: &[String]) -> Result<(), String> {
    let dir = req(args, "--out")?;
    let dir = Path::new(&dir);
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let (pem_path, key_path, aaguid_path) = (
        dir.join("attestation-root.pem"),
        dir.join("attestation-root.key"),
        dir.join("aaguid.hex"),
    );
    let force = args.iter().any(|a| a == "--force");
    if force || !(pem_path.exists() && key_path.exists()) {
        let key = random_key()?;
        let root = make_cert(ROOT_DN, ROOT_DN, &key, &key, true, None, validity(1, 3650)?)?;
        let pem = root.to_pem(LineEnding::LF).map_err(err("root pem"))?;
        // The root certificate is public (the API container reads it); the key is not.
        write_file(
            &key_path,
            data_encoding::HEXLOWER.encode(&key.to_bytes()).as_bytes(),
            0o600,
        )?;
        write_file(&pem_path, pem.as_bytes(), 0o644)?;
        eprintln!(
            "fake-authn: created the dev attestation root in {}",
            dir.display()
        );
    }
    write_file(
        &aaguid_path,
        data_encoding::HEXLOWER.encode(&DEV_AAGUID).as_bytes(),
        0o644,
    )?;
    println!("aaguid={}", data_encoding::HEXLOWER.encode(&DEV_AAGUID));
    println!("root={}", pem_path.display());
    Ok(())
}

// ---------------------------------------------------------------- credential

fn cose_es256(key: &SigningKey) -> Result<Vec<u8>, String> {
    let point = key.verifying_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    let int = |i: i64| Cbor::Integer(i.into());
    let map = Cbor::Map(vec![
        (int(1), int(2)),
        (int(3), int(-7)),
        (int(-1), int(1)),
        (int(-2), Cbor::Bytes(bytes[1..33].to_vec())),
        (int(-3), Cbor::Bytes(bytes[33..65].to_vec())),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&map, &mut out).map_err(err("cose key"))?;
    Ok(out)
}

struct Credential {
    cred_id: Vec<u8>,
    key: SigningKey,
    sign_count: u32,
}

fn load_credential(dir: &Path) -> Result<Credential, String> {
    let path = dir.join("credential.json");
    let v: Value = serde_json::from_slice(
        &fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?,
    )
    .map_err(err("credential.json"))?;
    let field = |name: &str| {
        v[name]
            .as_str()
            .ok_or_else(|| format!("credential.json has no {name}"))
    };
    Ok(Credential {
        cred_id: unb64("cred_id_b64url", field("cred_id_b64url")?)?,
        key: key_from_hex(field("seed_hex")?)?,
        sign_count: u32::try_from(v["sign_count"].as_u64().unwrap_or(0)).unwrap_or(0),
    })
}

fn save_credential(dir: &Path, c: &Credential) -> Result<(), String> {
    let v = json!({
        "cred_id_b64url": b64(&c.cred_id),
        "seed_hex": data_encoding::HEXLOWER.encode(&c.key.to_bytes()),
        "sign_count": c.sign_count,
    });
    write_file(
        &dir.join("credential.json"),
        v.to_string().as_bytes(),
        0o600,
    )
}

fn cbor_bytes(v: &Cbor) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).map_err(err("cbor"))?;
    Ok(out)
}

// ---------------------------------------------------------------- register

async fn post_json(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    body: Option<&Value>,
) -> Result<Value, String> {
    let mut rb = client.post(url).bearer_auth(token);
    if let Some(b) = body {
        rb = rb.json(b);
    }
    let res = rb.send().await.map_err(|e| format!("POST {url}: {e}"))?;
    let status = res.status();
    let text = res.text().await.map_err(err("response body"))?;
    if !status.is_success() {
        return Err(format!("POST {url} answered {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("POST {url}: bad JSON ({e}): {text}"))
}

fn register(args: &[String]) -> Result<(), String> {
    let api = req(args, "--api")?;
    let token = req(args, "--token")?;
    let dir = req(args, "--dir")?;
    let dir = Path::new(&dir);
    let origin = opt(args, "--origin").unwrap_or_else(|| DEFAULT_ORIGIN.to_owned());
    let ca_dir = opt(args, "--ca").unwrap_or_else(|| dir.display().to_string());
    let root_key = key_from_hex(
        &fs::read_to_string(Path::new(&ca_dir).join("attestation-root.key"))
            .map_err(|e| format!("read the dev root key (run `fake-authn ca --out DIR`): {e}"))?,
    )?;

    // Dev stack only: talk to it directly, with its dev CA, never through a proxy.
    let mut cb = reqwest::Client::builder().no_proxy();
    if let Some(ca) = opt(args, "--cacert") {
        let pem = fs::read(&ca).map_err(|e| format!("read {ca}: {e}"))?;
        cb = cb.add_root_certificate(reqwest::Certificate::from_pem(&pem).map_err(err("cacert"))?);
    }
    let client = cb.build().map_err(err("http client"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(err("runtime"))?;
    let base = api.trim_end_matches('/');

    let begin = rt.block_on(post_json(
        &client,
        &format!("{base}/api/v1/technicians/me/credentials/register/begin"),
        &token,
        None,
    ))?;
    let text = |name: &str| {
        begin[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("begin reply has no {name}"))
    };
    let challenge = unb64("challenge_b64url", &text("challenge_b64url")?)?;
    let rp_id = text("rp_id")?;
    let challenge_id = text("challenge_id")?;

    let cred = Credential {
        cred_id: random::<32>()?.to_vec(),
        key: random_key()?,
        sign_count: 0,
    };
    let cose = cose_es256(&cred.key)?;
    let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
    ad.push(0x01 | 0x04 | 0x40); // UP, UV, attested credential data
    ad.extend_from_slice(&0u32.to_be_bytes());
    ad.extend_from_slice(&DEV_AAGUID);
    ad.extend_from_slice(
        &u16::try_from(cred.cred_id.len())
            .map_err(err("cred id"))?
            .to_be_bytes(),
    );
    ad.extend_from_slice(&cred.cred_id);
    ad.extend_from_slice(&cose);
    let client_data = serde_json::to_vec(&json!({
        "type": "webauthn.create", "challenge": b64(&challenge), "origin": origin, "crossOrigin": false
    }))
    .map_err(err("clientDataJSON"))?;

    // A fresh attestation key per registration, certified by the dev root.
    let att_key = random_key()?;
    let leaf = make_cert(
        LEAF_DN,
        ROOT_DN,
        &att_key,
        &root_key,
        false,
        Some(DEV_AAGUID),
        validity(1, 30)?,
    )?;
    let mut msg = ad.clone();
    msg.extend_from_slice(&Sha256::digest(&client_data));
    let sig: DerSignature = att_key.sign(&msg);
    let att_obj = cbor_bytes(&Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text("packed".into())),
        (
            Cbor::Text("attStmt".into()),
            Cbor::Map(vec![
                (Cbor::Text("alg".into()), Cbor::Integer((-7).into())),
                (
                    Cbor::Text("sig".into()),
                    Cbor::Bytes(sig.as_bytes().to_vec()),
                ),
                (
                    Cbor::Text("x5c".into()),
                    Cbor::Array(vec![Cbor::Bytes(leaf.to_der().map_err(err("leaf der"))?)]),
                ),
            ]),
        ),
        (Cbor::Text("authData".into()), Cbor::Bytes(ad)),
    ]))?;

    let done = rt.block_on(post_json(
        &client,
        &format!("{base}/api/v1/technicians/me/credentials/register/finish"),
        &token,
        Some(&json!({
            "challenge_id": challenge_id,
            "attestation_object_b64url": b64(&att_obj),
            "client_data_json_b64url": b64(&client_data),
        })),
    ))?;
    save_credential(dir, &cred)?;
    println!("{done}");
    Ok(())
}

// ---------------------------------------------------------------- assert

fn assert_cmd(args: &[String]) -> Result<(), String> {
    let file = req(args, "--grant-response")?;
    let dir = req(args, "--dir")?;
    let dir = Path::new(&dir);
    let origin = opt(args, "--origin").unwrap_or_else(|| DEFAULT_ORIGIN.to_owned());
    let grant: Value =
        serde_json::from_slice(&fs::read(&file).map_err(|e| format!("read {file}: {e}"))?)
            .map_err(|e| format!("{file}: {e}"))?;
    let challenge = unb64(
        "challenge_b64url",
        grant["challenge_b64url"]
            .as_str()
            .ok_or("grant has no challenge_b64url")?,
    )?;
    let rp_id = grant["rp_id"].as_str().ok_or("grant has no rp_id")?;
    let mut cred = load_credential(dir)?;
    let cred_b64 = b64(&cred.cred_id);
    let allowed = grant["allow_credentials"]
        .as_array()
        .is_some_and(|a| a.iter().any(|c| c.as_str() == Some(cred_b64.as_str())));
    if !allowed {
        return Err("the grant does not allow this credential".into());
    }

    cred.sign_count += 1;
    let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
    ad.push(0x01 | 0x04); // UP, UV
    ad.extend_from_slice(&cred.sign_count.to_be_bytes());
    let client_data = serde_json::to_vec(&json!({
        "type": "webauthn.get", "challenge": b64(&challenge), "origin": origin, "crossOrigin": false
    }))
    .map_err(err("clientDataJSON"))?;
    let mut msg = ad.clone();
    msg.extend_from_slice(&Sha256::digest(&client_data));
    let sig: DerSignature = cred.key.sign(&msg);
    save_credential(dir, &cred)?;
    println!(
        "{}",
        json!({
            "credential_id_b64url": cred_b64,
            "authenticator_data_b64url": b64(&ad),
            "client_data_json_b64url": b64(&client_data),
            "signature_b64url": b64(sig.as_bytes()),
        })
    );
    Ok(())
}

/// Entry point: `args` are the words after `fake-authn`.
pub fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("ca") => ca(&args[1..]),
        Some("register") => register(&args[1..]),
        Some("assert") => assert_cmd(&args[1..]),
        _ => Err("usage: fake-authn ca --out DIR [--force] | \
                  register --api URL --token JWT --dir DIR [--ca DIR] [--cacert FILE] [--origin O] | \
                  assert --grant-response FILE --dir DIR [--origin O]"
            .to_string()),
    }
}
