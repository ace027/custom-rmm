//! Command line interface and command implementations.
//!
//! `keygen-command` creates the server's online command key. That key is an
//! unencrypted 32-byte Ed25519 seed (hex) protected only by file permissions
//! (0600); it must never be used for the root, catalog or techlist roles.
//! There is deliberately no way to export the seed of an age-encrypted root
//! file or of a card key.

use std::fs::OpenOptions;
use std::io::{BufRead, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use rmm_trust::docs::{Role, decode_doc};
use rmm_trust::envelope::Envelope;
use rmm_trust::keys::{KeyId, PublicKey};
use rmm_trust::sign::{Signer, sign_envelope};
use rmm_trust::verify::{FixedClock, MemorySeqStore, TrustStore};
use similar::TextDiff;

use crate::aaguid;
use crate::card_backend;
use crate::drafts::{DocType, check_techlist_hardware, load_draft, pretty_payload};
use crate::file_backend::{self, FileError};

/// Where the signing key lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    /// age-encrypted seed file.
    File(PathBuf),
    /// OpenPGP card, optionally selected by ident.
    Card(Option<String>),
}

impl FromStr for Backend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        if let Some(p) = s.strip_prefix("file:") {
            if p.is_empty() {
                return Err("file: needs a path".into());
            }
            return Ok(Self::File(PathBuf::from(p)));
        }
        if s == "card" {
            return Ok(Self::Card(None));
        }
        if let Some(id) = s.strip_prefix("card:") {
            if id.is_empty() {
                return Err("card: needs an ident".into());
            }
            return Ok(Self::Card(Some(id.to_owned())));
        }
        Err(format!(
            "unknown backend {s:?}; use file:<path>, card or card:<ident>"
        ))
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "rmm-sign",
    version,
    about = "Offline signing tool for the RMM trust chain"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Generate a root key, age-encrypted with a passphrase.
    KeygenRoot {
        /// Output file (must not exist).
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate the server's ONLINE command key as a plain hex seed file.
    ///
    /// The seed is stored unencrypted and protected only by file permissions
    /// (0600). Use it solely for the command role; never certify it for the
    /// root, catalog or techlist roles.
    KeygenCommand {
        /// Output seed file (read by the API via RMM_COMMAND_KEY_FILE).
        #[arg(long)]
        out: PathBuf,
        /// Overwrite --out if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Print the public key and key id of a backend.
    Pubkey {
        /// file:<path> | card[:<ident>]
        #[arg(long)]
        backend: Backend,
        /// Fail unless the key id (hex) matches.
        #[arg(long)]
        expect_key_id: Option<String>,
    },
    /// Sign a document draft.
    Sign {
        /// Document type.
        #[arg(long = "type", value_enum)]
        doc_type: DocType,
        /// JSON draft.
        #[arg(long = "in")]
        input: PathBuf,
        /// Previous envelope to diff against.
        #[arg(long)]
        prev: Option<PathBuf>,
        /// file:<path> | card[:<ident>]
        #[arg(long)]
        backend: Backend,
        /// Fail unless the signing key id (hex) matches.
        #[arg(long)]
        expect_key_id: Option<String>,
        /// Existing envelope to add this signature to (multi-sig).
        #[arg(long)]
        add_to: Option<PathBuf>,
        /// Output envelope.
        #[arg(long)]
        out: PathBuf,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
        /// Overwrite --out if it exists.
        #[arg(long)]
        force: bool,
        /// Also accept this authenticator AAGUID (32 hex digits) in a
        /// techlist, besides the compiled YubiKey 5 list. Repeatable.
        #[arg(long = "allow-aaguid", value_name = "HEX")]
        allow_aaguid: Vec<String>,
    },
    /// Verify an envelope against root keys.
    Verify {
        /// Comma separated root public keys (hex).
        #[arg(long, value_delimiter = ',', required = true)]
        roots: Vec<String>,
        /// Number of root signatures required before a manifest is installed.
        #[arg(long)]
        root_threshold: u8,
        /// Manifest envelope (needed for every other document type).
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Unix time to verify at (default: now).
        #[arg(long)]
        now: Option<u64>,
        /// Envelope to verify.
        file: PathBuf,
    },
    /// Print an envelope and its decoded payload without verifying it.
    Inspect {
        /// Envelope file.
        file: PathBuf,
    },
}

/// Parse arguments and run the selected command.
pub fn run() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::KeygenRoot { out } => keygen_root(&out),
        Cmd::KeygenCommand { out, force } => keygen_command(&out, force),
        Cmd::Pubkey {
            backend,
            expect_key_id,
        } => pubkey(&backend, expect_key_id.as_deref()),
        Cmd::Sign {
            doc_type,
            input,
            prev,
            backend,
            expect_key_id,
            add_to,
            out,
            yes,
            force,
            allow_aaguid,
        } => sign(&SignArgs {
            doc_type,
            input,
            prev,
            backend,
            expect_key_id,
            add_to,
            out,
            yes,
            force,
            allow_aaguid,
        }),
        Cmd::Verify {
            roots,
            root_threshold,
            manifest,
            now,
            file,
        } => verify(&roots, root_threshold, manifest.as_deref(), now, &file),
        Cmd::Inspect { file } => inspect(&file),
    }
}

/// Process exit code for an error: 2 for a wrong passphrase, 1 otherwise.
pub fn exit_code(e: &anyhow::Error) -> u8 {
    match e.downcast_ref::<FileError>() {
        Some(FileError::WrongPassphrase) => 2,
        _ => 1,
    }
}

fn parse_hex32(label: &str, s: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(s.trim()).with_context(|| format!("{label} is not valid hex"))?;
    raw.as_slice()
        .try_into()
        .map_err(|_| anyhow!("{label} must be 32 bytes (64 hex characters)"))
}

fn print_key(signer: &dyn Signer) {
    println!(
        "public_key: {}",
        hex::encode(signer.public_key().to_bytes())
    );
    println!("key_id: {}", hex::encode(signer.key_id().0));
}

fn keygen_root(out: &Path) -> Result<()> {
    if out.exists() {
        return Err(FileError::Exists(out.to_owned()).into());
    }
    let pass = file_backend::passphrase(true)?;
    let signer = file_backend::generate(out, pass)?;
    eprintln!("wrote {}", out.display());
    print_key(&signer);
    Ok(())
}

/// Create the online command key: a 32-byte seed as lowercase hex plus a
/// newline (the format `rmm_api::load_command_key` reads), mode 0600.
fn keygen_command(out: &Path, force: bool) -> Result<()> {
    use zeroize::Zeroizing;
    if out.exists() && !force {
        return Err(FileError::Exists(out.to_owned()).into());
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut seed[..]).map_err(|e| anyhow!("OS randomness unavailable: {e}"))?;
    let signer = rmm_trust::sign::Ed25519Signer::from_seed(&seed);
    let mut text = Zeroizing::new(hex::encode(&seed[..]));
    text.push('\n');
    write_secret(out, text.as_bytes(), force)?;
    eprintln!(
        "wrote {} (online server key: unencrypted, protected by file permissions only; \
         command role only)",
        out.display()
    );
    println!("public={}", hex::encode(signer.public_key().to_bytes()));
    println!("key_id={}", hex::encode(signer.key_id().0));
    Ok(())
}

/// Write secret bytes to a fresh temp file (0600 on Unix) and rename it into
/// place, never leaving a partially written or world-readable key.
fn write_secret(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    let werr = |e: std::io::Error| anyhow!("cannot write {}: {e}", path.display());
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    let tmp = PathBuf::from(name);
    let _ = std::fs::remove_file(&tmp);
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let res = (|| -> std::io::Result<()> {
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        if force {
            std::fs::rename(&tmp, path)
        } else {
            // Atomic no-clobber: fails if `path` appeared meanwhile.
            std::fs::hard_link(&tmp, path)?;
            std::fs::remove_file(&tmp)
        }
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        if e.kind() == ErrorKind::AlreadyExists {
            return Err(FileError::Exists(path.to_owned()).into());
        }
        return Err(werr(e));
    }
    Ok(())
}

fn open_backend(
    backend: &Backend,
    expect: Option<&str>,
    for_signing: bool,
) -> Result<Box<dyn Signer>> {
    let expect: Option<KeyId> = expect
        .map(|s| parse_hex32("--expect-key-id", s).map(KeyId))
        .transpose()?;
    let signer: Box<dyn Signer> = match backend {
        Backend::File(path) => {
            let pass = file_backend::passphrase(false)?;
            Box::new(file_backend::load(path, pass)?)
        }
        Backend::Card(ident) => card_backend::open(ident.as_deref(), for_signing, expect.as_ref())?,
    };
    if let Some(want) = expect
        && signer.key_id() != want
    {
        bail!(
            "key id {} does not match expected {}",
            hex::encode(signer.key_id().0),
            hex::encode(want.0)
        );
    }
    Ok(signer)
}

fn pubkey(backend: &Backend, expect: Option<&str>) -> Result<()> {
    let signer = open_backend(backend, expect, false)?;
    print_key(signer.as_ref());
    Ok(())
}

fn read_envelope(path: &Path) -> Result<Envelope> {
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    Envelope::from_bytes(&bytes).map_err(|e| anyhow!("{}: invalid envelope: {e}", path.display()))
}

fn doc_type_of(env: &Envelope) -> Result<DocType> {
    DocType::from_type_string(&env.r#type)
        .ok_or_else(|| anyhow!("unsupported envelope type {:?}", env.r#type))
}

/// Unified diff of `old` to `new` (an empty `old` yields the whole document).
fn unified_diff(old: &str, new: &str, old_label: &str) -> String {
    TextDiff::from_lines(old, new)
        .unified_diff()
        .context_radius(3)
        .header(old_label, "new draft")
        .to_string()
}

fn confirm() -> Result<()> {
    eprint!("Type 'yes' to sign: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("cannot read confirmation")?;
    if line.trim() != "yes" {
        bail!("aborted: confirmation was not 'yes'");
    }
    Ok(())
}

struct SignArgs {
    doc_type: DocType,
    input: PathBuf,
    prev: Option<PathBuf>,
    backend: Backend,
    expect_key_id: Option<String>,
    add_to: Option<PathBuf>,
    out: PathBuf,
    yes: bool,
    force: bool,
    allow_aaguid: Vec<String>,
}

fn sign(a: &SignArgs) -> Result<()> {
    let type_ = a.doc_type.type_string();
    let extra_aaguids = a
        .allow_aaguid
        .iter()
        .map(|s| aaguid::parse(s).map_err(|e| anyhow!("--allow-aaguid: {e}")))
        .collect::<Result<Vec<_>>>()?;
    if !extra_aaguids.is_empty() && a.doc_type != DocType::Techlist {
        bail!("--allow-aaguid only applies to --type techlist");
    }
    if a.out.exists() && !a.force {
        return Err(FileError::Exists(a.out.clone()).into());
    }
    let json = std::fs::read_to_string(&a.input)
        .with_context(|| format!("cannot read {}", a.input.display()))?;
    if a.doc_type == DocType::Techlist {
        check_techlist_hardware(&json, &extra_aaguids)
            .with_context(|| format!("draft {}", a.input.display()))?;
    }
    let draft =
        load_draft(a.doc_type, &json).with_context(|| format!("draft {}", a.input.display()))?;

    let (old_text, old_label) = match &a.prev {
        Some(p) => {
            let prev = read_envelope(p)?;
            if prev.r#type != type_ {
                bail!("--prev has type {} but --type is {type_}", prev.r#type);
            }
            (
                pretty_payload(a.doc_type, &prev.payload.0)?,
                p.display().to_string(),
            )
        }
        None => (String::new(), "(nothing)".to_owned()),
    };

    let existing = match &a.add_to {
        Some(p) => {
            let env = read_envelope(p)?;
            if env.r#type != type_ || env.payload.0 != draft.payload {
                bail!(
                    "--add-to {} carries a different document than the draft; refusing",
                    p.display()
                );
            }
            Some(env)
        }
        None => None,
    };

    let signer = open_backend(&a.backend, a.expect_key_id.as_deref(), true)?;
    let mut new_text = draft.pretty.clone();
    if !new_text.ends_with('\n') {
        new_text.push('\n');
    }
    let mut old_text = old_text;
    if !old_text.is_empty() && !old_text.ends_with('\n') {
        old_text.push('\n');
    }
    eprintln!(
        "Signing {type_} as key_id {}",
        hex::encode(signer.key_id().0)
    );
    eprintln!("{}", unified_diff(&old_text, &new_text, &old_label));
    if !a.yes {
        confirm()?;
    }

    let mut env = sign_envelope(type_, draft.payload, &[signer.as_ref()])
        .map_err(|e| anyhow!("signing failed: {e}"))?;
    if let Some(prior) = existing {
        let mut sigs = prior.sigs;
        for s in env.sigs {
            if sigs.iter().any(|x| x.key_id == s.key_id) {
                bail!(
                    "key {} has already signed this envelope",
                    hex::encode(s.key_id.0)
                );
            }
            sigs.push(s);
        }
        sigs.sort_by_key(|e| e.key_id);
        env.sigs = sigs;
    }

    let bytes = env
        .to_bytes()
        .map_err(|e| anyhow!("cannot encode envelope: {e}"))?;
    write_out(&a.out, &bytes, a.force)?;
    println!(
        "wrote {} ({} signature(s))",
        a.out.display(),
        env.sigs.len()
    );
    for s in &env.sigs {
        println!("signer: {}", hex::encode(s.key_id.0));
    }
    Ok(())
}

fn write_out(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    let werr = |e: std::io::Error| anyhow!("cannot write {}: {e}", path.display());
    if !force {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == ErrorKind::AlreadyExists {
                    anyhow::Error::from(FileError::Exists(path.to_owned()))
                } else {
                    werr(e)
                }
            })?;
        f.write_all(bytes).map_err(werr)?;
        return f.sync_all().map_err(werr);
    }
    // Overwrite atomically: write a sibling temp file, sync, then rename.
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    let tmp = std::path::PathBuf::from(name);
    let res = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(werr(e));
    }
    Ok(())
}

fn now_unix() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before 1970")?
        .as_secs())
}

fn verify(
    roots: &[String],
    threshold: u8,
    manifest: Option<&Path>,
    now: Option<u64>,
    file: &Path,
) -> Result<()> {
    let now = match now {
        Some(n) => n,
        None => now_unix()?,
    };
    let clock = FixedClock(now);
    let mut seq = MemorySeqStore::new();
    let roots: Vec<PublicKey> = roots
        .iter()
        .map(|r| {
            let raw = parse_hex32("root key", r)?;
            PublicKey::from_bytes(&raw).map_err(|e| anyhow!("invalid root key {r}: {e}"))
        })
        .collect::<Result<_>>()?;
    let mut store = TrustStore::new(roots.clone(), threshold);

    let target = std::fs::read(file).with_context(|| format!("cannot read {}", file.display()))?;
    let env = Envelope::from_bytes(&target)
        .map_err(|e| anyhow!("{}: invalid envelope: {e}", file.display()))?;
    let ty = doc_type_of(&env)?;

    if ty != DocType::Manifest {
        let mpath = manifest
            .ok_or_else(|| anyhow!("--manifest is required to verify a {} envelope", env.r#type))?;
        let mbytes =
            std::fs::read(mpath).with_context(|| format!("cannot read {}", mpath.display()))?;
        store
            .apply_manifest(&mbytes, &clock, &mut seq)
            .map_err(|e| anyhow!("manifest {}: {e}", mpath.display()))?;
    }

    let signers: Vec<KeyId> = match ty {
        DocType::Manifest => {
            store
                .apply_manifest(&target, &clock, &mut seq)
                .map_err(|e| anyhow!("verification failed: {e}"))?;
            let installed = store
                .manifest()
                .ok_or_else(|| anyhow!("manifest was not installed"))?;
            let keys = installed.root_public_keys().map_err(|e| anyhow!("{e}"))?;
            let ids: std::collections::BTreeSet<KeyId> = env
                .sigs
                .iter()
                .filter(|s| {
                    keys.iter()
                        .any(|k| k.key_id() == s.key_id && env.verify_sig(s, k).is_ok())
                })
                .map(|s| s.key_id)
                .collect();
            ids.into_iter().collect()
        }
        DocType::Revocations => {
            store
                .apply_revocations(&target, &clock, &mut seq)
                .map_err(|e| anyhow!("verification failed: {e}"))?;
            store
                .verify_role(&env, Role::ArtifactRevoke, now)
                .map_err(|e| anyhow!("verification failed: {e}"))?
        }
        DocType::Techlist => {
            store
                .apply_techlist(&target, &clock, &mut seq)
                .map_err(|e| anyhow!("verification failed: {e}"))?;
            store
                .verify_role(&env, Role::Techlist, now)
                .map_err(|e| anyhow!("verification failed: {e}"))?
        }
        DocType::Definition => {
            let ids = store
                .verify_role(&env, Role::Catalog, now)
                .map_err(|e| anyhow!("verification failed: {e}"))?;
            // Strict canonical decoding and static validation.
            let def = rmm_recipe::definition::Definition::from_envelope_payload(&env.payload.0)
                .map_err(|e| anyhow!("verification failed: {e}"))?;
            rmm_recipe::validate::validate_definition(&def, rmm_recipe::validate::BLOCKS)
                .map_err(|e| anyhow!("verification failed: {e}"))?;
            ids
        }
        DocType::Release => {
            // Role, strict canonical decoding, validation and time window.
            rmm_trust::docs::verify_release(&store, &target, now)
                .map_err(|e| anyhow!("verification failed: {e}"))?;
            store
                .verify_role(&env, Role::Release, now)
                .map_err(|e| anyhow!("verification failed: {e}"))?
        }
        DocType::Command => {
            let ids = store
                .verify_role(&env, Role::Command, now)
                .map_err(|e| anyhow!("verification failed: {e}"))?;
            // Strict canonical decoding and structural validation.
            let cmd: rmm_trust::docs::Command =
                decode_doc(&env.payload.0).map_err(|e| anyhow!("verification failed: {e}"))?;
            cmd.validate()
                .map_err(|e| anyhow!("verification failed: {e}"))?;
            if cmd.issued_at > now.saturating_add(rmm_trust::docs::SKEW_SECS) {
                bail!("verification failed: document not yet valid");
            }
            if now >= cmd.expires_at {
                bail!("verification failed: document expired");
            }
            ids
        }
    };

    println!("OK: {} verified at {now}", env.r#type);
    for id in &signers {
        println!("signer: {}", hex::encode(id.0));
    }
    println!("{}", pretty_payload(ty, &env.payload.0)?);
    Ok(())
}

fn inspect(file: &Path) -> Result<()> {
    let env = read_envelope(file)?;
    println!("version: {}", env.v);
    println!("type: {}", env.r#type);
    println!("content_id: {}", hex::encode(env.content_id()));
    println!("signatures: {}", env.sigs.len());
    for s in &env.sigs {
        println!("  key_id: {} alg: {}", hex::encode(s.key_id.0), s.alg);
    }
    match DocType::from_type_string(&env.r#type) {
        Some(ty) => println!("{}", pretty_payload(ty, &env.payload.0)?),
        None => println!("payload (hex): {}", hex::encode(&env.payload.0)),
    }
    Ok(())
}
