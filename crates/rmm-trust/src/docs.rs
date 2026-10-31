//! Signed trust documents: manifest, certificates, artifact revocations,
//! commands, shell grants and the technician list.
//!
//! Every document is carried as the canonical CBOR payload of an
//! [`Envelope`](crate::envelope::Envelope). Structs reject unknown fields and
//! [`decode_doc`] additionally requires the payload to be exactly the canonical
//! encoding of the decoded value, so one document has one byte representation.

use std::collections::{BTreeMap, BTreeSet};

use rmm_proto::canonical::{from_canonical_slice, to_canonical_vec};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::envelope::ALG_ED25519;
use crate::error::TrustError;
use crate::keys::{Bytes, KeyId, PublicKey};

/// Clock skew tolerance in seconds.
pub const SKEW_SECS: u64 = 300;
/// One day in seconds.
pub const DAY_SECS: u64 = 86_400;
/// Longest validity window of a trust manifest.
pub const MAX_MANIFEST_WINDOW: u64 = 400 * DAY_SECS;
/// Longest validity window of an artifact revocation list.
pub const MAX_REVOCATIONS_WINDOW: u64 = 60 * DAY_SECS;
/// Longest lifetime of a command.
pub const MAX_COMMAND_TTL: u64 = 7 * DAY_SECS;
/// Longest shell session a grant may allow.
pub const MAX_SHELL_DURATION: u32 = 4 * 3600;
/// COSE algorithm identifier for ES256.
pub const COSE_ES256: i32 = -7;
/// COSE algorithm identifier for EdDSA.
pub const COSE_EDDSA: i32 = -8;

/// A role a certified key may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Signs trust manifests.
    Root,
    /// Signs catalog definitions.
    Catalog,
    /// Signs release manifests.
    Release,
    /// Signs technician lists.
    Techlist,
    /// Signs artifact revocation lists.
    ArtifactRevoke,
    /// Signs commands (server command key).
    Command,
    /// Signs policies.
    Policy,
}

/// A key certified by the root inside a [`TrustManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cert {
    /// `SHA-256(pubkey)`.
    pub key_id: KeyId,
    /// Raw 32-byte Ed25519 public key.
    pub pubkey: Bytes,
    /// Signature algorithm; must be `ed25519`.
    pub alg: String,
    /// Roles this key may sign for.
    pub roles: Vec<Role>,
    /// Start of validity (inclusive).
    pub not_before: u64,
    /// End of validity (exclusive).
    pub not_after: u64,
    /// Human-readable label.
    pub label: String,
}

impl Cert {
    /// Parse the certified public key.
    pub fn public_key(&self) -> Result<PublicKey, TrustError> {
        parse_pubkey(&self.pubkey)
    }

    /// Whether `now` lies within `[not_before, not_after)`.
    pub fn valid_at(&self, now: u64) -> bool {
        self.not_before <= now && now < self.not_after
    }
}

/// The root-signed list of root keys, certificates and thresholds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustManifest {
    /// Strictly increasing sequence number.
    pub seq: u64,
    /// Issue time.
    pub issued_at: u64,
    /// Expiry time (exclusive).
    pub expires_at: u64,
    /// Raw 32-byte Ed25519 root public keys.
    pub root_keys: Vec<Bytes>,
    /// Number of distinct root signatures required.
    pub root_threshold: u8,
    /// Certified non-root keys.
    pub certs: Vec<Cert>,
    /// Signature threshold per role.
    pub thresholds: BTreeMap<Role, u8>,
    /// Key ids that must never be counted.
    pub revoked_keys: Vec<KeyId>,
    /// WebAuthn relying party id of the console.
    pub console_rp_id: String,
    /// Allowed WebAuthn origins of the console.
    pub console_origins: Vec<String>,
    /// Capability groups any policy may grant at most.
    pub capability_ceiling: Vec<String>,
    /// Reserved: out-of-band revocation mirrors.
    pub revocation_mirrors: Vec<String>,
}

/// Catalog-signed list of revoked artifact content ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRevocations {
    /// Strictly increasing sequence number.
    pub seq: u64,
    /// Issue time.
    pub issued_at: u64,
    /// Expiry time (exclusive); trust is stale afterwards.
    pub expires_at: u64,
    /// SHA-256 content ids of revoked artifacts.
    pub revoked_hashes: Vec<KeyId>,
}

/// A signed instruction for one agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    /// 16-byte nonce, used for replay protection.
    pub cmd_id: Bytes,
    /// Target agent.
    pub agent_id: String,
    /// Client (tenant) of the target agent.
    pub client_id: String,
    /// Issue time.
    pub issued_at: u64,
    /// Expiry time (exclusive).
    pub expires_at: u64,
    /// Hash of the policy the server evaluated.
    pub policy_hash: Bytes,
    /// What to do.
    pub body: CommandBody,
}

/// The action a [`Command`] carries.
///
/// The variant tag is the map key `kind`; because of that the `Collect`
/// field is carried on the wire as `collect_kind`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CommandBody {
    /// Invoke a catalog-signed definition.
    Invoke {
        /// The signed definition (envelope bytes).
        definition: Bytes,
        /// Parameters, a CBOR map with text keys.
        params: BTreeMap<String, ciborium::Value>,
    },
    /// Open a co-signed shell session.
    ShellOpen {
        /// Canonical [`ShellGrant`] bytes.
        grant: Bytes,
        /// WebAuthn assertion over the grant.
        assertion: Bytes,
    },
    /// Deliver new trust documents (envelope bytes).
    TrustUpdate {
        /// New manifest envelope.
        manifest: Option<Bytes>,
        /// New revocations envelope.
        revocations: Option<Bytes>,
        /// New technician list envelope.
        techlist: Option<Bytes>,
    },
    /// Run a read-only collector.
    Collect {
        /// Which collector to run.
        #[serde(rename = "collect_kind")]
        kind: String,
    },
}

/// Server-built shell grant, co-signed by a technician's WebAuthn assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellGrant {
    /// 16-byte grant id.
    pub grant_id: Bytes,
    /// Target agent.
    pub agent_id: String,
    /// Client of the target agent.
    pub client_id: String,
    /// Technician opening the shell.
    pub tech_id: String,
    /// WebAuthn credential id expected to sign.
    pub cred_id: Bytes,
    /// Issue time.
    pub issued_at: u64,
    /// Latest time the session may be opened.
    pub open_by: u64,
    /// Longest session length in seconds.
    pub max_duration: u32,
    /// Shell to start.
    pub shell: String,
    /// Whether the session is recorded.
    pub record: bool,
    /// Optional end-to-end encryption public key.
    pub e2e_pubkey: Option<Bytes>,
}

/// Techlist-signed list of technicians and their credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicianList {
    /// Strictly increasing sequence number.
    pub seq: u64,
    /// Issue time.
    pub issued_at: u64,
    /// Expiry time (exclusive).
    pub expires_at: u64,
    /// The technicians.
    pub techs: Vec<Technician>,
}

/// One technician.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Technician {
    /// Technician id.
    pub tech_id: String,
    /// Client ids this technician may act on; `"*"` means all.
    pub client_scope: Vec<String>,
    /// Permission names.
    pub perms: Vec<String>,
    /// Registered hardware credentials.
    pub creds: Vec<Credential>,
}

impl Technician {
    /// Whether `client_id` is in this technician's scope.
    pub fn in_scope(&self, client_id: &str) -> bool {
        self.client_scope.iter().any(|c| c == "*" || c == client_id)
    }
}

/// A WebAuthn credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    /// Credential id.
    pub cred_id: Bytes,
    /// COSE algorithm: -7 (ES256) or -8 (EdDSA).
    pub alg: i32,
    /// COSE_Key bytes.
    pub cose_pubkey: Bytes,
    /// 16-byte authenticator AAGUID.
    pub aaguid: Bytes,
}

fn invalid(msg: &str) -> TrustError {
    TrustError::InvalidDocument(msg.to_owned())
}

fn parse_pubkey(b: &Bytes) -> Result<PublicKey, TrustError> {
    let raw: [u8; 32] =
        b.0.as_slice()
            .try_into()
            .map_err(|_| invalid("public key must be 32 bytes"))?;
    PublicKey::from_bytes(&raw)
}

fn check_window(issued_at: u64, expires_at: u64, max: u64) -> Result<(), TrustError> {
    if expires_at <= issued_at {
        return Err(invalid("expires_at must be after issued_at"));
    }
    if expires_at - issued_at > max {
        return Err(invalid("validity window too long"));
    }
    Ok(())
}

/// Strictly decode a document payload. The payload must be canonical CBOR
/// and byte-identical to the canonical encoding of the decoded value.
pub fn decode_doc<T: Serialize + DeserializeOwned>(payload: &[u8]) -> Result<T, TrustError> {
    let doc: T = from_canonical_slice(payload)?;
    if to_canonical_vec(&doc)? != payload {
        return Err(invalid(
            "payload is not the canonical encoding of the document",
        ));
    }
    Ok(doc)
}

impl TrustManifest {
    /// Parsed root public keys.
    pub fn root_public_keys(&self) -> Result<Vec<PublicKey>, TrustError> {
        self.root_keys.iter().map(parse_pubkey).collect()
    }

    /// The certificate with `key_id`, if any.
    pub fn cert(&self, key_id: &KeyId) -> Option<&Cert> {
        self.certs.iter().find(|c| &c.key_id == key_id)
    }

    /// Whether `key_id` is listed in `revoked_keys`.
    pub fn is_key_revoked(&self, key_id: &KeyId) -> bool {
        self.revoked_keys.contains(key_id)
    }

    /// Structural validation.
    pub fn validate(&self) -> Result<(), TrustError> {
        check_window(self.issued_at, self.expires_at, MAX_MANIFEST_WINDOW)?;

        let roots = self.root_public_keys()?;
        let root_ids: BTreeSet<KeyId> = roots.iter().map(PublicKey::key_id).collect();
        if root_ids.len() != roots.len() {
            return Err(invalid("duplicate root key"));
        }
        if self.root_threshold == 0 || usize::from(self.root_threshold) > roots.len() {
            return Err(invalid(
                "root_threshold must be between 1 and the number of root keys",
            ));
        }

        let mut ids = BTreeSet::new();
        for cert in &self.certs {
            let pk = cert.public_key()?;
            if pk.key_id() != cert.key_id {
                return Err(invalid("cert key_id does not match pubkey"));
            }
            if cert.alg != ALG_ED25519 {
                return Err(invalid("unsupported cert algorithm"));
            }
            if cert.not_before >= cert.not_after {
                return Err(invalid("cert not_before must be before not_after"));
            }
            if !ids.insert(cert.key_id) {
                return Err(invalid("duplicate cert key_id"));
            }
        }

        for (role, &need) in &self.thresholds {
            if need == 0 {
                return Err(invalid("thresholds must be at least 1"));
            }
            let holders = self.certs.iter().filter(|c| c.roles.contains(role)).count();
            if usize::from(need) > holders {
                return Err(invalid(
                    "threshold exceeds the number of certs holding the role",
                ));
            }
        }
        Ok(())
    }
}

impl ArtifactRevocations {
    /// Structural validation.
    pub fn validate(&self) -> Result<(), TrustError> {
        check_window(self.issued_at, self.expires_at, MAX_REVOCATIONS_WINDOW)
    }

    /// Whether `content_id` is revoked.
    pub fn is_revoked(&self, content_id: &[u8; 32]) -> bool {
        self.revoked_hashes.iter().any(|h| &h.0 == content_id)
    }
}

impl Command {
    /// Structural validation.
    pub fn validate(&self) -> Result<(), TrustError> {
        if self.cmd_id.0.len() != 16 {
            return Err(invalid("cmd_id must be 16 bytes"));
        }
        check_window(self.issued_at, self.expires_at, MAX_COMMAND_TTL)
    }
}

impl ShellGrant {
    /// Structural validation.
    pub fn validate(&self) -> Result<(), TrustError> {
        if self.grant_id.0.len() != 16 {
            return Err(invalid("grant_id must be 16 bytes"));
        }
        if self.cred_id.0.is_empty() {
            return Err(invalid("cred_id must not be empty"));
        }
        if self.open_by <= self.issued_at {
            return Err(invalid("open_by must be after issued_at"));
        }
        if self.max_duration == 0 || self.max_duration > MAX_SHELL_DURATION {
            return Err(invalid("max_duration out of range"));
        }
        Ok(())
    }
}

impl TechnicianList {
    /// Structural validation.
    pub fn validate(&self) -> Result<(), TrustError> {
        if self.expires_at <= self.issued_at {
            return Err(invalid("expires_at must be after issued_at"));
        }
        let mut techs = BTreeSet::new();
        for tech in &self.techs {
            if !techs.insert(tech.tech_id.as_str()) {
                return Err(invalid("duplicate tech_id"));
            }
            for cred in &tech.creds {
                if cred.alg != COSE_ES256 && cred.alg != COSE_EDDSA {
                    return Err(invalid("credential alg must be -7 (ES256) or -8 (EdDSA)"));
                }
                if cred.aaguid.0.len() != 16 {
                    return Err(invalid("aaguid must be 16 bytes"));
                }
                if cred.cred_id.0.is_empty() {
                    return Err(invalid("cred_id must not be empty"));
                }
            }
        }
        Ok(())
    }

    /// The technician with `tech_id`, if any.
    pub fn tech(&self, tech_id: &str) -> Option<&Technician> {
        self.techs.iter().find(|t| t.tech_id == tech_id)
    }
}
