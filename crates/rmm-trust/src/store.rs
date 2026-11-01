//! The agent-side trust store: verifies manifests, revocations, technician
//! lists and commands. Time, sequence state and the replay cache are injected
//! so verification stays pure and testable.
//!
//! Every `apply_*` call is all-or-nothing: on any error neither the store nor
//! the [`SeqStore`] is changed.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::docs::{
    ArtifactRevocations, Command, CommandBody, Role, SKEW_SECS, TechnicianList, TrustManifest,
    decode_doc,
};
use crate::envelope::{
    ALG_ED25519, Envelope, TYPE_COMMAND, TYPE_MANIFEST, TYPE_REVOCATIONS, TYPE_TECHLIST,
};
use crate::error::TrustError;
use crate::keys::{KeyId, PublicKey};

/// Most signature entries an envelope may carry; bounds verification work.
pub const MAX_SIGS: usize = 16;

/// Source of the current time (Unix seconds).
pub trait Clock {
    /// Current Unix time in seconds.
    fn now(&self) -> u64;
}

/// Kinds of sequenced trust documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DocKind {
    /// [`TrustManifest`].
    Manifest,
    /// [`ArtifactRevocations`].
    Revocations,
    /// [`TechnicianList`].
    Techlist,
}

/// Persistent highest accepted `(seq, content_id)` per document kind.
pub trait SeqStore {
    /// The stored sequence number and payload hash.
    fn get(&self, kind: DocKind) -> Option<(u64, [u8; 32])>;
    /// Record an accepted document.
    fn put(&mut self, kind: DocKind, seq: u64, content_id: [u8; 32]);
}

/// Set of command ids already accepted.
pub trait ReplayCache {
    /// Returns true if `cmd_id` is already present; inserts it otherwise.
    fn seen(&mut self, cmd_id: &[u8], expires_at: u64) -> bool;
}

/// Verified trust state.
#[derive(Debug, Clone)]
pub struct TrustStore {
    root_keys: Vec<PublicKey>,
    root_threshold: u8,
    manifest: Option<TrustManifest>,
    revocations: Option<ArtifactRevocations>,
    techlist: Option<TechnicianList>,
    manifest_env: Option<Envelope>,
    revocations_env: Option<Envelope>,
    techlist_env: Option<Envelope>,
}

fn check_time(issued_at: u64, expires_at: u64, now: u64) -> Result<(), TrustError> {
    if issued_at > now.saturating_add(SKEW_SECS) {
        return Err(TrustError::NotYetValid);
    }
    if now >= expires_at {
        return Err(TrustError::Expired);
    }
    Ok(())
}

fn count_u8(n: usize) -> u8 {
    u8::try_from(n).unwrap_or(u8::MAX)
}

fn check_sig_count(env: &Envelope) -> Result<(), TrustError> {
    if env.sigs.len() > MAX_SIGS {
        return Err(TrustError::InvalidDocument("too many signatures".into()));
    }
    Ok(())
}

/// Count distinct, unrevoked keys from `keys` with a valid signature.
fn verify_roots(
    env: &Envelope,
    keys: &[PublicKey],
    threshold: u8,
    revoked: &[KeyId],
) -> Result<(), TrustError> {
    if threshold == 0 {
        return Err(TrustError::InvalidDocument("root threshold is 0".into()));
    }
    check_sig_count(env)?;
    let mut ok = BTreeSet::new();
    for entry in &env.sigs {
        if ok.contains(&entry.key_id) || revoked.contains(&entry.key_id) {
            continue;
        }
        if let Some(key) = keys.iter().find(|k| k.key_id() == entry.key_id)
            && env.verify_sig(entry, key).is_ok()
        {
            ok.insert(entry.key_id);
        }
    }
    if ok.len() < usize::from(threshold) {
        return Err(TrustError::BelowThreshold {
            role: Role::Root,
            got: count_u8(ok.len()),
            need: threshold,
        });
    }
    Ok(())
}

/// Reject `got` unless it is newer than, or identical to, every known state.
fn check_seq(
    known: &[Option<(u64, [u8; 32])>],
    got: u64,
    content_id: &[u8; 32],
) -> Result<(), TrustError> {
    for &(stored, id) in known.iter().flatten() {
        if got < stored {
            return Err(TrustError::Rollback { stored, got });
        }
        if got == stored && &id != content_id {
            return Err(TrustError::Equivocation);
        }
    }
    Ok(())
}

fn held(env: Option<&Envelope>, seq: Option<u64>) -> Option<(u64, [u8; 32])> {
    Some((seq?, env?.content_id()))
}

fn decode_typed(env_bytes: &[u8], type_: &str) -> Result<Envelope, TrustError> {
    let env = Envelope::from_bytes(env_bytes)?;
    if env.r#type != type_ {
        return Err(TrustError::WrongType);
    }
    check_sig_count(&env)?;
    Ok(env)
}

impl TrustStore {
    /// A store trusting only the compiled-in root keys. A threshold of 0
    /// never verifies anything (fail closed).
    pub fn new(compiled_roots: Vec<PublicKey>, threshold: u8) -> Self {
        Self {
            root_keys: compiled_roots,
            root_threshold: threshold,
            manifest: None,
            revocations: None,
            techlist: None,
            manifest_env: None,
            revocations_env: None,
            techlist_env: None,
        }
    }

    /// The current manifest.
    pub fn manifest(&self) -> Option<&TrustManifest> {
        self.manifest.as_ref()
    }

    /// The current artifact revocations.
    pub fn revocations(&self) -> Option<&ArtifactRevocations> {
        self.revocations.as_ref()
    }

    /// The current technician list.
    pub fn techlist(&self) -> Option<&TechnicianList> {
        self.techlist.as_ref()
    }

    fn current_roots(&self) -> Result<(Vec<PublicKey>, u8), TrustError> {
        match &self.manifest {
            Some(m) => Ok((m.root_public_keys()?, m.root_threshold)),
            None => Ok((self.root_keys.clone(), self.root_threshold)),
        }
    }

    /// Verify and install a manifest envelope. It must meet the threshold of
    /// the currently trusted roots and of its own root set.
    pub fn apply_manifest(
        &mut self,
        env_bytes: &[u8],
        clock: &dyn Clock,
        seq: &mut dyn SeqStore,
    ) -> Result<(), TrustError> {
        let now = clock.now();
        let env = decode_typed(env_bytes, TYPE_MANIFEST)?;
        let doc: TrustManifest = decode_doc(&env.payload.0)?;
        doc.validate()?;

        let mut revoked = doc.revoked_keys.clone();
        if let Some(m) = &self.manifest {
            revoked.extend_from_slice(&m.revoked_keys);
        }
        let (old_roots, old_threshold) = self.current_roots()?;
        verify_roots(&env, &old_roots, old_threshold, &revoked)?;
        verify_roots(&env, &doc.root_public_keys()?, doc.root_threshold, &revoked)?;

        check_time(doc.issued_at, doc.expires_at, now)?;
        let content_id = env.content_id();
        let mem = held(
            self.manifest_env.as_ref(),
            self.manifest.as_ref().map(|m| m.seq),
        );
        check_seq(&[seq.get(DocKind::Manifest), mem], doc.seq, &content_id)?;

        // Re-check the held documents under the new manifest; drop any whose
        // signers no longer qualify (fail closed).
        let mut next = self.clone();
        next.manifest = Some(doc.clone());
        next.manifest_env = Some(env);
        if let Some(e) = &next.revocations_env
            && next.verify_role(e, Role::ArtifactRevoke, now).is_err()
        {
            next.revocations = None;
            next.revocations_env = None;
        }
        if let Some(e) = &next.techlist_env
            && next.verify_role(e, Role::Techlist, now).is_err()
        {
            next.techlist = None;
            next.techlist_env = None;
        }
        *self = next;
        seq.put(DocKind::Manifest, doc.seq, content_id);
        Ok(())
    }

    /// Verify and install an artifact revocation list (role `artifact-revoke`).
    pub fn apply_revocations(
        &mut self,
        env_bytes: &[u8],
        clock: &dyn Clock,
        seq: &mut dyn SeqStore,
    ) -> Result<(), TrustError> {
        let now = clock.now();
        self.manifest_unexpired(now)?;
        let env = decode_typed(env_bytes, TYPE_REVOCATIONS)?;
        self.verify_role(&env, Role::ArtifactRevoke, now)?;
        let doc: ArtifactRevocations = decode_doc(&env.payload.0)?;
        doc.validate()?;
        check_time(doc.issued_at, doc.expires_at, now)?;
        let content_id = env.content_id();
        let mem = held(
            self.revocations_env.as_ref(),
            self.revocations.as_ref().map(|r| r.seq),
        );
        check_seq(&[seq.get(DocKind::Revocations), mem], doc.seq, &content_id)?;
        seq.put(DocKind::Revocations, doc.seq, content_id);
        self.revocations = Some(doc);
        self.revocations_env = Some(env);
        Ok(())
    }

    /// Verify and install a technician list (role `techlist`).
    pub fn apply_techlist(
        &mut self,
        env_bytes: &[u8],
        clock: &dyn Clock,
        seq: &mut dyn SeqStore,
    ) -> Result<(), TrustError> {
        let now = clock.now();
        self.manifest_unexpired(now)?;
        let env = decode_typed(env_bytes, TYPE_TECHLIST)?;
        self.verify_role(&env, Role::Techlist, now)?;
        let doc: TechnicianList = decode_doc(&env.payload.0)?;
        doc.validate()?;
        check_time(doc.issued_at, doc.expires_at, now)?;
        let content_id = env.content_id();
        let mem = held(
            self.techlist_env.as_ref(),
            self.techlist.as_ref().map(|t| t.seq),
        );
        check_seq(&[seq.get(DocKind::Techlist), mem], doc.seq, &content_id)?;
        seq.put(DocKind::Techlist, doc.seq, content_id);
        self.techlist = Some(doc);
        self.techlist_env = Some(env);
        Ok(())
    }

    /// Installing documents requires an installed, unexpired manifest.
    fn manifest_unexpired(&self, now: u64) -> Result<(), TrustError> {
        let m = self.manifest.as_ref().ok_or(TrustError::NoManifest)?;
        if now >= m.expires_at {
            return Err(TrustError::Stale);
        }
        Ok(())
    }

    fn check_entry(
        m: &TrustManifest,
        env: &Envelope,
        entry: &crate::envelope::SigEntry,
        role: Role,
        now: u64,
    ) -> Result<(), TrustError> {
        if m.is_key_revoked(&entry.key_id) {
            return Err(TrustError::KeyRevoked);
        }
        let cert = m.cert(&entry.key_id).ok_or(TrustError::UnknownKey)?;
        if !cert.roles.contains(&role) {
            return Err(TrustError::WrongRole);
        }
        if cert.alg != ALG_ED25519 || entry.alg != ALG_ED25519 {
            return Err(TrustError::UnsupportedAlg);
        }
        if !cert.valid_at(now) {
            return Err(TrustError::CertNotValid);
        }
        env.verify_sig(entry, &cert.public_key()?)
    }

    /// Distinct valid signer key ids for `role`, if they meet the role's
    /// threshold. A key is counted once, and only if it is certified for the
    /// role, its cert is valid at `now`, it is not revoked and its signature
    /// verifies. When no signer qualifies, the first signer's failure is
    /// returned; otherwise a shortfall is [`TrustError::BelowThreshold`].
    pub fn verify_role(
        &self,
        env: &Envelope,
        role: Role,
        now: u64,
    ) -> Result<Vec<KeyId>, TrustError> {
        let m = self.manifest.as_ref().ok_or(TrustError::NoManifest)?;
        let need = *m.thresholds.get(&role).ok_or(TrustError::WrongRole)?;
        if need == 0 {
            return Err(TrustError::InvalidDocument("threshold is 0".into()));
        }
        check_sig_count(env)?;
        let mut ok = BTreeSet::new();
        let mut first_err = None;
        for entry in &env.sigs {
            if ok.contains(&entry.key_id) {
                continue;
            }
            match Self::check_entry(m, env, entry, role, now) {
                Ok(()) => {
                    ok.insert(entry.key_id);
                }
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        if ok.len() >= usize::from(need) {
            return Ok(ok.into_iter().collect());
        }
        if ok.is_empty()
            && let Some(e) = first_err
        {
            return Err(e);
        }
        Err(TrustError::BelowThreshold {
            role,
            got: count_u8(ok.len()),
            need,
        })
    }

    /// Verify a command for this agent. Order: signature chain and role,
    /// freshness (skipped for `TrustUpdate`), agent/client binding, time
    /// window, artifact revocation, replay. The replay cache is only touched
    /// when every other check has passed.
    pub fn verify_command(
        &self,
        env_bytes: &[u8],
        agent_id: &str,
        client_id: &str,
        clock: &dyn Clock,
        replay: &mut dyn ReplayCache,
    ) -> Result<Command, TrustError> {
        let now = clock.now();
        if self.manifest.is_none() {
            return Err(TrustError::NoManifest);
        }
        let env = decode_typed(env_bytes, TYPE_COMMAND)?;
        self.verify_role(&env, Role::Command, now)?;
        let cmd: Command = decode_doc(&env.payload.0)?;
        if !matches!(cmd.body, CommandBody::TrustUpdate { .. }) {
            self.trust_fresh(now)?;
        }
        if cmd.agent_id != agent_id {
            return Err(TrustError::WrongAgent);
        }
        if cmd.client_id != client_id {
            return Err(TrustError::WrongClient);
        }
        cmd.validate()?;
        check_time(cmd.issued_at, cmd.expires_at, now)?;
        if let CommandBody::Invoke { definition, .. } = &cmd.body {
            let raw: [u8; 32] = Sha256::digest(&definition.0).into();
            let inner = Envelope::from_bytes(&definition.0)
                .ok()
                .map(|e| e.content_id());
            if self.is_artifact_revoked(&raw)
                || inner.is_some_and(|id| self.is_artifact_revoked(&id))
            {
                return Err(TrustError::ArtifactRevoked);
            }
        }
        if replay.seen(&cmd.cmd_id.0, cmd.expires_at) {
            return Err(TrustError::Replay);
        }
        Ok(cmd)
    }

    /// Ok if a manifest is installed and neither it nor the revocation list
    /// has expired.
    pub fn trust_fresh(&self, now: u64) -> Result<(), TrustError> {
        let m = self.manifest.as_ref().ok_or(TrustError::NoManifest)?;
        if now >= m.expires_at {
            return Err(TrustError::Stale);
        }
        match &self.revocations {
            Some(r) if now < r.expires_at => Ok(()),
            _ => Err(TrustError::Stale),
        }
    }

    /// Whether the installed revocation list lists `content_id`.
    pub fn is_artifact_revoked(&self, content_id: &[u8; 32]) -> bool {
        self.revocations
            .as_ref()
            .is_some_and(|r| r.is_revoked(content_id))
    }
}
