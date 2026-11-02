//! Agent-side verification of a `ShellOpen` command.
//!
//! The server command key alone can never open a shell: besides the signed
//! command, the agent requires a WebAuthn assertion over the exact grant
//! bytes, made by a hardware credential listed for the technician in the
//! techlist-signed [`TechnicianList`], with user verification.
//!
//! Check order (after the command envelope, binding, time-window and
//! command-replay checks of [`rmm_trust::store::TrustStore::verify_command`]):
//! grant decodes (canonical, structurally valid, no E2E key) -> grant and
//! command are bound to this agent and client -> `now <= open_by + 30 s` ->
//! `max_duration <= 14400` -> shell in the platform allowlist -> grant id not
//! seen -> technician listed -> client in the technician's scope -> credential
//! listed -> assertion verifies against `shell_challenge(grant bytes)`, the
//! manifest's console RP id and origins, with UV required. The session limit
//! ([`ShellReject::TooManySessions`]) is enforced when the session is opened.

use std::fmt;

use rmm_platform::pty::ShellKind;
use rmm_recipe::result::RejectReason;
use rmm_trust::docs::{
    COSE_EDDSA, COSE_ES256, Command, MAX_SHELL_DURATION, SKEW_SECS, ShellGrant, decode_doc,
};
use rmm_trust::store::TrustStore;
use rmm_trust::webauthn::{
    Assertion, CoseKey, Expected, parse_cose_key, shell_challenge, verify_assertion,
};

/// Seconds after `open_by` a grant is still accepted (clock skew).
pub const OPEN_GRACE_SECS: u64 = 30;

/// Domain separation of grant ids in the shared replay cache, so a grant id
/// can never collide with a command id.
const REPLAY_PREFIX: &[u8] = b"rmm.shell-grant/1\0";

/// Why a `ShellOpen` was refused. [`ShellReject::as_str`] is the stable
/// reason string reported in the signed result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellReject {
    /// The grant does not decode or is structurally invalid.
    BadGrant,
    /// The grant or command is for another agent or client.
    Binding,
    /// The grant's open window has passed (or it is not yet valid).
    Expired,
    /// `max_duration` is 0 or above the 4 h cap.
    MaxDuration,
    /// The requested shell is not allowlisted on this platform.
    ShellNotAllowed,
    /// The grant id was already used.
    Replay,
    /// The technician is not in the current technician list.
    UnknownTech,
    /// The agent's client is outside the technician's scope.
    OutOfScope,
    /// The credential is not listed for the technician.
    UnknownCredential,
    /// The WebAuthn assertion does not verify.
    BadAssertion,
    /// The concurrent-session limit is reached (or shells are unavailable).
    TooManySessions,
    /// The shell process could not be started.
    SpawnFailed,
}

impl ShellReject {
    /// Stable reason string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadGrant => "bad_grant",
            Self::Binding => "binding",
            Self::Expired => "expired",
            Self::MaxDuration => "max_duration",
            Self::ShellNotAllowed => "shell_not_allowed",
            Self::Replay => "replay",
            Self::UnknownTech => "unknown_tech",
            Self::OutOfScope => "out_of_scope",
            Self::UnknownCredential => "unknown_credential",
            Self::BadAssertion => "bad_assertion",
            Self::TooManySessions => "too_many_sessions",
            Self::SpawnFailed => "spawn_failed",
        }
    }

    /// The closest generic [`RejectReason`] for the signed result.
    pub fn reject_reason(self) -> RejectReason {
        match self {
            Self::BadGrant | Self::MaxDuration | Self::TooManySessions | Self::SpawnFailed => {
                RejectReason::Validation
            }
            Self::Binding => RejectReason::WrongAgent,
            Self::Expired => RejectReason::Expired,
            Self::ShellNotAllowed | Self::OutOfScope => RejectReason::Capability,
            Self::Replay => RejectReason::Replay,
            Self::UnknownTech | Self::UnknownCredential | Self::BadAssertion => {
                RejectReason::BadSignature
            }
        }
    }
}

impl fmt::Display for ShellReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for ShellReject {}

/// A grant that passed every check.
#[derive(Debug, Clone)]
pub struct VerifiedGrant {
    /// The decoded grant.
    pub grant: ShellGrant,
    /// The technician who co-signed it.
    pub tech_id: String,
    /// The allowlisted shell to start.
    pub kind: ShellKind,
}

impl VerifiedGrant {
    /// Session id: the grant id as lowercase hex.
    pub fn sid(&self) -> String {
        rmm_proto::subjects::sid_from_grant_id(&self.grant.grant_id.0)
    }
}

/// Key under which a grant id is stored in the replay cache.
pub fn replay_key(grant_id: &[u8]) -> Vec<u8> {
    let mut k = REPLAY_PREFIX.to_vec();
    k.extend_from_slice(grant_id);
    k
}

/// Replay-cache expiry for a grant: `open_by + grace + max_duration + skew`.
/// An undecodable grant never reaches the replay check; it gets `u64::MAX`.
pub fn replay_expiry(grant_bytes: &[u8]) -> u64 {
    decode_doc::<ShellGrant>(grant_bytes).map_or(u64::MAX, |g| {
        g.open_by
            .saturating_add(OPEN_GRACE_SECS)
            .saturating_add(u64::from(g.max_duration))
            .saturating_add(SKEW_SECS)
    })
}

fn reject<T>(r: ShellReject, why: impl fmt::Display) -> Result<T, ShellReject> {
    tracing::warn!(reason = r.as_str(), "shell open rejected: {why}");
    Err(r)
}

/// Verify a `ShellOpen`. `cmd` is the already verified command, `grant_bytes`
/// the canonical grant it carries, `seen` the replay check (returns true if
/// the key was already present; inserts it otherwise).
#[allow(clippy::too_many_arguments)]
pub fn verify_shell_open(
    cmd: &Command,
    grant_bytes: &[u8],
    assertion: &Assertion,
    trust: &TrustStore,
    agent_id: &str,
    client_id: &str,
    now: u64,
    seen: &dyn Fn(&[u8]) -> bool,
) -> Result<VerifiedGrant, ShellReject> {
    let grant: ShellGrant = match decode_doc(grant_bytes) {
        Ok(g) => g,
        Err(e) => return reject(ShellReject::BadGrant, e),
    };
    if grant.grant_id.0.len() != 16
        || grant.cred_id.0.is_empty()
        || grant.open_by <= grant.issued_at
    {
        return reject(ShellReject::BadGrant, "structurally invalid grant");
    }
    if grant.e2e_pubkey.is_some() {
        // End-to-end encryption is not implemented; accepting the key would
        // let the technician believe the session is end-to-end protected.
        return reject(ShellReject::BadGrant, "e2e_pubkey is not supported");
    }
    if grant.agent_id != agent_id
        || grant.client_id != client_id
        || cmd.agent_id != grant.agent_id
        || cmd.client_id != grant.client_id
    {
        return reject(ShellReject::Binding, "grant is for another agent or client");
    }
    if now > grant.open_by.saturating_add(OPEN_GRACE_SECS) {
        return reject(ShellReject::Expired, "open_by has passed");
    }
    if grant.issued_at > now.saturating_add(SKEW_SECS) {
        return reject(ShellReject::Expired, "grant issued in the future");
    }
    if grant.max_duration == 0 || grant.max_duration > MAX_SHELL_DURATION {
        return reject(ShellReject::MaxDuration, grant.max_duration);
    }
    let Some(kind) = ShellKind::parse(&grant.shell) else {
        return reject(ShellReject::ShellNotAllowed, &grant.shell);
    };
    if seen(&replay_key(&grant.grant_id.0)) {
        return reject(ShellReject::Replay, "grant id already used");
    }

    let Some(tech) = trust.techlist().and_then(|l| l.tech(&grant.tech_id)) else {
        return reject(ShellReject::UnknownTech, &grant.tech_id);
    };
    if !tech.in_scope(client_id) {
        return reject(ShellReject::OutOfScope, &grant.tech_id);
    }
    let Some(cred) = tech.creds.iter().find(|c| c.cred_id == grant.cred_id) else {
        return reject(ShellReject::UnknownCredential, &grant.tech_id);
    };

    let Some(manifest) = trust.manifest() else {
        return reject(ShellReject::BadAssertion, "no manifest");
    };
    if manifest.console_rp_id.is_empty() || manifest.console_origins.is_empty() {
        return reject(ShellReject::BadAssertion, "manifest has no console RP");
    }
    let key = match parse_cose_key(&cred.cose_pubkey.0) {
        Ok(k) => k,
        Err(e) => return reject(ShellReject::BadAssertion, e),
    };
    let alg_ok = matches!(
        (&key, cred.alg),
        (CoseKey::Es256(_), COSE_ES256) | (CoseKey::Ed25519(_), COSE_EDDSA)
    );
    if !alg_ok {
        return reject(
            ShellReject::BadAssertion,
            "credential alg does not match its key",
        );
    }
    let expected = Expected {
        challenge: shell_challenge(grant_bytes),
        rp_id: &manifest.console_rp_id,
        origins: &manifest.console_origins,
        require_uv: true,
    };
    if let Err(e) = verify_assertion(assertion, &expected, &key) {
        return reject(ShellReject::BadAssertion, e);
    }

    Ok(VerifiedGrant {
        tech_id: grant.tech_id.clone(),
        grant,
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_are_stable() {
        assert_eq!(ShellReject::BadGrant.as_str(), "bad_grant");
        assert_eq!(
            ShellReject::TooManySessions.to_string(),
            "too_many_sessions"
        );
        assert_ne!(replay_key(&[1; 16]), vec![1; 16]);
        assert_eq!(replay_expiry(b"junk"), u64::MAX);
    }
}
