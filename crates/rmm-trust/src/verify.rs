//! Verification side of the trust chain.

use std::collections::BTreeMap;

pub use crate::envelope::{Envelope, SigEntry, pae, signing_message};
pub use crate::store::{Clock, DocKind, ReplayCache, SeqStore, TrustStore};

use crate::docs::SKEW_SECS;

/// Protocol version this verifier understands.
pub fn supported_protocol() -> u16 {
    rmm_proto::PROTOCOL_VERSION
}

/// A clock that always returns the same time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}

/// In-memory [`SeqStore`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemorySeqStore {
    entries: BTreeMap<DocKind, (u64, [u8; 32])>,
}

impl MemorySeqStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SeqStore for MemorySeqStore {
    fn get(&self, kind: DocKind) -> Option<(u64, [u8; 32])> {
        self.entries.get(&kind).copied()
    }

    fn put(&mut self, kind: DocKind, seq: u64, content_id: [u8; 32]) {
        self.entries.insert(kind, (seq, content_id));
    }
}

/// In-memory [`ReplayCache`]. On insert, entries whose
/// `expires_at + SKEW_SECS < now` are pruned, where `now` is the time last
/// given to [`MemoryReplayCache::set_now`]. Such commands are rejected as
/// expired before the cache is consulted, so pruning them is safe.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryReplayCache {
    entries: BTreeMap<Vec<u8>, u64>,
    now: u64,
}

impl MemoryReplayCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the time used for pruning.
    pub fn set_now(&mut self, now: u64) {
        self.now = now;
    }

    /// Number of cached command ids.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl ReplayCache for MemoryReplayCache {
    fn seen(&mut self, cmd_id: &[u8], expires_at: u64) -> bool {
        if self.entries.contains_key(cmd_id) {
            return true;
        }
        let now = self.now;
        self.entries
            .retain(|_, exp| exp.saturating_add(SKEW_SECS) >= now);
        self.entries.insert(cmd_id.to_vec(), expires_at);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_matches() {
        assert_eq!(super::supported_protocol(), rmm_proto::PROTOCOL_VERSION);
    }

    #[test]
    fn replay_cache_detects_and_prunes() {
        let mut c = MemoryReplayCache::new();
        c.set_now(1000);
        assert!(!c.seen(b"a", 1100));
        assert!(c.seen(b"a", 1100));
        c.set_now(1100 + SKEW_SECS);
        assert!(!c.seen(b"b", 5000));
        assert_eq!(c.len(), 2, "not yet past expires_at + skew");
        c.set_now(1101 + SKEW_SECS);
        assert!(!c.seen(b"c", 5000));
        assert_eq!(c.len(), 2, "a pruned");
        assert!(!c.seen(b"a", 1100));
    }

    #[test]
    fn seq_store_round_trip() {
        let mut s = MemorySeqStore::new();
        assert_eq!(s.get(DocKind::Manifest), None);
        s.put(DocKind::Manifest, 3, [1; 32]);
        assert_eq!(s.get(DocKind::Manifest), Some((3, [1; 32])));
        assert_eq!(s.get(DocKind::Techlist), None);
    }
}
