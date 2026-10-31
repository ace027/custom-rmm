//! Verification side of the trust chain.

use std::collections::BTreeMap;
use std::sync::Arc;

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

/// Default maximum number of command ids held by a [`MemoryReplayCache`].
pub const DEFAULT_REPLAY_CAPACITY: usize = 65_536;

/// In-memory [`ReplayCache`]. On insert, entries whose
/// `expires_at + SKEW_SECS < now` are pruned, where `now` comes from the
/// [`Clock`] given at construction. Such commands are rejected as expired
/// before the cache is consulted, so pruning them is safe. The cache is
/// bounded: when it is full after pruning, new ids are reported as seen
/// (fail closed), so the command is rejected rather than memory growing.
pub struct MemoryReplayCache {
    entries: BTreeMap<Vec<u8>, u64>,
    clock: Arc<dyn Clock + Send + Sync>,
    capacity: usize,
}

impl std::fmt::Debug for MemoryReplayCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryReplayCache")
            .field("len", &self.entries.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl MemoryReplayCache {
    /// An empty cache pruned against `clock`, with the default capacity.
    pub fn new(clock: impl Clock + Send + Sync + 'static) -> Self {
        Self::with_capacity(clock, DEFAULT_REPLAY_CAPACITY)
    }

    /// An empty cache pruned against `clock`, holding at most `capacity` ids.
    pub fn with_capacity(clock: impl Clock + Send + Sync + 'static, capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            clock: Arc::new(clock),
            capacity,
        }
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
        let now = self.clock.now();
        self.entries
            .retain(|_, exp| exp.saturating_add(SKEW_SECS) >= now);
        if self.entries.len() >= self.capacity {
            return true;
        }
        self.entries.insert(cmd_id.to_vec(), expires_at);
        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn protocol_matches() {
        assert_eq!(super::supported_protocol(), rmm_proto::PROTOCOL_VERSION);
    }

    #[derive(Clone)]
    struct SharedClock(Arc<Mutex<u64>>);

    impl Clock for SharedClock {
        fn now(&self) -> u64 {
            *self.0.lock().unwrap()
        }
    }

    #[test]
    fn replay_cache_detects_and_prunes() {
        let t = Arc::new(Mutex::new(1000));
        let mut c = MemoryReplayCache::new(SharedClock(t.clone()));
        assert!(!c.seen(b"a", 1100));
        assert!(c.seen(b"a", 1100));
        *t.lock().unwrap() = 1100 + SKEW_SECS;
        assert!(!c.seen(b"b", 5000));
        assert_eq!(c.len(), 2, "not yet past expires_at + skew");
        *t.lock().unwrap() = 1101 + SKEW_SECS;
        assert!(!c.seen(b"c", 5000));
        assert_eq!(c.len(), 2, "a pruned");
        assert!(!c.seen(b"a", 1100));
    }

    #[test]
    fn replay_cache_fails_closed_when_full() {
        let mut c = MemoryReplayCache::with_capacity(FixedClock(1000), 2);
        assert!(!c.seen(b"a", 5000));
        assert!(!c.seen(b"b", 5000));
        assert!(c.seen(b"c", 5000), "full cache rejects new ids");
        assert_eq!(c.len(), 2);
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
