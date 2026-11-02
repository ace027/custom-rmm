//! Encrypted local store: the outbox, the command inbox, the command replay
//! cache, the persisted trust sequence floors and the trust and policy caches.
//!
//! One SQLite file (`agent-store.db`) lives in the agent state dir. Values are
//! sealed at the application level with XChaCha20-Poly1305 under a random
//! store key that is kept in `store.key`, protected like the agent key. Every
//! value uses a fresh random nonce and the AAD `table || 0x00 || row key`, so a
//! ciphertext copied into another row does not decrypt. Row keys, timestamps,
//! priorities, subjects and sizes stay in clear.
//!
//! All methods are synchronous; async callers use `spawn_blocking`.

use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::TryRng;
use rmm_platform::KeyStore;
use rmm_trust::docs::SKEW_SECS;
use rmm_trust::store::{DocKind, ReplayCache, SeqStore};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// File name of the database inside the state dir.
pub const DB_FILE: &str = "agent-store.db";
/// File name of the protected store key inside the state dir.
pub const STORE_KEY_FILE: &str = "store.key";
/// Default maximum number of outbox rows.
pub const MAX_OUTBOX_ROWS: u64 = 50_000;
/// Default maximum number of stored outbox payload bytes (64 MiB).
pub const MAX_OUTBOX_BYTES: u64 = 64 * 1024 * 1024;

const SCHEMA_VERSION: i64 = 2;
/// Finished inbox rows older than this are pruned (the CMD stream max age).
const INBOX_DONE_RETENTION_S: u64 = 7 * 86_400;
const NONCE_LEN: usize = 24;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a store operation failed.
#[derive(Debug)]
pub enum StoreError {
    /// SQLite reported an error.
    Db(String),
    /// A value did not decrypt: wrong store key or tampered data.
    Decrypt,
    /// A value could not be encrypted.
    Encrypt,
    /// The store key could not be read, created or saved.
    Key(String),
    /// The database exists but its store key is gone; it is unreadable.
    MissingKey,
    /// The database was written by a newer agent.
    NewerSchema(i64),
    /// A stored row has an impossible shape.
    Corrupt(&'static str),
    /// File system failure.
    Io(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Db(e) => write!(f, "store database error: {e}"),
            Self::Decrypt => write!(f, "store value failed to decrypt (wrong key or tampered)"),
            Self::Encrypt => write!(f, "store value failed to encrypt"),
            Self::Key(e) => write!(f, "store key error: {e}"),
            Self::MissingKey => write!(f, "store key is missing but the store database exists"),
            Self::NewerSchema(v) => write!(f, "store schema version {v} is newer than supported"),
            Self::Corrupt(what) => write!(f, "corrupt store row: {what}"),
            Self::Io(e) => write!(f, "store i/o error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Db(e.to_string())
    }
}

/// Result alias of this module.
pub type Result<T> = std::result::Result<T, StoreError>;

/// One queued outbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxItem {
    /// Queue position; the handle for [`Store::outbox_delete`].
    pub seq: i64,
    /// Message id (also the JetStream `Nats-Msg-Id`).
    pub msg_id: [u8; 16],
    /// NATS subject to publish to.
    pub subject: String,
    /// Drain priority; lower drains first, 0 is never dropped.
    pub priority: u8,
    /// Decrypted message body.
    pub payload: Vec<u8>,
}

/// Outbox size bounds.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Most rows kept.
    pub max_rows: u64,
    /// Most stored payload bytes kept (ciphertext length, nonce and tag included).
    pub max_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rows: MAX_OUTBOX_ROWS,
            max_bytes: MAX_OUTBOX_BYTES,
        }
    }
}

/// The encrypted store. Safe to share between threads.
pub struct Store {
    conn: Mutex<Connection>,
    key: Zeroizing<[u8; 32]>,
    limits: Limits,
    dropped: AtomicU64,
    seq_write_failed: AtomicBool,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("limits", &self.limits)
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// A pending inbox row: its id and the opened envelope (or why it failed).
pub type InboxRow = (Vec<u8>, Result<Vec<u8>>);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn aad(table: &str, row_key: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(table.len() + 1 + row_key.len());
    a.extend_from_slice(table.as_bytes());
    a.push(0);
    a.extend_from_slice(row_key);
    a
}

fn cipher(key: &[u8; 32]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| StoreError::Encrypt)
}

/// Encrypt `plaintext` for `(table, row_key)`; the result is `nonce || ciphertext`.
fn seal(key: &[u8; 32], table: &str, row_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| StoreError::Encrypt)?;
    let xnonce = XNonce::try_from(&nonce[..]).map_err(|_| StoreError::Encrypt)?;
    let ct = cipher(key)?
        .encrypt(
            &xnonce,
            Payload {
                msg: plaintext,
                aad: &aad(table, row_key),
            },
        )
        .map_err(|_| StoreError::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a blob made by [`seal`] for the same `(table, row_key)`.
fn open(key: &[u8; 32], table: &str, row_key: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return Err(StoreError::Decrypt);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let xnonce = XNonce::try_from(nonce).map_err(|_| StoreError::Decrypt)?;
    cipher(key)?
        .decrypt(
            &xnonce,
            Payload {
                msg: ct,
                aad: &aad(table, row_key),
            },
        )
        .map_err(|_| StoreError::Decrypt)
}

fn kind_name(kind: DocKind) -> &'static str {
    match kind {
        DocKind::Manifest => "manifest",
        DocKind::Revocations => "revocations",
        DocKind::Techlist => "techlist",
    }
}

fn seq_aad_key(kind: &str, seq: i64) -> Vec<u8> {
    // The clear-text seq is bound into the AAD of content_id, so editing it
    // makes the floor unreadable instead of silently lowering it.
    let mut k = kind.as_bytes().to_vec();
    k.push(0);
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

fn create_db_file(path: &Path) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .map(drop)
        .map_err(|e| StoreError::Io(format!("create {}: {e}", path.display())))
}

fn migrate(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::NewerSchema(version));
    }
    if version < 1 {
        tx.execute_batch(
            "CREATE TABLE outbox(
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 msg_id BLOB NOT NULL UNIQUE,
                 subject TEXT NOT NULL,
                 priority INTEGER NOT NULL,
                 created_at INTEGER NOT NULL,
                 payload BLOB NOT NULL);
             CREATE INDEX outbox_drain ON outbox(priority, seq);
             CREATE TABLE replay(
                 cmd_id_hash BLOB PRIMARY KEY,
                 expires_at INTEGER NOT NULL);
             CREATE INDEX replay_expiry ON replay(expires_at);
             CREATE TABLE seq_floor(
                 kind TEXT PRIMARY KEY,
                 seq INTEGER NOT NULL,
                 content_id BLOB NOT NULL);
             CREATE TABLE trust(
                 kind TEXT PRIMARY KEY,
                 envelope BLOB NOT NULL);
             CREATE TABLE policy(
                 key TEXT PRIMARY KEY,
                 value BLOB NOT NULL);
             PRAGMA user_version = 1;",
        )?;
    }
    if version < 2 {
        tx.execute_batch(
            "CREATE TABLE inbox(
                 cmd_id BLOB PRIMARY KEY,
                 envelope BLOB NOT NULL,
                 received_at INTEGER NOT NULL,
                 state TEXT NOT NULL CHECK (state IN ('pending', 'done')));
             CREATE INDEX inbox_pending ON inbox(state, received_at);
             PRAGMA user_version = 2;",
        )?;
    }
    tx.commit()?;
    Ok(())
}

impl Store {
    /// Open (or create) the store in `state_dir`. `key` is the key store for
    /// `store.key` (`rmm_platform::keystore_named(state_dir, STORE_KEY_FILE)`);
    /// the key is created on first open. An existing database without its key
    /// is an error, never a reason to start a new store.
    pub fn open(state_dir: &Path, key: &dyn KeyStore) -> Result<Self> {
        Self::open_with_limits(state_dir, key, Limits::default())
    }

    /// Like [`Store::open`] with explicit outbox bounds.
    pub fn open_with_limits(state_dir: &Path, key: &dyn KeyStore, limits: Limits) -> Result<Self> {
        let db_path = state_dir.join(DB_FILE);
        let store_key = match key.load().map_err(|e| StoreError::Key(e.to_string()))? {
            Some(k) => Zeroizing::new(k),
            None => {
                if db_path.exists() {
                    return Err(StoreError::MissingKey);
                }
                let mut k = Zeroizing::new([0u8; 32]);
                rand::rngs::SysRng
                    .try_fill_bytes(&mut k[..])
                    .map_err(|e| StoreError::Key(e.to_string()))?;
                key.store(&k).map_err(|e| StoreError::Key(e.to_string()))?;
                k
            }
        };
        create_db_file(&db_path)?;
        let mut conn = Connection::open(&db_path)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        migrate(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            key: store_key,
            limits,
            dropped: AtomicU64::new(0),
            seq_write_failed: AtomicBool::new(false),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // Every mutation runs in a transaction, so a panic elsewhere cannot
        // leave the connection half-written; keep serving.
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Outbox rows dropped by the bounds since this store was opened.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// True once a [`SeqStore::put`] could not be persisted. The trait cannot
    /// return the error, so callers check this after applying documents.
    pub fn seq_write_failed(&self) -> bool {
        self.seq_write_failed.load(Ordering::Relaxed)
    }

    /// Queue a message. Returns `Ok(false)` if the bounds dropped it, and
    /// `Ok(true)` if it was queued or `msg_id` was already queued (no-op).
    ///
    /// When over a bound, rows with priority >= the new row's (and > 0) are
    /// dropped, highest priority number first and oldest first; priority 0 is
    /// never dropped.
    pub fn outbox_push(
        &self,
        msg_id: [u8; 16],
        subject: &str,
        priority: u8,
        payload: &[u8],
    ) -> Result<bool> {
        let blob = seal(&self.key, "outbox", &msg_id, payload)?;
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO outbox(msg_id, subject, priority, created_at, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &msg_id[..],
                subject,
                i64::from(priority),
                to_i64(now_secs()),
                blob
            ],
        )?;
        if inserted == 0 {
            return Ok(true);
        }
        let new_seq = tx.last_insert_rowid();
        let (rows, bytes): (i64, i64) = tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(payload)), 0) FROM outbox",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (mut rows, mut bytes) = (rows, bytes);
        let (max_rows, max_bytes) = (to_i64(self.limits.max_rows), to_i64(self.limits.max_bytes));
        let mut kept = true;
        let mut dropped = 0u64;
        while rows > max_rows || bytes > max_bytes {
            let victim: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT seq, LENGTH(payload) FROM outbox
                     WHERE priority > 0 AND priority >= ?1
                     ORDER BY priority DESC, seq ASC LIMIT 1",
                    params![i64::from(priority)],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((seq, len)) = victim else { break };
            tx.execute("DELETE FROM outbox WHERE seq = ?1", params![seq])?;
            rows -= 1;
            bytes -= len;
            dropped += 1;
            if seq == new_seq {
                kept = false;
            }
        }
        tx.commit()?;
        self.dropped.fetch_add(dropped, Ordering::Relaxed);
        Ok(kept)
    }

    /// Up to `limit` queued messages in drain order: priority, then seq.
    pub fn outbox_peek(&self, limit: usize) -> Result<Vec<OutboxItem>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT seq, msg_id, subject, priority, payload FROM outbox
             ORDER BY priority ASC, seq ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![to_i64(limit as u64)], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, id, subject, priority, blob) = row?;
            let msg_id: [u8; 16] = id
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("outbox msg_id length"))?;
            let priority =
                u8::try_from(priority).map_err(|_| StoreError::Corrupt("outbox priority"))?;
            let payload = open(&self.key, "outbox", &msg_id, &blob)?;
            out.push(OutboxItem {
                seq,
                msg_id,
                subject,
                priority,
                payload,
            });
        }
        Ok(out)
    }

    /// Remove a delivered message; a missing row is fine.
    pub fn outbox_delete(&self, seq: i64) -> Result<()> {
        self.lock()
            .execute("DELETE FROM outbox WHERE seq = ?1", params![seq])?;
        Ok(())
    }

    /// Delete every queued message and return how many were removed. Used
    /// after re-enrolling under a new agent id, whose credentials cannot
    /// publish on the old subjects.
    pub fn outbox_clear(&self) -> Result<u64> {
        let n = self.lock().execute("DELETE FROM outbox", [])?;
        Ok(n as u64)
    }

    /// Number of queued messages.
    pub fn outbox_len(&self) -> Result<u64> {
        let n: i64 = self
            .lock()
            .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))?;
        u64::try_from(n).map_err(|_| StoreError::Corrupt("outbox count"))
    }

    /// Number of replay-cache entries.
    pub fn replay_len(&self) -> Result<u64> {
        let n: i64 = self
            .lock()
            .query_row("SELECT COUNT(*) FROM replay", [], |r| r.get(0))?;
        u64::try_from(n).map_err(|_| StoreError::Corrupt("replay count"))
    }

    /// Record a received command envelope as pending, replacing any row with
    /// the same `cmd_id` (a redelivery is processed again and then rejected
    /// as a replay). Finished rows older than seven days are pruned.
    pub fn inbox_put(&self, cmd_id: &[u8], envelope: &[u8]) -> Result<()> {
        let blob = seal(&self.key, "inbox", cmd_id, envelope)?;
        let now = now_secs();
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM inbox WHERE state = 'done' AND received_at < ?1",
            params![to_i64(now.saturating_sub(INBOX_DONE_RETENTION_S))],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO inbox(cmd_id, envelope, received_at, state)
             VALUES (?1, ?2, ?3, 'pending')",
            params![cmd_id, blob, to_i64(now)],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The oldest pending `(cmd_id, envelope)`.
    pub fn inbox_next_pending(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        self.inbox_next_pending_row()?
            .map(|(id, env)| env.map(|e| (id, e)))
            .transpose()
    }

    /// Like [`Store::inbox_next_pending`], but a row that cannot be opened
    /// (AEAD failure, corrupt blob) is returned with its error instead of
    /// failing the call, so the caller can retire it.
    pub fn inbox_next_pending_row(&self) -> Result<Option<InboxRow>> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .lock()
            .query_row(
                "SELECT cmd_id, envelope FROM inbox WHERE state = 'pending'
                 ORDER BY received_at ASC, rowid ASC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.map(|(id, blob)| {
            let env = open(&self.key, "inbox", &id, &blob);
            (id, env)
        }))
    }

    /// Mark a command as finished; a missing row is fine.
    pub fn inbox_mark_done(&self, cmd_id: &[u8]) -> Result<()> {
        self.lock().execute(
            "UPDATE inbox SET state = 'done' WHERE cmd_id = ?1",
            params![cmd_id],
        )?;
        Ok(())
    }

    /// Number of pending inbox rows.
    pub fn inbox_pending_len(&self) -> Result<u64> {
        let n: i64 = self.lock().query_row(
            "SELECT COUNT(*) FROM inbox WHERE state = 'pending'",
            [],
            |r| r.get(0),
        )?;
        u64::try_from(n).map_err(|_| StoreError::Corrupt("inbox count"))
    }

    /// Cache the verified trust envelope of `kind`, replacing the previous one.
    pub fn trust_put(&self, kind: DocKind, envelope: &[u8]) -> Result<()> {
        let name = kind_name(kind);
        let blob = seal(&self.key, "trust", name.as_bytes(), envelope)?;
        self.lock().execute(
            "INSERT OR REPLACE INTO trust(kind, envelope) VALUES (?1, ?2)",
            params![name, blob],
        )?;
        Ok(())
    }

    /// The cached trust envelope of `kind`.
    pub fn trust_get(&self, kind: DocKind) -> Result<Option<Vec<u8>>> {
        let name = kind_name(kind);
        let blob: Option<Vec<u8>> = self
            .lock()
            .query_row(
                "SELECT envelope FROM trust WHERE kind = ?1",
                params![name],
                |r| r.get(0),
            )
            .optional()?;
        blob.map(|b| open(&self.key, "trust", name.as_bytes(), &b))
            .transpose()
    }

    /// Store a policy value under `key`, replacing the previous one.
    pub fn policy_put(&self, key: &str, value: &[u8]) -> Result<()> {
        let blob = seal(&self.key, "policy", key.as_bytes(), value)?;
        self.lock().execute(
            "INSERT OR REPLACE INTO policy(key, value) VALUES (?1, ?2)",
            params![key, blob],
        )?;
        Ok(())
    }

    /// The policy value under `key`.
    pub fn policy_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let blob: Option<Vec<u8>> = self
            .lock()
            .query_row(
                "SELECT value FROM policy WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()?;
        blob.map(|b| open(&self.key, "policy", key.as_bytes(), &b))
            .transpose()
    }

    fn floor_get(&self, kind: DocKind) -> Result<Option<(u64, [u8; 32])>> {
        let name = kind_name(kind);
        let row: Option<(i64, Vec<u8>)> = self
            .lock()
            .query_row(
                "SELECT seq, content_id FROM seq_floor WHERE kind = ?1",
                params![name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((seq, blob)) = row else {
            return Ok(None);
        };
        let plain = open(&self.key, "seq_floor", &seq_aad_key(name, seq), &blob)?;
        let id: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupt("seq_floor content_id length"))?;
        let seq = u64::try_from(seq).map_err(|_| StoreError::Corrupt("seq_floor seq"))?;
        Ok(Some((seq, id)))
    }

    fn floor_put(&self, kind: DocKind, seq: u64, content_id: [u8; 32]) -> Result<()> {
        let name = kind_name(kind);
        let seq = i64::try_from(seq).map_err(|_| StoreError::Corrupt("seq_floor seq"))?;
        let blob = seal(&self.key, "seq_floor", &seq_aad_key(name, seq), &content_id)?;
        self.lock().execute(
            "INSERT OR REPLACE INTO seq_floor(kind, seq, content_id) VALUES (?1, ?2, ?3)",
            params![name, seq, blob],
        )?;
        Ok(())
    }

    fn replay_seen(&self, cmd_id: &[u8], expires_at: u64) -> Result<bool> {
        let hash: [u8; 32] = Sha256::digest(cmd_id).into();
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM replay WHERE expires_at + ?1 < ?2",
            params![to_i64(SKEW_SECS), to_i64(now_secs())],
        )?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO replay(cmd_id_hash, expires_at) VALUES (?1, ?2)",
            params![&hash[..], to_i64(expires_at)],
        )?;
        tx.commit()?;
        Ok(inserted == 0)
    }
}

// Fail closed: a store that cannot answer must make verification reject, so a
// failed read reports a floor no document can reach and a failed replay check
// reports "already seen".
const UNREADABLE_FLOOR: (u64, [u8; 32]) = (u64::MAX, [0; 32]);

fn seq_get(store: &Store, kind: DocKind) -> Option<(u64, [u8; 32])> {
    if store.seq_write_failed() {
        return Some(UNREADABLE_FLOOR);
    }
    match store.floor_get(kind) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "seq floor unreadable; rejecting trust documents");
            Some(UNREADABLE_FLOOR)
        }
    }
}

fn seq_put(store: &Store, kind: DocKind, seq: u64, content_id: [u8; 32]) {
    if let Err(e) = store.floor_put(kind, seq, content_id) {
        tracing::error!(error = %e, "seq floor not persisted");
        store.seq_write_failed.store(true, Ordering::Relaxed);
    }
}

fn replay_seen(store: &Store, cmd_id: &[u8], expires_at: u64) -> bool {
    store.replay_seen(cmd_id, expires_at).unwrap_or_else(|e| {
        tracing::error!(error = %e, "replay cache unavailable; treating command as replayed");
        true
    })
}

impl SeqStore for Store {
    fn get(&self, kind: DocKind) -> Option<(u64, [u8; 32])> {
        seq_get(self, kind)
    }

    fn put(&mut self, kind: DocKind, seq: u64, content_id: [u8; 32]) {
        seq_put(self, kind, seq, content_id);
    }
}

impl SeqStore for &Store {
    fn get(&self, kind: DocKind) -> Option<(u64, [u8; 32])> {
        seq_get(self, kind)
    }

    fn put(&mut self, kind: DocKind, seq: u64, content_id: [u8; 32]) {
        seq_put(self, kind, seq, content_id);
    }
}

impl ReplayCache for Store {
    fn seen(&mut self, cmd_id: &[u8], expires_at: u64) -> bool {
        replay_seen(self, cmd_id, expires_at)
    }
}

impl ReplayCache for &Store {
    fn seen(&mut self, cmd_id: &[u8], expires_at: u64) -> bool {
        replay_seen(self, cmd_id, expires_at)
    }
}
