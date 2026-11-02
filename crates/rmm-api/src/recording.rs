//! Shell session recordings: asciicast v2 files, their retention and the
//! admin download.
//!
//! One file per session at `<recording_dir>/<client_id>/<session_id>.cast`
//! (directories 0700, files 0600). Every event is written as it happens; at
//! the end the SHA-256 and size are stored on the session row, so a changed
//! file is detected when it is downloaded. Input events (`i`) include what the
//! technician typed, so treat the files as sensitive.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use axum::extract::{Path as AxPath, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rmm_db::scope::{Scope, begin_scoped};
use rmm_db::shell;
use sha2::{Digest, Sha256};
use sqlx::types::Uuid;
use sqlx::types::chrono::{DateTime, Utc};

use crate::auth::{Admin, RequireRole};
use crate::shell::parse_grant_id;
use crate::state::AppState;
use crate::{ApiError, ErrorBody};

/// Media type of a recording.
pub const CONTENT_TYPE: &str = "application/x-asciicast";
/// Default retention in days.
pub const DEFAULT_RETENTION_DAYS: u32 = 365;
/// Sessions deleted per retention batch.
const PURGE_BATCH: i64 = 100;

/// A finished recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// Path relative to the recording directory.
    pub rel_path: String,
    /// SHA-256 of the file.
    pub sha256: [u8; 32],
    /// Size of the file in bytes.
    pub bytes: u64,
}

/// Writer of one asciicast v2 file.
#[derive(Debug)]
pub struct Recorder {
    file: File,
    rel_path: String,
    start: Instant,
    hasher: Sha256,
    bytes: u64,
    /// Incomplete UTF-8 sequence at the end of the last output chunk.
    out_tail: Vec<u8>,
    /// Same for input.
    in_tail: Vec<u8>,
}

fn private_dir(path: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn create_private(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Decode `tail + data` as UTF-8: invalid bytes become U+FFFD, an incomplete
/// sequence at the end is kept in `tail` for the next chunk.
fn utf8_text(tail: &mut Vec<u8>, data: &[u8]) -> String {
    let mut buf = std::mem::take(tail);
    buf.extend_from_slice(data);
    let mut out = String::with_capacity(buf.len());
    let mut rest = buf.as_slice();
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                break;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                out.push_str(&String::from_utf8_lossy(good));
                match e.error_len() {
                    Some(n) => {
                        out.push('\u{fffd}');
                        rest = &bad[n..];
                    }
                    None => {
                        *tail = bad.to_vec();
                        break;
                    }
                }
            }
        }
    }
    out
}

impl Recorder {
    /// Create `<dir>/<client_id>/<sid>.cast` and write the header.
    pub fn create(
        dir: &Path,
        client_id: Uuid,
        sid: &str,
        title: &str,
        cols: u16,
        rows: u16,
    ) -> io::Result<Self> {
        let client_dir = dir.join(client_id.to_string());
        private_dir(&client_dir)?;
        let rel_path = format!("{client_id}/{sid}.cast");
        let file = create_private(&client_dir.join(format!("{sid}.cast")))?;
        let mut rec = Self {
            file,
            rel_path,
            start: Instant::now(),
            hasher: Sha256::new(),
            bytes: 0,
            out_tail: Vec::new(),
            in_tail: Vec::new(),
        };
        let header = serde_json::json!({
            "version": 2,
            "width": cols,
            "height": rows,
            "timestamp": Utc::now().timestamp(),
            "title": title,
        });
        rec.write_line(&header.to_string())?;
        Ok(rec)
    }

    fn write_line(&mut self, line: &str) -> io::Result<()> {
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        // One write per event, so the file holds every event seen so far.
        self.file.write_all(&buf)?;
        self.hasher.update(&buf);
        self.bytes += buf.len() as u64;
        Ok(())
    }

    fn event(&mut self, kind: &str, text: &str) -> io::Result<()> {
        let secs = (self.start.elapsed().as_secs_f64() * 1e6).round() / 1e6;
        let line = serde_json::to_string(&(secs, kind, text)).map_err(io::Error::other)?;
        self.write_line(&line)
    }

    /// Terminal output.
    pub fn output(&mut self, data: &[u8]) -> io::Result<()> {
        let text = utf8_text(&mut self.out_tail, data);
        if text.is_empty() {
            return Ok(());
        }
        self.event("o", &text)
    }

    /// Keystrokes.
    pub fn input(&mut self, data: &[u8]) -> io::Result<()> {
        let text = utf8_text(&mut self.in_tail, data);
        if text.is_empty() {
            return Ok(());
        }
        self.event("i", &text)
    }

    /// Terminal size change.
    pub fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        self.event("r", &format!("{cols}x{rows}"))
    }

    /// Sync the file and return its path, hash and size.
    pub fn finish(self) -> io::Result<Finished> {
        self.file.sync_data()?;
        Ok(Finished {
            rel_path: self.rel_path,
            sha256: self.hasher.finalize().into(),
            bytes: self.bytes,
        })
    }
}

/// A stored recording path is relative and stays inside the recording directory.
fn safe_relative(rel: &str) -> bool {
    let p = Path::new(rel);
    !rel.is_empty() && !p.is_absolute() && p.components().all(|c| matches!(c, Component::Normal(_)))
}

/// Download a session's recording.
#[utoipa::path(
    get,
    path = "/api/v1/shell-sessions/{session_id}/recording",
    params(("session_id" = String, Path, description = "Session id (hex)")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "asciicast v2 recording", content_type = "application/x-asciicast", body = String),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 403, description = "Missing RMM.Admin", body = ErrorBody),
        (status = 404, description = "Unknown session or no recording", body = ErrorBody),
        (status = 500, description = "The file does not match the stored hash", body = ErrorBody)
    )
)]
pub async fn get_recording(
    State(state): State<AppState>,
    RequireRole(claims, _): RequireRole<Admin>,
    AxPath(session_id): AxPath<String>,
) -> Result<Response, ApiError> {
    let grant_id = parse_grant_id(&session_id)?;
    let mut tx = begin_scoped(
        &state.pool,
        &Scope::Service("admin-recordings"),
        &claims.actor(),
    )
    .await?;
    let row = shell::shell_session(&mut tx, &grant_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("unknown session".into()))?;
    drop(tx);
    let rel = row
        .recording_path
        .filter(|p| safe_relative(p))
        .ok_or_else(|| ApiError::NotFound("session has no recording".into()))?;
    let path = state.recording_dir.join(&rel);
    let data = tokio::task::spawn_blocking(move || std::fs::read(path))
        .await
        .map_err(ApiError::internal)?
        .map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                ApiError::NotFound("recording file is gone".into())
            } else {
                ApiError::internal(err)
            }
        })?;
    if let Some(want) = &row.recording_sha256
        && Sha256::digest(&data).as_slice() != want.as_slice()
    {
        tracing::error!(session_id, "recording does not match its stored hash");
        return Err(ApiError::Internal);
    }
    let mut res = (StatusCode::OK, data).into_response();
    res.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    Ok(res)
}

/// Delete sessions (and their recording files) created more than `days` ago.
/// Returns how many sessions were removed.
pub async fn purge_older_than(state: &AppState, days: u32) -> Result<usize, ApiError> {
    let cutoff =
        DateTime::<Utc>::from_timestamp(Utc::now().timestamp() - i64::from(days) * 86_400, 0)
            .ok_or_else(|| ApiError::internal("retention cutoff out of range"))?;
    let mut removed = 0;
    loop {
        let mut tx = begin_scoped(
            &state.pool,
            &Scope::Service("recording-retention"),
            "retention",
        )
        .await?;
        let old = shell::recordings_older_than(&mut tx, cutoff, PURGE_BATCH).await?;
        if old.is_empty() {
            return Ok(removed);
        }
        let mut batch = 0;
        for s in &old {
            if let Some(rel) = &s.recording_path {
                if !safe_relative(rel) {
                    tracing::error!(rel, "stored recording path is unsafe; file kept");
                } else if let Err(err) = std::fs::remove_file(state.recording_dir.join(rel))
                    && err.kind() != io::ErrorKind::NotFound
                {
                    // Keep the row so the file is not orphaned; try again tomorrow.
                    tracing::error!(%err, rel, "cannot delete recording; row kept");
                    continue;
                }
            }
            if shell::delete_shell_session(&mut tx, &s.grant_id).await? {
                batch += 1;
            }
        }
        tx.commit().await?;
        removed += batch;
        if batch == 0 || old.len() < usize::try_from(PURGE_BATCH).unwrap_or(usize::MAX) {
            return Ok(removed);
        }
    }
}

/// Run [`purge_older_than`] now and then daily, forever.
pub async fn retention_loop(state: AppState, days: u32) {
    let mut tick = tokio::time::interval(Duration::from_secs(24 * 3600));
    loop {
        tick.tick().await;
        match purge_older_than(&state, days).await {
            Ok(0) => tracing::debug!(days, "recording retention: nothing to delete"),
            Ok(n) => tracing::info!(days, removed = n, "recording retention deleted sessions"),
            Err(_) => tracing::error!("recording retention failed"),
        }
    }
}

/// Where recordings of a session live, for tests and tooling.
pub fn path_of(dir: &Path, client_id: Uuid, sid: &str) -> PathBuf {
    dir.join(client_id.to_string()).join(format!("{sid}.cast"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_across_chunks() {
        let mut tail = Vec::new();
        let euro = "€".as_bytes();
        assert_eq!(utf8_text(&mut tail, &euro[..2]), "");
        assert_eq!(utf8_text(&mut tail, &euro[2..]), "€");
        assert_eq!(utf8_text(&mut tail, b"a\xffb"), "a\u{fffd}b");
        assert!(tail.is_empty());
    }

    #[test]
    fn relative_paths() {
        assert!(safe_relative("a/b.cast"));
        assert!(!safe_relative("../b.cast"));
        assert!(!safe_relative("/etc/passwd"));
        assert!(!safe_relative(""));
    }
}
