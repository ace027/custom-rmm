//! Release artifact hosting.
//!
//! An Admin uploads the raw artifact; the server streams it to a temporary
//! file in `RMM_ARTIFACT_DIR` while hashing, then renames it to
//! `<dir>/<sha256 hex>` (files 0600, directory 0700). The name is computed
//! here, never taken from the client, and the file only appears under its
//! hash once complete: an interrupted upload leaves nothing there. Download is
//! unauthenticated and streamed. The channel is untrusted by design because
//! the hash is signed in the release manifest and verified by the updater.

use std::path::{Path, PathBuf};

use axum::Json;
use axum::body::Body;
use axum::extract::{Path as AxPath, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use rmm_db::repo;
use rmm_db::scope::{Scope, begin_scoped};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use utoipa::ToSchema;

use crate::auth::{Admin, RequireRole};
use crate::state::AppState;
use crate::{ApiError, ErrorBody};

/// Largest artifact accepted (256 MiB), same as a release manifest allows.
pub const MAX_ARTIFACT_BYTES: u64 = rmm_trust::docs::MAX_ARTIFACT_SIZE;
/// Body limit of the upload route.
pub const BODY_LIMIT: usize = 268_435_456;
/// Name prefix of in-progress uploads (never a valid artifact name).
const TEMP_PREFIX: &str = ".upload-";
/// Download read size.
const CHUNK: usize = 64 * 1024;

/// Result of a stored upload.
#[derive(Debug, Serialize, ToSchema)]
pub struct UploadResponse {
    /// Lowercase hex SHA-256 computed by the server; the artifact's name.
    pub sha256_hex: String,
    /// Size in bytes.
    pub size: u64,
}

/// Removes the temporary file unless disarmed, also when the request future
/// is dropped because the client went away.
struct TempFile {
    path: PathBuf,
    armed: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

async fn private_dir(path: &Path) -> std::io::Result<()> {
    let mut b = tokio::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    b.mode(0o700);
    b.create(path).await
}

/// Delete in-progress uploads older than an hour (left by a crash). Run at
/// startup.
pub fn sweep_stale(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let cutoff = std::time::Duration::from_secs(3600);
    for e in entries.flatten() {
        let stale = e.file_name().to_string_lossy().starts_with(TEMP_PREFIX)
            && e.metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > cutoff);
        if stale {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

fn io_err(err: std::io::Error) -> ApiError {
    ApiError::internal(err)
}

/// Upload a release artifact; the server names it by its SHA-256.
#[utoipa::path(
    post,
    path = "/api/v1/admin/artifacts",
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Artifact stored", body = UploadResponse),
        (status = 400, description = "Empty or interrupted upload", body = ErrorBody),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 403, description = "Missing RMM.Admin", body = ErrorBody),
        (status = 413, description = "Larger than 256 MiB", body = ErrorBody)
    )
)]
pub async fn upload_artifact(
    State(state): State<AppState>,
    RequireRole(claims, _): RequireRole<Admin>,
    body: Body,
) -> Result<(StatusCode, Json<UploadResponse>), ApiError> {
    let dir = &state.artifact_dir;
    private_dir(dir).await.map_err(io_err)?;

    let temp_path = dir.join(format!("{TEMP_PREFIX}{}", uuid::Uuid::new_v4()));
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let file = opts.open(&temp_path).await.map_err(io_err)?;
    let mut temp = TempFile {
        path: temp_path,
        armed: true,
    };
    let mut file = tokio::io::BufWriter::new(file);

    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ApiError::BadRequest("upload interrupted".into()))?;
        size += chunk.len() as u64;
        if size > MAX_ARTIFACT_BYTES {
            return Err(ApiError::PayloadTooLarge("artifact exceeds 256 MiB".into()));
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(io_err)?;
    }
    if size == 0 {
        return Err(ApiError::BadRequest("empty artifact".into()));
    }
    file.flush().await.map_err(io_err)?;
    file.get_ref().sync_all().await.map_err(io_err)?;
    drop(file);

    let hash: [u8; 32] = hasher.finalize().into();
    let sha256_hex = data_encoding::HEXLOWER.encode(&hash);
    tokio::fs::rename(&temp.path, dir.join(&sha256_hex))
        .await
        .map_err(io_err)?;
    temp.armed = false;

    let actor = claims.actor();
    let mut tx = begin_scoped(&state.pool, &Scope::Service("admin-artifact"), &actor).await?;
    repo::insert_audit(
        &mut tx,
        &actor,
        "artifact.upload",
        None,
        &format!("artifact:{sha256_hex}"),
        &serde_json::json!({"size": size}),
    )
    .await?;
    tx.commit().await?;
    tracing::info!(%sha256_hex, size, "artifact stored");
    Ok((
        StatusCode::CREATED,
        Json(UploadResponse { sha256_hex, size }),
    ))
}

fn is_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Download an artifact by its SHA-256 (no authentication: the hash is signed).
#[utoipa::path(
    get,
    path = "/v1/artifacts/{sha256_hex}",
    params(("sha256_hex" = String, Path, description = "Lowercase hex SHA-256")),
    responses(
        (status = 200, description = "The artifact bytes", content_type = "application/octet-stream", body = Vec<u8>),
        (status = 404, description = "No such artifact", body = ErrorBody)
    )
)]
pub async fn download_artifact(
    State(state): State<AppState>,
    AxPath(sha256_hex): AxPath<String>,
) -> Result<Response, ApiError> {
    let not_found = || ApiError::NotFound("no such artifact".into());
    // Only a full lowercase hash maps to a file: no path can escape the dir.
    if !is_hash(&sha256_hex) {
        return Err(not_found());
    }
    let file = match tokio::fs::File::open(state.artifact_dir.join(&sha256_hex)).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(not_found()),
        Err(e) => return Err(io_err(e)),
    };
    let len = file.metadata().await.map_err(io_err)?.len();
    let stream = futures_util::stream::try_unfold(file, |mut file| async move {
        let mut buf = vec![0u8; CHUNK];
        let n = file.read(&mut buf).await?;
        if n == 0 {
            return Ok::<_, std::io::Error>(None);
        }
        buf.truncate(n);
        Ok(Some((axum::body::Bytes::from(buf), file)))
    });
    let mut res = Body::from_stream(stream).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    Ok(res)
}
