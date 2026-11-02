//! Trust and release distribution reads: the newest stored envelope of each
//! trust document kind, served to agents over NATS.
//!
//! Queries are runtime-checked (`sqlx::query`) so they need no entry in the
//! offline `.sqlx` cache.

use sqlx::Row;

use crate::repo::{Result, Tx};

/// Newest stored envelope of each kind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Latest {
    /// Latest `(seq, envelope)` of the manifest.
    pub manifest: Option<(i64, Vec<u8>)>,
    /// Latest revocations.
    pub revocations: Option<(i64, Vec<u8>)>,
    /// Latest technician list.
    pub techlist: Option<(i64, Vec<u8>)>,
    /// Latest release manifest.
    pub release: Option<(i64, Vec<u8>)>,
}

/// The highest-seq envelope of every kind in one statement.
pub async fn latest(tx: &mut Tx<'_>) -> Result<Latest> {
    let rows = sqlx::query(
        "select distinct on (kind) kind, seq, envelope
         from msp.trust_artifact order by kind, seq desc",
    )
    .fetch_all(&mut **tx)
    .await?;
    let mut out = Latest::default();
    for r in rows {
        let kind: String = r.try_get("kind")?;
        let entry = Some((r.try_get::<i64, _>("seq")?, r.try_get("envelope")?));
        match kind.as_str() {
            "manifest" => out.manifest = entry,
            "revocations" => out.revocations = entry,
            "techlist" => out.techlist = entry,
            "release" => out.release = entry,
            _ => {}
        }
    }
    Ok(out)
}

/// Highest `(seq, content_id)` stored for `kind`.
pub async fn latest_of(tx: &mut Tx<'_>, kind: &str) -> Result<Option<(i64, Vec<u8>)>> {
    let row = sqlx::query(
        "select seq, content_id from msp.trust_artifact
         where kind = $1 order by seq desc limit 1",
    )
    .bind(kind)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| Ok((r.try_get("seq")?, r.try_get("content_id")?)))
        .transpose()
}
