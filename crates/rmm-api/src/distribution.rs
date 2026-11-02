//! Trust and release distribution over NATS request/reply.
//!
//! The api process answers two subjects from the database, in queue group
//! `api` so any replica serves a request:
//!
//! - `svc.trust.latest`: a CBOR map `{manifest?, revocations?, techlist?}` of
//!   the newest stored envelopes ([`TrustLatest`]);
//! - `svc.release.latest`: a CBOR map `{release?}` ([`ReleaseLatest`]); an
//!   empty map when no release is stored.
//!
//! The reply is untrusted data: agents verify every envelope against their
//! compiled roots, so a wrong or stale answer can only withhold an update.
//! When the database fails no reply is sent and the agent's request times out.

use std::sync::Arc;

use futures_util::StreamExt;
use rmm_db::releases;
use rmm_db::scope::{Scope, begin_scoped};
use rmm_proto::canonical::to_canonical_vec;
use rmm_trust::docs::{ReleaseLatest, TrustLatest};
use rmm_trust::keys::Bytes;
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::ApiError;
use crate::state::AppState;

/// Subject answered with the latest trust documents.
pub const TRUST_SUBJECT: &str = "svc.trust.latest";
/// Subject answered with the latest release.
pub const RELEASE_SUBJECT: &str = "svc.release.latest";
/// Queue group of the responders.
pub const QUEUE_GROUP: &str = "api";
/// Requests answered concurrently per subject; extra requests are dropped and
/// the agent retries on its next refresh.
const MAX_IN_FLIGHT: usize = 32;

async fn latest(pool: &PgPool) -> Result<releases::Latest, ApiError> {
    let mut tx = begin_scoped(pool, &Scope::Service("distribution"), "api").await?;
    let latest = releases::latest(&mut tx).await?;
    tx.commit().await?;
    Ok(latest)
}

/// The `svc.trust.latest` reply.
pub async fn trust_reply(pool: &PgPool) -> Result<Vec<u8>, ApiError> {
    let l = latest(pool).await?;
    let doc = TrustLatest {
        manifest: l.manifest.map(|(_, e)| Bytes(e)),
        revocations: l.revocations.map(|(_, e)| Bytes(e)),
        techlist: l.techlist.map(|(_, e)| Bytes(e)),
    };
    to_canonical_vec(&doc).map_err(ApiError::internal)
}

/// The `svc.release.latest` reply.
pub async fn release_reply(pool: &PgPool) -> Result<Vec<u8>, ApiError> {
    let l = latest(pool).await?;
    let doc = ReleaseLatest {
        release: l.release.map(|(_, e)| Bytes(e)),
    };
    to_canonical_vec(&doc).map_err(ApiError::internal)
}

async fn respond(pool: &PgPool, subject: &str) -> Result<Vec<u8>, ApiError> {
    if subject == TRUST_SUBJECT {
        trust_reply(pool).await
    } else {
        release_reply(pool).await
    }
}

async fn serve(client: async_nats::Client, pool: PgPool, subject: &'static str) {
    let mut sub = match client
        .queue_subscribe(subject, QUEUE_GROUP.to_owned())
        .await
    {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(%err, subject, "cannot subscribe distribution responder");
            return;
        }
    };
    tracing::info!(subject, "distribution responder running");
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    while let Some(msg) = sub.next().await {
        let Some(reply) = msg.reply else { continue };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            tracing::warn!(subject, "distribution responder busy; request dropped");
            continue;
        };
        let (client, pool) = (client.clone(), pool.clone());
        tokio::spawn(async move {
            match respond(&pool, subject).await {
                Ok(body) => {
                    if let Err(err) = client.publish(reply, body.into()).await {
                        tracing::warn!(%err, subject, "distribution reply not sent");
                    }
                }
                Err(_) => tracing::error!(subject, "distribution reply failed"),
            }
            drop(permit);
        });
    }
    tracing::warn!(subject, "distribution responder stopped");
}

/// Start both responders on the state's NATS client. `None` without a
/// client.
pub fn spawn(state: &AppState) -> Option<Vec<JoinHandle<()>>> {
    let client = state.nats.clone()?;
    Some(
        [TRUST_SUBJECT, RELEASE_SUBJECT]
            .into_iter()
            .map(|subject| tokio::spawn(serve(client.clone(), state.pool.clone(), subject)))
            .collect(),
    )
}
