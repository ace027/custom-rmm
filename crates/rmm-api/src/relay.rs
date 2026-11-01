//! Browser WebSocket relay between a technician's console and an agent shell.
//!
//! The browser connects with the single-use ticket from `open`. Browser binary
//! frames are keystrokes; text frames are JSON (`{"type":"resize","cols","rows"}`).
//! The relay subscribes to the session's `.out` subject, forwards output as
//! binary frames and answers every forwarded chunk with `ShellCtl::Ack` only
//! after the browser socket accepted it: a slow browser withholds credit and
//! the agent stops reading its PTY. A `ShellCtl::Ping` goes out every 15 s;
//! the agent closes a session that hears none for 45 s.
//!
//! A browser that sends a close frame ends the shell at once (`ShellCtl::Close`).
//! A browser that vanishes without one (no close frame, or silent for 45 s)
//! gets no `Close`: the relay just stops pinging and the agent ends the
//! session itself with `liveness`.

use std::time::Duration;

use async_nats::Client;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::response::Response;
use futures_util::StreamExt;
use rmm_db::scope::{Scope, begin_scoped};
use rmm_db::shell::{self, ShellSessionRow};
use rmm_proto::shell::{
    Bytes as WireBytes, MAX_CHUNK, PING_INTERVAL_SECS, ShellCtl, ShellIn, ShellOut,
};
use rmm_proto::subjects::{shell_ctl, shell_in, shell_out, sid_from_grant_id};
use serde::Deserialize;
use tokio::time::Instant;

use crate::recording::Recorder;
use crate::shell::{parse_grant_id, ticket_hash};
use crate::state::AppState;
use crate::{ApiError, ErrorBody};

/// Largest browser frame accepted.
const MAX_WS_MESSAGE: usize = 64 * 1024;
/// A browser silent for this long is treated as gone.
const BROWSER_SILENCE: Duration = Duration::from_secs(45);
/// Slack past the grant's `max_duration` before the relay gives up by itself.
const MAX_DURATION_GRACE: Duration = Duration::from_secs(30);
/// Terminal size limits accepted from the browser.
const MAX_DIM: u16 = 1000;

/// Query of the relay endpoint.
#[derive(Debug, Deserialize)]
pub struct WsQuery {
    /// Single-use ticket from `open`.
    pub ticket: String,
}

/// Why the relay loop ended.
enum End {
    Exit(i32),
    AgentClosed(String),
    BrowserClosed,
    BrowserGone,
    MaxDuration,
    Link,
    Recording,
}

impl End {
    fn reason(&self) -> String {
        match self {
            Self::Exit(_) => "exit".into(),
            Self::AgentClosed(r) => r.clone(),
            Self::BrowserClosed => "browser_closed".into(),
            Self::BrowserGone => "browser_disconnect".into(),
            Self::MaxDuration => "max_duration".into(),
            Self::Link => "link".into(),
            Self::Recording => "recording_unavailable".into(),
        }
    }
}

#[derive(Deserialize)]
struct BrowserCtl {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    cols: u16,
    #[serde(default)]
    rows: u16,
}

/// Connect the browser to a shell session opened with a ticket.
#[utoipa::path(
    get,
    path = "/api/v1/shell-sessions/{session_id}/ws",
    params(
        ("session_id" = String, Path, description = "Session id (hex)"),
        ("ticket" = String, Query, description = "Single-use ticket from open")
    ),
    responses(
        (status = 101, description = "WebSocket upgrade: binary frames carry terminal bytes, text frames carry JSON control"),
        (status = 401, description = "Ticket unknown, used, expired or for another session", body = ErrorBody),
        (status = 404, description = "Unknown session", body = ErrorBody),
        (status = 409, description = "Session is not waiting for a browser", body = ErrorBody),
        (status = 503, description = "No NATS connection", body = ErrorBody)
    )
)]
pub async fn shell_ws(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Query(q): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let grant_id = parse_grant_id(&session_id)?;
    let nats = state
        .nats
        .clone()
        .ok_or_else(|| ApiError::Unavailable("no NATS connection".into()))?;

    // The ticket is the credential; it is burned even if the rest fails.
    let mut tx = begin_scoped(&state.pool, &Scope::Service("shell-relay"), "ws-ticket").await?;
    let consumed = shell::consume_ws_ticket(&mut tx, &ticket_hash(&q.ticket)).await?;
    tx.commit().await?;
    let (ticket_grant, client_id) = consumed.ok_or(ApiError::Unauthorized)?;
    if ticket_grant != grant_id {
        return Err(ApiError::Unauthorized);
    }

    let mut tx = begin_scoped(&state.pool, &Scope::Clients(vec![client_id]), "ws-ticket").await?;
    let row = shell::shell_session(&mut tx, &grant_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("unknown session".into()))?;
    drop(tx);
    if row.status != "opening" {
        return Err(ApiError::Conflict(
            "session is not waiting for a browser".into(),
        ));
    }
    Ok(ws
        .max_message_size(MAX_WS_MESSAGE)
        .max_frame_size(MAX_WS_MESSAGE)
        .on_upgrade(move |socket| relay(state, nats, row, socket)))
}

async fn publish(nats: &Client, subject: &str, payload: Result<Vec<u8>, impl std::fmt::Display>) {
    match payload {
        Ok(bytes) => {
            if let Err(err) = nats.publish(subject.to_owned(), bytes.into()).await {
                tracing::warn!(%err, subject, "relay publish failed");
            }
        }
        Err(err) => tracing::warn!(%err, subject, "relay message not encodable"),
    }
}

fn control_json(value: &serde_json::Value) -> Message {
    Message::Text(value.to_string().into())
}

async fn relay(state: AppState, nats: Client, row: ShellSessionRow, mut socket: WebSocket) {
    let sid = sid_from_grant_id(&row.grant_id);
    let agent = row.agent_id.to_string();
    let (in_subj, out_subj, ctl_subj) = (
        shell_in(&agent, &sid),
        shell_out(&agent, &sid),
        shell_ctl(&agent, &sid),
    );

    let mut sub = match nats.subscribe(out_subj.clone()).await {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(%err, %sid, "cannot subscribe to shell output");
            let _ = socket
                .send(control_json(
                    &serde_json::json!({"type": "closed", "reason": "link"}),
                ))
                .await;
            mark_closed(&state, &row, "link", None).await;
            return;
        }
    };
    // Make sure the subscription is live before the agent is told anything.
    let _ = nats.flush().await;

    let title = format!("{} {}", row.agent_id, row.tech_id);
    let mut rec = match Recorder::create(&state.recording_dir, row.client_id, &sid, &title, 80, 24)
    {
        Ok(r) => Some(r),
        Err(err) => {
            tracing::error!(%err, %sid, "cannot create the recording; closing the session");
            None
        }
    };

    let max =
        Duration::from_secs(u64::try_from(row.max_duration).unwrap_or(0)) + MAX_DURATION_GRACE;
    let deadline = Instant::now() + max;
    let mut ping = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_rx = Instant::now();
    let mut opened = false;

    let end = if rec.is_none() {
        End::Recording
    } else {
        loop {
            tokio::select! {
                msg = sub.next() => {
                    let Some(msg) = msg else { break End::Link };
                    if !opened {
                        opened = true;
                        set_status(&state, &row, &["opening"], "open", None).await;
                    }
                    match ShellOut::from_cbor(&msg.payload) {
                        Ok(ShellOut::Data { seq, data }) => {
                            if let Some(r) = rec.as_mut()
                                && let Err(err) = r.output(&data.0)
                            {
                                tracing::error!(%err, %sid, "recording write failed");
                                break End::Recording;
                            }
                            if socket.send(Message::Binary(data.0.into())).await.is_err() {
                                break End::BrowserGone;
                            }
                            // The socket took the chunk: give the agent its credit back.
                            publish(&nats, &ctl_subj, ShellCtl::Ack { seq }.to_cbor()).await;
                        }
                        Ok(ShellOut::Exit { code }) => break End::Exit(code),
                        Ok(ShellOut::Closed { reason }) => break End::AgentClosed(reason),
                        Err(err) => tracing::warn!(%err, %sid, "undecodable shell output dropped"),
                    }
                }
                frame = socket.recv() => {
                    last_rx = Instant::now();
                    match frame {
                        None | Some(Err(_)) => break End::BrowserGone,
                        Some(Ok(Message::Close(_))) => break End::BrowserClosed,
                        Some(Ok(Message::Binary(bytes))) => {
                            if let Some(r) = rec.as_mut()
                                && let Err(err) = r.input(&bytes)
                            {
                                tracing::error!(%err, %sid, "recording write failed");
                                break End::Recording;
                            }
                            for chunk in bytes.chunks(MAX_CHUNK) {
                                let msg = ShellIn::Data { data: WireBytes(chunk.to_vec()) };
                                publish(&nats, &in_subj, msg.to_cbor()).await;
                            }
                        }
                        Some(Ok(Message::Text(text))) => {
                            match serde_json::from_str::<BrowserCtl>(&text) {
                                Ok(c) if c.kind == "resize"
                                    && (1..=MAX_DIM).contains(&c.cols)
                                    && (1..=MAX_DIM).contains(&c.rows) =>
                                {
                                    if let Some(r) = rec.as_mut()
                                        && let Err(err) = r.resize(c.cols, c.rows)
                                    {
                                        tracing::error!(%err, %sid, "recording write failed");
                                        break End::Recording;
                                    }
                                    let msg = ShellIn::Resize { cols: c.cols, rows: c.rows };
                                    publish(&nats, &in_subj, msg.to_cbor()).await;
                                }
                                _ => tracing::debug!(%sid, "ignored browser control message"),
                            }
                        }
                        Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    }
                }
                _ = ping.tick() => {
                    if last_rx.elapsed() > BROWSER_SILENCE {
                        break End::BrowserGone;
                    }
                    publish(&nats, &ctl_subj, ShellCtl::Ping.to_cbor()).await;
                    if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break End::BrowserGone;
                    }
                }
                () = tokio::time::sleep_until(deadline) => break End::MaxDuration,
            }
        }
    };

    // Tell the agent to stop unless it ended itself or the browser vanished
    // (then the agent's liveness timer ends the session).
    if matches!(
        end,
        End::BrowserClosed | End::MaxDuration | End::Recording | End::Link
    ) {
        publish(&nats, &ctl_subj, ShellCtl::Close.to_cbor()).await;
    }
    if !matches!(end, End::BrowserClosed | End::BrowserGone) {
        let note = match &end {
            End::Exit(code) => serde_json::json!({"type": "exit", "code": code}),
            other => serde_json::json!({"type": "closed", "reason": other.reason()}),
        };
        let _ = socket.send(control_json(&note)).await;
        let _ = socket.send(Message::Close(None)).await;
    }

    let finished = rec.take().map(|r| r.finish());
    let recording = match finished {
        Some(Ok(f)) => Some(f),
        Some(Err(err)) => {
            tracing::error!(%err, %sid, "cannot finish the recording");
            None
        }
        None => None,
    };
    mark_closed(&state, &row, &end.reason(), recording.as_ref()).await;
}

async fn set_status(
    state: &AppState,
    row: &ShellSessionRow,
    from: &[&str],
    to: &str,
    reason: Option<&str>,
) {
    let result = async {
        let mut tx =
            begin_scoped(&state.pool, &Scope::Clients(vec![row.client_id]), "relay").await?;
        shell::update_shell_status(&mut tx, &row.grant_id, from, to, reason).await?;
        tx.commit().await?;
        Ok::<(), ApiError>(())
    }
    .await;
    if result.is_err() {
        tracing::error!(session_id = %sid_from_grant_id(&row.grant_id), to, "cannot update the session status");
    }
}

/// Close the session in the database and store its recording hash.
async fn mark_closed(
    state: &AppState,
    row: &ShellSessionRow,
    reason: &str,
    recording: Option<&crate::recording::Finished>,
) {
    let result = async {
        let mut tx =
            begin_scoped(&state.pool, &Scope::Clients(vec![row.client_id]), "relay").await?;
        shell::update_shell_status(
            &mut tx,
            &row.grant_id,
            &["opening", "open"],
            "closed",
            Some(reason),
        )
        .await?;
        if let Some(f) = recording {
            shell::set_recording(
                &mut tx,
                &row.grant_id,
                &f.rel_path,
                &f.sha256,
                i64::try_from(f.bytes).unwrap_or(i64::MAX),
            )
            .await?;
        }
        tx.commit().await?;
        Ok::<(), ApiError>(())
    }
    .await;
    if result.is_err() {
        tracing::error!(session_id = %sid_from_grant_id(&row.grant_id), "cannot close the session");
    }
}
