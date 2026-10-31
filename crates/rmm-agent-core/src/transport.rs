//! Outbound NATS-over-WebSocket connection using the device key as nkey.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use async_nats::{Auth, AuthError, ConnectOptions, Event};
use nkeys::{KeyPair, KeyPairType};
use rand::TryRng;
use tokio::sync::mpsc::UnboundedSender;

use crate::identity::Identity;

/// Longest wait between reconnect attempts.
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(60);

/// Connection state changes reported to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// Connected (or reconnected).
    Connected,
    /// Connection lost; the client keeps retrying.
    Disconnected,
    /// The client was closed for good.
    Closed,
}

/// Transport setup failure.
#[derive(Debug)]
pub struct TransportError(String);

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TransportError {}

/// Exponential delay (500 ms doubling, capped at 60 s) with jitter in the
/// upper half of the range.
pub fn reconnect_delay(attempts: usize) -> Duration {
    let exp = u32::try_from(attempts.min(10)).unwrap_or(10);
    let base = Duration::from_millis(500)
        .saturating_mul(1u32 << exp)
        .min(MAX_RECONNECT_DELAY);
    let mut r = [0u8; 4];
    let _ = rand::rngs::SysRng.try_fill_bytes(&mut r);
    let frac = u64::from(u32::from_le_bytes(r)) % 1000;
    let half = base / 2;
    half + half * u32::try_from(frac).unwrap_or(0) / 1000
}

/// Connect to the identity's NATS URL, reporting state changes on `events`.
/// Initial connect failures are retried in the background, so this returns
/// before the first [`ConnState::Connected`].
pub async fn connect_observed(
    identity: &Identity,
    seed: &[u8; 32],
    extra_ca: Option<&Path>,
    events: UnboundedSender<ConnState>,
) -> Result<async_nats::Client, TransportError> {
    let kp = KeyPair::new_from_raw(KeyPairType::User, *seed)
        .map_err(|e| TransportError(format!("nkey: {e}")))?;
    let public = kp.public_key();
    let kp = std::sync::Arc::new(kp);

    // The async-nats `nkeys` feature is not enabled in this workspace, so the
    // nonce is signed here with the same key pair (nkey user auth).
    let mut opts = ConnectOptions::with_auth_callback(move |nonce| {
        let kp = std::sync::Arc::clone(&kp);
        let public = public.clone();
        async move {
            let mut auth = Auth::new();
            auth.signature = Some(
                kp.sign(&nonce)
                    .map_err(|e| AuthError::new(format!("nkey sign: {e}")))?,
            );
            auth.nkey = Some(public);
            Ok(auth)
        }
    })
    .name(format!("rmm-agent/{}", env!("CARGO_PKG_VERSION")))
    .custom_inbox_prefix(format!("_INBOX_{}", identity.agent_id))
    .retry_on_initial_connect()
    .reconnect_delay_callback(reconnect_delay)
    .event_callback(move |event| {
        let events = events.clone();
        async move {
            let state = match event {
                Event::Connected => ConnState::Connected,
                Event::Disconnected => ConnState::Disconnected,
                Event::Closed => ConnState::Closed,
                _ => return,
            };
            let _ = events.send(state);
        }
    });
    if identity.nats_url.starts_with("wss://") || identity.nats_url.starts_with("tls://") {
        opts = opts.require_tls(true);
    }
    if let Some(ca) = extra_ca {
        opts = opts.add_root_certificates(ca.to_path_buf());
    }
    opts.connect(identity.nats_url.as_str())
        .await
        .map_err(|e| TransportError(format!("connect: {e}")))
}

/// [`connect_observed`] without state notifications.
pub async fn connect(
    identity: &Identity,
    seed: &[u8; 32],
    extra_ca: Option<&Path>,
) -> Result<async_nats::Client, TransportError> {
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    connect_observed(identity, seed, extra_ca, tx).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_is_capped_and_jittered() {
        for attempts in [0, 1, 5, 20, 1000] {
            let d = reconnect_delay(attempts);
            assert!(d <= MAX_RECONNECT_DELAY, "{attempts}: {d:?}");
            assert!(d >= Duration::from_millis(250), "{attempts}: {d:?}");
        }
        assert!(reconnect_delay(1000) >= Duration::from_secs(30));
    }
}
