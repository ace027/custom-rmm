//! Command intake against a real NATS JetStream server: a command published
//! on `agent.<id>.cmd` must reach the agent through its durable pull
//! consumer, be stored, acked and answered with a queued result.
//!
//! Needs a running NATS (the dev stack): set `RMM_TEST_NATS_URL`, e.g.
//! `nats://127.0.0.1:4222`. Connects as the static `api` user from
//! `deploy/.env.example` (password overridable with `RMM_NATS_API_PASSWORD`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_nats::jetstream::{self, consumer, stream};
use rmm_agent_core::blocks::{Args, BlockOutput, BlockRunner, StepCtx};
use rmm_agent_core::commands::{self, Agent, CMD_STREAM, IntakeOptions, consumer_name, intake};
use rmm_agent_core::identity::Identity;
use rmm_agent_core::store::{STORE_KEY_FILE, Store};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Runs nothing; the test command is rejected before any block runs.
#[derive(Debug)]
struct NoBlocks;

impl BlockRunner for NoBlocks {
    fn run(&self, block: &str, _args: &Args, _ctx: &StepCtx<'_>) -> Result<BlockOutput, String> {
        Err(format!("unexpected block {block}"))
    }
}

#[tokio::test]
async fn pulled_command_is_stored_acked_and_answered() {
    let Ok(url) = std::env::var("RMM_TEST_NATS_URL") else {
        println!("skipping intake_nats: RMM_TEST_NATS_URL is unset");
        return;
    };
    let password =
        std::env::var("RMM_NATS_API_PASSWORD").unwrap_or_else(|_| "dev-only-nats-api".into());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let agent_id = Uuid::from_u128(nanos ^ (u128::from(std::process::id()) << 64));

    // Same inbox prefix as the real agent connection (transport.rs).
    let client = async_nats::ConnectOptions::with_user_and_password("api".into(), password)
        .custom_inbox_prefix(format!("_INBOX_{agent_id}"))
        .connect(url.as_str())
        .await
        .expect("connect to NATS");
    let js = jetstream::new(client.clone());
    // Same stream and consumer shape as rmm-api's ensure_agent_consumer.
    let cmd_stream = js
        .get_or_create_stream(stream::Config {
            name: CMD_STREAM.to_owned(),
            subjects: vec!["agent.*.cmd".to_owned()],
            storage: stream::StorageType::File,
            max_age: Duration::from_secs(7 * 24 * 3600),
            duplicate_window: Duration::from_secs(600),
            ..Default::default()
        })
        .await
        .expect("CMD stream");
    let name = consumer_name(&agent_id.to_string());
    cmd_stream
        .create_consumer(consumer::pull::Config {
            durable_name: Some(name.clone()),
            filter_subject: format!("agent.{agent_id}.cmd"),
            ack_policy: consumer::AckPolicy::Explicit,
            max_deliver: 5,
            ..Default::default()
        })
        .await
        .expect("agent consumer");

    let dir: PathBuf = std::env::temp_dir().join(format!("rmm-intake-nats-{agent_id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let key = rmm_platform::keystore_named(&dir, STORE_KEY_FILE);
    let store = Arc::new(Store::open(&dir, key.as_ref()).expect("open store"));

    let identity = Identity {
        agent_id,
        device_id: Uuid::nil(),
        client_id: Uuid::nil(),
        nats_url: url.clone(),
        server_url: String::new(),
    };
    let (roots, threshold) =
        commands::parse_roots(include_str!("fixtures/root.pub.hex").trim(), None).expect("root");
    let agent = Agent::new(
        agent_id.to_string(),
        Uuid::nil().to_string(),
        [0x55; 32],
        roots,
        threshold,
    );
    let shutdown = CancellationToken::new();
    let opts = IntakeOptions {
        agent: Arc::new(agent),
        blocks: Arc::new(NoBlocks),
        outbox_wake: Arc::new(Notify::new()),
        shutdown: shutdown.clone(),
    };
    let task = {
        let (client, store) = (client.clone(), Arc::clone(&store));
        tokio::spawn(async move { intake(client, &identity, store, opts).await })
    };

    js.publish(format!("agent.{agent_id}.cmd"), "not an envelope".into())
        .await
        .expect("publish")
        .await
        .expect("publish ack");

    // A garbage envelope is rejected, but still stored, acked and answered.
    let deadline = Instant::now() + Duration::from_secs(20);
    while store.outbox_len().expect("outbox") == 0 {
        assert!(
            Instant::now() < deadline,
            "command was never received from consumer {name}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut acked = false;
    while Instant::now() < deadline {
        let info = cmd_stream
            .consumer_info(&name)
            .await
            .expect("consumer info");
        if info.num_ack_pending == 0 && info.ack_floor.consumer_sequence >= 1 {
            acked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    let _ = cmd_stream.delete_consumer(&name).await;
    let _ = std::fs::remove_dir_all(&dir);

    assert!(acked, "command was stored but never acked");
    assert_eq!(store.inbox_pending_len().expect("inbox"), 0);
    assert_eq!(store.outbox_len().expect("outbox"), 1);
}
