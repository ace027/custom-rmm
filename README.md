# custom-rmm

A security-first remote monitoring and management backend written as a Rust Cargo workspace. It contains a Windows-first endpoint agent, a watchdog/updater, a session helper, the server processes (API, ingest, auth callout, migrations), shared protocol and trust crates, and an offline signing CLI. The trust chain is designed so that a compromised server cannot run arbitrary code on endpoints. The web UI lives elsewhere; this repository exports an OpenAPI document.

## Crates

| Crate | Kind | Responsibility | Windows |
| --- | --- | --- | --- |
| rmm-proto | lib | Wire types, IDs, NATS subject builders | yes |
| rmm-trust | lib | Trust-chain verification; `sign` feature gates signing code | yes |
| rmm-recipe | lib | Action-definition schema and static recipe validation | yes |
| rmm-platform | lib | Platform trait with per-OS implementations (only crate allowing unsafe) | yes |
| rmm-agent-core | lib | Platform-agnostic agent logic | yes |
| rmm-agent | bin | Endpoint agent | yes |
| rmm-watchdog | bin | Watchdog and updater (std only, no tokio) | yes |
| rmm-session | bin | Session helper | yes |
| rmm-db | lib | Database pool, migrations, scoped transactions | no |
| rmm-api | lib | HTTP routes and OpenAPI document | no |
| rmm-server | bin | `api`, `ingest`, `authd`, `migrate`, `openapi`, `healthcheck` | no |
| rmm-sign | bin | Offline signing CLI | yes |

`xtask/` holds developer automation.

## Quick commands

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo xwin build --target x86_64-pc-windows-msvc -p rmm-agent --locked
scripts/check-layering.sh      # enforce crate layering; scripts/test-layering.sh self-tests it
cargo run -p xtask -- openapi  # regenerate docs/openapi.json (add --check to detect drift)
```

## Documents

- Product spec: [docs/spec.md](docs/spec.md)
- Phase 1 design: [.planning/explorations/2026-10-31-rmm-backend-phase1-design.md](.planning/explorations/2026-10-31-rmm-backend-phase1-design.md)
