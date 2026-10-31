# Memory — User Preferences

Managed by the memory manager. Learnings recorded with /triad:learn are kept below the table.

## Preferences

| ID | Date | Branch | Decision Point | Context | Proposed | User Choice | Signal | Agent | Tags |
|----|------|--------|----------------|---------|----------|-------------|--------|-------|------|
| D-001 | 2026-10-31 | claude/rmm-backend-explore-plan-6pu4ue | manual-edit | Phase 1, post-build manual edit to Cargo.lock | Agent output for Cargo.lock (see plan 01-02 SUMMARY.md) | User edited Cargo.lock — +107/-282 lines: -version = "0.42.0" / +version = "0.51.0" / -checksum = "08f6da6d49a956424ca4e28fe93656f790d748b469eaccb / ... | corrective | engineering-infrastructure-devops | manual-edit, lock, engineering |
| D-002 | 2026-10-31 | claude/rmm-backend-explore-plan-6pu4ue | manual-edit | Phase 1, post-build manual edit to Cargo.toml | Agent output for Cargo.toml (see plan 01-02 SUMMARY.md) | User edited Cargo.toml — +1/-1 lines: -async-nats = { version = "0.42", default-features = false, / +async-nats = { version = "0.51", default-features = false, | corrective | engineering-infrastructure-devops | manual-edit, toml, engineering |
| D-003 | 2026-10-31 | claude/rmm-backend-explore-plan-6pu4ue | review-verdict | Phase 1 review | PASS | accepted | positive | system | review |
