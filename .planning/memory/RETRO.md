# Retrospectives

## 2026-10-31 — Process decision: pull requests for CI

**Context**: Phases 1-3 were built and pushed to `claude/rmm-backend-explore-plan-6pu4ue` without a pull request. `.github/workflows/ci.yml` only runs on `pull_request` and on pushes to `main`, so none of the four CI jobs (lint, windows-cross, test-linux, test-windows) ever ran on GitHub. `test-windows` in particular has never been exercised.

**Decision (user)**: Open pull requests so CI runs. Use the GitHub MCP tools (`mcp__github__*`); the `gh` CLI is not available in this environment.

### Action Items
- [High] Keep an open pull request for the working branch, created with the GitHub MCP tools, so CI runs on every push.
- [High] Before marking a phase shipped, check the PR's CI results; a red `test-windows` or `windows-cross` job blocks the phase like a failing local check.
- [Medium] When a new working branch starts, open its pull request right after the first push.
