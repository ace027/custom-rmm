# Pitfalls

Project-specific pitfalls recorded via `/triad:learn`.
Referenced by `/triad:plan` and `/triad:build` for context-aware execution.

## PIT-001: Check leftovers vs HEAD build before discarding review edits
- **Date**: 2026-11-01
- **Type**: pitfall
- **Tags**: review, git, build, leftovers
- **Phase**: 6

After a review loop, uncommitted edits may be the missing half of a committed fix (2018ece called Store::outbox_clear whose store.rs part was left uncommitted). Before discarding leftovers, build HEAD without them (git stash, cargo check); discard only if HEAD still compiles and passes.

---
