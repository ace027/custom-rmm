# Codebase Search Guide

Artifacts: `.planning/CODEBASE.md`, `.planning/codebase/index.jsonl` (chunks), `.planning/codebase/symbols.json` (entry points, routes, APIs, modules, tests, config, dependencies, ownership, risk areas).

## Query planning
Turn a question into `{terms, path_hints, symbol_hints, domain_hints}`.

## Retrieval order
1. Path hints (exact or partial paths in index.jsonl)
2. Symbol hints (symbols.json and chunk `symbols`)
3. Terms and aliases (chunk `keywords` and `aliases`)
4. CODEBASE.md headings
5. Read the original source

Always read the original source before acting on a result.

## Example
`/triad:map --query "auth session lifecycle"`

## Map Search Results

| Rank | Chunk | Path | Lines | Kind | Why it matched |
|------|-------|------|-------|------|----------------|
| 1 | map:src-auth-session:001 | src/auth/session.ts | 1-120 | module | path + symbol "createSession" |

### Read Next
- `src/auth/session.ts` lines 1-120

## Safety rules
- Summaries are not truth; the source is.
- Check freshness (`/triad:map --check`) before relying on the map.
- Do not load the whole index; query it.
- When the map and the source disagree, the source wins.
