# ADR-006: Streamable HTTP MCP + Typed AST `{{jwt.*}}` RLS, Unfurler-Safe ChatOps HITL & Sideband `EXPLAIN` Cost Guard

- **Status:** Accepted (`v0.5.0`)
- **Date:** 2026-11-22

## Context

As `pgveil` expands from local `stdio` MCP agents and developer workstations to multi-tenant cloud AI agents and production clusters, three systems-level failure modes emerge in naive designs:

1. **Second-Order SQL Injection in Dynamic Tenant Filters:** Interpolating JWT claims (`{{jwt.tenant_id}}`) as text prior to SQL parsing forces a custom string scanner to guess PostgreSQL quoting state (`'...'`, `$$...$$`, `E'\''`, `--`), creating lexer-confusion bypass risks.
2. **Link-Unfurler Auto-Approval in ChatOps HITL:** Messaging platforms (Slack, Discord, Microsoft Teams, Defender SafeLinks) automatically `GET`-prefetch URLs embedded in chat notifications within milliseconds. Any state-mutating `GET` approval link will silently auto-approve destructive `UPDATE`/`DELETE` queries before a human sees the alert.
3. **Wire-State Corruption & Latency Tax from In-Band `EXPLAIN`:** Sending `EXPLAIN (FORMAT JSON)` over a client's live PostgreSQL wire socket destroys unnamed portals (`""`), desynchronizes Extended Query `Flush` (`'H'`) pipelines, risks aborting open client transactions (`txStatus == 'T'`), and doubles OLTP round-trip latency.

## Decisions

### 1. Typed Sentinel `A_Const` AST Substitution (`internal/firewall/rls.go`)
- Policy `row_filters` templates replace `{{jwt.<claim>}}` and session placeholders with pure alphanumeric sentinel tokens (`__pgveil_ph_N__`) prior to `pg_query.Parse`.
- Untrusted claim values never touch the SQL lexer; instead, `pgveil` walks the parsed PostgreSQL 17 C AST and writes claim values directly into `*pg_query.Node_AConst` string leaves before calling `pg_query.Deparse`.
- Missing or empty `{{jwt.<claim>}}` attributes **fail closed** (`ErrMissingRLSClaim`, `SQLSTATE 42501`).
- Streamable HTTP `/mcp` (`2025-03-26`) verifies `HS256`/`RS256`/`ES256` tokens (including coalesced 30s-cooldown JWKS caching), binds `Mcp-Session-Id` to the authenticated `Subject` to prevent cross-tenant session replay, enforces `allowed_profiles` privilege-escalation guards, and holds **zero database connections** while waiting on HITL approvals.

### 2. Unfurler-Safe Two-Phase ChatOps Callbacks (`internal/chatops/`)
- Native Slack Block Kit interactive buttons are verified via `X-Slack-Request-Timestamp` (`±300s`) and `X-Slack-Signature` (`v0=` HMAC-SHA256).
- For Discord, Teams, Telegram, and generic webhooks, `GET /webhooks/hitl/callback` is strictly **read-only and idempotent**, rendering a zero-JS, CSP-locked HTML review card. State transitions occur exclusively via **`POST /webhooks/hitl/callback`** carrying an action-bound HMAC token (`act:<id>:<approve|deny>:<exp>`).
- Concurrent resolutions across Web Workbench and Slack use atomic `AlreadyResolvedError` snapshots so duplicate clicks receive deterministic status updates without double execution.

### 3. Sideband Read-Only `EXPLAIN` Pool + TTL LRU Plan Cache (`internal/firewall/cost_runner.go`)
- `CostRunner` evaluates `EXPLAIN (FORMAT JSON)` (and `GENERIC_PLAN` for `$1` parameterized queries) over a bounded, read-only sideband `pgxpool` (`MaxConns: 4`, `default_transaction_read_only = on`, `statement_timeout = '500ms'`) strictly **after** Virtual RLS rewriting.
- Extracted `PlanMetrics` (`TotalCost`, `PlanRows`, `SeqScanTables`) are cached in a `2,048`-entry `60s` TTL LRU keyed by `(profile, policyVersion, AST fingerprint, RLS rules)`, yielding `~0µs` steady-state overhead and automatic invalidation on policy hot-reload.
- Profile `max_query_duration` is injected silently at wire session startup (`SET statement_timeout`) and protected by AST GUC lockdown blocking `SET`/`RESET statement_timeout`, `RESET ALL`, `DISCARD ALL`, and `set_config('statement_timeout', ...)`.
