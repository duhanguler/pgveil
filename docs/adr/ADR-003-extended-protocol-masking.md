# ADR-003: Wire-Level Dynamic Masking & Extended Protocol Format Negotiation

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

Modern PostgreSQL drivers (`pgx/v5`, `psycopg3`, `asyncpg`, `JDBC`) default to the **Extended Query Protocol** (`Parse → Bind → Describe → Execute → Sync`) and frequently request **binary wire format (`formatCode = 1`)** for columns.

If a proxy replaces a binary-encoded column or masks a `RowDescription`/`DataRow` cell without coordinating format codes, strict drivers reject the frame with a binary decoding error.

## Decision

1. On `Bind ('B')` messages for sessions where masking is enabled, `pgveil` rewrites the trailing result-column format codes to `[count=1, format=0 (text)]` (`pgwire.RewriteBindResultFormatsToText`).
2. On `RowDescription ('T')`, `pgveil` precomputes a flat `[]pii.Strategy` slice aligned by column ordinal so the hot `DataRow ('D')` loop performs zero map allocations or string lowercasing per row.
3. Unruled text columns use a single-pass O(n) ASCII pre-filter (`fastWorthScanning`) before invoking regex + checksum validators (TCKN mod-10, ISO 13616 Mod-97 IBAN, Turkish VKN, Luhn Credit Card, SSN, Secrets), skipping clean cells like `"delivered"` or `"Istanbul"` in ~20 ns.
4. `DataRow` frames are re-encoded **only when at least one cell is modified**, preserving zero-overhead forwarding for clean rows.

## Consequences

- **Positive:** 100% compatibility across `psql`, `pgx/v5`, `psycopg3`, `node-pg`, and `DBeaver` with zero binary frame corruption.
- **Positive:** Sub-millisecond overhead even on multi-column PII result sets.
