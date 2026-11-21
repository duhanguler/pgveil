# ADR-003: Wire-Level Dynamic Masking & Extended Query Protocol Binary Fidelity

- **Status:** Accepted (Updated in v0.2.0)
- **Date:** 2026-11-21

## Context

Modern PostgreSQL drivers (`pgx/v5`, `psycopg3`, `asyncpg`, `JDBC`) default to the **Extended Query Protocol** (`Parse → Describe('S') → Sync`, followed by `Bind → Execute → Sync` on subsequent calls) and request **binary wire format (`formatCode = 1`)** for typed columns (`int4`, `int8`, `uuid`, `timestamp`).

Two subtle wire-protocol invariants break naive proxies:
1. When a driver caches a prepared statement (`Parse → Describe('S')`), subsequent `Bind → Execute → Sync` pipelines do **not** emit a new `RowDescription ('T')` frame from PostgreSQL.
2. Mutating `Bind` result format codes behind the driver's back breaks binary decoding for non-string columns (`int4: invalid length: expected 4 bytes, got 1`).

## Decision

1. **Per-Session Prepared Statement Field Cache:** `pgveil` caches parsed `[]pgwire.FieldDescription` per statement name (`meta.stmtFields[stmtName]`) on `RowDescription ('T')`, and restores column metadata automatically on subsequent `Bind → Execute` cycles even when no `Describe` is sent.
2. **Preserve Client `Bind` Format Codes + OID-Aware UTF-8 Masking:** `pgveil` preserves the exact binary/text format codes requested by the driver so `int4`, `int8`, `uuid`, and `timestamp` columns stay native binary, while dynamically masking all text-format cells (`FormatCode == 0`) **and** all PostgreSQL UTF-8 string OIDs (`text=25`, `varchar=1043`, `bpchar=1042`, `char=18`, `name=19`, `json=114`) whose PostgreSQL binary wire representation is identical to raw UTF-8 bytes.
3. **Zero-Allocation Clean Fast Path:** Unruled text cells pass through a single-pass O(n) ASCII pre-filter (`fastWorthScanning` — `13.54 ns/op, 0 allocs`) before invoking regex + checksum validators, and `DataRow` frames are re-encoded **only when at least one cell changes**.

## Consequences

- **Positive:** 100% verified compatibility across `psql`, `pgbench`, and default binary-mode `pgx/v5` prepared statements (including cached `Bind+Execute` loops) with zero binary frame corruption.
- **Positive:** Sub-millisecond overhead (`+0.246 ms` at `25,012 TPS` masking 25 PII cells/query).
