# ADR-002: Real PostgreSQL 17 AST Parsing vs. Regex SQL Filtering

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

Prompt-injected AI agents and creative SQL payloads trivially bypass naive regex or keyword-based SQL filters via:
- Modifying CTEs disguised as `SELECT`: `WITH x AS (DELETE FROM orders RETURNING *) SELECT * FROM x;`
- Tautological `WHERE` clauses: `DELETE FROM orders WHERE 1 = 1` or `WHERE id = 5 OR true`
- Piggybacked multi-statement injection: `SELECT 1; DROP TABLE users;`
- Nested server-escape functions inside expressions: `SELECT COALESCE(pg_read_file('/etc/passwd'), '')`
- Restricted table access buried inside subqueries or joins.

## Decision

Embed PostgreSQL's own C parser (`libpg_query` via `github.com/pganalyze/pg_query_go/v6`) directly into the `internal/firewall` package and evaluate policies on the parsed AST.

## Consequences

- **Positive:** 100% PostgreSQL syntax fidelity (dollar-quoting, CTEs, subqueries, comments, type casts) with ~15–40 µs parse time per query.
- **Positive:** Deterministic query fingerprinting (`pg_query.Fingerprint`) for clean audit aggregation and anomaly detection without leaking literal query parameters.
- **Trade-off:** Requires CGO during compilation (`CGO_ENABLED=1`), handled transparently in multi-stage Docker builds and CI/GoReleaser matrices.
