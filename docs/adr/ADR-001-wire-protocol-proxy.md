# ADR-001: PostgreSQL Wire Protocol v3 Proxy vs. Database Extensions or ORM Middleware

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

Organizations connecting AI SQL agents (Claude Code, Cursor, MCP PostgreSQL servers, LangChain), BI tools (Metabase, Superset, DBeaver), and engineers to PostgreSQL need two guarantees simultaneously:
1. Dynamic, role-aware PII masking (GDPR, KVKK, PCI-DSS, HIPAA, Secrets) before sensitive data reaches LLM context windows or laptops.
2. Hard guardrails against destructive queries (`DROP`, unscoped `DELETE`, `pg_read_file`, bulk exfiltration).

Existing approaches suffer from structural trade-offs:
- **PostgreSQL extensions** (e.g., `postgresql_anonymizer`) require superuser extension installs inside managed RDS/Cloud SQL instances, alter schemas/views, and do not provide synchronous Human-in-the-Loop approvals or Kafka audit streaming.
- **ORM / application middleware** only protects one language stack and is bypassed immediately by `psql`, DBeaver, BI tools, and third-party MCP servers.
- **Offline dump anonymizers** only sanitize static snapshots and cannot guard live read replicas or interactive agents.

## Decision

Implement `pgveil` as a standalone **PostgreSQL Wire Protocol v3 TCP/TLS proxy** in Go.

Clients connect using standard drivers (`psql`, `pgx`, `psycopg`, `node-pg`, `JDBC`, `@modelcontextprotocol/server-postgres`) by pointing only to port `6432` and setting `application_name` (or database `user`).

## Consequences

- **Positive:** Zero schema changes, zero PostgreSQL extensions required, works identically on AWS RDS, Cloud SQL, Supabase, Neon, and self-hosted PostgreSQL 14–17.
- **Positive:** Single enforcement chokepoint for every client language and MCP tool.
- **Trade-off:** The proxy must faithfully implement both Simple Query (`'Q'`) and Extended Query (`'P'`, `'B'`, `'D'`, `'E'`, `'S'`) framing, authentication relay (`SCRAM-SHA-256`, `MD5`, `cleartext`, `trust`), and `CancelRequest`/`SSLRequest` negotiation.
