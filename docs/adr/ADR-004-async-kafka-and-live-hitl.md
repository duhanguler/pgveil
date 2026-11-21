# ADR-004: Non-Blocking Kafka Audit Pipeline & Synchronous HITL Wire Holds

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

Enterprise compliance (KVKK, GDPR, SOC 2, ISO 27001) requires durable, tamper-evident audit trails of every query and immediate security alerting on attack bursts. Writing synchronously to an audit database inside the proxy query loop would add milliseconds of latency and couple database availability to audit storage health.

Conversely, when an AI agent attempts a scoped state mutation (`UPDATE orders SET status='refunded' WHERE id=1001`), organizations want a human operator to approve or deny the action *before* it executes — without forcing custom client retries.

## Decision

1. **Non-Blocking Event Bus + Dedicated Kafka Worker:** The proxy publishes `AuditEvent` structs into a bounded in-memory channel feeding a pure-Go `franz-go` Kafka/Redpanda producer (`pgveil.audit.queries` and `pgveil.alerts.security`). A separate `pgveil-audit-worker` service consumes events in consumer groups, batch-inserts them into PostgreSQL (`pgveil_audit_log`), routes poison records to `pgveil.audit.dlq`, and triggers burst-attack anomaly alerts.
2. **Synchronous Wire-Level HITL Hold (`hitl_mode: hold`):** When the AST firewall returns `ActionRequireHITL`, the proxy registers an `ApprovalRequest`, pushes a live Server-Sent Event (`event: approval`) to the Web Console, and blocks the connection's goroutine on a per-request channel with a bounded timeout. Upon operator **Approve**, the original PostgreSQL wire frame is forwarded upstream immediately; upon **Deny** or timeout, a standard `ErrorResponse` (`SQLSTATE 42501`) + `ReadyForQuery` is synthesized so the session stays intact.

## Consequences

- **Positive:** Audit durability and Kafka broker stalls never impact query latency on the wire hot path.
- **Positive:** Any off-the-shelf SQL client (`psql`, MCP Postgres server, LangChain) gets live Human-in-the-Loop write approval with zero client-side code changes.
