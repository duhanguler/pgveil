# ADR-005: AST Side-Channel PII Inference Protection & Native MCP Server Mode

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

Two practical security gaps emerge when deploying dynamic PII masking in front of autonomous AI SQL agents:

1. **Side-Channel Oracle Attacks on Masked Columns:** Even if `SELECT email, tckn FROM customers` masks values in outbound `DataRow` packets, an adversarial or prompt-injected agent can reconstruct raw values bit-by-bit via SQL predicates, sorting, or string slicing:
   - `SELECT id FROM customers WHERE tckn LIKE '100000%'`
   - `SELECT id, SUBSTRING(iban, 1, 10) AS prefix FROM customers`
   - `SELECT id FROM customers ORDER BY ssn`
   - `SELECT id, tckn || '' AS raw_id FROM customers` (evading column-name rules via aliased expression projection).
2. **MCP Ergonomics Without Node.js Overhead:** Many developers connect Claude Desktop, Cursor, or Claude Code directly to PostgreSQL over stdio MCP. Requiring a separate Node.js wrapper (`@modelcontextprotocol/server-postgres`) *plus* a running proxy adds friction and still leaks restricted table names through `information_schema` unless filtered.

## Decision

1. **AST Side-Channel Inference Guard (`block_pii_inference`):** Extend `internal/firewall` to walk `WhereClause`, `HavingClause`, `SortClause`, `GroupClause`, `JoinExpr.Quals`, and expression projections (`SUBSTRING`, `LEFT`, `RIGHT`, `ASCII`, `MD5`, `ENCODE`, `||`, `CASE`) in the PostgreSQL 17 AST, blocking references to `protected_columns` before execution.
2. **Native Zero-Dependency MCP Server (`pgveil mcp`):** Implement JSON-RPC 2.0 MCP over stdio directly inside the single Go binary (`internal/mcpserver`), exposing `list_tables` (automatically omitting `denied_tables`), `describe_table` (refusing restricted tables and annotating active masking strategies), `query`, and `explain_query` enforced by the exact same AST firewall, rate limiter, and multi-compliance PII masker.
3. **Automatic Schema Discovery (`pgveil discover`):** Sample live `information_schema` tables against all 8 checksum-validated compliance packs to auto-generate both `column_rules` and `protected_columns` with zero manual inventory work.

## Consequences

- **Positive:** Closes both direct exfiltration (`DataRow`) and indirect inference (`WHERE`/`ORDER BY`/`SUBSTRING`) channels inside one deterministic AST pass.
- **Positive:** Developers can adopt `pgveil` either as a universal PostgreSQL wire proxy (`:6432`) or as a zero-dependency native MCP server (`pgveil mcp`).
