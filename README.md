<p align="center">
  <img src="docs/assets/banner.svg" alt="pgveil — Zero-Trust PostgreSQL Wire-Protocol PII Masking & AI-Agent SQL Firewall Proxy" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/duhanguler/pgveil/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/duhanguler/pgveil/ci.yml?branch=main&style=flat-square&label=CI" alt="CI" /></a>
  <a href="https://codecov.io/gh/duhanguler/pgveil"><img src="https://codecov.io/gh/duhanguler/pgveil/graph/badge.svg" alt="Codecov" /></a>
  <a href="https://pkg.go.dev/github.com/duhanguler/pgveil"><img src="https://pkg.go.dev/badge/github.com/duhanguler/pgveil.svg" alt="Go Reference" /></a>
  <a href="https://mcpservers.org/servers/duhanguler/pgveil"><img src="https://mcpservers.org/badge.svg" alt="Listed on mcpservers.org" /></a>
  <a href="https://github.com/duhanguler/pgveil/releases"><img src="https://img.shields.io/badge/Release-v0.4.0-18181b?style=flat-square" alt="v0.4.0" /></a>
  <a href="https://github.com/duhanguler/homebrew-tap"><img src="https://img.shields.io/badge/Homebrew-duhanguler%2Ftap%2Fpgveil-18181b?style=flat-square&logo=homebrew&logoColor=white" alt="Homebrew Tap" /></a>
  <img src="https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.26+" />
  <img src="https://img.shields.io/badge/PostgreSQL-14--17%20Wire%20v3-336791?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL Wire v3" />
  <img src="https://img.shields.io/badge/AST-libpg__query%2017-18181b?style=flat-square" alt="PostgreSQL 17 AST" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-18181b?style=flat-square" alt="Apache 2.0 License" /></a>
</p>

# pgveil

**Zero-trust PostgreSQL Wire Protocol v3 proxy, AST Virtual RLS rewriter & native MCP server in Go** — dynamic wire-speed PII masking (**8 compliance packs: GDPR, KVKK, PCI-DSS, HIPAA, LGPD, PIPEDA, UK-GDPR, Secrets**), real **PostgreSQL 17 AST SQL firewall**, **AST-level Virtual Row-Level Security (tenant predicate injection)**, **multi-hop CTE taint & PII side-channel oracle guard**, **automatic live schema PII discovery & `pgveil init` wizard**, **synchronous Human-in-the-Loop (HITL) wire holds**, **runaway AI-agent loop circuit breaker**, **shadow audit-only rollout mode**, async **Kafka audit streaming**, **OpenTelemetry/Prometheus observability**, an embedded **Precision Database Workbench (`68 KB` gzip, Dark + Light theme)**, and a production **Kubernetes Helm chart**.

Give **AI agents (Claude Code, Cursor, MCP, LangChain)**, BI tools (**Metabase, Superset, DBeaver**), and developers live access to PostgreSQL — **with zero database extensions, zero schema changes, and a 1-line port swap (`5432` → `6432`) or zero-Node.js native `pgveil mcp`**.

```bash
# Try it live in 3 seconds — zero Docker, zero external PostgreSQL required!
brew install duhanguler/tap/pgveil && pgveil demo

# Or scan your own PostgreSQL database and generate a validated pgveil.yaml automatically
pgveil init --dsn "postgres://user:pass@localhost:5432/mydb"
```

```diff
- postgres://app:secret@db.internal:5432/prod
+ postgres://app:secret@pgveil.internal:6432/prod?application_name=claude-mcp
```

---

### Embedded Precision Database Workbench (Dark & Swiss Light)

Built directly into the single Go binary (`67 KB` gzip) — line-numbered SQL & YAML syntax highlighting, live AST pre-flight indicator, `⌘K` Command Palette, right-side Audit Inspector slide-over drawer, live HITL wire-hold countdown, and automatic Dark / Swiss Light theme switching.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/console-playground.png" />
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/console-light.png" />
    <img src="docs/assets/console-playground.png" alt="pgveil Embedded Precision Database Workbench — Live Wire SQL Masking & AST Guard" width="100%" />
  </picture>
</p>

<details>
  <summary>Preview Swiss Light &amp; Carbon Dark Workbench side-by-side</summary>
  <br />
  <p align="center">
    <img src="docs/assets/console-light.png" alt="pgveil Workbench — Swiss Light Theme" width="100%" />
  </p>
</details>

---

## Why pgveil?

In 2026, teams are connecting autonomous AI SQL agents, coding assistants (Claude Code, Cursor, MCP servers), and BI analysts directly to PostgreSQL replicas and production databases. One hallucinated `DELETE FROM orders WHERE 1=1`, a prompt-injected `SELECT pg_read_file('/etc/passwd')`, a side-channel oracle probe (`WHERE tckn LIKE '100000%'`), or an innocent `SELECT * FROM customers` dumping 500,000 customer rows into an LLM context window creates an immediate outage or **GDPR / KVKK / PCI-DSS / HIPAA** breach.

| Capability | `pgveil` | `postgresql_anonymizer` | `PgBouncer` | `pgdump-obfuscator` | MCP Wrapper Scripts |
|---|:---:|:---:|:---:|:---:|:---:|
| Zero PostgreSQL extensions / RDS, Cloud SQL, Neon, Supabase TLS | **Yes** | No (superuser ext) | **Yes** | **Yes** | **Yes** |
| Works for **every** client (`psql`, `pgx`, `psycopg`, DBeaver, MCP) | **Yes** | **Yes** | **Yes** | Offline dumps only | MCP only |
| Real PostgreSQL 17 AST firewall (CTEs, tautologies, multi-stmt) | **Yes** | No | No | No | Regex only |
| **AST Virtual Row-Level Security (RLS)** (tenant predicate injection via `Deparse`) | **Yes** | No | No | No | No |
| **AST PII Side-Channel Oracle & CTE Taint Guard** (`WHERE tckn LIKE`, `c::text`, `ORDER BY 2`) | **Yes** | No | No | No | No |
| Live wire-speed PII & secret masking (`DataRow` rewriting + binary `pgx`) | **Yes** (`+0.25ms`) | Views/static | No | Static dump | Post-fetch only |
| Zero-config sandbox (`pgveil demo`) & live schema onboarding (`pgveil init`) | **Yes** | No | No | No | No |
| Native zero-Node.js MCP stdio server (`pgveil mcp`) | **Yes** | No | No | No | Node/Python only |
| **Live synchronous HITL approval hold** + Shadow `audit` mode + Loop breaker | **Yes** | No | No | No | No |
| Async Kafka audit stream + OTel + Prometheus + Grafana + Helm | **Yes** | No | Metrics only | No | No |

---

## AST-Level Virtual Row-Level Security (RLS)

Enforce **multi-tenant and regional row isolation at the PostgreSQL wire layer** without creating database RLS policies, views, or touching application SQL. `pgveil` parses each approved query into PostgreSQL 17's C AST (`libpg_query`), qualifies table aliases, places `LEFT JOIN` predicates cleanly into `ON` clauses (and wraps `FULL OUTER JOIN` tables as subqueries), preserves Extended Query `$1`/`$2` parameters, escapes session placeholders (`{{db_user}}`, `{{database}}`, `{{application_name}}`), and deparses canonical PostgreSQL SQL via `pg_query.Deparse`:

```yaml
profiles:
  - name: "tenant_tr"
    firewall:
      row_filters:
        - table: "customers"
          predicate: "city = 'Istanbul'"
        - table: "orders"
          predicate: "currency = 'TRY'"
        # Dynamic session binding (SQLi-safe quote-escaped):
        # - table: "invoices"
        #   predicate: "owner = '{{db_user}}'"
```

```sql
-- Client sends:
SELECT c.id, c.full_name, c.city, o.order_number, o.currency
FROM customers c LEFT JOIN orders o ON c.id = o.customer_id;

-- pgveil rewrites on the wire (Simple Query, Extended Parse $1, and MCP):
SELECT c.id, c.full_name, c.city, o.order_number, o.currency
FROM customers c LEFT JOIN orders o ON c.id = o.customer_id AND o.currency = 'TRY'
WHERE c.city = 'Istanbul';
```

> **Security Ordering Invariant:** Firewall guards (`block_write_without_where`, tautology checks, PII side-channel taint) always run on the **original** client AST *before* Virtual RLS injects predicates — so an unscoped `DELETE FROM orders` is always blocked instead of silently wiping a tenant's rows.

<p align="center">
  <img src="docs/assets/console-rls.png" alt="pgveil AST Virtual Row-Level Security Live Rewrite & Masking Workbench" width="100%" />
</p>

---

## Automatic Live Schema PII Discovery (`pgveil discover` & `pgveil init`)

Point `pgveil discover` at any existing PostgreSQL database to audit unmasked sensitive columns across **8 checksum-validated compliance packs** and emit a ready-to-use `pgveil.yaml` policy block in seconds:

```bash
pgveil discover --dsn "postgres://pgveil:pgveil_dev_password@127.0.0.1:5432/pgveil_demo?sslmode=disable"
```

```text
pgveil Schema PII Discovery — database="pgveil_demo" tables=5 columns=38 findings=12

TABLE.COLUMN              RISK      COMPLIANCE                       STRATEGY  SAMPLE MASKED
------------              ----      ----------                       --------  -------------
api_secrets.secret_value  CRITICAL  SECRETS                          redact    [REDACTED:GITHUB_TOKEN]
customers.full_name       MEDIUM    GDPR,KVKK                        hash      [heuristic match]
customers.email           HIGH      GDPR,KVKK                        partial   a***@example.com.tr
customers.phone           MEDIUM    GDPR,KVKK                        partial   +90  *** ** 21
customers.tckn            CRITICAL  KVKK                             partial   100******46
customers.ssn             CRITICAL  HIPAA                            redact    [REDACTED:US_SSN]
customers.iban            HIGH      GDPR,KVKK                        partial   TR33 **** **** **** 1326
orders.shipping_note      CRITICAL  GDPR,KVKK,PCI-DSS                partial   Call +90  *** ** 21 at gate
payments.card_number      CRITICAL  PCI-DSS                          last4     ****-****-****-4242
support_tickets.body      CRITICAL  GDPR,HIPAA,KVKK,PCI-DSS,SECRETS  redact    Hello, please refund order ORD-2026-1001 to my IBAN TR33 **** **** **** 1326...

Recommended denied_tables: api_secrets
```

<p align="center">
  <img src="docs/assets/console-discovery.png" alt="pgveil Automatic Schema PII Discovery Console" width="100%" />
</p>

---

## See It in Action (Real `psql` & `pgx/v5` Wire Sessions)

Connect with any unmodified PostgreSQL client by setting `application_name=claude-mcp` on port `6432`:

```sql
-- 1. Structured columns masked dynamically on the wire (JOIN-preserving HMAC hash + partial masks)
SELECT id, full_name, email, phone, tckn, iban FROM customers ORDER BY id LIMIT 4;

 id |    full_name     |        email        |     phone      |    tckn     |           iban
----+------------------+---------------------+----------------+-------------+--------------------------
  1 | tok_5351939b7cc5 | a***@example.com.tr | +90  *** ** 21 | 100******46 | TR33 **** **** **** 1326
  2 | tok_c602dcb1b2f4 | m***@acme.io        | +90  *** ** 80 | 123******50 | TR33 **** **** **** 1326
  3 | tok_85015ababe75 | e***@eu-shop.de     | +49  *** ** 03 | 246******94 | DE89 **** **** **** 3000
  4 | tok_e6779f53504a | m***@fintech-us.com | +1 4 *** ** 94 | 314******62 | GB29 **** **** **** 6819

-- 2. Free-text columns auto-scanned for embedded PII & leaked cloud credentials
SELECT id, subject, body FROM support_tickets ORDER BY id LIMIT 2;

 id |           subject            | body
----+------------------------------+-----------------------------------------------------------------------------------------------------------------------------
  1 | IBAN refund transfer request | Hello, please refund order ORD-2026-1001 to my IBAN TR33 **** **** **** 1326. My TCKN is 100******46 and email a***@example.com.tr.
  2 | API integration error log    | Our webhook failed while authenticating with key [REDACTED:AWS_ACCESS_KEY] and card ****-****-****-4242. Contact m***@fintech-us.com (SSN [REDACTED:US_SSN]).

-- 3. Bulk exfiltration capped at 25 rows with genuine PostgreSQL NOTICE
SELECT id, email FROM customers;
NOTICE:  pgveil: result truncated to 25 rows (15 excess rows suppressed by profile "ai_agent" row-exfiltration budget)
(25 rows)

-- 4. AST Firewall blocks destructive SQL, tautologies, modifying CTEs, server escapes & PII side-channel oracles
DROP TABLE orders;
-- ERROR:  DDL / privilege statement (DROP) is blocked for profile "ai_agent" (SQLSTATE 42501)

DELETE FROM orders WHERE 1 = 1;
-- ERROR:  Unscoped DELETE without effective WHERE clause (or tautology like 1=1) is blocked (SQLSTATE 42501)

SELECT id, full_name FROM customers WHERE tckn LIKE '100000%';
-- ERROR:  PII side-channel inference blocked: protected column "tckn" referenced in WHERE predicate (SQLSTATE 42501)

SELECT id, SUBSTRING(iban, 1, 10) AS prefix FROM customers;
-- ERROR:  PII side-channel inference blocked: protected column "iban" referenced in expression function substring() (SQLSTATE 42501)

SELECT pg_read_file('/etc/passwd');
-- ERROR:  Dangerous PostgreSQL function blocked: pg_read_file (SQLSTATE 42501)

-- 5. Live Synchronous HITL Hold: connection pauses cleanly until an operator clicks Approve in the Web Console
UPDATE orders SET status = 'refunded' WHERE id = 1001;
-- [Paused on wire -> Operator approves in http://localhost:8088 -> Immediately resumes]
UPDATE 1
```

---

## Architecture

```mermaid
flowchart LR
    Clients["Clients & AI Agents<br/>psql · pgx · psycopg · DBeaver<br/>Claude/Cursor MCP · LangChain"] -->|"PostgreSQL Wire Protocol v3<br/>(:6432 TCP / TLS)<br/>or Native MCP stdio"| Proxy["pgveil Proxy & MCP (Go)<br/>• Simple + Extended Query (Cached Stmts)<br/>• PostgreSQL 17 AST + PII Oracle Guard<br/>• Rate Limiter & Runaway Loop Breaker<br/>• Synchronous HITL Hold + Shadow Mode<br/>• Dynamic Wire-Speed PII Masker (8 Packs)<br/>• Embedded Web Console + Discovery (:8088)"]

    Proxy -->|"Policy-Verified SQL<br/>(Optional Upstream TLS)"| PG[("PostgreSQL 14–17<br/>RDS · Cloud SQL · Neon · Local")]

    Proxy -->|"Non-Blocking Async Events"| Kafka["Apache Kafka / Redpanda<br/>• pgveil.audit.queries<br/>• pgveil.alerts.security"]
    Kafka --> Worker["pgveil-audit-worker (Go)<br/>• Batch pgx Sink (pgveil_audit_log)<br/>• Dead-Letter Queue (DLQ)<br/>• Burst Attack Anomaly Webhook"]

    Proxy -.->|"OTLP / Metrics"| Obs["OpenTelemetry + Jaeger<br/>Prometheus + Grafana"]
    Worker -.->|"Metrics"| Obs
```

### Core Engineering Highlights
- **Full Wire Protocol v3 + Extended Binary Fidelity (`internal/pgwire`, `internal/proxy`):** Supports `SSLRequest` (client TLS termination & upstream TLS for RDS/Cloud SQL/Neon/Supabase), `GSSENCRequest`, `CancelRequest`, `SCRAM-SHA-256` / `MD5` / `cleartext` / `trust` auth relay, Simple Query (`'Q'`), and Extended Query pipelines (`Parse`, `Bind`, `Describe`, `Execute`, `Sync`) with per-session prepared statement metadata caching so strict binary drivers (`pgx/v5`, `psycopg3`, `JDBC`) work seamlessly ([ADR-003](docs/adr/ADR-003-extended-protocol-masking.md)).
- **PostgreSQL 17 AST Firewall + Side-Channel Oracle Guard (`internal/firewall`):** Embeds PostgreSQL's own C parser (`libpg_query`) to defeat bypasses that regex proxies miss — modifying CTEs (`WITH d AS (DELETE ...) SELECT * FROM d`), always-true tautologies (`WHERE 1=1`, `WHERE id=5 OR true`), multi-statement SQLi, `pg_read_file` / `COPY TO PROGRAM` / `DO $$` / `SET ROLE`, **plus AST side-channel PII inference probes** (`WHERE tckn LIKE '100%'`, `SUBSTRING(iban,1,8) AS x`, `tckn || ''`, `ORDER BY ssn`, `CASE WHEN ssn = ...`) ([ADR-002](docs/adr/ADR-002-postgresql-ast-firewall.md), [ADR-005](docs/adr/ADR-005-pii-inference-and-native-mcp.md)).
- **Zero-False-Positive 8-Pack Global Compliance Engine (`internal/pii`):**
  - **`kvkk`** (Türkiye): 11-digit **TCKN** mod-10, 26-char **TR IBAN** ISO 13616 Mod-97, 10-digit **VKN** tax ID checksum, Turkish mobile phones, email
  - **`gdpr`** (EU): **EU IBAN** Mod-97 (`DE`, `FR`, `GB`, `NL`, `ES`, `IT`, ...), email, international phones, IPv4
  - **`pci-dss`**: **Credit Cards** (Visa, Mastercard, Amex, Discover, Troy) with **Luhn + BIN** validation
  - **`hipaa`** (US): **US SSN** (SSA area/group/serial validation), email, phone
  - **`lgpd`** (Brazil): **Brazilian CPF** (dual mod-11 check digits)
  - **`pipeda`** (Canada): **Canadian SIN** (Luhn validation)
  - **`uk-gdpr`** (UK): **UK NINO** (official HMRC prefix exclusion rules)
  - **`secrets`**: AWS access keys (`AKIA...`), GitHub tokens (`ghp_`, `github_pat_`), OpenAI keys (`sk-...`), JWTs, PEM private keys
  - **6 Masking Strategies:** `partial`, `redact`, `last4`, `hash` (HMAC-SHA256 deterministic **JOIN-preserving pseudonymization**), `fake`, and `null`.
- **Enterprise Rollout Safety:** Per-profile **Shadow / Audit-Only Mode (`mode: audit`)** emits `WOULD_BLOCK` / `WOULD_HITL` telemetry without breaking traffic; **Runaway AI-Agent Loop Circuit Breaker & QPM Rate Limiter** (`internal/ratelimit`) stops stuck retry loops with `SQLSTATE 53300`; **Webhook alerts** notify Slack/Teams/Discord on live HITL holds and CRITICAL blocks; **SIGHUP / REST API hot-reload** swaps policies with zero downtime.

---

## Benchmarks (Real Measured Results)

All benchmarks below were executed locally on **Apple M3 Pro (arm64)** against **PostgreSQL 16.14** using our reproducible scripts in [`benchmarks/`](benchmarks/).

### 1. Live `pgbench` Wire-Protocol Throughput & Overhead
8 concurrent clients, 4 threads, returning 5 rows × 7 columns (`id, full_name, email, phone, tckn, iban, city`) — **25 PII cells masked per query** in `ai_agent` mode:

| Mode | Throughput (TPS) | Avg Latency | Added Wire Overhead | Failed Tx |
|---|---:|---:|---:|---:|
| Direct PostgreSQL 16 (`:5432`) | **107,536 TPS** | `0.074 ms` | baseline | `0.000%` |
| Through `pgveil` — `admin` (Full PG17 AST + Audit) | **29,161 TPS** | `0.274 ms` | **`+0.200 ms`** (`200 µs`) | `0.000%` |
| Through `pgveil` — `ai_agent` (AST + **25 PII cells/query masked live**) | **25,012 TPS** | `0.320 ms` | **`+0.246 ms`** (`246 µs`) | `0.000%` |

> **625,000+ dynamically masked PII cells per second** on a single node with **sub-millisecond (`0.246 ms`) overhead** and **0 failed transactions** across 150,098 queries.

### 2. Go Core Microbenchmarks (`go test -bench=. -benchmem`)

| Benchmark | Latency / Op | Memory / Op | Allocs / Op |
|---|---:|---:|---:|
| `BenchmarkMaskCleanCellFastPath` (O(n) ASCII pre-filter) | **`13.54 ns`** | **`0 B`** | **`0`** |
| `BenchmarkMaskExplicitColumn` (TCKN partial mask) | **`86.96 ns`** | `272 B` | `3` |
| `BenchmarkMaskFreeTextWithPII` (multi-pack content scan) | **`26.31 µs`** | `7,906 B` | `25` |
| `BenchmarkEvaluateAST` (PG17 C parser on multi-table JOIN) | **`50.35 µs`** | `8,992 B` | `188` |

### 3. `k6` Control Plane & End-to-End Wire Load Test (`benchmarks/k6/control_plane_load.js`)
30 concurrent VUs, 25 seconds, mixing AST+PII inspections and live PostgreSQL wire proxy executions:

| Metric | Measured Result |
|---|---:|
| Total Requests / Checks Passed | **25,699 requests** · **57,832 / 57,832 checks (`100.00%`)** |
| Error Rate (`http_req_failed`) | **`0.00%`** (0 failures, 0 PII leaks) |
| `/api/v1/inspect` (AST + Multi-Pack PII Scan) | **p50 `274 µs`** · **p95 `696.8 µs`** |
| `/api/v1/playground/query` (Full TCP Wire Round-Trip) | **p50 `6.0 ms`** · **p95 `10.86 ms`** |

---

## Quick Start

### Option 1 — Instant Zero-Config Demo & Onboarding (Homebrew — macOS & Linux)

```bash
brew install duhanguler/tap/pgveil

# 1. Launch the embedded in-memory PostgreSQL sandbox + Precision Workbench (:8088) + Wire Proxy (:6432)
#    Zero Docker, zero external PostgreSQL, zero config files needed!
pgveil demo

# 2. Ready for your own database? Auto-scan & generate a validated pgveil.yaml in 2 seconds
pgveil init --dsn "postgres://user:pass@localhost:5432/mydb" --output pgveil.yaml

# 3. Start the production wire proxy (:6432) + Workbench UI (:8088)
pgveil serve --config pgveil.yaml

# 4. Or run the zero-Node.js native MCP stdio server for Claude Desktop / Cursor
pgveil mcp --config pgveil.yaml --profile ai_agent
```

### Option 2 — Full Enterprise Stack in 1 Command (Docker Compose)
Launches **PostgreSQL 16** (pre-seeded with synthetic e-commerce/fintech PII), **`pgveil` Proxy** (`:6432` wire + `:8088` Web Console), **Redpanda (Kafka)**, **`pgveil-audit-worker`**, **Jaeger**, **Prometheus**, and **Grafana** (pre-provisioned dashboard):

```bash
git clone https://github.com/duhanguler/pgveil.git
cd pgveil
docker compose up --build
```

- **Embedded Precision Workbench & PII Discovery:** `http://localhost:8088`
- **PostgreSQL Wire Proxy:** `postgres://pgveil:pgveil_dev_password@localhost:6432/pgveil_demo?application_name=claude-mcp`
- **Grafana Dashboard:** `http://localhost:3000` (`admin` / `pgveil_grafana`)
- **Jaeger Distributed Traces:** `http://localhost:16686`

### Option 3 — Build From Source & CLI (`demo`, `init`, `serve`, `discover`, `mcp`, `scan`, `validate`)

```bash
make build

# Run instant zero-config sandbox (no external PostgreSQL needed!)
./bin/pgveil demo

# Scan any live PostgreSQL DB and synthesize a complete validated pgveil.yaml
./bin/pgveil init --dsn "postgres://user:pass@localhost:5432/mydb" --output pgveil.yaml

# Start wire proxy + embedded Web Console
./bin/pgveil serve --config configs/pgveil.yaml

# Run zero-Node.js native MCP stdio server (hides denied_tables, enforces AST + Virtual RLS + PII masking)
./bin/pgveil mcp --config configs/pgveil.yaml --profile ai_agent

# Test any SQL query against the AST firewall & Virtual RLS rewriter in CI (exits 2 if BLOCKED)
./bin/pgveil scan --sql "SELECT c.id, o.order_number FROM customers c LEFT JOIN orders o ON c.id = o.customer_id" --profile tenant_tr
```

### Option 4 — Connect Claude Desktop / Cursor MCP (Zero Node.js or Wire Mode)
Native single-binary MCP ([`examples/mcp-claude/pgveil_native_mcp.json`](examples/mcp-claude/pgveil_native_mcp.json)):

```json
{
  "mcpServers": {
    "pgveil-native-postgres": {
      "command": "/opt/homebrew/bin/pgveil",
      "args": ["mcp", "--config", "/path/to/configs/pgveil.yaml", "--profile", "ai_agent"]
    }
  }
}
```

Or wire-proxy mode with the official Postgres MCP server ([`examples/mcp-claude/claude_desktop_config.json`](examples/mcp-claude/claude_desktop_config.json)) and Python `psycopg` agent ([`examples/python-agent/agent_demo.py`](examples/python-agent/agent_demo.py)).

### Option 5 — Production Kubernetes Deployment (Helm)

```bash
helm lint deploy/helm/pgveil
helm upgrade --install pgveil deploy/helm/pgveil \
  --namespace database-security --create-namespace \
  --set upstream.addr=postgres-primary.database.svc.cluster.local:5432 \
  --set security.maskingSecret="$PGVEIL_MASKING_SECRET"
```

---

## Architecture Decision Records (ADRs)

- [ADR-001: PostgreSQL Wire Protocol v3 Proxy vs. DB Extensions or ORM Middleware](docs/adr/ADR-001-wire-protocol-proxy.md)
- [ADR-002: Real PostgreSQL 17 AST Parsing vs. Regex SQL Filtering](docs/adr/ADR-002-postgresql-ast-firewall.md)
- [ADR-003: Wire-Level Dynamic Masking & Extended Query Protocol Binary Fidelity](docs/adr/ADR-003-extended-protocol-masking.md)
- [ADR-004: Non-Blocking Kafka Audit Pipeline & Synchronous HITL Wire Holds](docs/adr/ADR-004-async-kafka-and-live-hitl.md)
- [ADR-005: AST Side-Channel PII Inference Protection & Native MCP Server Mode](docs/adr/ADR-005-pii-inference-and-native-mcp.md)

---

## Project Layout

```text
pgveil/
├── cmd/
│   ├── pgveil/              # Single-binary CLI (demo, init, serve, discover, mcp, scan, validate) + embedded UI
│   └── audit-worker/        # Kafka consumer group worker (batch pgx sink, DLQ, burst anomaly alerts)
├── internal/
│   ├── pgwire/              # PostgreSQL Wire Protocol v3 binary framing (Simple & Extended + Parse rewrite)
│   ├── firewall/            # PostgreSQL 17 C AST SQL firewall, CTE taint guard & Virtual RLS rewriter
│   ├── demo/                # Pure-Go AST-backed in-memory PostgreSQL Wire v3 sandbox (`pgveil demo`)
│   ├── pii/                 # Zero-false-positive 8-pack compliance engine (GDPR/KVKK/PCI/HIPAA/LGPD/PIPEDA/UK/Secrets)
│   ├── discover/            # Live information_schema PII scanner & `pgveil init` starter-config generator
│   ├── mcpserver/           # Native zero-dependency JSON-RPC 2.0 MCP stdio server (with Virtual RLS)
│   ├── ratelimit/           # Per-profile QPM limiter & runaway AI-agent loop circuit breaker
│   ├── proxy/               # Bidirectional wire proxy, upstream TLS, Virtual RLS, shadow audit & live HITL holds
│   ├── hitl/                # Synchronous approval coordinator with SSE live notifications
│   ├── policy/              # Declarative YAML RBAC profiles + AST predicate validation + SIGHUP/API hot-reload
│   ├── events/              # Non-blocking audit ring buffer, SSE hub & franz-go Kafka producer
│   ├── telemetry/           # OpenTelemetry OTLP tracing + Prometheus histograms/counters
│   ├── api/                 # Control Plane REST/SSE API, live wire Playground & Discovery endpoint
│   └── webui/               # //go:embed compiled React + TypeScript Control Plane
├── web/                     # React 18 + TypeScript + Vite + Tailwind Console source
├── configs/pgveil.yaml      # Declarative profiles (ai_agent, tenant_tr, analyst, developer, admin)
├── deploy/
│   ├── docker/              # Postgres demo seed, Prometheus config & Grafana dashboard JSON
│   └── helm/pgveil/         # Production Kubernetes Helm chart (HPA, PDB, NetworkPolicy)
├── benchmarks/              # Reproducible pgbench comparison & k6 load test suite
├── examples/                # Native MCP, Claude/Cursor MCP & Python psycopg AI agent integrations
└── docs/adr/                # Architecture Decision Records
```

---

## Contributing & License

Contributions, regional compliance packs, and AST security test cases are very welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

Licensed under the **Apache License 2.0** — see [LICENSE](LICENSE).
