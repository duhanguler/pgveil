<p align="center">
  <img src="docs/assets/banner.svg" alt="pgveil — Zero-Trust PostgreSQL Wire-Protocol PII Masking & AI-Agent SQL Firewall Proxy" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/duhanguler/pgveil/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/duhanguler/pgveil/ci.yml?branch=main&style=flat-square&label=CI" alt="CI" /></a>
  <img src="https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.26+" />
  <img src="https://img.shields.io/badge/PostgreSQL-14--17%20Wire%20v3-336791?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL Wire v3" />
  <img src="https://img.shields.io/badge/AST-libpg__query%2017-10b981?style=flat-square" alt="PostgreSQL 17 AST" />
  <img src="https://img.shields.io/badge/Compliance-GDPR%20%C2%B7%20KVKK%20%C2%B7%20PCI--DSS%20%C2%B7%20HIPAA-0ea5e9?style=flat-square" alt="Compliance Packs" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square" alt="Apache 2.0 License" /></a>
</p>

# pgveil

**Zero-trust PostgreSQL Wire Protocol v3 proxy in Go** — dynamic wire-speed PII masking (**GDPR, KVKK, PCI-DSS, HIPAA, Secrets**), real **PostgreSQL 17 AST SQL firewall**, **synchronous Human-in-the-Loop (HITL) wire holds**, async **Kafka audit streaming**, **OpenTelemetry/Prometheus observability**, an **embedded React Web Console**, and a production **Kubernetes Helm chart**.

Give **AI agents (Claude Code, Cursor, MCP PostgreSQL servers, LangChain)**, BI tools (**Metabase, Superset, DBeaver**), and developers live access to PostgreSQL — **with zero database extensions, zero schema changes, and a 1-line port swap (`5432` → `6432`)**.

```diff
- postgres://app:secret@db.internal:5432/prod
+ postgres://app:secret@pgveil.internal:6432/prod?application_name=claude-mcp
```

---

<p align="center">
  <img src="docs/assets/console-playground.png" alt="pgveil Embedded Control Plane & Live Wire SQL Playground" width="100%" />
</p>

---

## Why pgveil?

In 2026, teams are plugging autonomous AI SQL agents, coding assistants (Claude Code, Cursor, MCP servers), and BI analysts directly into PostgreSQL replicas and production databases. One hallucinated `DELETE FROM orders WHERE 1=1`, a prompt-injected `SELECT pg_read_file('/etc/passwd')`, or an innocent `SELECT * FROM customers` dumping 500,000 customer rows into an LLM context window creates an immediate outage or **GDPR / KVKK / PCI-DSS** breach.

| Capability | `pgveil` | `postgresql_anonymizer` | `PgBouncer` | `pgdump-obfuscator` | MCP Wrapper Scripts |
|---|:---:|:---:|:---:|:---:|:---:|
| Zero PostgreSQL extensions / RDS & Cloud SQL compatible | **Yes** | No (superuser ext) | **Yes** | **Yes** | **Yes** |
| Works for **every** client (`psql`, `pgx`, `psycopg`, DBeaver, MCP) | **Yes** | **Yes** | **Yes** | Offline dumps only | MCP only |
| Real PostgreSQL 17 AST firewall (CTEs, tautologies, multi-stmt) | **Yes** | No | No | No | Regex only |
| Live wire-speed PII & secret masking (`DataRow` rewriting) | **Yes** (`+0.25ms`) | Views/static | No | Static dump | Post-fetch only |
| Checksum-validated PII (**TCKN, TR/EU IBAN, VKN, Luhn CC, SSN**) | **Yes** | Manual rules | No | Manual | No |
| Row-exfiltration budget + PostgreSQL `NOTICE` truncation | **Yes** | No | No | No | No |
| **Live synchronous HITL approval hold** on the wire | **Yes** | No | No | No | Rarely |
| Async Kafka audit stream + OTel + Prometheus + Grafana + Helm | **Yes** | No | Metrics only | No | No |

---

## See It in Action (Real `psql` Wire Session)

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

-- 4. AST Firewall blocks destructive SQL, tautologies, modifying CTEs, server escapes & restricted tables
DROP TABLE orders;
-- ERROR:  DDL / privilege statement (DROP) is blocked for profile "ai_agent" (SQLSTATE 42501)

DELETE FROM orders WHERE 1 = 1;
-- ERROR:  Unscoped DELETE without effective WHERE clause (or tautology like 1=1) is blocked (SQLSTATE 42501)

SELECT pg_read_file('/etc/passwd');
-- ERROR:  Dangerous PostgreSQL function blocked: pg_read_file (SQLSTATE 42501)

SELECT * FROM api_secrets;
-- ERROR:  Access to restricted table "api_secrets" is denied for profile "ai_agent" (SQLSTATE 42501)

-- 5. Live Synchronous HITL Hold: connection pauses cleanly until an operator clicks Approve in the Web Console
UPDATE orders SET status = 'refunded' WHERE id = 1001;
-- [Paused on wire -> Operator approves in http://localhost:8088 -> Immediately resumes]
UPDATE 1
```

---

## Architecture

```mermaid
flowchart LR
    Clients["Clients & AI Agents<br/>psql · pgx · psycopg · DBeaver<br/>Claude/Cursor MCP · LangChain"] -->|"PostgreSQL Wire Protocol v3<br/>(:6432 TCP / TLS)"| Proxy["pgveil Proxy (Go)<br/>• Simple + Extended Query Framing<br/>• PostgreSQL 17 AST Firewall<br/>• Synchronous HITL Wire Hold<br/>• Dynamic Wire-Speed PII Masker<br/>• Row-Exfiltration Budget Cap<br/>• Embedded Web Console (:8088)"]

    Proxy -->|"Policy-Verified SQL"| PG[("PostgreSQL 14–17<br/>Zero Extensions Required")]

    Proxy -->|"Non-Blocking Async Events"| Kafka["Apache Kafka / Redpanda<br/>• pgveil.audit.queries<br/>• pgveil.alerts.security"]
    Kafka --> Worker["pgveil-audit-worker (Go)<br/>• Batch pgx Sink (pgveil_audit_log)<br/>• Dead-Letter Queue (DLQ)<br/>• Burst Attack Anomaly Webhook"]

    Proxy -.->|"OTLP / Metrics"| Obs["OpenTelemetry + Jaeger<br/>Prometheus + Grafana"]
    Worker -.->|"Metrics"| Obs
```

### Core Engineering Highlights
- **Full Wire Protocol v3 Parity (`internal/pgwire`, `internal/proxy`):** Transparently handles `SSLRequest` (optional TLS termination), `GSSENCRequest`, `CancelRequest`, `SCRAM-SHA-256` / `MD5` / `cleartext` / `trust` auth relay, Simple Query (`'Q'`), and Extended Query pipelines (`Parse`, `Bind`, `Describe`, `Execute`, `Sync`). On masked Extended Protocol portals, `pgveil` negotiates text result formats on `Bind` so strict drivers (`pgx/v5`, `psycopg3`, `JDBC`) never hit binary decoding errors ([ADR-003](docs/adr/ADR-003-extended-protocol-masking.md)).
- **PostgreSQL 17 AST Firewall (`internal/firewall`):** Embeds PostgreSQL's own C parser (`libpg_query`) to defeat bypasses that regex proxies miss — modifying CTEs (`WITH d AS (DELETE ...) SELECT * FROM d`), always-true tautologies (`WHERE 1=1`, `WHERE id=5 OR true`), multi-statement SQL injection, nested server escapes (`COALESCE(pg_read_file(...), '')`, `COPY TO PROGRAM`, `DO $$`, `SET ROLE`), and restricted tables hidden inside subqueries ([ADR-002](docs/adr/ADR-002-postgresql-ast-firewall.md)).
- **Zero-False-Positive Multi-Compliance PII Engine (`internal/pii`):** Built-in packs validated with real mathematical checksums so random numeric IDs are never corrupted:
  - **`kvkk`** (Türkiye): 11-digit **TCKN** mod-10 checksum, 26-char **TR IBAN** ISO 13616 Mod-97, 10-digit **VKN** tax ID checksum, Turkish mobile phones, email
  - **`gdpr`** (EU): **EU IBAN** Mod-97 (`DE`, `FR`, `GB`, `NL`, `ES`, `IT`, ...), email, international phones, IPv4
  - **`pci-dss`**: **Credit Cards** (Visa, Mastercard, Amex, Discover, Troy) with **Luhn + BIN** validation
  - **`hipaa`** (US): **US SSN** (SSA area/group/serial rules), email, phone
  - **`secrets`**: AWS access keys (`AKIA...`), GitHub tokens (`ghp_`, `github_pat_`), OpenAI keys (`sk-...`), JWTs, PEM private keys
  - **6 Masking Strategies:** `partial`, `redact`, `last4`, `hash` (HMAC-SHA256 deterministic **JOIN-preserving pseudonymization**), `fake`, and `null`.
- **Zero-Downtime Policy Hot-Reload:** Update `pgveil.yaml` live via `kill -HUP <pid>` or the Web Console's Policy Editor (`PUT /api/v1/policies/yaml`) with strict pre-swap schema validation.

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

> That translates to **625,000+ dynamically masked PII cells per second** on a single node with **sub-millisecond (`0.246 ms`) overhead** and **0 failed transactions** across 150,098 queries.

### 2. Go Core Microbenchmarks (`go test -bench=. -benchmem`)

| Benchmark | Latency / Op | Memory / Op | Allocs / Op |
|---|---:|---:|---:|
| `BenchmarkMaskCleanCellFastPath` (O(n) ASCII pre-filter) | **`13.54 ns`** | **`0 B`** | **`0`** |
| `BenchmarkMaskExplicitColumn` (TCKN partial mask) | **`86.96 ns`** | `272 B` | `3` |
| `BenchmarkMaskFreeTextWithPII` (all 5 compliance packs) | **`26.31 µs`** | `7,906 B` | `25` |
| `BenchmarkEvaluateAST` (PG17 C parser on multi-table JOIN) | **`50.35 µs`** | `8,992 B` | `188` |

### 3. `k6` Control Plane & End-to-End Wire Load Test (`benchmarks/k6/control_plane_load.js`)
30 concurrent VUs, 25 seconds, mixing AST+PII inspections and live PostgreSQL wire proxy executions:

| Metric | Measured Result |
|---|---:|
| Total Requests / Checks Passed | **25,699 requests** · **57,832 / 57,832 checks (`100.00%`)** |
| Error Rate (`http_req_failed`) | **`0.00%`** (0 failures, 0 PII leaks) |
| `/api/v1/inspect` (AST + 5-Pack PII Scan) | **p50 `274 µs`** · **p95 `696.8 µs`** |
| `/api/v1/playground/query` (Full TCP Wire Round-Trip) | **p50 `6.0 ms`** · **p95 `10.86 ms`** |

---

## Quick Start

### Option 1 — Full Enterprise Stack in 1 Command (Docker Compose)
Launches **PostgreSQL 16** (pre-seeded with synthetic e-commerce/fintech PII), **`pgveil` Proxy** (`:6432` wire + `:8088` Web Console), **Redpanda (Kafka)**, **`pgveil-audit-worker`**, **Jaeger**, **Prometheus**, and **Grafana** (pre-provisioned dashboard):

```bash
git clone https://github.com/duhanguler/pgveil.git
cd pgveil
docker compose up --build
```

- **Embedded Web Console & Live SQL Playground:** `http://localhost:8088`
- **PostgreSQL Wire Proxy:** `postgres://pgveil:pgveil_dev_password@localhost:6432/pgveil_demo?application_name=claude-mcp`
- **Grafana Dashboard:** `http://localhost:3000` (`admin` / `pgveil_grafana`)
- **Jaeger Distributed Traces:** `http://localhost:16686`
- **Prometheus Metrics:** `http://localhost:8088/metrics`

### Option 2 — Single Binary Against Any Existing PostgreSQL

```bash
make build
./bin/pgveil serve --config configs/pgveil.yaml
```

### Option 3 — CLI Static SQL & PII Policy Scanner (CI/CD Ready)

```bash
# Validate policy YAML in CI
./bin/pgveil validate --config configs/pgveil.yaml

# Test any SQL statement against the PostgreSQL 17 AST firewall (exits 2 if BLOCKED)
./bin/pgveil scan \
  --sql "WITH d AS (DELETE FROM orders WHERE 1=1 RETURNING *) SELECT * FROM d" \
  --profile ai_agent
```

### Option 4 — Protect Claude Desktop / Cursor MCP Postgres in 1 Line
See [`examples/mcp-claude/claude_desktop_config.json`](examples/mcp-claude/claude_desktop_config.json) and [`examples/python-agent/agent_demo.py`](examples/python-agent/agent_demo.py):

```json
{
  "mcpServers": {
    "postgres-zero-trust": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-postgres",
        "postgres://pgveil:pgveil_dev_password@127.0.0.1:6432/pgveil_demo?sslmode=disable&application_name=claude-mcp"
      ]
    }
  }
}
```

### Option 5 — Production Kubernetes Deployment (Helm)

```bash
helm lint deploy/helm/pgveil
helm upgrade --install pgveil deploy/helm/pgveil \
  --namespace database-security --create-namespace \
  --set upstream.addr=postgres-primary.database.svc.cluster.local:5432 \
  --set security.maskingSecret="$PGVEIL_MASKING_SECRET"
```

Includes non-root `securityContext`, read-only root filesystem, readiness/liveness probes, `HorizontalPodAutoscaler`, `PodDisruptionBudget`, `NetworkPolicy`, and the dedicated `pgveil-audit-worker` Deployment.

---

## Architecture Decision Records (ADRs)

- [ADR-001: PostgreSQL Wire Protocol v3 Proxy vs. DB Extensions or ORM Middleware](docs/adr/ADR-001-wire-protocol-proxy.md)
- [ADR-002: Real PostgreSQL 17 AST Parsing vs. Regex SQL Filtering](docs/adr/ADR-002-postgresql-ast-firewall.md)
- [ADR-003: Wire-Level Dynamic Masking & Extended Protocol Format Negotiation](docs/adr/ADR-003-extended-protocol-masking.md)
- [ADR-004: Non-Blocking Kafka Audit Pipeline & Synchronous HITL Wire Holds](docs/adr/ADR-004-async-kafka-and-live-hitl.md)

---

## Project Layout

```text
pgveil/
├── cmd/
│   ├── pgveil/              # Single-binary wire proxy + embedded Web Console CLI (serve, validate, scan)
│   └── audit-worker/        # Kafka consumer group worker (batch pgx sink, DLQ, burst anomaly alerts)
├── internal/
│   ├── pgwire/              # PostgreSQL Wire Protocol v3 binary framing (Simple & Extended)
│   ├── firewall/            # PostgreSQL 17 C AST SQL firewall (libpg_query)
│   ├── pii/                 # Zero-false-positive GDPR, KVKK, PCI-DSS, HIPAA & Secrets masker
│   ├── proxy/               # Bidirectional wire proxy, row-exfiltration cap & live HITL hold
│   ├── hitl/                # Synchronous approval coordinator with SSE live notifications
│   ├── policy/              # Declarative YAML RBAC profiles + SIGHUP/API hot-reload
│   ├── events/              # Non-blocking audit ring buffer, SSE hub & franz-go Kafka producer
│   ├── telemetry/           # OpenTelemetry OTLP tracing + Prometheus histograms/counters
│   ├── api/                 # Control Plane REST/SSE API + live wire SQL Playground
│   └── webui/               # //go:embed compiled React + TypeScript Control Plane
├── web/                     # React 18 + TypeScript + Vite + Tailwind Console source
├── configs/pgveil.yaml      # Declarative profiles (ai_agent, analyst, developer, admin)
├── deploy/
│   ├── docker/              # Postgres demo seed, Prometheus config & Grafana dashboard JSON
│   └── helm/pgveil/         # Production Kubernetes Helm chart (HPA, PDB, NetworkPolicy)
├── benchmarks/              # Reproducible pgbench comparison & k6 load test suite
├── examples/                # Claude/Cursor MCP & Python psycopg AI agent integrations
└── docs/adr/                # Architecture Decision Records
```

---

## Roadmap

- [ ] Built-in connection multiplexing / transaction pooling mode
- [ ] Optional Slack & Microsoft Teams interactive approval buttons for live HITL holds
- [ ] Additional regional compliance packs (Brazilian CPF/CNPJ, UK NINO, Indian Aadhaar)
- [ ] Automated PII column schema discovery & policy drift alerts
- [ ] Upstream mTLS client certificate authentication

---

## Contributing & License

Contributions, regional compliance packs, and AST security test cases are very welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

Licensed under the **Apache License 2.0** — see [LICENSE](LICENSE).
