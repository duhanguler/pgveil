# Contributing to pgveil

Thank you for your interest in contributing to **pgveil**!

## Local Development Setup

Prerequisites:
- Go 1.26+ (with C compiler for `libpg_query` AST parser)
- Node.js 20+ (only if modifying the embedded React Web Console under `web/`)
- PostgreSQL 16+ or Docker Compose

```bash
# 1. Run full race-enabled unit & wire integration tests
make test

# 2. Run PII & AST microbenchmarks
make bench

# 3. Build embedded Web Console & Go binaries
make build

# 4. Launch full stack (PostgreSQL 16 + pgveil + Redpanda + Audit Worker + Jaeger + Prometheus + Grafana)
make docker-up
```

## Contribution Guidelines

1. **Zero-False-Positive PII Detectors:** New regional compliance packs (e.g., Brazilian CPF, Indian Aadhaar, UK NINO, German Steuer-ID) should implement mathematical checksum validation whenever the standard defines one, along with positive and negative test fixtures in `internal/pii/pii_test.go`.
2. **AST Firewall Rules:** New security rules must operate on the parsed PostgreSQL AST in `internal/firewall/firewall.go` rather than raw string regexes, and must include bypass-attempt tests (CTEs, subqueries, tautologies).
3. **Wire Protocol Safety:** Changes to `internal/pgwire` or `internal/proxy` must pass `go test -race ./...` and preserve both Simple Query and Extended Query protocol compatibility.
4. **Pull Requests:** Keep PRs focused, update relevant ADRs in `docs/adr/` if introducing architectural trade-offs, and ensure `make test` and `make helm-lint` pass cleanly.
