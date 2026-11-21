#!/usr/bin/env bash
set -euo pipefail

# Compares direct PostgreSQL 16 throughput & latency against pgveil Wire Protocol v3 Proxy
# across passthrough (admin), AST firewall + explicit column masking (analyst), and
# full zero-trust AI agent mode (AST + auto-PII + row cap).

PG_HOST="${PG_HOST:-127.0.0.1}"
PG_PORT="${PG_PORT:-5432}"
PROXY_PORT="${PROXY_PORT:-6432}"
PG_USER="${PG_USER:-pgveil}"
PG_DB="${PG_DB:-pgveil_demo}"
DURATION="${DURATION:-10}"
CLIENTS="${CLIENTS:-8}"
THREADS="${THREADS:-4}"

export PGPASSWORD="${PGPASSWORD:-pgveil_dev_password}"

SCRIPT_FILE="$(mktemp)"
cat <<'EOF' > "$SCRIPT_FILE"
SELECT id, full_name, email, phone, tckn, iban, city FROM customers WHERE id <= 5 ORDER BY id;
EOF
trap 'rm -f "$SCRIPT_FILE"' EXIT

echo "=== 1. Direct PostgreSQL (${PG_HOST}:${PG_PORT}) ==="
pgbench -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" \
  -n -M simple -c "$CLIENTS" -j "$THREADS" -T "$DURATION" -f "$SCRIPT_FILE" "$PG_DB"

echo ""
echo "=== 2. Through pgveil — admin profile (AST audit only, unmasked) ==="
PGAPPNAME=admin pgbench -h "$PG_HOST" -p "$PROXY_PORT" -U "$PG_USER" \
  -n -M simple -c "$CLIENTS" -j "$THREADS" -T "$DURATION" -f "$SCRIPT_FILE" "$PG_DB"

echo ""
echo "=== 3. Through pgveil — ai_agent profile (AST firewall + dynamic KVKK/GDPR wire masking) ==="
PGAPPNAME=ai_agent pgbench -h "$PG_HOST" -p "$PROXY_PORT" -U "$PG_USER" \
  -n -M simple -c "$CLIENTS" -j "$THREADS" -T "$DURATION" -f "$SCRIPT_FILE" "$PG_DB"
