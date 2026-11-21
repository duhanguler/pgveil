package demo

import "fmt"

// BuildDemoConfigYAML returns a self-contained, validated pgveil YAML configuration
// wired to the embedded in-memory demo PostgreSQL server so `pgveil demo` runs cleanly
// from any directory without requiring configs/pgveil.yaml on disk.
func BuildDemoConfigYAML(listenAddr, adminAddr, upstreamAddr string) []byte {
	return []byte(fmt.Sprintf(`# pgveil zero-config interactive demo configuration (ephemeral in-memory PostgreSQL backend)
server:
  listen_addr: %q
  admin_addr: %q
  upstream_addr: %q
  upstream_user: "pgveil"
  upstream_password: ""
  upstream_database: "pgveil_demo"
  tls:
    enabled: false
  upstream_tls:
    enabled: false

notifications:
  webhook_url: ""

security:
  masking_secret: "pgveil-demo-ephemeral-hmac-secret"
  hitl_default_timeout: "60s"
  compliance_packs:
    - gdpr
    - kvkk
    - pci-dss
    - hipaa
    - secrets

telemetry:
  service_name: "pgveil-demo"
  prometheus_enabled: true
  otel_enabled: false

kafka:
  enabled: false

default_profile: "analyst"

profiles:
  - name: "ai_agent"
    description: "Zero-trust sandbox for AI SQL agents, Claude Code, Cursor, and MCP Postgres servers."
    mode: "enforce"
    match:
      application_names: ["ai_agent", "claude-mcp*", "cursor*", "langchain*", "mcp-postgres*"]
      users: ["ai_agent", "mcp_readonly"]
    firewall:
      allow_statements: ["SELECT", "EXPLAIN", "SHOW"]
      block_ddl: true
      block_multi_statement: true
      block_write_without_where: true
      block_dangerous_functions: true
      block_system_catalogs: true
      block_pii_inference: true
      protected_columns: ["tckn", "national_id", "ssn", "iban", "card_number", "credit_card", "secret_value", "password_hash"]
      require_hitl_statements: ["UPDATE", "DELETE", "INSERT"]
      hitl_mode: "hold"
      hitl_timeout: "60s"
      denied_tables: ["api_secrets", "pg_shadow", "pg_authid", "pg_roles"]
      max_rows: 25
      max_rows_action: "truncate"
    masking:
      enabled: true
      auto_detect_pii: true
      compliance_packs: ["gdpr", "kvkk", "pci-dss", "hipaa", "secrets"]
      column_rules:
        - column: "email"
          strategy: "partial"
        - column: "full_name"
          strategy: "hash"
        - column: "phone"
          strategy: "partial"
        - column: "tckn"
          strategy: "partial"
        - column: "national_id"
          strategy: "partial"
        - column: "ssn"
          strategy: "redact"
        - column: "iban"
          strategy: "partial"
        - column: "card_number"
          strategy: "last4"
        - column: "credit_card"
          strategy: "last4"
        - column: "secret_value"
          strategy: "redact"
        - column: "api_key"
          strategy: "redact"
        - column: "password_hash"
          strategy: "redact"

  - name: "tenant_tr"
    description: "AST-level Virtual Row-Level Security (RLS) tenant profile: enforces city='Istanbul' & currency='TRY' automatically on wire."
    mode: "enforce"
    match:
      application_names: ["tenant_tr*", "tr-regional*"]
      users: ["tenant_tr"]
    firewall:
      allow_statements: ["SELECT", "EXPLAIN", "SHOW"]
      block_ddl: true
      block_multi_statement: true
      block_write_without_where: true
      block_dangerous_functions: true
      block_system_catalogs: true
      block_pii_inference: true
      protected_columns: ["tckn", "national_id", "ssn", "iban", "card_number", "credit_card", "secret_value"]
      require_hitl_statements: ["UPDATE", "DELETE"]
      hitl_mode: "hold"
      hitl_timeout: "60s"
      denied_tables: ["api_secrets", "pg_shadow", "pg_authid", "pg_roles"]
      row_filters:
        - table: "customers"
          predicate: "city = 'Istanbul'"
        - table: "orders"
          predicate: "currency = 'TRY'"
      max_rows: 100
      max_rows_action: "truncate"
    masking:
      enabled: true
      auto_detect_pii: true
      compliance_packs: ["gdpr", "kvkk", "pci-dss", "hipaa", "secrets"]
      column_rules:
        - column: "email"
          strategy: "partial"
        - column: "full_name"
          strategy: "hash"
        - column: "phone"
          strategy: "partial"
        - column: "tckn"
          strategy: "partial"
        - column: "iban"
          strategy: "partial"
        - column: "card_number"
          strategy: "last4"
        - column: "secret_value"
          strategy: "redact"

  - name: "analyst"
    description: "Read-only BI & analytics profile with JOIN-preserving pseudonymization and row budgets."
    match:
      application_names: ["analyst*", "metabase*", "superset*", "dbeaver*"]
      users: ["analyst", "bi_reader"]
    firewall:
      allow_statements: ["SELECT", "EXPLAIN", "SHOW"]
      block_ddl: true
      block_multi_statement: true
      block_write_without_where: true
      block_dangerous_functions: true
      block_system_catalogs: true
      denied_tables: ["api_secrets", "pg_shadow", "pg_authid"]
      max_rows: 500
      max_rows_action: "truncate"
    masking:
      enabled: true
      auto_detect_pii: true
      compliance_packs: ["gdpr", "kvkk", "pci-dss", "hipaa", "secrets"]
      column_rules:
        - column: "email"
          strategy: "hash"
        - column: "phone"
          strategy: "partial"
        - column: "tckn"
          strategy: "hash"
        - column: "ssn"
          strategy: "redact"
        - column: "iban"
          strategy: "partial"
        - column: "card_number"
          strategy: "last4"
        - column: "secret_value"
          strategy: "redact"

  - name: "developer"
    description: "Staging/production debugging profile: masked PII, safe scoped writes with HITL approval."
    match:
      application_names: ["developer*", "dev_*", "datagrip*"]
      users: ["developer"]
    firewall:
      allow_statements: ["SELECT", "EXPLAIN", "SHOW", "INSERT", "UPDATE"]
      block_ddl: true
      block_multi_statement: true
      block_write_without_where: true
      block_dangerous_functions: true
      block_system_catalogs: false
      require_hitl_statements: ["DELETE", "UPDATE"]
      hitl_mode: "hold"
      hitl_timeout: "60s"
      denied_tables: ["api_secrets"]
      max_rows: 2000
      max_rows_action: "truncate"
    masking:
      enabled: true
      auto_detect_pii: true
      compliance_packs: ["pci-dss", "kvkk", "secrets"]
      column_rules:
        - column: "tckn"
          strategy: "partial"
        - column: "iban"
          strategy: "partial"
        - column: "card_number"
          strategy: "last4"
        - column: "secret_value"
          strategy: "redact"

  - name: "admin"
    description: "Break-glass DBA profile: full unmasked access, audited asynchronously with DDL/multi-statement logging."
    match:
      application_names: ["admin*", "pgveil-admin*"]
      users: ["admin", "dba"]
    firewall:
      allow_statements: ["*"]
      block_ddl: false
      block_multi_statement: false
      block_write_without_where: false
      block_dangerous_functions: false
      block_system_catalogs: false
      denied_tables: []
      max_rows: 0
    masking:
      enabled: false
      auto_detect_pii: false
`, listenAddr, adminAddr, upstreamAddr))
}
