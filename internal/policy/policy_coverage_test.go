package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPolicyEnvOverridesDefaultsRedactionAndReloadFile(t *testing.T) {
	t.Setenv("PGVEIL_LISTEN_ADDR", ":7432")
	t.Setenv("PGVEIL_ADMIN_ADDR", ":9088")
	t.Setenv("PGVEIL_UPSTREAM_ADDR", "db.local:5432")
	t.Setenv("PGVEIL_UPSTREAM_USER", "envuser")
	t.Setenv("PGVEIL_UPSTREAM_PASSWORD", "envpass!@#")
	t.Setenv("PGVEIL_UPSTREAM_DATABASE", "envdb")
	t.Setenv("PGVEIL_MASKING_SECRET", "env-hmac-secret-123")
	t.Setenv("PGVEIL_ADMIN_TOKEN", "env-admin-token")
	t.Setenv("PGVEIL_KAFKA_ENABLED", "true")
	t.Setenv("PGVEIL_KAFKA_BROKERS", "k1:9092, k2:9092")
	t.Setenv("PGVEIL_OTEL_ENABLED", "true")
	t.Setenv("PGVEIL_OTEL_ENDPOINT", "otel:4317")
	t.Setenv("PGVEIL_ALERT_WEBHOOK", "https://hooks.example.test/alert")
	t.Setenv("PGVEIL_UPSTREAM_TLS", "true")

	raw := `
server:
  upstream_password: "yaml_password"
security:
  masking_secret: "yaml_secret"
  admin_token: "yaml_token"
notifications:
  webhook_url: "https://hooks.example.test/orig"
default_profile: "shadow"
profiles:
  - name: "shadow"
    mode: "audit"
    match:
      application_names: ["shadow*"]
      users: ["shadow_user"]
    firewall:
      allow_statements: ["SELECT"]
      hitl_timeout: "15s"
      rate_limit:
        loop_window: "20s"
      row_filters:
        - table: "customers"
          predicate: "COALESCE(city, 'Istanbul') = 'Istanbul' AND (tier IS NOT NULL) AND (active IS TRUE) AND id::text != '' AND CASE WHEN tier = 'vip' THEN true ELSE false END AND city = ANY(ARRAY['Istanbul','Ankara']) AND lower(city) IN ('istanbul','ankara')"
    masking:
      enabled: true
      column_rules:
        - column: "email"
          strategy: "partial"
`
	tmp := filepath.Join(t.TempDir(), "pgveil.yaml")
	if err := os.WriteFile(tmp, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := LoadFile(tmp)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	cfg := mgr.Config()
	if cfg.Server.ListenAddr != ":7432" || cfg.Server.AdminAddr != ":9088" || !cfg.Kafka.Enabled || len(cfg.Kafka.Brokers) != 2 || !cfg.Telemetry.OTelEnabled || !cfg.Server.UpstreamTLS.Enabled {
		t.Fatalf("env overrides not applied: %+v", cfg)
	}

	var nilProf *RoleProfile
	if nilProf.IsAuditOnly() || nilProf.ColumnStrategy("email") != "" || nilProf.EnabledEntities() != nil || nilProf.HITLTimeoutDuration(10*time.Second) != 10*time.Second || nilProf.HITLTimeoutDuration(0) != 60*time.Second {
		t.Fatal("nil RoleProfile helpers failed")
	}

	p, ok := mgr.GetProfileByName("shadow")
	if !ok || !p.IsAuditOnly() {
		t.Fatal("expected shadow profile in audit mode")
	}
	if p.Firewall.LoopWindowDuration() != 20*time.Second {
		t.Fatalf("expected 20s loop window, got %v", p.Firewall.LoopWindowDuration())
	}
	if p.HITLTimeoutDuration(0) != 15*time.Second {
		t.Fatalf("expected 15s HITL timeout, got %v", p.HITLTimeoutDuration(0))
	}
	if mgr.Masker() == nil {
		t.Fatal("expected non-nil masker")
	}

	redacted, ver := mgr.RedactedYAML()
	if ver != 1 || strings.Contains(redacted, "yaml_password") || strings.Contains(redacted, "yaml_secret") || !strings.Contains(redacted, RedactedPlaceholder) {
		t.Fatalf("RedactedYAML leaked secret or missing placeholder: %s", redacted)
	}
	if err := mgr.ReloadBytes([]byte(redacted)); err != nil {
		t.Fatalf("ReloadBytes with redacted placeholders: %v", err)
	}
	if err := mgr.ReloadFile(); err != nil {
		t.Fatalf("ReloadFile: %v", err)
	}

	t.Setenv("PGVEIL_KAFKA_ENABLED", "false")
	if _, err := LoadBytes([]byte(raw)); err != nil {
		t.Fatalf("LoadBytes kafka=false: %v", err)
	}

	dsn1 := BuildDSN("0.0.0.0:6432", "u:ser", "p@ss/w", "mydb", "app", true)
	if !strings.Contains(dsn1, "127.0.0.1:6432") || !strings.Contains(dsn1, "sslmode=require") {
		t.Fatalf("unexpected dsn1: %s", dsn1)
	}
	dsn2 := BuildDSN(":6432", "onlyuser", "", "mydb", "", false)
	if !strings.Contains(dsn2, "127.0.0.1:6432") || !strings.Contains(dsn2, "sslmode=disable") {
		t.Fatalf("unexpected dsn2: %s", dsn2)
	}

	memMgr, err := LoadBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := memMgr.ReloadFile(); err == nil {
		t.Fatal("expected ReloadFile error for in-memory manager")
	}
}

func TestPolicyValidationErrors(t *testing.T) {
	if _, err := LoadFile("/nonexistent/path/pgveil.yaml"); err == nil {
		t.Fatal("expected read error")
	}
	cases := []struct {
		name string
		yml  string
	}{
		{"invalid_yaml", "profiles: ["},
		{"no_profiles", "default_profile: a\nprofiles: []"},
		{"empty_name", "profiles:\n  - name: \"\""},
		{"dup_name", "profiles:\n  - name: a\n  - name: a"},
		{"bad_mode", "profiles:\n  - name: a\n    mode: invalid"},
		{"bad_max_rows_action", "profiles:\n  - name: a\n    firewall:\n      max_rows_action: explode"},
		{"bad_hitl_mode", "profiles:\n  - name: a\n    firewall:\n      hitl_mode: magic"},
		{"bad_default_profile", "default_profile: missing\nprofiles:\n  - name: a"},
		{"empty_rf_table", "profiles:\n  - name: a\n    firewall:\n      row_filters:\n        - table: \"\"\n          predicate: \"id = 1\""},
		{"nul_rf_pred", "profiles:\n  - name: a\n    firewall:\n      row_filters:\n        - table: customers\n          predicate: \"id = 1\\0\""},
		{"extra_clause_rf", "profiles:\n  - name: a\n    firewall:\n      row_filters:\n        - table: customers\n          predicate: \"id = 1 LIMIT 5\""},
		{"subquery_in_case", "profiles:\n  - name: a\n    firewall:\n      row_filters:\n        - table: customers\n          predicate: \"CASE WHEN id IN (SELECT 1) THEN true ELSE false END\""},
		{"subquery_in_coalesce", "profiles:\n  - name: a\n    firewall:\n      row_filters:\n        - table: customers\n          predicate: \"COALESCE((SELECT 1), 1) = 1\""},
		{"subquery_in_nulltest", "profiles:\n  - name: a\n    firewall:\n      row_filters:\n        - table: customers\n          predicate: \"(SELECT 1) IS NOT NULL\""},
		{"subquery_in_booltest", "profiles:\n  - name: a\n    firewall:\n      row_filters:\n        - table: customers\n          predicate: \"(EXISTS (SELECT 1)) IS TRUE\""},
		{"subquery_in_typecast", "profiles:\n  - name: a\n    firewall:\n      row_filters:\n        - table: customers\n          predicate: \"(SELECT 1)::int = 1\""},
		{"subquery_in_func", "profiles:\n  - name: a\n    firewall:\n      row_filters:\n        - table: customers\n          predicate: \"lower((SELECT 'a')) = 'a'\""},
		{"subquery_in_array", "profiles:\n  - name: a\n    firewall:\n      row_filters:\n        - table: customers\n          predicate: \"id = ANY(ARRAY[(SELECT 1)])\""},
		{"subquery_in_list", "profiles:\n  - name: a\n    firewall:\n      row_filters:\n        - table: customers\n          predicate: \"id IN ((SELECT 1), 2)\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadBytes([]byte(tc.yml)); err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}
}
