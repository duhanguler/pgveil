package discover_test

import (
	"strings"
	"testing"

	"github.com/duhanguler/pgveil/internal/discover"
	"github.com/duhanguler/pgveil/internal/pii"
	"github.com/duhanguler/pgveil/internal/policy"
)

func TestGenerateStarterConfig_RoundTripValidates(t *testing.T) {
	report := &discover.Report{
		Database:       "prod_fintech",
		TablesScanned:  5,
		ColumnsScanned: 32,
		FindingsCount:  3,
		Findings: []discover.Finding{
			{
				Schema:              "public",
				Table:               "customers",
				Column:              "tckn",
				CompliancePacks:     []string{"kvkk"},
				RiskLevel:           "CRITICAL",
				RecommendedStrategy: pii.StrategyPartial,
			},
			{
				Schema:              "public",
				Table:               "customers",
				Column:              "email",
				CompliancePacks:     []string{"gdpr", "kvkk"},
				RiskLevel:           "HIGH",
				RecommendedStrategy: pii.StrategyPartial,
			},
			{
				Schema:              "public",
				Table:               "payments",
				Column:              "card_number",
				CompliancePacks:     []string{"pci-dss"},
				RiskLevel:           "CRITICAL",
				RecommendedStrategy: pii.StrategyLast4,
			},
		},
		RecommendedTables: []string{"api_secrets"},
	}

	dsn := "postgres://appuser:s3cr3t@db.internal:5433/prod_fintech?sslmode=require"
	yml, err := discover.GenerateStarterConfig(report, dsn)
	if err != nil {
		t.Fatalf("GenerateStarterConfig failed: %v", err)
	}

	mgr, err := policy.LoadBytes([]byte(yml))
	if err != nil {
		t.Fatalf("generated starter config failed policy validation: %v\nYAML:\n%s", err, yml)
	}
	cfg := mgr.Config()
	if cfg.Server.UpstreamAddr != "db.internal:5433" {
		t.Fatalf("expected upstream db.internal:5433, got %q", cfg.Server.UpstreamAddr)
	}
	if !cfg.Server.UpstreamTLS.Enabled {
		t.Fatal("expected upstream_tls.enabled=true for sslmode=require")
	}
	if !strings.HasPrefix(cfg.Security.MaskingSecret, "pgveil_") || len(cfg.Security.MaskingSecret) < 40 {
		t.Fatalf("expected cryptographic masking secret, got %q", cfg.Security.MaskingSecret)
	}

	ai, ok := mgr.GetProfileByName("ai_agent")
	if !ok {
		t.Fatal("missing ai_agent profile")
	}
	if len(ai.Firewall.ProtectedColumns) != 3 {
		t.Fatalf("expected 3 protected columns, got %v", ai.Firewall.ProtectedColumns)
	}
	if ai.ColumnStrategy("card_number") != pii.StrategyLast4 {
		t.Fatalf("expected last4 for card_number, got %q", ai.ColumnStrategy("card_number"))
	}
}
