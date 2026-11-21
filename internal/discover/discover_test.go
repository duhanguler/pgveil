package discover

import (
	"strings"
	"testing"

	"github.com/duhanguler/pgveil/internal/pii"
)

func TestBuildRecommendedYAML(t *testing.T) {
	findings := []Finding{
		{
			Table:               "customers",
			Column:              "tckn",
			RiskLevel:           "CRITICAL",
			RecommendedStrategy: pii.StrategyPartial,
			CompliancePacks:     []string{"kvkk"},
		},
		{
			Table:               "payments",
			Column:              "card_number",
			RiskLevel:           "CRITICAL",
			RecommendedStrategy: pii.StrategyLast4,
			CompliancePacks:     []string{"pci-dss"},
		},
		{
			Table:               "support_tickets",
			Column:              "body",
			RiskLevel:           "CRITICAL",
			RecommendedStrategy: pii.StrategyRedact,
			CompliancePacks:     []string{"secrets", "kvkk"},
		},
	}

	yml := buildRecommendedYAML(findings, []string{"api_secrets"})
	if !strings.Contains(yml, "block_pii_inference: true") {
		t.Fatalf("expected block_pii_inference in generated YAML:\n%s", yml)
	}
	if !strings.Contains(yml, "column: tckn") || !strings.Contains(yml, "strategy: last4") {
		t.Fatalf("expected tckn & card_number rules in generated YAML:\n%s", yml)
	}
	if strings.Contains(yml, "column: body") {
		t.Fatalf("expected free-text column 'body' to be handled by auto_detect_pii, not explicit column_rules:\n%s", yml)
	}
	if !strings.Contains(yml, "api_secrets") {
		t.Fatalf("expected denied_tables api_secrets:\n%s", yml)
	}
}
