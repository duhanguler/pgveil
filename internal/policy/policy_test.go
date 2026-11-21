package policy

import (
	"testing"

	"github.com/duhanguler/pgveil/internal/pii"
)

func TestLoadAndMatchProfiles(t *testing.T) {
	mgr, err := LoadFile("../../configs/pgveil.yaml")
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}

	cases := []struct {
		user    string
		appName string
		want    string
	}{
		{"pgveil", "claude-mcp-server", "ai_agent"},
		{"pgveil", "cursor-agent", "ai_agent"},
		{"ai_agent", "psql", "ai_agent"},
		{"pgveil", "metabase-prod", "analyst"},
		{"developer", "pgx", "developer"},
		{"admin", "psql", "admin"},
		{"unknown_user", "unknown_app", "analyst"}, // default_profile
	}
	for _, tc := range cases {
		got := mgr.MatchProfile(tc.user, tc.appName)
		if got.Name != tc.want {
			t.Errorf("MatchProfile(%q, %q) = %q, want %q", tc.user, tc.appName, got.Name, tc.want)
		}
	}

	ai, ok := mgr.GetProfileByName("ai_agent")
	if !ok {
		t.Fatal("ai_agent profile not found")
	}
	if ai.ColumnStrategy("TCKN") != pii.StrategyPartial {
		t.Errorf("expected case-insensitive column strategy partial for TCKN, got %q", ai.ColumnStrategy("TCKN"))
	}
	if !ai.EnabledEntities()[pii.EntityTCKN] || !ai.EnabledEntities()[pii.EntityCreditCard] {
		t.Errorf("expected KVKK and PCI-DSS entities enabled for ai_agent")
	}
}

func TestHotReloadValidation(t *testing.T) {
	mgr, err := LoadFile("../../configs/pgveil.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.ReloadBytes([]byte("profiles: []\n")); err == nil {
		t.Fatal("expected invalid YAML with 0 profiles to fail hot reload")
	}
	raw, v1 := mgr.RawYAML()
	if err := mgr.ReloadBytes([]byte(raw)); err != nil {
		t.Fatalf("valid hot reload failed: %v", err)
	}
	_, v2 := mgr.RawYAML()
	if v2 != v1+1 {
		t.Fatalf("expected version increment from %d to %d, got %d", v1, v1+1, v2)
	}
}
