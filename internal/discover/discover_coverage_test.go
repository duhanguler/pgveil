package discover

import (
	"context"
	"strings"
	"testing"

	"github.com/duhanguler/pgveil/internal/demo"
	"github.com/duhanguler/pgveil/internal/pii"
)

func TestDiscoverScanLiveAndHelpers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := demo.NewServer()
	addr, err := srv.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("demo start: %v", err)
	}
	dsn := "postgres://pgveil@" + addr + "/pgveil_demo?sslmode=disable"

	rep1, err := Scan(ctx, dsn, 0, "sec")
	if err != nil || rep1.FindingsCount < 10 {
		t.Fatalf("Scan(0): err=%v count=%d", err, rep1.FindingsCount)
	}
	rep2, err := Scan(ctx, dsn, 999, "sec")
	if err != nil || rep2.TablesScanned != 5 {
		t.Fatalf("Scan(999): err=%v tables=%d", err, rep2.TablesScanned)
	}

	if _, err := Scan(ctx, "postgres://invalid-host-that-does-not-exist:1/x?connect_timeout=1", 10, "s"); err == nil {
		t.Fatal("expected error for bad DSN")
	}

	for _, col := range []string{"password", "tckn", "ssn", "card_number", "iban", "email", "phone", "full_name", "plain"} {
		heuristicFromColumnName(col)
	}
	packs := packsForEntities(map[string]int{
		string(pii.EntityTCKN):         1,
		string(pii.EntityEUIBAN):       1,
		string(pii.EntityEmail):        1,
		string(pii.EntityCreditCard):   1,
		string(pii.EntityUSSSN):        1,
		string(pii.EntityBRCPF):        1,
		string(pii.EntityCASIN):        1,
		string(pii.EntityUKNINO):       1,
		string(pii.EntityAWSAccessKey): 1,
		"secret_column":                1,
		"person_name":                  1,
	})
	if len(packs) < 8 {
		t.Fatalf("expected all 8 packs resolved, got %v", packs)
	}

	if s, r := recommendStrategyAndRisk(map[string]int{string(pii.EntityEmail): 1}, "", ""); s != pii.StrategyPartial || r != "HIGH" {
		t.Fatalf("unexpected email recommendation: %s/%s", s, r)
	}
	if s, r := recommendStrategyAndRisk(map[string]int{string(pii.EntityIPv4): 1}, "", ""); s != pii.StrategyPartial || r != "MEDIUM" {
		t.Fatalf("unexpected default recommendation: %s/%s", s, r)
	}

	if _, err := GenerateStarterConfig(nil, dsn); err == nil {
		t.Fatal("expected error for nil report")
	}
	emptyYml, err := GenerateStarterConfig(&Report{Database: "empty_db"}, "not-a-valid-url")
	if err != nil || !strings.Contains(emptyYml, "column_rules: []") {
		t.Fatalf("unexpected empty starter config: err=%v yml=%s", err, emptyYml)
	}
}
