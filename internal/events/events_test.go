package events

import (
	"testing"
	"time"

	"github.com/duhanguler/pgveil/internal/policy"
)

func TestRingBufferSummaryAndSSE(t *testing.T) {
	bus := NewBus(3, policy.KafkaConfig{}, nil)
	defer bus.Close()

	ch, unsub := bus.Subscribe()
	defer unsub()

	bus.Publish(AuditEvent{
		RoleProfile:     "ai_agent",
		StatementType:   "SELECT",
		Decision:        "MASKED",
		RowsReturned:    5,
		PIIFieldsMasked: 10,
		PIIEntities:     map[string]int{"tckn": 5, "tr_iban": 5},
		ProxyOverheadUs: 120,
	})
	bus.Publish(AuditEvent{
		RoleProfile:     "ai_agent",
		StatementType:   "DROP",
		Decision:        "BLOCKED",
		PolicyRule:      "block_ddl",
		ProxyOverheadUs: 40,
	})
	bus.Publish(AuditEvent{
		RoleProfile:     "analyst",
		StatementType:   "SELECT",
		Decision:        "TRUNCATED",
		RowsReturned:    500,
		RowsTruncated:   true,
		ProxyOverheadUs: 200,
	})
	// 4th event evicts 1st from bounded ring of capacity 3
	bus.Publish(AuditEvent{
		RoleProfile:     "admin",
		StatementType:   "SELECT",
		Decision:        "ALLOW",
		RowsReturned:    2,
		ProxyOverheadUs: 40,
	})

	select {
	case ev := <-ch:
		if ev.Decision != "MASKED" {
			t.Fatalf("expected first streamed event MASKED, got %s", ev.Decision)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SSE subscriber event")
	}

	recent := bus.Recent(10, "", "")
	if len(recent) != 3 {
		t.Fatalf("expected bounded ring len=3, got %d", len(recent))
	}
	if recent[0].RoleProfile != "admin" {
		t.Fatalf("expected newest-first order, got %s", recent[0].RoleProfile)
	}

	sum := bus.Summary()
	if sum.TotalQueries != 4 || sum.BlockedQueries != 1 || sum.TotalPIIFields != 10 || sum.TruncatedQueries != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	if sum.AvgProxyOverhead != 100.0 {
		t.Fatalf("expected avg overhead 100.0us, got %.2f", sum.AvgProxyOverhead)
	}
}
