package events

import (
	"strings"
	"testing"

	"github.com/duhanguler/pgveil/internal/policy"
)

func TestBusRingBufferFiltersAndSubscriptions(t *testing.T) {
	b := NewBus(2, policy.KafkaConfig{}, nil)
	defer b.Close()

	ch, unsub := b.Subscribe()

	longSQL := "SELECT '" + strings.Repeat("ş", 600) + "'"
	b.Publish(AuditEvent{
		RoleProfile:         "ai_agent",
		Decision:            "MASKED",
		PolicyRule:          "policy_allow",
		RawSQLPreview:       longSQL,
		RewrittenSQLPreview: longSQL,
		RLSRewritten:        true,
		RLSRulesApplied:     []string{"customers: city = 'Istanbul'"},
		RowsReturned:        5,
		PIIFieldsMasked:     3,
		PIIEntities:         map[string]int{"tckn": 2, "email": 1},
		ProxyOverheadUs:     100,
	})
	ev1 := <-ch
	if len([]rune(ev1.RawSQLPreview)) > 505 || len([]rune(ev1.RewrittenSQLPreview)) > 505 {
		t.Fatalf("expected truncated UTF-8 SQL previews")
	}

	b.Publish(AuditEvent{
		RoleProfile:     "ai_agent",
		Decision:        "BLOCKED",
		PolicyRule:      "block_ddl",
		RawSQLPreview:   "DROP TABLE orders",
		ProxyOverheadUs: 40,
	})
	<-ch

	// 3rd event wraps capacity=2 ring buffer
	b.Publish(AuditEvent{
		RoleProfile:     "analyst",
		Decision:        "TRUNCATED",
		PolicyRule:      "policy_allow",
		RawSQLPreview:   "SELECT * FROM customers",
		RowsReturned:    25,
		RowsTruncated:   true,
		ProxyOverheadUs: 80,
	})
	<-ch
	unsub()

	b.Publish(AuditEvent{
		RoleProfile: "ai_agent",
		Decision:    "HITL_DENIED",
		PolicyRule:  "require_hitl_update",
	})

	all := b.Recent(10, "", "")
	if len(all) != 2 {
		t.Fatalf("expected capacity=2 ring buffer, got %d", len(all))
	}
	if len(b.Recent(0, "HITL_DENIED", "ai_agent")) != 1 {
		t.Fatalf("expected 1 filtered HITL_DENIED event")
	}
	if len(b.Recent(10, "BLOCKED", "analyst")) != 0 {
		t.Fatalf("expected 0 mismatched events")
	}

	sum := b.Summary()
	if sum.TotalQueries != 4 || sum.BlockedQueries != 2 || sum.MaskedQueries != 1 || sum.TruncatedQueries != 1 || sum.HITLTriggered != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	if sum.PIIByEntity["tckn"] != 2 || sum.BlockedByRule["block_ddl"] != 1 {
		t.Fatalf("unexpected breakdown maps: %+v", sum)
	}

	// Idempotent double close
	b.Close()
	b.Close()

	// Default capacity + Kafka producer startup & graceful close
	bk := NewBus(0, policy.KafkaConfig{
		Enabled:     true,
		Brokers:     []string{"127.0.0.1:1"},
		ClientID:    "pgveil-test",
		AuditTopic:  "pgveil.audit",
		AlertsTopic: "pgveil.alerts",
	}, nil)
	bk.Close()
}
