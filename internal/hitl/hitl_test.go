package hitl

import (
	"context"
	"testing"
	"time"
)

func TestLiveHoldApproveAndDeny(t *testing.T) {
	mgr := NewManager(50)

	// 1. Live hold -> operator approves asynchronously
	req := mgr.Create(ApprovalRequest{
		RoleProfile:   "ai_agent",
		StatementType: "UPDATE",
		SQL:           "UPDATE orders SET status='refunded' WHERE id=1001",
	}, 5*time.Second)

	go func() {
		time.Sleep(30 * time.Millisecond)
		_, _ = mgr.Resolve(req.ID, true, "duhan", "verified ticket #1001")
	}()

	st, note := mgr.Wait(context.Background(), req)
	if st != StatusApproved || note != "verified ticket #1001" {
		t.Fatalf("got (%s, %q), want (APPROVED, verified ticket #1001)", st, note)
	}

	// 2. Live hold -> operator denies
	req2 := mgr.Create(ApprovalRequest{
		RoleProfile:   "ai_agent",
		StatementType: "DELETE",
		SQL:           "DELETE FROM orders WHERE id=1002",
	}, 5*time.Second)

	go func() {
		time.Sleep(25 * time.Millisecond)
		_, _ = mgr.Resolve(req2.ID, false, "secops", "not authorized")
	}()

	st2, _ := mgr.Wait(context.Background(), req2)
	if st2 != StatusDenied {
		t.Fatalf("got %s, want DENIED", st2)
	}

	// 3. Timeout expiration
	req3 := mgr.Create(ApprovalRequest{
		RoleProfile:   "ai_agent",
		StatementType: "UPDATE",
		SQL:           "UPDATE orders SET status='x' WHERE id=1",
	}, 40*time.Millisecond)
	st3, _ := mgr.Wait(context.Background(), req3)
	if st3 != StatusExpired {
		t.Fatalf("got %s, want EXPIRED", st3)
	}
}
