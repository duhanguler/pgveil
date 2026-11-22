package hitl

import (
	"context"
	"testing"
	"time"
)

func TestManagerLifecycleAndSubscribers(t *testing.T) {
	mgr := NewManager(2) // small ring to test eviction
	if mgr.PendingCount() != 0 {
		t.Fatalf("expected 0 pending")
	}

	ch, unsub := mgr.Subscribe()
	defer unsub()

	// 1. Create & Approve
	r1 := mgr.Create(ApprovalRequest{RoleProfile: "ai_agent", SQL: "UPDATE orders SET status='x' WHERE id=1"}, 5*time.Second)
	if mgr.PendingCount() != 1 {
		t.Fatalf("expected 1 pending, got %d", mgr.PendingCount())
	}
	<-ch // creation broadcast

	go func() {
		_, _ = mgr.Resolve(r1.ID, true, "", "looks good")
	}()
	st, note := mgr.Wait(context.Background(), r1)
	if st != StatusApproved || note != "looks good" {
		t.Fatalf("expected approved/'looks good', got %s/%q", st, note)
	}
	<-ch // resolution broadcast

	// Double resolve must error
	if _, err := mgr.Resolve(r1.ID, false, "op", "late"); err == nil {
		t.Fatal("expected error resolving already-resolved request")
	}
	// Unknown ID must error
	if _, err := mgr.Resolve("hitl_does_not_exist", true, "op", ""); err == nil {
		t.Fatal("expected error resolving unknown request")
	}

	// 2. Create & Deny
	r2 := mgr.Create(ApprovalRequest{RoleProfile: "ai_agent", SQL: "DELETE FROM orders WHERE id=2"}, 5*time.Second)
	go func() {
		_, _ = mgr.Resolve(r2.ID, false, "sec-lead", "denied")
	}()
	st2, note2 := mgr.Wait(context.Background(), r2)
	if st2 != StatusDenied || note2 != "denied" {
		t.Fatalf("expected denied, got %s/%q", st2, note2)
	}

	// 3. Timeout expiry + ring eviction (3rd item evicts resolved r1)
	r3 := mgr.Create(ApprovalRequest{RoleProfile: "developer", SQL: "UPDATE orders SET status='y' WHERE id=3"}, 30*time.Millisecond)
	st3, _ := mgr.Wait(context.Background(), r3)
	if st3 != StatusExpired {
		t.Fatalf("expected expired on timeout, got %s", st3)
	}

	// 4. Context cancellation expiry
	r4 := mgr.Create(ApprovalRequest{RoleProfile: "developer", SQL: "UPDATE orders SET status='z' WHERE id=4"}, 5*time.Second)
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	st4, _ := mgr.Wait(cctx, r4)
	if st4 != StatusExpired {
		t.Fatalf("expected expired on ctx cancel, got %s", st4)
	}

	// List all and filtered
	all := mgr.List("")
	if len(all) == 0 {
		t.Fatal("expected non-empty list")
	}
	expired := mgr.List(string(StatusExpired))
	if len(expired) == 0 {
		t.Fatal("expected expired items in filtered list")
	}

	// 5. Get, AlreadyResolvedError, and CreateWithQuota per-actor & global limits
	if _, ok := mgr.Get("does_not_exist"); ok {
		t.Fatal("expected missing Get to return false")
	}
	var nilARE *AlreadyResolvedError
	if nilARE.Error() == "" {
		t.Fatal("expected safe Error() on nil AlreadyResolvedError")
	}
	q1, err := mgr.CreateWithQuota(ApprovalRequest{RoleProfile: "ai", ActorKey: "ai:sub1", SQL: "DELETE 1"}, time.Minute, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	q2, err := mgr.CreateWithQuota(ApprovalRequest{RoleProfile: "ai", ActorKey: "ai:sub1", SQL: "DELETE 2"}, time.Minute, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	// 3rd concurrent pending hold for same actor -> ErrHITLQuotaExceeded!
	if _, err := mgr.CreateWithQuota(ApprovalRequest{RoleProfile: "ai", ActorKey: "ai:sub1", SQL: "DELETE 3"}, time.Minute, 10, 2); err == nil {
		t.Fatal("expected per-actor quota exceeded")
	}
	// Global limit = 2 -> another actor also blocked!
	if _, err := mgr.CreateWithQuota(ApprovalRequest{RoleProfile: "ai", ActorKey: "ai:sub2", SQL: "DELETE 4"}, time.Minute, 2, 5); err == nil {
		t.Fatal("expected global quota exceeded")
	}
	if got, ok := mgr.Get(q1.ID); !ok || got.Status != StatusPending {
		t.Fatalf("unexpected Get: %+v", got)
	}
	_, _ = mgr.Resolve(q1.ID, true, "op1", "ok")
	_, dupErr := mgr.Resolve(q1.ID, false, "op2", "too late")
	if dupErr == nil || dupErr.Error() == "" {
		t.Fatal("expected AlreadyResolvedError on duplicate Resolve")
	}
	_, _ = mgr.Resolve(q2.ID, false, "op1", "no")
}
