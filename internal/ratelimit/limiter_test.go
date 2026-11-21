package ratelimit

import (
	"testing"
	"time"
)

func TestQPMAndRunawayLoopDetection(t *testing.T) {
	lim := NewLimiter()

	// 1. Runaway loop trips after threshold identical fingerprints
	for i := 0; i < 4; i++ {
		d := lim.Check("ai_agent:10.0.0.1", "fp_abc", 100, 4, 10*time.Second)
		if !d.Allowed {
			t.Fatalf("attempt %d unexpectedly blocked: %s", i+1, d.Reason)
		}
	}
	d := lim.Check("ai_agent:10.0.0.1", "fp_abc", 100, 4, 10*time.Second)
	if d.Allowed || d.Rule != "runaway_agent_loop" {
		t.Fatalf("expected runaway_agent_loop block, got %+v", d)
	}

	// 2. QPM quota trips on distinct fingerprints
	for i := 0; i < 3; i++ {
		res := lim.Check("ai_agent:10.0.0.2", "fp_"+string(rune('a'+i)), 3, 50, 10*time.Second)
		if !res.Allowed {
			t.Fatalf("qpm attempt %d unexpectedly blocked: %s", i+1, res.Reason)
		}
	}
	res := lim.Check("ai_agent:10.0.0.2", "fp_z", 3, 50, 10*time.Second)
	if res.Allowed || res.Rule != "rate_limit_qpm" {
		t.Fatalf("expected rate_limit_qpm block, got %+v", res)
	}
}
