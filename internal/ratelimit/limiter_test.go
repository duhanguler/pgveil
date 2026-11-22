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

	// 3. Disabled limits always allow
	if d := lim.Check("ai_agent:10.0.0.3", "fp", 0, 0, 0); !d.Allowed {
		t.Fatal("expected disabled limits to allow")
	}

	// 4. Default loopWindow and lazy eviction of stale buckets & stale fingerprints
	lim.mu.Lock()
	stale := time.Now().Add(-10 * time.Minute)
	for i := 0; i < 2055; i++ {
		lim.buckets["stale:"+string(rune(i/100+33))+string(rune(i%100+33))+time.Duration(i).String()] = &bucket{
			lastTouched: stale,
			fpTimes:     map[string][]time.Time{},
		}
	}
	bigBucket := &bucket{lastTouched: time.Now(), fpTimes: make(map[string][]time.Time, 520)}
	for i := 0; i < 520; i++ {
		bigBucket.fpTimes["old_"+time.Duration(i).String()] = []time.Time{stale}
	}
	lim.buckets["ai_agent:heavy"] = bigBucket
	lim.mu.Unlock()

	if d := lim.Check("ai_agent:heavy", "fp_new", 100, 5, 0); !d.Allowed {
		t.Fatalf("expected heavy bucket check allowed after pruning, got %+v", d)
	}
	lim.mu.Lock()
	if len(lim.buckets) > 10 {
		t.Fatalf("expected stale buckets evicted, still %d", len(lim.buckets))
	}
	if len(lim.buckets["ai_agent:heavy"].fpTimes) != 1 {
		t.Fatalf("expected stale fingerprints evicted, still %d", len(lim.buckets["ai_agent:heavy"].fpTimes))
	}
	lim.mu.Unlock()
}
