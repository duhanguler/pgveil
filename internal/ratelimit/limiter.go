package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

// Config configures per-profile query rate limiting and runaway AI-agent loop detection.
type Config struct {
	MaxQueriesPerMinute int           `yaml:"max_queries_per_minute" json:"max_queries_per_minute"`
	LoopThreshold       int           `yaml:"loop_threshold" json:"loop_threshold"`
	LoopWindow          time.Duration `yaml:"-" json:"-"`
	LoopWindowRaw       string        `yaml:"loop_window" json:"loop_window"`
}

// Decision captures whether a query is permitted or throttled by the rate/loop guard.
type Decision struct {
	Allowed bool
	Rule    string
	Reason  string
}

type bucket struct {
	qpmTimes    []time.Time
	fpTimes     map[string][]time.Time
	lastTouched time.Time
}

// Limiter enforces sliding-window QPM quotas and detects runaway identical-fingerprint query loops.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

func NewLimiter() *Limiter {
	return &Limiter{
		buckets: make(map[string]*bucket),
	}
}

// Check records a query execution attempt for key (e.g., "ai_agent:127.0.0.1") and SQL fingerprint.
func (l *Limiter) Check(key, fingerprint string, maxQPM, loopThreshold int, loopWindow time.Duration) Decision {
	if maxQPM <= 0 && loopThreshold <= 0 {
		return Decision{Allowed: true}
	}
	now := time.Now()
	if loopWindow <= 0 {
		loopWindow = 15 * time.Second
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Periodic lazy eviction if map grows large
	if len(l.buckets) > 2048 {
		staleCutoff := now.Add(-5 * time.Minute)
		for k, b := range l.buckets {
			if b.lastTouched.Before(staleCutoff) {
				delete(l.buckets, k)
			}
		}
	}

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{fpTimes: make(map[string][]time.Time)}
		l.buckets[key] = b
	}
	b.lastTouched = now

	// 1. Sliding-window QPM quota
	if maxQPM > 0 {
		cutoff := now.Add(-time.Minute)
		kept := b.qpmTimes[:0]
		for _, ts := range b.qpmTimes {
			if ts.After(cutoff) {
				kept = append(kept, ts)
			}
		}
		if len(kept) >= maxQPM {
			b.qpmTimes = kept
			return Decision{
				Allowed: false,
				Rule:    "rate_limit_qpm",
				Reason:  fmt.Sprintf("Rate limit exceeded: max %d queries/minute for %q", maxQPM, key),
			}
		}
		b.qpmTimes = append(kept, now)
	}

	// 2. Runaway AI-Agent Loop Circuit Breaker (identical fingerprint burst)
	if loopThreshold > 0 && fingerprint != "" && fingerprint != "unparseable" {
		cutoff := now.Add(-loopWindow)
		// Lazily prune expired fingerprints inside long-lived client buckets to bound memory
		if len(b.fpTimes) > 512 {
			for fpKey, times := range b.fpTimes {
				if len(times) == 0 || !times[len(times)-1].After(cutoff) {
					delete(b.fpTimes, fpKey)
				}
			}
		}
		hist := b.fpTimes[fingerprint]
		kept := hist[:0]
		for _, ts := range hist {
			if ts.After(cutoff) {
				kept = append(kept, ts)
			}
		}
		kept = append(kept, now)
		b.fpTimes[fingerprint] = kept
		if len(kept) > loopThreshold {
			return Decision{
				Allowed: false,
				Rule:    "runaway_agent_loop",
				Reason:  fmt.Sprintf("Runaway query loop detected: identical fingerprint %s repeated >%d times in %s", fingerprint, loopThreshold, loopWindow),
			}
		}
	}

	return Decision{Allowed: true}
}
