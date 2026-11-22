package hitl

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Status represents the lifecycle state of a Human-in-the-Loop approval request.
type Status string

const (
	StatusPending  Status = "PENDING"
	StatusApproved Status = "APPROVED"
	StatusDenied   Status = "DENIED"
	StatusExpired  Status = "EXPIRED"
)

// ApprovalRequest captures a paused high-risk SQL query waiting for operator review.
type ApprovalRequest struct {
	ID              string    `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	ClientAddr      string    `json:"client_addr"`
	DBUser          string    `json:"db_user"`
	Database        string    `json:"database"`
	ApplicationName string    `json:"application_name"`
	RoleProfile     string    `json:"role_profile"`
	StatementType   string    `json:"statement_type"`
	RiskLevel       string    `json:"risk_level"`
	Rule            string    `json:"rule"`
	Reason          string    `json:"reason"`
	Tables          []string  `json:"tables"`
	SQL             string    `json:"sql"`
	Status          Status    `json:"status"`
	Reviewer        string     `json:"reviewer,omitempty"`
	ReviewerNote    string     `json:"reviewer_note,omitempty"`
	ActorKey        string     `json:"-"`

	ch chan Status
}

const (
	DefaultMaxPendingGlobal   = 128
	DefaultMaxPendingPerActor = 4
)

var ErrHITLQuotaExceeded = errors.New("concurrent HITL pending approval quota exceeded")

// AlreadyResolvedError is returned when a second operator attempts to resolve an approval
// that was already approved, denied, or expired on another channel (e.g. Web vs Slack).
type AlreadyResolvedError struct {
	Request *ApprovalRequest
}

func (e *AlreadyResolvedError) Error() string {
	if e == nil || e.Request == nil {
		return "approval request already resolved"
	}
	return fmt.Sprintf("approval request %q already resolved (%s by %s)", e.Request.ID, e.Request.Status, e.Request.Reviewer)
}

// Manager coordinates live synchronous query holds and operator approvals/denials.
type Manager struct {
	mu          sync.RWMutex
	requests    map[string]*ApprovalRequest
	order       []string
	maxHistory  int
	subscribers map[chan ApprovalRequest]struct{}
}

// NewManager creates an approval coordinator with bounded in-memory history.
func NewManager(maxHistory int) *Manager {
	if maxHistory <= 0 {
		maxHistory = 200
	}
	return &Manager{
		requests:    make(map[string]*ApprovalRequest),
		order:       make([]string, 0, maxHistory),
		maxHistory:  maxHistory,
		subscribers: make(map[chan ApprovalRequest]struct{}),
	}
}

// Create registers a new pending approval request (used in both "hold" and "reject" modes).
func (m *Manager) Create(req ApprovalRequest, timeout time.Duration) *ApprovalRequest {
	stored, _ := m.CreateWithQuota(req, timeout, 0, 0)
	return stored
}

// CreateWithQuota enforces bounded global and per-actor pending hold quotas to prevent
// goroutine/socket exhaustion DoS when runaway agents trigger hold-mode HITL.
func (m *Manager) CreateWithQuota(req ApprovalRequest, timeout time.Duration, maxGlobal, maxPerActor int) (*ApprovalRequest, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	now := time.Now().UTC()

	m.mu.Lock()
	defer m.mu.Unlock()

	if maxGlobal > 0 || maxPerActor > 0 {
		globalPending := 0
		actorPending := 0
		for _, r := range m.requests {
			if r.Status == StatusPending {
				globalPending++
				if req.ActorKey != "" && r.ActorKey == req.ActorKey {
					actorPending++
				}
			}
		}
		if maxGlobal > 0 && globalPending >= maxGlobal {
			return nil, fmt.Errorf("%w: global limit %d reached", ErrHITLQuotaExceeded, maxGlobal)
		}
		if maxPerActor > 0 && req.ActorKey != "" && actorPending >= maxPerActor {
			return nil, fmt.Errorf("%w: actor %q has %d pending holds (max %d)", ErrHITLQuotaExceeded, req.ActorKey, actorPending, maxPerActor)
		}
	}

	req.ID = generateID()
	req.CreatedAt = now
	req.ExpiresAt = now.Add(timeout)
	req.Status = StatusPending
	req.ch = make(chan Status, 1)

	stored := &req
	m.requests[stored.ID] = stored
	m.order = append(m.order, stored.ID)
	if len(m.order) > m.maxHistory {
		evict := m.order[0]
		m.order = m.order[1:]
		if old, ok := m.requests[evict]; ok && old.Status != StatusPending {
			delete(m.requests, evict)
		}
	}
	m.broadcastLocked(*stored)
	cp := *stored
	return &cp, nil
}

// Get returns an immutable snapshot of an approval request by ID without mutating state
// (used by idempotent GET preview cards).
func (m *Manager) Get(id string) (*ApprovalRequest, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	req, ok := m.requests[id]
	if !ok {
		return nil, false
	}
	cp := *req
	return &cp, true
}

// Wait blocks until an operator approves/denies the request, the timeout elapses, or ctx is canceled.
func (m *Manager) Wait(ctx context.Context, req *ApprovalRequest) (Status, string) {
	remaining := time.Until(req.ExpiresAt)
	if remaining <= 0 {
		remaining = time.Second
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()

	select {
	case st := <-req.ch:
		m.mu.RLock()
		note := req.ReviewerNote
		if cur, ok := m.requests[req.ID]; ok {
			note = cur.ReviewerNote
		}
		m.mu.RUnlock()
		return st, note
	case <-timer.C:
		m.expire(req.ID, "Approval window timed out")
		return StatusExpired, "Approval window timed out"
	case <-ctx.Done():
		m.expire(req.ID, "Client disconnected while waiting for approval")
		return StatusExpired, "Client disconnected"
	}
}

// Resolve approves or denies a pending query and immediately unblocks the waiting wire session.
func (m *Manager) Resolve(id string, approve bool, reviewer, note string) (*ApprovalRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, ok := m.requests[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	if req.Status != StatusPending {
		cp := *req
		return &cp, &AlreadyResolvedError{Request: &cp}
	}
	now := time.Now().UTC()
	req.ResolvedAt = &now
	if reviewer == "" {
		reviewer = "console-operator"
	}
	req.Reviewer = reviewer
	req.ReviewerNote = note
	if approve {
		req.Status = StatusApproved
	} else {
		req.Status = StatusDenied
	}
	select {
	case req.ch <- req.Status:
	default:
	}
	snapshot := *req
	m.broadcastLocked(snapshot)
	return &snapshot, nil
}

func (m *Manager) expire(id, note string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, ok := m.requests[id]
	if !ok || req.Status != StatusPending {
		return
	}
	now := time.Now().UTC()
	req.ResolvedAt = &now
	req.Status = StatusExpired
	req.ReviewerNote = note
	m.broadcastLocked(*req)
}

// List returns approval requests newest-first, optionally filtered by status.
func (m *Manager) List(statusFilter string) []ApprovalRequest {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ApprovalRequest, 0, len(m.order))
	for i := len(m.order) - 1; i >= 0; i-- {
		req, ok := m.requests[m.order[i]]
		if !ok {
			continue
		}
		if statusFilter != "" && string(req.Status) != statusFilter {
			continue
		}
		out = append(out, *req)
	}
	return out
}

// PendingCount returns how many queries are currently paused awaiting human review.
func (m *Manager) PendingCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, req := range m.requests {
		if req.Status == StatusPending {
			n++
		}
	}
	return n
}

// Subscribe returns a live channel of approval state transitions (for SSE streaming).
func (m *Manager) Subscribe() (<-chan ApprovalRequest, func()) {
	ch := make(chan ApprovalRequest, 32)
	m.mu.Lock()
	m.subscribers[ch] = struct{}{}
	m.mu.Unlock()
	return ch, func() {
		m.mu.Lock()
		delete(m.subscribers, ch)
		close(ch)
		m.mu.Unlock()
	}
}

func (m *Manager) broadcastLocked(req ApprovalRequest) {
	for ch := range m.subscribers {
		select {
		case ch <- req:
		default:
		}
	}
}

var ErrNotFound = errors.New("approval not found")

func generateID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "hitl_" + hex.EncodeToString(b[:])
}
