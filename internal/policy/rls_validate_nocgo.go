//go:build !cgo

package policy

import (
	"errors"
	"strings"
)

// validateRowFilter provides pure-Go structural validation when built with CGO_ENABLED=0
// (e.g., for static pgveil-audit-worker builds that share internal/events).
func validateRowFilter(rf RowFilterPolicy) error {
	if strings.TrimSpace(rf.Table) == "" {
		return errors.New("table cannot be empty")
	}
	pred := strings.TrimSpace(rf.Predicate)
	if pred == "" {
		return errors.New("predicate cannot be empty")
	}
	if strings.IndexByte(pred, 0) >= 0 {
		return errors.New("predicate contains embedded NUL byte")
	}
	if strings.Contains(pred, ";") {
		return errors.New("predicate cannot contain statement separator ';'")
	}
	return nil
}
