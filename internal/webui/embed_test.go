package webui

import (
	"io/fs"
	"testing"
)

func TestDistFS(t *testing.T) {
	sub, err := DistFS()
	if err != nil {
		t.Fatalf("DistFS failed: %v", err)
	}
	entries, err := fs.ReadDir(sub, ".")
	if err != nil || len(entries) == 0 {
		t.Fatalf("expected non-empty embedded web dist directory, err=%v len=%d", err, len(entries))
	}
}
