package pgwire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRewriteParseMessage(t *testing.T) {
	// Construct Parse payload: stmt="stmt_1\0", query="SELECT * FROM customers WHERE id = $1\0", count=1, oid=23
	var orig bytes.Buffer
	orig.WriteString("stmt_1")
	orig.WriteByte(0)
	orig.WriteString("SELECT * FROM customers WHERE id = $1")
	orig.WriteByte(0)
	_ = binary.Write(&orig, binary.BigEndian, uint16(1))
	_ = binary.Write(&orig, binary.BigEndian, uint32(23))

	newSQL := "SELECT * FROM customers WHERE id = $1 AND customers.city = 'Istanbul'"
	rewritten, err := RewriteParseMessage(orig.Bytes(), newSQL)
	if err != nil {
		t.Fatalf("RewriteParseMessage failed: %v", err)
	}

	gotStmt, gotQuery, err := ParseParseMessage(rewritten)
	if err != nil {
		t.Fatalf("ParseParseMessage failed: %v", err)
	}
	if gotStmt != "stmt_1" {
		t.Fatalf("stmt name mismatch: got %q", gotStmt)
	}
	if gotQuery != newSQL {
		t.Fatalf("query mismatch: got %q", gotQuery)
	}
	// Verify trailing parameter OIDs preserved byte-for-byte
	tail := rewritten[len("stmt_1")+1+len(newSQL)+1:]
	if len(tail) != 6 || binary.BigEndian.Uint16(tail[0:2]) != 1 || binary.BigEndian.Uint32(tail[2:6]) != 23 {
		t.Fatalf("trailing parameter OIDs corrupted: %x", tail)
	}
}

func TestEncodeParseRowDescriptionRoundTrip(t *testing.T) {
	in := []FieldDescription{
		{Name: "id", DataTypeOID: 23, DataTypeSize: 4, TypeModifier: -1, FormatCode: 0},
		{Name: "full_name", DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, FormatCode: 0},
	}
	encoded := EncodeRowDescription(in)
	out, err := ParseRowDescription(encoded)
	if err != nil {
		t.Fatalf("ParseRowDescription failed: %v", err)
	}
	if len(out) != 2 || out[0].Name != "id" || out[0].DataTypeOID != 23 || out[1].Name != "full_name" || out[1].DataTypeSize != -1 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestBuildSimpleQuery(t *testing.T) {
	p := BuildSimpleQuery("SELECT 1")
	if len(p) != 9 || p[8] != 0 || ParseSimpleQuery(p) != "SELECT 1" {
		t.Fatalf("unexpected BuildSimpleQuery payload: %q", p)
	}
	if ParseSimpleQuery([]byte("SELECT 2")) != "SELECT 2" {
		t.Fatalf("ParseSimpleQuery without trailing NUL failed")
	}
	if n := BuildNoticeResponse("NOTICE", "00000", "hello"); len(n) == 0 {
		t.Fatal("BuildNoticeResponse returned empty")
	}
	if c := BuildCommandComplete("SELECT 1"); string(c) != "SELECT 1\x00" {
		t.Fatalf("unexpected CommandComplete: %q", c)
	}
	for _, st := range []byte{'I', 'T', 'E'} {
		if got := BuildReadyForQuery(st); len(got) != 1 || got[0] != st {
			t.Fatalf("BuildReadyForQuery(%q) = %q", st, got)
		}
	}
	if got := BuildReadyForQuery('X'); len(got) != 1 || got[0] != 'I' {
		t.Fatalf("BuildReadyForQuery invalid fallback = %q", got)
	}
	if _, _, err := ParseParseMessage([]byte("no_nul")); err == nil {
		t.Fatal("expected error on truncated Parse message")
	}
	if _, err := RewriteParseMessage([]byte("no_nul"), "SELECT 1"); err == nil {
		t.Fatal("expected error on malformed RewriteParseMessage")
	}
}
