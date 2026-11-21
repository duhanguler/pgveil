package pgwire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestStartupPacketParse(t *testing.T) {
	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, ProtocolVersion30)
	for _, s := range []string{"user", "ai_agent", "database", "pgveil_demo", "application_name", "claude-mcp-server"} {
		body.WriteString(s)
		body.WriteByte(0)
	}
	body.WriteByte(0)

	var frame bytes.Buffer
	_ = binary.Write(&frame, binary.BigEndian, uint32(body.Len()+4))
	frame.Write(body.Bytes())

	pkt, err := ReadStartupPacket(&frame)
	if err != nil {
		t.Fatalf("ReadStartupPacket error: %v", err)
	}
	if pkt.Code != ProtocolVersion30 {
		t.Fatalf("code = %d, want %d", pkt.Code, ProtocolVersion30)
	}
	if pkt.Params["user"] != "ai_agent" || pkt.Params["application_name"] != "claude-mcp-server" {
		t.Fatalf("unexpected params: %+v", pkt.Params)
	}
}

func TestDataRowRoundTripWithNullAndUTF8(t *testing.T) {
	cols := [][]byte{
		[]byte("1001"),
		[]byte("Ayşe Kaya"),
		nil, // SQL NULL
		[]byte(""),
		[]byte("TR33 **** **** **** 1326"),
	}
	encoded := EncodeDataRow(cols)
	decoded, err := ParseDataRow(encoded)
	if err != nil {
		t.Fatalf("ParseDataRow failed: %v", err)
	}
	if len(decoded) != len(cols) {
		t.Fatalf("len = %d, want %d", len(decoded), len(cols))
	}
	if decoded[2] != nil {
		t.Fatalf("expected col 2 to remain SQL NULL (nil), got %q", decoded[2])
	}
	if decoded[3] == nil || len(decoded[3]) != 0 {
		t.Fatalf("expected col 3 to remain empty non-nil string, got %#v", decoded[3])
	}
	if string(decoded[1]) != "Ayşe Kaya" {
		t.Fatalf("UTF-8 mismatch: got %q", decoded[1])
	}
}

func TestRewriteBindResultFormatsToText(t *testing.T) {
	// Build a Bind payload with 1 binary param and 2 binary result formats.
	var b bytes.Buffer
	b.WriteString("p1\x00stmt_1\x00")
	_ = binary.Write(&b, binary.BigEndian, uint16(0)) // 0 param format codes
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // 1 param
	_ = binary.Write(&b, binary.BigEndian, int32(2))
	b.WriteString("42")
	_ = binary.Write(&b, binary.BigEndian, uint16(2)) // 2 result format codes (binary)
	_ = binary.Write(&b, binary.BigEndian, uint16(1))
	_ = binary.Write(&b, binary.BigEndian, uint16(1))

	portal, stmt, rewritten, err := RewriteBindResultFormatsToText(b.Bytes())
	if err != nil {
		t.Fatalf("RewriteBindResultFormatsToText error: %v", err)
	}
	if portal != "p1" || stmt != "stmt_1" {
		t.Fatalf("got portal=%q stmt=%q", portal, stmt)
	}
	tail := rewritten[len(rewritten)-4:]
	count := binary.BigEndian.Uint16(tail[0:2])
	fmtCode := binary.BigEndian.Uint16(tail[2:4])
	if count != 1 || fmtCode != 0 {
		t.Fatalf("expected rewritten result format count=1 code=0 (text), got count=%d code=%d", count, fmtCode)
	}
}

func TestMessageFramingRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	errPayload := BuildErrorResponse("ERROR", "42501", "pgveil blocked query", "policy: block_ddl", "request admin approval")
	if err := WriteMessage(&buf, MsgErrorResponse, errPayload); err != nil {
		t.Fatal(err)
	}
	msgType, got, err := ReadMessage(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != MsgErrorResponse {
		t.Fatalf("got type %q want %q", msgType, MsgErrorResponse)
	}
	if !bytes.Equal(got, errPayload) {
		t.Fatalf("payload mismatch")
	}
}
