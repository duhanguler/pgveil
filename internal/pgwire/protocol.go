package pgwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// PostgreSQL Wire Protocol v3 constants.
const (
	ProtocolVersion30 uint32 = 196608   // (3 << 16) | 0
	SSLRequestCode    uint32 = 80877103 // (1234 << 16) | 5679
	GSSENCRequestCode uint32 = 80877104 // (1234 << 16) | 5680
	CancelRequestCode uint32 = 80877102 // (1234 << 16) | 5678

	MaxMessageSize = 64 * 1024 * 1024 // 64 MiB safety cap
)

// Frontend (Client -> Backend) message type bytes.
const (
	MsgQuery     byte = 'Q'
	MsgParse     byte = 'P'
	MsgBind      byte = 'B'
	MsgDescribe  byte = 'D'
	MsgExecute   byte = 'E'
	MsgSync      byte = 'S'
	MsgFlush     byte = 'H'
	MsgClose     byte = 'C'
	MsgTerminate byte = 'X'
	MsgPassword  byte = 'p'
	MsgCopyData  byte = 'd'
	MsgCopyDone  byte = 'c'
	MsgCopyFail  byte = 'f'
)

// Backend (Server -> Client) message type bytes.
const (
	MsgAuth            byte = 'R'
	MsgBackendKeyData  byte = 'K'
	MsgParameterStatus byte = 'S'
	MsgReadyForQuery   byte = 'Z'
	MsgRowDescription  byte = 'T'
	MsgDataRow         byte = 'D'
	MsgCommandComplete byte = 'C'
	MsgErrorResponse   byte = 'E'
	MsgNoticeResponse  byte = 'N'
	MsgEmptyQuery      byte = 'I'
	MsgNoData          byte = 'n'
	MsgParseComplete   byte = '1'
	MsgBindComplete    byte = '2'
	MsgCloseComplete   byte = '3'
	MsgPortalSuspended byte = 's'
)

// StartupPacket represents the untyped initial handshake packet from a PostgreSQL client.
type StartupPacket struct {
	Code   uint32
	Params map[string]string
	Raw    []byte // Exact wire bytes including the 4-byte length prefix
}

// ReadStartupPacket reads a PostgreSQL v3 startup / SSL / GSSENC / Cancel frame.
func ReadStartupPacket(r io.Reader) (*StartupPacket, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	totalLen := binary.BigEndian.Uint32(lenBuf[:])
	if totalLen < 8 || totalLen > 1024*1024 {
		return nil, fmt.Errorf("invalid startup packet length: %d", totalLen)
	}
	raw := make([]byte, totalLen)
	copy(raw[:4], lenBuf[:])
	if _, err := io.ReadFull(r, raw[4:]); err != nil {
		return nil, err
	}
	code := binary.BigEndian.Uint32(raw[4:8])
	pkt := &StartupPacket{
		Code:   code,
		Params: make(map[string]string),
		Raw:    raw,
	}
	if code == ProtocolVersion30 {
		body := raw[8:]
		for len(body) > 0 && body[0] != 0 {
			kEnd := bytes.IndexByte(body, 0)
			if kEnd < 0 {
				break
			}
			key := string(body[:kEnd])
			body = body[kEnd+1:]
			vEnd := bytes.IndexByte(body, 0)
			if vEnd < 0 {
				break
			}
			val := string(body[:vEnd])
			body = body[vEnd+1:]
			pkt.Params[key] = val
		}
	}
	return pkt, nil
}

// ReadMessage reads a single typed PostgreSQL v3 wire message: [type:1][len:4][payload:len-4].
func ReadMessage(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	msgType := hdr[0]
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length < 4 || length > MaxMessageSize {
		return 0, nil, fmt.Errorf("invalid wire message length %d for type %q", length, msgType)
	}
	payloadLen := length - 4
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return msgType, payload, nil
}

// WriteMessage writes a typed PostgreSQL v3 wire message in a single write call.
func WriteMessage(w io.Writer, msgType byte, payload []byte) error {
	buf := make([]byte, 5+len(payload))
	buf[0] = msgType
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)+4))
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	return err
}

// FieldDescription describes a single column in a RowDescription ('T') message.
type FieldDescription struct {
	Name         string
	TableOID     uint32
	ColumnAttr   uint16
	DataTypeOID  uint32
	DataTypeSize int16
	TypeModifier int32
	FormatCode   uint16 // 0 = text, 1 = binary
}

// ParseRowDescription decodes a PostgreSQL RowDescription ('T') payload.
func ParseRowDescription(payload []byte) ([]FieldDescription, error) {
	if len(payload) < 2 {
		return nil, errors.New("truncated RowDescription")
	}
	numFields := int(binary.BigEndian.Uint16(payload[0:2]))
	fields := make([]FieldDescription, 0, numFields)
	off := 2
	for i := 0; i < numFields; i++ {
		nul := bytes.IndexByte(payload[off:], 0)
		if nul < 0 {
			return nil, errors.New("unterminated column name in RowDescription")
		}
		name := string(payload[off : off+nul])
		off += nul + 1
		if off+18 > len(payload) {
			return nil, errors.New("truncated field metadata in RowDescription")
		}
		f := FieldDescription{
			Name:         name,
			TableOID:     binary.BigEndian.Uint32(payload[off : off+4]),
			ColumnAttr:   binary.BigEndian.Uint16(payload[off+4 : off+6]),
			DataTypeOID:  binary.BigEndian.Uint32(payload[off+6 : off+10]),
			DataTypeSize: int16(binary.BigEndian.Uint16(payload[off+10 : off+12])),
			TypeModifier: int32(binary.BigEndian.Uint32(payload[off+12 : off+16])),
			FormatCode:   binary.BigEndian.Uint16(payload[off+16 : off+18]),
		}
		off += 18
		fields = append(fields, f)
	}
	return fields, nil
}

// ParseDataRow decodes a DataRow ('D') payload into slices per column.
// A nil slice represents SQL NULL (length = -1); an empty non-nil slice represents "".
func ParseDataRow(payload []byte) ([][]byte, error) {
	if len(payload) < 2 {
		return nil, errors.New("truncated DataRow")
	}
	numCols := int(binary.BigEndian.Uint16(payload[0:2]))
	cols := make([][]byte, numCols)
	off := 2
	for i := 0; i < numCols; i++ {
		if off+4 > len(payload) {
			return nil, errors.New("truncated DataRow column length")
		}
		colLen := int32(binary.BigEndian.Uint32(payload[off : off+4]))
		off += 4
		if colLen == -1 {
			cols[i] = nil
			continue
		}
		if colLen < 0 || off+int(colLen) > len(payload) {
			return nil, fmt.Errorf("invalid DataRow column length %d", colLen)
		}
		cols[i] = payload[off : off+int(colLen)]
		off += int(colLen)
	}
	return cols, nil
}

// EncodeDataRow encodes columns back into a valid PostgreSQL DataRow ('D') payload.
func EncodeDataRow(cols [][]byte) []byte {
	size := 2
	for _, c := range cols {
		size += 4
		if c != nil {
			size += len(c)
		}
	}
	buf := make([]byte, size)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(cols)))
	off := 2
	for _, c := range cols {
		if c == nil {
			binary.BigEndian.PutUint32(buf[off:off+4], 0xFFFFFFFF) // -1
			off += 4
			continue
		}
		binary.BigEndian.PutUint32(buf[off:off+4], uint32(len(c)))
		off += 4
		copy(buf[off:], c)
		off += len(c)
	}
	return buf
}

// ParseSimpleQuery extracts the SQL string from a Query ('Q') payload.
func ParseSimpleQuery(payload []byte) string {
	if idx := bytes.IndexByte(payload, 0); idx >= 0 {
		return string(payload[:idx])
	}
	return string(payload)
}

// ParseParseMessage extracts prepared statement name and SQL query from a Parse ('P') payload.
func ParseParseMessage(payload []byte) (stmtName string, query string, err error) {
	n1 := bytes.IndexByte(payload, 0)
	if n1 < 0 {
		return "", "", errors.New("invalid Parse message: missing stmt name terminator")
	}
	stmtName = string(payload[:n1])
	rest := payload[n1+1:]
	n2 := bytes.IndexByte(rest, 0)
	if n2 < 0 {
		return "", "", errors.New("invalid Parse message: missing query terminator")
	}
	query = string(rest[:n2])
	return stmtName, query, nil
}

// ParseBindInfo parses portal and statement names from a Bind ('B') payload, and optionally
// returns a rewritten Bind payload forcing text result format codes (0) so extended-protocol
// drivers (pgx, psycopg3, JDBC) safely receive masked strings without binary decoding errors.
func RewriteBindResultFormatsToText(payload []byte) (portalName, stmtName string, rewritten []byte, err error) {
	n1 := bytes.IndexByte(payload, 0)
	if n1 < 0 {
		return "", "", nil, errors.New("invalid Bind: missing portal name")
	}
	portalName = string(payload[:n1])
	off := n1 + 1
	n2 := bytes.IndexByte(payload[off:], 0)
	if n2 < 0 {
		return "", "", nil, errors.New("invalid Bind: missing statement name")
	}
	stmtName = string(payload[off : off+n2])
	off += n2 + 1

	// Skip parameter format codes
	if off+2 > len(payload) {
		return portalName, stmtName, payload, nil
	}
	numParamFmts := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2 + numParamFmts*2
	if off+2 > len(payload) {
		return portalName, stmtName, payload, nil
	}
	// Skip parameter values
	numParams := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	for i := 0; i < numParams; i++ {
		if off+4 > len(payload) {
			return portalName, stmtName, payload, nil
		}
		pLen := int32(binary.BigEndian.Uint32(payload[off : off+4]))
		off += 4
		if pLen > 0 {
			off += int(pLen)
		}
	}
	if off+2 > len(payload) {
		return portalName, stmtName, payload, nil
	}
	// Replace result-column format codes section with count=1, code=0 (all text).
	out := make([]byte, off+4)
	copy(out[:off], payload[:off])
	binary.BigEndian.PutUint16(out[off:off+2], 1)
	binary.BigEndian.PutUint16(out[off+2:off+4], 0)
	return portalName, stmtName, out, nil
}

// BuildErrorResponse constructs a spec-compliant PostgreSQL ErrorResponse ('E') payload.
func BuildErrorResponse(severity, sqlState, message, detail, hint string) []byte {
	var b bytes.Buffer
	writeField := func(code byte, val string) {
		if val == "" {
			return
		}
		b.WriteByte(code)
		b.WriteString(val)
		b.WriteByte(0)
	}
	writeField('S', severity)
	writeField('V', severity)
	writeField('C', sqlState)
	writeField('M', message)
	writeField('D', detail)
	writeField('H', hint)
	b.WriteByte(0)
	return b.Bytes()
}

// BuildNoticeResponse constructs a PostgreSQL NoticeResponse ('N') payload.
func BuildNoticeResponse(severity, sqlState, message string) []byte {
	return BuildErrorResponse(severity, sqlState, message, "", "")
}

// BuildCommandComplete constructs a CommandComplete ('C') payload (e.g., "SELECT 25").
func BuildCommandComplete(tag string) []byte {
	out := make([]byte, len(tag)+1)
	copy(out, tag)
	return out
}

// BuildReadyForQuery constructs a ReadyForQuery ('Z') payload ('I'=idle, 'T'=in tx, 'E'=failed tx).
func BuildReadyForQuery(txStatus byte) []byte {
	if txStatus != 'I' && txStatus != 'T' && txStatus != 'E' {
		txStatus = 'I'
	}
	return []byte{txStatus}
}
