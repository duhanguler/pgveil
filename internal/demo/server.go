package demo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/duhanguler/pgveil/internal/pgwire"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// Server is a pure-Go, AST-backed in-memory PostgreSQL Wire Protocol v3 server powering `pgveil demo`.
// It requires zero external PostgreSQL or Docker dependencies and speaks real Simple & Extended
// Query protocols compatible with psql, pgx/v5, psycopg3, pgveil proxy, discover.Scan, and pgveil mcp.
type Server struct {
	mu       sync.RWMutex
	catalog  *Catalog
	listener net.Listener
	wg       sync.WaitGroup
}

// NewServer initializes a new in-memory demo PostgreSQL server pre-seeded with the synthetic dataset.
func NewServer() *Server {
	return &Server{
		catalog: NewCatalog(),
	}
}

// Start binds listenAddr (e.g. "127.0.0.1:0" for an ephemeral port) and serves connections until ctx is canceled.
func (s *Server) Start(ctx context.Context, listenAddr string) (string, error) {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", fmt.Errorf("demo server listen %s: %w", listenAddr, err)
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			s.wg.Add(1)
			go func(c net.Conn) {
				defer s.wg.Done()
				s.handleConn(ctx, c)
			}(conn)
		}
	}()

	return ln.Addr().String(), nil
}

// Addr returns the bound TCP address of the running demo server.
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Wait blocks until the listener and all active client sessions have closed.
func (s *Server) Wait() {
	s.wg.Wait()
}

type queryResult struct {
	fields     []pgwire.FieldDescription
	rows       [][]*string
	commandTag string
	hasRows    bool
}

type boundPortal struct {
	sql           string
	params        []*string
	resultFormats []uint16
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// 1. Handshake: SSLRequest / GSSENCRequest / StartupMessage
	var startup *pgwire.StartupPacket
	for {
		pkt, err := pgwire.ReadStartupPacket(conn)
		if err != nil {
			return
		}
		if pkt.Code == pgwire.SSLRequestCode || pkt.Code == pgwire.GSSENCRequestCode {
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
			continue
		}
		if pkt.Code == pgwire.CancelRequestCode {
			return
		}
		if pkt.Code != pgwire.ProtocolVersion30 {
			_ = pgwire.WriteMessage(conn, pgwire.MsgErrorResponse,
				pgwire.BuildErrorResponse("FATAL", "0A000", "unsupported protocol version", "", ""))
			return
		}
		startup = pkt
		break
	}
	_ = startup

	bw := bufio.NewWriterSize(conn, 32*1024)
	br := bufio.NewReaderSize(conn, 32*1024)

	// Send AuthenticationOk + standard ParameterStatus + BackendKeyData + ReadyForQuery
	_ = pgwire.WriteMessage(bw, pgwire.MsgAuth, []byte{0, 0, 0, 0})
	for _, kv := range [][2]string{
		{"server_version", "16.4 (pgveil-demo)"},
		{"server_encoding", "UTF8"},
		{"client_encoding", "UTF8"},
		{"standard_conforming_strings", "on"},
		{"DateStyle", "ISO, MDY"},
		{"TimeZone", "UTC"},
		{"integer_datetimes", "on"},
	} {
		p := append(append([]byte(kv[0]), 0), append([]byte(kv[1]), 0)...)
		_ = pgwire.WriteMessage(bw, pgwire.MsgParameterStatus, p)
	}
	var bk [8]byte
	binary.BigEndian.PutUint32(bk[0:4], 4242)
	binary.BigEndian.PutUint32(bk[4:8], 9999)
	_ = pgwire.WriteMessage(bw, pgwire.MsgBackendKeyData, bk[:])
	_ = pgwire.WriteMessage(bw, pgwire.MsgReadyForQuery, pgwire.BuildReadyForQuery('I'))
	if err := bw.Flush(); err != nil {
		return
	}

	stmts := make(map[string]string)
	portals := make(map[string]*boundPortal)
	inError := false

	// 2. Wire protocol loop (Simple + Extended Query)
	for {
		if ctx.Err() != nil {
			return
		}
		msgType, payload, err := pgwire.ReadMessage(br)
		if err != nil {
			return
		}

		switch msgType {
		case pgwire.MsgTerminate:
			return

		case pgwire.MsgQuery:
			sql := pgwire.ParseSimpleQuery(payload)
			s.handleSimpleQuery(bw, sql)
			if err := bw.Flush(); err != nil {
				return
			}

		case pgwire.MsgParse:
			if inError {
				continue
			}
			stmtName, query, perr := pgwire.ParseParseMessage(payload)
			if perr != nil {
				inError = true
				_ = pgwire.WriteMessage(bw, pgwire.MsgErrorResponse,
					pgwire.BuildErrorResponse("ERROR", "08P01", perr.Error(), "", ""))
				continue
			}
			if strings.TrimSpace(query) != "" {
				if _, perr := pg_query.Parse(query); perr != nil {
					inError = true
					_ = pgwire.WriteMessage(bw, pgwire.MsgErrorResponse,
						pgwire.BuildErrorResponse("ERROR", "42601", perr.Error(), "", ""))
					continue
				}
			}
			stmts[stmtName] = query
			_ = pgwire.WriteMessage(bw, pgwire.MsgParseComplete, nil)

		case pgwire.MsgBind:
			if inError {
				continue
			}
			portalName, stmtName, params, resFmts, berr := parseBindPayload(payload)
			if berr != nil {
				inError = true
				_ = pgwire.WriteMessage(bw, pgwire.MsgErrorResponse,
					pgwire.BuildErrorResponse("ERROR", "08P01", berr.Error(), "", ""))
				continue
			}
			q, ok := stmts[stmtName]
			if !ok {
				inError = true
				_ = pgwire.WriteMessage(bw, pgwire.MsgErrorResponse,
					pgwire.BuildErrorResponse("ERROR", "26000", fmt.Sprintf("prepared statement %q does not exist", stmtName), "", ""))
				continue
			}
			portals[portalName] = &boundPortal{sql: q, params: params, resultFormats: resFmts}
			_ = pgwire.WriteMessage(bw, pgwire.MsgBindComplete, nil)

		case pgwire.MsgDescribe:
			if inError {
				continue
			}
			if len(payload) < 1 {
				continue
			}
			kind := payload[0]
			name := pgwire.ParseSimpleQuery(payload[1:])
			if kind == 'S' {
				q := stmts[name]
				oids := s.inferParamOIDs(q)
				pBuf := make([]byte, 2+len(oids)*4)
				binary.BigEndian.PutUint16(pBuf[0:2], uint16(len(oids)))
				for i, oid := range oids {
					binary.BigEndian.PutUint32(pBuf[2+i*4:6+i*4], oid)
				}
				_ = pgwire.WriteMessage(bw, pgwire.MsgParameterDescription, pBuf)
				res, derr := s.describeSQL(q, nil)
				if derr != nil {
					_ = pgwire.WriteMessage(bw, pgwire.MsgNoData, nil)
				} else if res.hasRows {
					_ = pgwire.WriteMessage(bw, pgwire.MsgRowDescription, pgwire.EncodeRowDescription(res.fields))
				} else {
					_ = pgwire.WriteMessage(bw, pgwire.MsgNoData, nil)
				}
			} else {
				p := portals[name]
				if p == nil {
					_ = pgwire.WriteMessage(bw, pgwire.MsgNoData, nil)
					continue
				}
				res, derr := s.describeSQL(p.sql, p.resultFormats)
				if derr != nil || !res.hasRows {
					_ = pgwire.WriteMessage(bw, pgwire.MsgNoData, nil)
				} else {
					_ = pgwire.WriteMessage(bw, pgwire.MsgRowDescription, pgwire.EncodeRowDescription(res.fields))
				}
			}

		case pgwire.MsgExecute:
			if inError {
				continue
			}
			portalName := pgwire.ParseSimpleQuery(payload)
			p := portals[portalName]
			if p == nil {
				inError = true
				_ = pgwire.WriteMessage(bw, pgwire.MsgErrorResponse,
					pgwire.BuildErrorResponse("ERROR", "34000", fmt.Sprintf("portal %q does not exist", portalName), "", ""))
				continue
			}
			if strings.TrimSpace(p.sql) == "" {
				_ = pgwire.WriteMessage(bw, pgwire.MsgEmptyQuery, nil)
				continue
			}
			res, qerr := s.executeSQL(p.sql, p.params)
			if qerr != nil {
				inError = true
				_ = pgwire.WriteMessage(bw, pgwire.MsgErrorResponse,
					pgwire.BuildErrorResponse("ERROR", "42000", qerr.Error(), "", ""))
				continue
			}
			applyResultFormats(res.fields, p.resultFormats)
			if res.hasRows {
				for _, row := range res.rows {
					encoded := make([][]byte, len(row))
					for i, cell := range row {
						var oid uint32 = OIDText
						var fc uint16
						if i < len(res.fields) {
							oid = res.fields[i].DataTypeOID
							fc = res.fields[i].FormatCode
						}
						encoded[i] = encodeCell(cell, oid, fc)
					}
					_ = pgwire.WriteMessage(bw, pgwire.MsgDataRow, pgwire.EncodeDataRow(encoded))
				}
			}
			_ = pgwire.WriteMessage(bw, pgwire.MsgCommandComplete, pgwire.BuildCommandComplete(res.commandTag))

		case pgwire.MsgClose:
			if len(payload) >= 1 {
				kind := payload[0]
				name := pgwire.ParseSimpleQuery(payload[1:])
				if kind == 'S' {
					delete(stmts, name)
				} else {
					delete(portals, name)
				}
			}
			if !inError {
				_ = pgwire.WriteMessage(bw, pgwire.MsgCloseComplete, nil)
			}

		case pgwire.MsgFlush:
			if err := bw.Flush(); err != nil {
				return
			}

		case pgwire.MsgSync:
			inError = false
			_ = pgwire.WriteMessage(bw, pgwire.MsgReadyForQuery, pgwire.BuildReadyForQuery('I'))
			if err := bw.Flush(); err != nil {
				return
			}
		}
	}
}

func (s *Server) handleSimpleQuery(bw io.Writer, sql string) {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" || trimmed == ";" {
		_ = pgwire.WriteMessage(bw, pgwire.MsgEmptyQuery, nil)
		_ = pgwire.WriteMessage(bw, pgwire.MsgReadyForQuery, pgwire.BuildReadyForQuery('I'))
		return
	}

	tree, err := pg_query.Parse(trimmed)
	if err != nil {
		_ = pgwire.WriteMessage(bw, pgwire.MsgErrorResponse,
			pgwire.BuildErrorResponse("ERROR", "42601", err.Error(), "", ""))
		_ = pgwire.WriteMessage(bw, pgwire.MsgReadyForQuery, pgwire.BuildReadyForQuery('I'))
		return
	}
	if len(tree.Stmts) == 0 {
		_ = pgwire.WriteMessage(bw, pgwire.MsgEmptyQuery, nil)
		_ = pgwire.WriteMessage(bw, pgwire.MsgReadyForQuery, pgwire.BuildReadyForQuery('I'))
		return
	}

	for _, raw := range tree.Stmts {
		if raw == nil || raw.Stmt == nil {
			continue
		}
		res, qerr := s.executeStmt(raw.Stmt, nil)
		if qerr != nil {
			_ = pgwire.WriteMessage(bw, pgwire.MsgErrorResponse,
				pgwire.BuildErrorResponse("ERROR", "42000", qerr.Error(), "", ""))
			_ = pgwire.WriteMessage(bw, pgwire.MsgReadyForQuery, pgwire.BuildReadyForQuery('I'))
			return
		}
		if res.hasRows {
			_ = pgwire.WriteMessage(bw, pgwire.MsgRowDescription, pgwire.EncodeRowDescription(res.fields))
			for _, row := range res.rows {
				encoded := make([][]byte, len(row))
				for i, cell := range row {
					if cell != nil {
						encoded[i] = []byte(*cell)
					}
				}
				_ = pgwire.WriteMessage(bw, pgwire.MsgDataRow, pgwire.EncodeDataRow(encoded))
			}
		}
		_ = pgwire.WriteMessage(bw, pgwire.MsgCommandComplete, pgwire.BuildCommandComplete(res.commandTag))
	}
	_ = pgwire.WriteMessage(bw, pgwire.MsgReadyForQuery, pgwire.BuildReadyForQuery('I'))
}

func (s *Server) describeSQL(sql string, resultFormats []uint16) (*queryResult, error) {
	if strings.TrimSpace(sql) == "" {
		return &queryResult{}, nil
	}
	tree, err := pg_query.Parse(sql)
	if err != nil || len(tree.Stmts) == 0 || tree.Stmts[0].Stmt == nil {
		return nil, fmt.Errorf("cannot describe statement")
	}
	stmt := tree.Stmts[0].Stmt
	switch x := stmt.Node.(type) {
	case *pg_query.Node_SelectStmt:
		// Execute with empty params only to infer column names & OIDs cleanly (or infer from schema)
		s.mu.RLock()
		fields, ferr := s.inferSelectFields(x.SelectStmt, nil)
		s.mu.RUnlock()
		if ferr != nil {
			return nil, ferr
		}
		applyResultFormats(fields, resultFormats)
		return &queryResult{fields: fields, hasRows: true}, nil
	case *pg_query.Node_VariableShowStmt:
		name := strings.ToLower(x.VariableShowStmt.Name)
		if name == "" {
			name = "setting"
		}
		f := []pgwire.FieldDescription{{Name: name, DataTypeOID: OIDText, DataTypeSize: -1, TypeModifier: -1}}
		applyResultFormats(f, resultFormats)
		return &queryResult{fields: f, hasRows: true}, nil
	case *pg_query.Node_ExplainStmt:
		f := []pgwire.FieldDescription{{Name: "QUERY PLAN", DataTypeOID: OIDText, DataTypeSize: -1, TypeModifier: -1}}
		applyResultFormats(f, resultFormats)
		return &queryResult{fields: f, hasRows: true}, nil
	default:
		return &queryResult{hasRows: false}, nil
	}
}

func (s *Server) executeSQL(sql string, params []*string) (*queryResult, error) {
	tree, err := pg_query.Parse(sql)
	if err != nil {
		return nil, err
	}
	if len(tree.Stmts) == 0 || tree.Stmts[0].Stmt == nil {
		return &queryResult{commandTag: "OK"}, nil
	}
	return s.executeStmt(tree.Stmts[0].Stmt, params)
}

func (s *Server) executeStmt(stmt *pg_query.Node, params []*string) (*queryResult, error) {
	switch x := stmt.Node.(type) {
	case *pg_query.Node_SelectStmt:
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.execSelect(x.SelectStmt, params, nil)

	case *pg_query.Node_UpdateStmt:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.execUpdate(x.UpdateStmt, params)

	case *pg_query.Node_DeleteStmt:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.execDelete(x.DeleteStmt, params)

	case *pg_query.Node_ExplainStmt:
		return s.execExplain(x.ExplainStmt), nil

	case *pg_query.Node_VariableShowStmt:
		name := strings.ToLower(x.VariableShowStmt.Name)
		val := "on"
		switch name {
		case "server_version":
			val = "16.4 (pgveil-demo)"
		case "server_encoding", "client_encoding":
			val = "UTF8"
		case "transaction_isolation":
			val = "read committed"
		case "search_path":
			val = `"$user", public`
		}
		return &queryResult{
			fields:     []pgwire.FieldDescription{{Name: name, DataTypeOID: OIDText, DataTypeSize: -1, TypeModifier: -1}},
			rows:       [][]*string{{sp(val)}},
			commandTag: "SHOW",
			hasRows:    true,
		}, nil

	case *pg_query.Node_VariableSetStmt:
		return &queryResult{commandTag: "SET"}, nil

	case *pg_query.Node_TransactionStmt:
		switch x.TransactionStmt.Kind {
		case pg_query.TransactionStmtKind_TRANS_STMT_BEGIN, pg_query.TransactionStmtKind_TRANS_STMT_START:
			return &queryResult{commandTag: "BEGIN"}, nil
		case pg_query.TransactionStmtKind_TRANS_STMT_COMMIT:
			return &queryResult{commandTag: "COMMIT"}, nil
		case pg_query.TransactionStmtKind_TRANS_STMT_ROLLBACK:
			return &queryResult{commandTag: "ROLLBACK"}, nil
		default:
			return &queryResult{commandTag: "OK"}, nil
		}

	case *pg_query.Node_DeallocateStmt:
		return &queryResult{commandTag: "DEALLOCATE"}, nil
	case *pg_query.Node_DiscardStmt:
		return &queryResult{commandTag: "DISCARD"}, nil
	case *pg_query.Node_ClosePortalStmt:
		return &queryResult{commandTag: "CLOSE CURSOR"}, nil

	default:
		return nil, fmt.Errorf("unsupported statement in pgveil demo engine")
	}
}

// ---------- In-Memory Relational AST Engine ----------

type rowCol struct {
	qualifier string // lowercased alias or table name
	name      string // lowercased column name
	origName  string
	colDef    ColumnDef
}

type rowEnv struct {
	cols []rowCol
	vals []*string
}

func (e *rowEnv) lookup(qualifier, col string) (*string, bool) {
	lq := strings.ToLower(qualifier)
	lc := strings.ToLower(col)
	for i, c := range e.cols {
		if c.name == lc && (lq == "" || c.qualifier == lq) {
			return e.vals[i], true
		}
	}
	return nil, false
}

func (s *Server) resolveSource(rv *pg_query.RangeVar, ctes map[string]*Table) (*Table, string, error) {
	if rv == nil {
		return nil, "", errors.New("missing table reference")
	}
	bare := strings.ToLower(rv.Relname)
	alias := bare
	if rv.Alias != nil && rv.Alias.Aliasname != "" {
		alias = strings.ToLower(rv.Alias.Aliasname)
	}
	if rv.Schemaname == "" && ctes != nil {
		if cteTbl, ok := ctes[bare]; ok {
			return cteTbl, alias, nil
		}
	}
	tbl := s.catalog.ResolveTable(rv.Schemaname, rv.Relname)
	if tbl == nil {
		full := rv.Relname
		if rv.Schemaname != "" {
			full = rv.Schemaname + "." + rv.Relname
		}
		return nil, "", fmt.Errorf("relation %q does not exist", full)
	}
	return tbl, alias, nil
}

func tableToRows(tbl *Table, alias string) ([]rowCol, []rowEnv) {
	cols := make([]rowCol, len(tbl.Columns))
	for i, c := range tbl.Columns {
		cols[i] = rowCol{
			qualifier: strings.ToLower(alias),
			name:      strings.ToLower(c.Name),
			origName:  c.Name,
			colDef:    c,
		}
	}
	envs := make([]rowEnv, len(tbl.Rows))
	for i, r := range tbl.Rows {
		cp := make([]*string, len(r))
		copy(cp, r)
		envs[i] = rowEnv{cols: cols, vals: cp}
	}
	return cols, envs
}

func (s *Server) evalFromNode(n *pg_query.Node, params []*string, ctes map[string]*Table) ([]rowCol, []rowEnv, error) {
	switch x := n.Node.(type) {
	case *pg_query.Node_RangeVar:
		tbl, alias, err := s.resolveSource(x.RangeVar, ctes)
		if err != nil {
			return nil, nil, err
		}
		cols, envs := tableToRows(tbl, alias)
		return cols, envs, nil

	case *pg_query.Node_RangeSubselect:
		subSel := x.RangeSubselect.Subquery.GetSelectStmt()
		if subSel == nil {
			return nil, nil, errors.New("unsupported subquery in FROM")
		}
		res, err := s.execSelect(subSel, params, ctes)
		if err != nil {
			return nil, nil, err
		}
		alias := "subquery"
		if x.RangeSubselect.Alias != nil && x.RangeSubselect.Alias.Aliasname != "" {
			alias = strings.ToLower(x.RangeSubselect.Alias.Aliasname)
		}
		subTbl := resultToTable(alias, res)
		cols, envs := tableToRows(subTbl, alias)
		return cols, envs, nil

	case *pg_query.Node_JoinExpr:
		je := x.JoinExpr
		lCols, lRows, err := s.evalFromNode(je.Larg, params, ctes)
		if err != nil {
			return nil, nil, err
		}
		rCols, rRows, err := s.evalFromNode(je.Rarg, params, ctes)
		if err != nil {
			return nil, nil, err
		}
		mergedCols := make([]rowCol, 0, len(lCols)+len(rCols))
		mergedCols = append(mergedCols, lCols...)
		mergedCols = append(mergedCols, rCols...)

		var out []rowEnv
		rMatched := make([]bool, len(rRows))
		for _, lr := range lRows {
			lHit := false
			for ri, rr := range rRows {
				vals := make([]*string, 0, len(lr.vals)+len(rr.vals))
				vals = append(vals, lr.vals...)
				vals = append(vals, rr.vals...)
				cand := rowEnv{cols: mergedCols, vals: vals}
				ok := true
				if je.Quals != nil {
					ok = s.evalBool(je.Quals, &cand, params, ctes)
				}
				if ok {
					out = append(out, cand)
					lHit = true
					rMatched[ri] = true
				}
			}
			if !lHit && (je.Jointype == pg_query.JoinType_JOIN_LEFT || je.Jointype == pg_query.JoinType_JOIN_FULL) {
				vals := make([]*string, len(lCols)+len(rCols))
				copy(vals, lr.vals)
				out = append(out, rowEnv{cols: mergedCols, vals: vals})
			}
		}
		if je.Jointype == pg_query.JoinType_JOIN_RIGHT || je.Jointype == pg_query.JoinType_JOIN_FULL {
			for ri, rr := range rRows {
				if !rMatched[ri] {
					vals := make([]*string, len(lCols)+len(rCols))
					copy(vals[len(lCols):], rr.vals)
					out = append(out, rowEnv{cols: mergedCols, vals: vals})
				}
			}
		}
		return mergedCols, out, nil
	}
	return nil, nil, errors.New("unsupported FROM clause node")
}

func (s *Server) evalFromClause(from []*pg_query.Node, params []*string, ctes map[string]*Table) ([]rowCol, []rowEnv, error) {
	if len(from) == 0 {
		return nil, []rowEnv{{}}, nil
	}
	cols, rows, err := s.evalFromNode(from[0], params, ctes)
	if err != nil {
		return nil, nil, err
	}
	for _, fc := range from[1:] {
		rCols, rRows, err := s.evalFromNode(fc, params, ctes)
		if err != nil {
			return nil, nil, err
		}
		merged := append(append([]rowCol{}, cols...), rCols...)
		var next []rowEnv
		for _, lr := range rows {
			for _, rr := range rRows {
				vals := append(append([]*string{}, lr.vals...), rr.vals...)
				next = append(next, rowEnv{cols: merged, vals: vals})
			}
		}
		cols = merged
		rows = next
	}
	return cols, rows, nil
}

func (s *Server) inferSelectFields(sel *pg_query.SelectStmt, ctes map[string]*Table) ([]pgwire.FieldDescription, error) {
	if sel.Larg != nil {
		return s.inferSelectFields(sel.Larg, ctes)
	}
	// Resolve FROM columns without running full data scan where possible
	var fromCols []rowCol
	for _, fc := range sel.FromClause {
		c, err := s.inferFromCols(fc, ctes)
		if err == nil {
			fromCols = append(fromCols, c...)
		}
	}
	return buildTargetFields(sel.TargetList, fromCols), nil
}

func (s *Server) inferFromCols(n *pg_query.Node, ctes map[string]*Table) ([]rowCol, error) {
	switch x := n.Node.(type) {
	case *pg_query.Node_RangeVar:
		tbl, alias, err := s.resolveSource(x.RangeVar, ctes)
		if err != nil {
			return nil, err
		}
		cols := make([]rowCol, len(tbl.Columns))
		for i, c := range tbl.Columns {
			cols[i] = rowCol{qualifier: alias, name: strings.ToLower(c.Name), origName: c.Name, colDef: c}
		}
		return cols, nil
	case *pg_query.Node_JoinExpr:
		lc, _ := s.inferFromCols(x.JoinExpr.Larg, ctes)
		rc, _ := s.inferFromCols(x.JoinExpr.Rarg, ctes)
		return append(lc, rc...), nil
	}
	return nil, nil
}

func buildTargetFields(targets []*pg_query.Node, fromCols []rowCol) []pgwire.FieldDescription {
	var fields []pgwire.FieldDescription
	for idx, tn := range targets {
		rt := tn.GetResTarget()
		if rt == nil {
			continue
		}
		if cr := rt.Val.GetColumnRef(); cr != nil {
			if len(cr.Fields) == 1 && cr.Fields[0].GetAStar() != nil {
				for _, fc := range fromCols {
					fields = append(fields, colDefToField(fc.colDef))
				}
				continue
			}
			if len(cr.Fields) == 2 && cr.Fields[1].GetAStar() != nil {
				qual := strings.ToLower(cr.Fields[0].GetString_().GetSval())
				for _, fc := range fromCols {
					if fc.qualifier == qual {
						fields = append(fields, colDefToField(fc.colDef))
					}
				}
				continue
			}
		}
		name, colDef := inferTargetMeta(rt, fromCols, idx)
		fd := colDefToField(colDef)
		fd.Name = name
		fields = append(fields, fd)
	}
	return fields
}

func colDefToField(cd ColumnDef) pgwire.FieldDescription {
	oid := cd.OID
	if oid == 0 {
		oid = OIDText
	}
	size := cd.TypeSize
	if size == 0 {
		size = -1
	}
	return pgwire.FieldDescription{
		Name:         cd.Name,
		DataTypeOID:  oid,
		DataTypeSize: size,
		TypeModifier: -1,
		FormatCode:   0,
	}
}

func inferTargetMeta(rt *pg_query.ResTarget, fromCols []rowCol, idx int) (string, ColumnDef) {
	def := ColumnDef{OID: OIDText, TypeSize: -1}
	name := rt.Name

	val := rt.Val
	if tc := val.GetTypeCast(); tc != nil {
		// Unwrap `col::text`
		if name == "" {
			if cr := tc.Arg.GetColumnRef(); cr != nil && len(cr.Fields) > 0 {
				if st := cr.Fields[len(cr.Fields)-1].GetString_(); st != nil {
					name = st.Sval
				}
			}
		}
		if name == "" {
			name = fmt.Sprintf("column_%d", idx+1)
		}
		return name, def
	}

	if cr := val.GetColumnRef(); cr != nil && len(cr.Fields) > 0 {
		var qual, col string
		if len(cr.Fields) == 1 {
			col = cr.Fields[0].GetString_().GetSval()
		} else {
			qual = cr.Fields[len(cr.Fields)-2].GetString_().GetSval()
			col = cr.Fields[len(cr.Fields)-1].GetString_().GetSval()
		}
		if name == "" {
			name = col
		}
		lq, lc := strings.ToLower(qual), strings.ToLower(col)
		for _, fc := range fromCols {
			if fc.name == lc && (lq == "" || fc.qualifier == lq) {
				def = fc.colDef
				break
			}
		}
		return name, def
	}

	if fc := val.GetFuncCall(); fc != nil && len(fc.Funcname) > 0 {
		fn := strings.ToLower(fc.Funcname[len(fc.Funcname)-1].GetString_().GetSval())
		if name == "" {
			name = fn
		}
		if fn == "count" {
			def = ColumnDef{OID: OIDInt4, TypeSize: 4}
		}
		return name, def
	}

	if ac := val.GetAConst(); ac != nil && ac.GetIval() != nil {
		if name == "" {
			name = "?column?"
		}
		return name, ColumnDef{OID: OIDInt4, TypeSize: 4}
	}

	if name == "" {
		name = fmt.Sprintf("?column_%d?", idx+1)
	}
	return name, def
}

func (s *Server) execSelect(sel *pg_query.SelectStmt, params []*string, parentCTEs map[string]*Table) (*queryResult, error) {
	// Materialize CTEs
	ctes := make(map[string]*Table, len(parentCTEs)+2)
	for k, v := range parentCTEs {
		ctes[k] = v
	}
	if sel.WithClause != nil {
		for _, cn := range sel.WithClause.Ctes {
			cte := cn.GetCommonTableExpr()
			if cte == nil || cte.Ctequery == nil {
				continue
			}
			cteSel := cte.Ctequery.GetSelectStmt()
			if cteSel == nil {
				continue
			}
			res, err := s.execSelect(cteSel, params, ctes)
			if err != nil {
				return nil, err
			}
			ctes[strings.ToLower(cte.Ctename)] = resultToTable(cte.Ctename, res)
		}
	}

	// Set operations (UNION / UNION ALL)
	if sel.Larg != nil && sel.Rarg != nil {
		lRes, err := s.execSelect(sel.Larg, params, ctes)
		if err != nil {
			return nil, err
		}
		rRes, err := s.execSelect(sel.Rarg, params, ctes)
		if err != nil {
			return nil, err
		}
		rows := append(append([][]*string{}, lRes.rows...), rRes.rows...)
		if !sel.All {
			rows = dedupeRows(rows)
		}
		return &queryResult{
			fields:     lRes.fields,
			rows:       rows,
			commandTag: fmt.Sprintf("SELECT %d", len(rows)),
			hasRows:    true,
		}, nil
	}

	fromCols, envs, err := s.evalFromClause(sel.FromClause, params, ctes)
	if err != nil {
		return nil, err
	}

	// Filter WHERE
	var filtered []rowEnv
	if sel.WhereClause == nil {
		filtered = envs
	} else {
		for i := range envs {
			if s.evalBool(sel.WhereClause, &envs[i], params, ctes) {
				filtered = append(filtered, envs[i])
			}
		}
	}

	fields := buildTargetFields(sel.TargetList, fromCols)

	// Detect aggregate queries (e.g. SELECT COUNT(*) FROM customers)
	hasAgg := false
	for _, tn := range sel.TargetList {
		if rt := tn.GetResTarget(); rt != nil && containsAggregate(rt.Val) {
			hasAgg = true
			break
		}
	}

	var projected [][]*string
	if hasAgg || len(sel.GroupClause) > 0 {
		projected = s.execAggregate(sel, filtered, params, ctes)
	} else {
		// Apply ORDER BY before projection (so ORDER BY col not in SELECT list still works!)
		if len(sel.SortClause) > 0 {
			s.sortEnvs(filtered, sel.SortClause, sel.TargetList, params, ctes)
		}
		projected = make([][]*string, 0, len(filtered))
		for i := range filtered {
			row := s.projectRow(sel.TargetList, &filtered[i], params, ctes)
			projected = append(projected, row)
		}
	}

	if len(sel.DistinctClause) > 0 {
		projected = dedupeRows(projected)
	}

	// Apply OFFSET and LIMIT
	if sel.LimitOffset != nil {
		if v := s.evalExpr(sel.LimitOffset, nil, params, ctes); v != nil {
			if off, err := strconv.Atoi(*v); err == nil && off > 0 {
				if off >= len(projected) {
					projected = nil
				} else {
					projected = projected[off:]
				}
			}
		}
	}
	if sel.LimitCount != nil {
		if v := s.evalExpr(sel.LimitCount, nil, params, ctes); v != nil {
			if lim, err := strconv.Atoi(*v); err == nil && lim >= 0 && lim < len(projected) {
				projected = projected[:lim]
			}
		}
	}

	return &queryResult{
		fields:     fields,
		rows:       projected,
		commandTag: fmt.Sprintf("SELECT %d", len(projected)),
		hasRows:    true,
	}, nil
}

func (s *Server) projectRow(targets []*pg_query.Node, env *rowEnv, params []*string, ctes map[string]*Table) []*string {
	var out []*string
	for _, tn := range targets {
		rt := tn.GetResTarget()
		if rt == nil {
			continue
		}
		if cr := rt.Val.GetColumnRef(); cr != nil {
			if len(cr.Fields) == 1 && cr.Fields[0].GetAStar() != nil {
				out = append(out, env.vals...)
				continue
			}
			if len(cr.Fields) == 2 && cr.Fields[1].GetAStar() != nil {
				qual := strings.ToLower(cr.Fields[0].GetString_().GetSval())
				for i, c := range env.cols {
					if c.qualifier == qual {
						out = append(out, env.vals[i])
					}
				}
				continue
			}
		}
		out = append(out, s.evalExpr(rt.Val, env, params, ctes))
	}
	return out
}

func (s *Server) execAggregate(sel *pg_query.SelectStmt, envs []rowEnv, params []*string, ctes map[string]*Table) [][]*string {
	type group struct {
		key  string
		rows []rowEnv
	}
	var groups []*group
	byKey := make(map[string]*group)

	if len(sel.GroupClause) == 0 {
		groups = []*group{{key: "", rows: envs}}
	} else {
		for _, env := range envs {
			var parts []string
			for _, g := range sel.GroupClause {
				v := s.evalExpr(g, &env, params, ctes)
				if v == nil {
					parts = append(parts, "\x00NULL")
				} else {
					parts = append(parts, *v)
				}
			}
			k := strings.Join(parts, "\x1f")
			gr, ok := byKey[k]
			if !ok {
				gr = &group{key: k}
				byKey[k] = gr
				groups = append(groups, gr)
			}
			gr.rows = append(gr.rows, env)
		}
	}

	var out [][]*string
	for _, gr := range groups {
		var row []*string
		for _, tn := range sel.TargetList {
			rt := tn.GetResTarget()
			if rt == nil {
				continue
			}
			row = append(row, s.evalAggExpr(rt.Val, gr.rows, params, ctes))
		}
		out = append(out, row)
	}
	return out
}

func (s *Server) evalAggExpr(n *pg_query.Node, groupRows []rowEnv, params []*string, ctes map[string]*Table) *string {
	if fc := n.GetFuncCall(); fc != nil && len(fc.Funcname) > 0 {
		fn := strings.ToLower(fc.Funcname[len(fc.Funcname)-1].GetString_().GetSval())
		switch fn {
		case "count":
			if fc.AggStar || len(fc.Args) == 0 {
				return sp(strconv.Itoa(len(groupRows)))
			}
			cnt := 0
			for i := range groupRows {
				if s.evalExpr(fc.Args[0], &groupRows[i], params, ctes) != nil {
					cnt++
				}
			}
			return sp(strconv.Itoa(cnt))
		case "sum", "avg":
			sum := 0.0
			cnt := 0
			for i := range groupRows {
				if v := s.evalExpr(fc.Args[0], &groupRows[i], params, ctes); v != nil {
					if f, err := strconv.ParseFloat(*v, 64); err == nil {
						sum += f
						cnt++
					}
				}
			}
			if cnt == 0 {
				return nil
			}
			if fn == "avg" {
				return sp(fmt.Sprintf("%.2f", sum/float64(cnt)))
			}
			if math.Mod(sum, 1) == 0 {
				return sp(fmt.Sprintf("%.0f", sum))
			}
			return sp(fmt.Sprintf("%.2f", sum))
		case "min", "max":
			var best *string
			for i := range groupRows {
				v := s.evalExpr(fc.Args[0], &groupRows[i], params, ctes)
				if v == nil {
					continue
				}
				if best == nil {
					best = v
				} else {
					cmp := compareStrings(*v, *best)
					if (fn == "min" && cmp < 0) || (fn == "max" && cmp > 0) {
						best = v
					}
				}
			}
			return best
		}
	}
	if len(groupRows) > 0 {
		return s.evalExpr(n, &groupRows[0], params, ctes)
	}
	return s.evalExpr(n, nil, params, ctes)
}

func (s *Server) execUpdate(upd *pg_query.UpdateStmt, params []*string) (*queryResult, error) {
	tbl, alias, err := s.resolveSource(upd.Relation, nil)
	if err != nil {
		return nil, err
	}
	cols, envs := tableToRows(tbl, alias)
	colIdx := make(map[string]int, len(cols))
	for i, c := range cols {
		colIdx[c.name] = i
	}
	updated := 0
	for i := range envs {
		if upd.WhereClause == nil || s.evalBool(upd.WhereClause, &envs[i], params, nil) {
			for _, tn := range upd.TargetList {
				rt := tn.GetResTarget()
				if rt == nil {
					continue
				}
				idx, ok := colIdx[strings.ToLower(rt.Name)]
				if !ok {
					return nil, fmt.Errorf("column %q of relation %q does not exist", rt.Name, tbl.Name)
				}
				tbl.Rows[i][idx] = s.evalExpr(rt.Val, &envs[i], params, nil)
			}
			updated++
		}
	}
	return &queryResult{commandTag: fmt.Sprintf("UPDATE %d", updated)}, nil
}

func (s *Server) execDelete(del *pg_query.DeleteStmt, params []*string) (*queryResult, error) {
	tbl, alias, err := s.resolveSource(del.Relation, nil)
	if err != nil {
		return nil, err
	}
	_, envs := tableToRows(tbl, alias)
	kept := make([][]*string, 0, len(tbl.Rows))
	deleted := 0
	for i := range envs {
		if del.WhereClause == nil || s.evalBool(del.WhereClause, &envs[i], params, nil) {
			deleted++
			continue
		}
		kept = append(kept, tbl.Rows[i])
	}
	tbl.Rows = kept
	return &queryResult{commandTag: fmt.Sprintf("DELETE %d", deleted)}, nil
}

func (s *Server) sortEnvs(envs []rowEnv, sortClauses []*pg_query.Node, targets []*pg_query.Node, params []*string, ctes map[string]*Table) {
	sort.SliceStable(envs, func(i, j int) bool {
		for _, sn := range sortClauses {
			sb := sn.GetSortBy()
			if sb == nil {
				continue
			}
			expr := sb.Node
			// Support positional ORDER BY 1, 2
			if ac := expr.GetAConst(); ac != nil && ac.GetIval() != nil {
				pos := int(ac.GetIval().Ival) - 1
				if pos >= 0 && pos < len(targets) {
					if rt := targets[pos].GetResTarget(); rt != nil {
						expr = rt.Val
					}
				}
			}
			vi := s.evalExpr(expr, &envs[i], params, ctes)
			vj := s.evalExpr(expr, &envs[j], params, ctes)
			if vi == nil && vj == nil {
				continue
			}
			desc := sb.SortbyDir == pg_query.SortByDir_SORTBY_DESC
			if vi == nil {
				return desc
			}
			if vj == nil {
				return !desc
			}
			cmp := compareStrings(*vi, *vj)
			if cmp == 0 {
				continue
			}
			if desc {
				return cmp > 0
			}
			return cmp < 0
		}
		return false
	})
}

func (s *Server) evalBool(n *pg_query.Node, env *rowEnv, params []*string, ctes map[string]*Table) bool {
	if n == nil {
		return true
	}
	switch x := n.Node.(type) {
	case *pg_query.Node_BoolExpr:
		switch x.BoolExpr.Boolop {
		case pg_query.BoolExprType_AND_EXPR:
			for _, a := range x.BoolExpr.Args {
				if !s.evalBool(a, env, params, ctes) {
					return false
				}
			}
			return true
		case pg_query.BoolExprType_OR_EXPR:
			for _, a := range x.BoolExpr.Args {
				if s.evalBool(a, env, params, ctes) {
					return true
				}
			}
			return false
		case pg_query.BoolExprType_NOT_EXPR:
			if len(x.BoolExpr.Args) == 1 {
				return !s.evalBool(x.BoolExpr.Args[0], env, params, ctes)
			}
		}

	case *pg_query.Node_NullTest:
		val := s.evalExpr(x.NullTest.Arg, env, params, ctes)
		if x.NullTest.Nulltesttype == pg_query.NullTestType_IS_NULL {
			return val == nil
		}
		return val != nil

	case *pg_query.Node_BooleanTest:
		b := s.evalBool(x.BooleanTest.Arg, env, params, ctes)
		switch x.BooleanTest.Booltesttype {
		case pg_query.BoolTestType_IS_TRUE, pg_query.BoolTestType_IS_NOT_FALSE:
			return b
		case pg_query.BoolTestType_IS_FALSE, pg_query.BoolTestType_IS_NOT_TRUE:
			return !b
		}

	case *pg_query.Node_SubLink:
		subSel := x.SubLink.Subselect.GetSelectStmt()
		if subSel == nil {
			return false
		}
		res, err := s.execSelect(subSel, params, ctes)
		if err != nil {
			return false
		}
		if x.SubLink.SubLinkType == pg_query.SubLinkType_EXISTS_SUBLINK {
			return len(res.rows) > 0
		}
		if x.SubLink.SubLinkType == pg_query.SubLinkType_ANY_SUBLINK {
			lv := s.evalExpr(x.SubLink.Testexpr, env, params, ctes)
			if lv == nil {
				return false
			}
			for _, r := range res.rows {
				if len(r) > 0 && r[0] != nil && compareStrings(*lv, *r[0]) == 0 {
					return true
				}
			}
			return false
		}

	case *pg_query.Node_AExpr:
		ae := x.AExpr
		op := ""
		if len(ae.Name) > 0 {
			op = ae.Name[len(ae.Name)-1].GetString_().GetSval()
		}
		lv := s.evalExpr(ae.Lexpr, env, params, ctes)
		switch ae.Kind {
		case pg_query.A_Expr_Kind_AEXPR_IN:
			if lv == nil {
				return false
			}
			matched := false
			if list := ae.Rexpr.GetList(); list != nil {
				for _, it := range list.Items {
					rv := s.evalExpr(it, env, params, ctes)
					if rv != nil && compareStrings(*lv, *rv) == 0 {
						matched = true
						break
					}
				}
			}
			if op == "<>" {
				return !matched
			}
			return matched

		case pg_query.A_Expr_Kind_AEXPR_LIKE:
			rv := s.evalExpr(ae.Rexpr, env, params, ctes)
			if lv == nil || rv == nil {
				return false
			}
			m := sqlLikeMatch(*lv, *rv, false)
			if op == "!~~" {
				return !m
			}
			return m

		case pg_query.A_Expr_Kind_AEXPR_ILIKE:
			rv := s.evalExpr(ae.Rexpr, env, params, ctes)
			if lv == nil || rv == nil {
				return false
			}
			m := sqlLikeMatch(*lv, *rv, true)
			if op == "!~~*" {
				return !m
			}
			return m

		case pg_query.A_Expr_Kind_AEXPR_BETWEEN, pg_query.A_Expr_Kind_AEXPR_NOT_BETWEEN:
			if lv == nil {
				return false
			}
			if list := ae.Rexpr.GetList(); list != nil && len(list.Items) == 2 {
				lo := s.evalExpr(list.Items[0], env, params, ctes)
				hi := s.evalExpr(list.Items[1], env, params, ctes)
				if lo == nil || hi == nil {
					return false
				}
				inRange := compareStrings(*lv, *lo) >= 0 && compareStrings(*lv, *hi) <= 0
				if ae.Kind == pg_query.A_Expr_Kind_AEXPR_NOT_BETWEEN {
					return !inRange
				}
				return inRange
			}

		default:
			rv := s.evalExpr(ae.Rexpr, env, params, ctes)
			if lv == nil || rv == nil {
				return false
			}
			cmp := compareStrings(*lv, *rv)
			switch op {
			case "=":
				return cmp == 0
			case "<>", "!=":
				return cmp != 0
			case "<":
				return cmp < 0
			case "<=":
				return cmp <= 0
			case ">":
				return cmp > 0
			case ">=":
				return cmp >= 0
			}
		}

	case *pg_query.Node_AConst:
		if b := x.AConst.GetBoolval(); b != nil {
			return b.Boolval
		}
	}

	v := s.evalExpr(n, env, params, ctes)
	return v != nil && (strings.EqualFold(*v, "true") || *v == "t" || *v == "1")
}

func (s *Server) evalExpr(n *pg_query.Node, env *rowEnv, params []*string, ctes map[string]*Table) *string {
	if n == nil {
		return nil
	}
	switch x := n.Node.(type) {
	case *pg_query.Node_AConst:
		ac := x.AConst
		if ac.Isnull {
			return nil
		}
		if sv := ac.GetSval(); sv != nil {
			return sp(sv.Sval)
		}
		if iv := ac.GetIval(); iv != nil {
			return sp(strconv.FormatInt(int64(iv.Ival), 10))
		}
		if fv := ac.GetFval(); fv != nil {
			return sp(fv.Fval)
		}
		if bv := ac.GetBoolval(); bv != nil {
			if bv.Boolval {
				return sp("true")
			}
			return sp("false")
		}

	case *pg_query.Node_ParamRef:
		idx := int(x.ParamRef.Number) - 1
		if idx >= 0 && idx < len(params) {
			return params[idx]
		}
		return nil

	case *pg_query.Node_ColumnRef:
		if env == nil {
			return nil
		}
		fields := x.ColumnRef.Fields
		if len(fields) == 1 {
			if st := fields[0].GetString_(); st != nil {
				v, _ := env.lookup("", st.Sval)
				return v
			}
		} else if len(fields) >= 2 {
			q := fields[len(fields)-2].GetString_().GetSval()
			c := fields[len(fields)-1].GetString_().GetSval()
			v, _ := env.lookup(q, c)
			return v
		}

	case *pg_query.Node_TypeCast:
		return s.evalExpr(x.TypeCast.Arg, env, params, ctes)

	case *pg_query.Node_CoalesceExpr:
		for _, a := range x.CoalesceExpr.Args {
			if v := s.evalExpr(a, env, params, ctes); v != nil {
				return v
			}
		}
		return nil

	case *pg_query.Node_CaseExpr:
		for _, w := range x.CaseExpr.Args {
			if cw := w.GetCaseWhen(); cw != nil {
				if s.evalBool(cw.Expr, env, params, ctes) {
					return s.evalExpr(cw.Result, env, params, ctes)
				}
			}
		}
		return s.evalExpr(x.CaseExpr.Defresult, env, params, ctes)

	case *pg_query.Node_AExpr:
		op := ""
		if len(x.AExpr.Name) > 0 {
			op = x.AExpr.Name[len(x.AExpr.Name)-1].GetString_().GetSval()
		}
		lv := s.evalExpr(x.AExpr.Lexpr, env, params, ctes)
		rv := s.evalExpr(x.AExpr.Rexpr, env, params, ctes)
		if op == "||" {
			if lv == nil || rv == nil {
				return nil
			}
			return sp(*lv + *rv)
		}
		if lv != nil && rv != nil {
			lf, e1 := strconv.ParseFloat(*lv, 64)
			rf, e2 := strconv.ParseFloat(*rv, 64)
			if e1 == nil && e2 == nil {
				var out float64
				switch op {
				case "+":
					out = lf + rf
				case "-":
					out = lf - rf
				case "*":
					out = lf * rf
				case "/":
					if rf == 0 {
						return nil
					}
					out = lf / rf
				default:
					return nil
				}
				if math.Mod(out, 1) == 0 {
					return sp(fmt.Sprintf("%.0f", out))
				}
				return sp(fmt.Sprintf("%.2f", out))
			}
		}

	case *pg_query.Node_FuncCall:
		if len(x.FuncCall.Funcname) == 0 {
			return nil
		}
		fn := strings.ToLower(x.FuncCall.Funcname[len(x.FuncCall.Funcname)-1].GetString_().GetSval())
		switch fn {
		case "current_database":
			return sp(s.catalog.Database)
		case "version":
			return sp("PostgreSQL 16.4 (pgveil-demo embedded sandbox)")
		case "now":
			return sp("2026-11-21 12:00:00+00")
		case "lower":
			if len(x.FuncCall.Args) >= 1 {
				if v := s.evalExpr(x.FuncCall.Args[0], env, params, ctes); v != nil {
					return sp(strings.ToLower(*v))
				}
			}
		case "upper":
			if len(x.FuncCall.Args) >= 1 {
				if v := s.evalExpr(x.FuncCall.Args[0], env, params, ctes); v != nil {
					return sp(strings.ToUpper(*v))
				}
			}
		case "trim", "btrim":
			if len(x.FuncCall.Args) >= 1 {
				if v := s.evalExpr(x.FuncCall.Args[0], env, params, ctes); v != nil {
					return sp(strings.TrimSpace(*v))
				}
			}
		case "length", "char_length":
			if len(x.FuncCall.Args) >= 1 {
				if v := s.evalExpr(x.FuncCall.Args[0], env, params, ctes); v != nil {
					return sp(strconv.Itoa(len([]rune(*v))))
				}
			}
		case "substring", "substr":
			if len(x.FuncCall.Args) >= 2 {
				v := s.evalExpr(x.FuncCall.Args[0], env, params, ctes)
				startS := s.evalExpr(x.FuncCall.Args[1], env, params, ctes)
				if v != nil && startS != nil {
					runes := []rune(*v)
					start, _ := strconv.Atoi(*startS)
					if start < 1 {
						start = 1
					}
					idx := start - 1
					if idx >= len(runes) {
						return sp("")
					}
					if len(x.FuncCall.Args) >= 3 {
						if lenS := s.evalExpr(x.FuncCall.Args[2], env, params, ctes); lenS != nil {
							ln, _ := strconv.Atoi(*lenS)
							if ln < 0 {
								ln = 0
							}
							end := idx + ln
							if end > len(runes) {
								end = len(runes)
							}
							return sp(string(runes[idx:end]))
						}
					}
					return sp(string(runes[idx:]))
				}
			}
		}

	case *pg_query.Node_SubLink:
		if subSel := x.SubLink.Subselect.GetSelectStmt(); subSel != nil {
			if res, err := s.execSelect(subSel, params, ctes); err == nil && len(res.rows) > 0 && len(res.rows[0]) > 0 {
				return res.rows[0][0]
			}
		}
	}
	return nil
}

// ---------- Wire & Helper Utilities ----------

func parseBindPayload(payload []byte) (portalName, stmtName string, params []*string, resultFormats []uint16, err error) {
	n1 := bytes.IndexByte(payload, 0)
	if n1 < 0 {
		return "", "", nil, nil, errors.New("invalid Bind: missing portal name")
	}
	portalName = string(payload[:n1])
	off := n1 + 1
	n2 := bytes.IndexByte(payload[off:], 0)
	if n2 < 0 {
		return "", "", nil, nil, errors.New("invalid Bind: missing stmt name")
	}
	stmtName = string(payload[off : off+n2])
	off += n2 + 1

	if off+2 > len(payload) {
		return portalName, stmtName, nil, nil, nil
	}
	numParamFmts := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	paramFmts := make([]uint16, numParamFmts)
	for i := 0; i < numParamFmts; i++ {
		if off+2 > len(payload) {
			return portalName, stmtName, nil, nil, errors.New("truncated param formats")
		}
		paramFmts[i] = binary.BigEndian.Uint16(payload[off : off+2])
		off += 2
	}

	if off+2 > len(payload) {
		return portalName, stmtName, nil, nil, nil
	}
	numParams := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	params = make([]*string, numParams)
	for i := 0; i < numParams; i++ {
		if off+4 > len(payload) {
			return portalName, stmtName, nil, nil, errors.New("truncated param length")
		}
		pLen := int32(binary.BigEndian.Uint32(payload[off : off+4]))
		off += 4
		if pLen == -1 {
			params[i] = nil
			continue
		}
		if pLen < 0 || off+int(pLen) > len(payload) {
			return portalName, stmtName, nil, nil, errors.New("invalid param length")
		}
		raw := payload[off : off+int(pLen)]
		off += int(pLen)

		var fmtCode uint16
		if len(paramFmts) == 1 {
			fmtCode = paramFmts[0]
		} else if i < len(paramFmts) {
			fmtCode = paramFmts[i]
		}
		if fmtCode == 1 && len(raw) == 4 {
			v := int32(binary.BigEndian.Uint32(raw))
			params[i] = sp(strconv.FormatInt(int64(v), 10))
		} else if fmtCode == 1 && len(raw) == 8 {
			v := int64(binary.BigEndian.Uint64(raw))
			params[i] = sp(strconv.FormatInt(v, 10))
		} else {
			params[i] = sp(string(raw))
		}
	}

	if off+2 <= len(payload) {
		numResFmts := int(binary.BigEndian.Uint16(payload[off : off+2]))
		off += 2
		resultFormats = make([]uint16, 0, numResFmts)
		for i := 0; i < numResFmts && off+2 <= len(payload); i++ {
			resultFormats = append(resultFormats, binary.BigEndian.Uint16(payload[off:off+2]))
			off += 2
		}
	}
	return portalName, stmtName, params, resultFormats, nil
}

func applyResultFormats(fields []pgwire.FieldDescription, req []uint16) {
	for i := range fields {
		var code uint16
		if len(req) == 1 {
			code = req[0]
		} else if i < len(req) {
			code = req[i]
		}
		// Only emit binary wire encoding for OIDs whose binary encoding is fixed & lossless here (int4 & text);
		// leave numeric/timestamptz as text format (0) so pgx/psycopg3 decode them cleanly via text codecs.
		if code == 1 && (fields[i].DataTypeOID == OIDInt4 || fields[i].DataTypeOID == OIDText) {
			fields[i].FormatCode = 1
		} else {
			fields[i].FormatCode = 0
		}
	}
}

func encodeCell(val *string, oid uint32, formatCode uint16) []byte {
	if val == nil {
		return nil
	}
	if formatCode == 1 && oid == OIDInt4 {
		if n, err := strconv.ParseInt(*val, 10, 32); err == nil {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(int32(n)))
			return b[:]
		}
	}
	return []byte(*val)
}

var paramRefRe = regexp.MustCompile(`\$(\d+)`)

func maxParamIndex(sql string) int {
	max := 0
	for _, m := range paramRefRe.FindAllStringSubmatch(sql, -1) {
		if n, err := strconv.Atoi(m[1]); err == nil && n > max {
			max = n
		}
	}
	return max
}

func (s *Server) inferParamOIDs(sql string) []uint32 {
	maxP := maxParamIndex(sql)
	if maxP == 0 {
		return nil
	}
	oids := make([]uint32, maxP)
	for i := range oids {
		oids[i] = OIDText
	}
	tree, err := pg_query.Parse(sql)
	if err != nil || len(tree.Stmts) == 0 || tree.Stmts[0].Stmt == nil {
		return oids
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var fromCols []rowCol
	var walk func(n *pg_query.Node)
	colOID := func(cr *pg_query.ColumnRef) uint32 {
		if cr == nil || len(cr.Fields) == 0 {
			return 0
		}
		var qual, col string
		if len(cr.Fields) == 1 {
			col = cr.Fields[0].GetString_().GetSval()
		} else {
			qual = cr.Fields[len(cr.Fields)-2].GetString_().GetSval()
			col = cr.Fields[len(cr.Fields)-1].GetString_().GetSval()
		}
		lq, lc := strings.ToLower(qual), strings.ToLower(col)
		for _, fc := range fromCols {
			if fc.name == lc && (lq == "" || fc.qualifier == lq) {
				return fc.colDef.OID
			}
		}
		return 0
	}

	walk = func(n *pg_query.Node) {
		if n == nil {
			return
		}
		switch x := n.Node.(type) {
		case *pg_query.Node_ExplainStmt:
			walk(x.ExplainStmt.Query)
		case *pg_query.Node_SelectStmt:
			for _, fc := range x.SelectStmt.FromClause {
				if c, err := s.inferFromCols(fc, nil); err == nil {
					fromCols = append(fromCols, c...)
				}
			}
			walk(x.SelectStmt.WhereClause)
		case *pg_query.Node_UpdateStmt:
			if c, err := s.inferFromCols(&pg_query.Node{Node: &pg_query.Node_RangeVar{RangeVar: x.UpdateStmt.Relation}}, nil); err == nil {
				fromCols = append(fromCols, c...)
			}
			for _, t := range x.UpdateStmt.TargetList {
				if rt := t.GetResTarget(); rt != nil {
					if pr := rt.Val.GetParamRef(); pr != nil {
						idx := int(pr.Number) - 1
						if idx >= 0 && idx < len(oids) {
							for _, fc := range fromCols {
								if fc.name == strings.ToLower(rt.Name) && fc.colDef.OID != 0 {
									oids[idx] = fc.colDef.OID
									break
								}
							}
						}
					}
				}
			}
			walk(x.UpdateStmt.WhereClause)
		case *pg_query.Node_DeleteStmt:
			if c, err := s.inferFromCols(&pg_query.Node{Node: &pg_query.Node_RangeVar{RangeVar: x.DeleteStmt.Relation}}, nil); err == nil {
				fromCols = append(fromCols, c...)
			}
			walk(x.DeleteStmt.WhereClause)
		case *pg_query.Node_BoolExpr:
			for _, a := range x.BoolExpr.Args {
				walk(a)
			}
		case *pg_query.Node_AExpr:
			if pr := x.AExpr.Rexpr.GetParamRef(); pr != nil {
				if cr := x.AExpr.Lexpr.GetColumnRef(); cr != nil {
					if idx := int(pr.Number) - 1; idx >= 0 && idx < len(oids) {
						if oid := colOID(cr); oid != 0 {
							oids[idx] = oid
						}
					}
				}
			}
			if pr := x.AExpr.Lexpr.GetParamRef(); pr != nil {
				if cr := x.AExpr.Rexpr.GetColumnRef(); cr != nil {
					if idx := int(pr.Number) - 1; idx >= 0 && idx < len(oids) {
						if oid := colOID(cr); oid != 0 {
							oids[idx] = oid
						}
					}
				}
			}
			walk(x.AExpr.Lexpr)
			walk(x.AExpr.Rexpr)
		}
	}
	walk(tree.Stmts[0].Stmt)
	return oids
}

func resultToTable(name string, res *queryResult) *Table {
	cols := make([]ColumnDef, len(res.fields))
	for i, f := range res.fields {
		cols[i] = ColumnDef{Name: f.Name, OID: f.DataTypeOID, TypeSize: f.DataTypeSize, DataType: "text"}
	}
	return &Table{Schema: "pg_temp", Name: name, Columns: cols, Rows: res.rows}
}

func containsAggregate(n *pg_query.Node) bool {
	if n == nil {
		return false
	}
	if fc := n.GetFuncCall(); fc != nil && len(fc.Funcname) > 0 {
		fn := strings.ToLower(fc.Funcname[len(fc.Funcname)-1].GetString_().GetSval())
		if fn == "count" || fn == "sum" || fn == "avg" || fn == "min" || fn == "max" {
			return true
		}
	}
	return false
}

func compareStrings(a, b string) int {
	fa, e1 := strconv.ParseFloat(a, 64)
	fb, e2 := strconv.ParseFloat(b, 64)
	if e1 == nil && e2 == nil {
		if fa < fb {
			return -1
		}
		if fa > fb {
			return 1
		}
		return 0
	}
	return strings.Compare(a, b)
}

func sqlLikeMatch(val, pattern string, caseInsensitive bool) bool {
	if caseInsensitive {
		val = strings.ToLower(val)
		pattern = strings.ToLower(pattern)
	}
	var re strings.Builder
	re.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '%':
			re.WriteString(".*")
		case '_':
			re.WriteString(".")
		default:
			re.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	re.WriteString("$")
	compiled, err := regexp.Compile("(?s)" + re.String())
	if err != nil {
		return false
	}
	return compiled.MatchString(val)
}

func dedupeRows(rows [][]*string) [][]*string {
	seen := make(map[string]bool, len(rows))
	var out [][]*string
	for _, r := range rows {
		var sb strings.Builder
		for _, c := range r {
			if c == nil {
				sb.WriteString("\x00NULL\x1f")
			} else {
				sb.WriteString(*c)
				sb.WriteByte('\x1f')
			}
		}
		k := sb.String()
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	return out
}

func (s *Server) execExplain(exp *pg_query.ExplainStmt) *queryResult {
	isJSON := false
	for _, opt := range exp.Options {
		de := opt.GetDefElem()
		if de != nil && strings.EqualFold(de.Defname, "format") && de.Arg != nil {
			if sv := de.Arg.GetString_(); sv != nil && strings.EqualFold(sv.Sval, "json") {
				isJSON = true
			}
		}
	}

	planSQL := ""
	if exp.Query != nil {
		if dep, err := pg_query.Deparse(&pg_query.ParseResult{
			Stmts: []*pg_query.RawStmt{{Stmt: exp.Query}},
		}); err == nil {
			planSQL = dep
		}
	}

	if !isJSON {
		rows := [][]*string{
			{sp("pgveil Embedded Demo Plan (AST Virtual RLS & Firewall Active)")},
			{sp("  -> Executed SQL: " + planSQL)},
		}
		return &queryResult{
			fields:     []pgwire.FieldDescription{{Name: "QUERY PLAN", DataTypeOID: OIDText, DataTypeSize: -1, TypeModifier: -1}},
			rows:       rows,
			commandTag: "EXPLAIN",
			hasRows:    true,
		}
	}

	nodeType := "Seq Scan"
	relName := "customers"
	totalCost := 18.5
	planRows := 40.0
	tableCount := 0
	hasSelectiveFilter := false
	hasSmallLimit := false

	if sel := exp.Query.GetSelectStmt(); sel != nil {
		if sel.WhereClause != nil {
			hasSelectiveFilter = true
		}
		if sel.LimitCount != nil {
			hasSmallLimit = true
		}
		tableCount, relName = countSelectRelations(sel)
	} else if upd := exp.Query.GetUpdateStmt(); upd != nil {
		tableCount = 1 + len(upd.FromClause)
		if upd.Relation != nil && upd.Relation.Relname != "" {
			relName = upd.Relation.Relname
		}
		hasSelectiveFilter = upd.WhereClause != nil
	} else if del := exp.Query.GetDeleteStmt(); del != nil {
		tableCount = 1 + len(del.UsingClause)
		if del.Relation != nil && del.Relation.Relname != "" {
			relName = del.Relation.Relname
		}
		hasSelectiveFilter = del.WhereClause != nil
	}

	switch {
	case tableCount >= 3 && !hasSmallLimit:
		nodeType = "Nested Loop"
		totalCost = 92400.0
		planRows = 250000
	case strings.Contains(strings.ToUpper(planSQL), "CROSS JOIN") && !hasSmallLimit:
		nodeType = "Nested Loop"
		totalCost = 88500.0
		planRows = 200000
	case hasSelectiveFilter || hasSmallLimit:
		nodeType = "Index Scan"
		totalCost = 8.45
		planRows = 5
	}

	var childPlans []map[string]any
	if nodeType == "Nested Loop" {
		childPlans = []map[string]any{
			{
				"Node Type":     "Seq Scan",
				"Relation Name": relName,
				"Schema":        "public",
				"Total Cost":    totalCost,
				"Plan Rows":     planRows,
			},
		}
	}
	planObj := map[string]any{
		"Node Type":     nodeType,
		"Relation Name": relName,
		"Schema":        "public",
		"Startup Cost":  0.0,
		"Total Cost":    totalCost,
		"Plan Rows":     planRows,
		"Plan Width":    64,
	}
	if len(childPlans) > 0 {
		planObj["Plans"] = childPlans
	}
	jsonBytes, _ := json.MarshalIndent([]map[string]any{{"Plan": planObj}}, "", "  ")
	return &queryResult{
		fields:     []pgwire.FieldDescription{{Name: "QUERY PLAN", DataTypeOID: OIDText, DataTypeSize: -1, TypeModifier: -1}},
		rows:       [][]*string{{sp(string(jsonBytes))}},
		commandTag: "EXPLAIN",
		hasRows:    true,
	}
}

func countSelectRelations(sel *pg_query.SelectStmt) (int, string) {
	count := 0
	firstRel := "customers"
	var walk func(n *pg_query.Node)
	walk = func(n *pg_query.Node) {
		if n == nil {
			return
		}
		switch x := n.Node.(type) {
		case *pg_query.Node_RangeVar:
			if x.RangeVar != nil && x.RangeVar.Relname != "" {
				if count == 0 {
					firstRel = x.RangeVar.Relname
				}
				count++
			}
		case *pg_query.Node_JoinExpr:
			walk(x.JoinExpr.Larg)
			walk(x.JoinExpr.Rarg)
		case *pg_query.Node_RangeSubselect:
			if x.RangeSubselect != nil && x.RangeSubselect.Subquery != nil {
				if sub := x.RangeSubselect.Subquery.GetSelectStmt(); sub != nil {
					c, r := countSelectRelations(sub)
					if count == 0 && c > 0 {
						firstRel = r
					}
					count += c
				}
			}
		}
	}
	for _, fc := range sel.FromClause {
		walk(fc)
	}
	return count, firstRel
}
