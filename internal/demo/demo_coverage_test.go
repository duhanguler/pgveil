package demo_test

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/duhanguler/pgveil/internal/demo"
	"github.com/duhanguler/pgveil/internal/pgwire"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/jackc/pgx/v5"
)

func TestDemoConfigAndSQLFeatureMatrix(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	srv := demo.NewServer()
	addr, err := srv.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if srv.Addr() != addr {
		t.Fatalf("Addr mismatch: %q vs %q", srv.Addr(), addr)
	}

	// Validate BuildDemoConfigYAML compiles cleanly
	if _, err := policy.LoadBytes(demo.BuildDemoConfigYAML(":6432", ":8088", addr)); err != nil {
		t.Fatalf("BuildDemoConfigYAML failed validation: %v", err)
	}

	// Wire handshake edge cases: SSLRequest, GSSENCRequest, CancelRequest, unknown code
	for _, code := range []uint32{pgwire.SSLRequestCode, pgwire.GSSENCRequestCode, pgwire.CancelRequestCode, 12345} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		var pkt [8]byte
		binary.BigEndian.PutUint32(pkt[0:4], 8)
		binary.BigEndian.PutUint32(pkt[4:8], code)
		_, _ = c.Write(pkt[:])
		var reply [16]byte
		_, _ = c.Read(reply[:])
		_ = c.Close()
	}

	// Simple Protocol comprehensive SQL engine coverage
	dsn := policy.BuildDSN(addr, "pgveil", "", "pgveil_demo", "cov", false)
	cfg, _ := pgx.ParseConfig(dsn)
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("simple connect: %v", err)
	}

	queries := []string{
		"SHOW server_version",
		"SHOW client_encoding",
		"SHOW transaction_isolation",
		"SHOW search_path",
		"SET client_encoding = 'UTF8'",
		"BEGIN",
		"COMMIT",
		"ROLLBACK",
		"DISCARD ALL",
		"DEALLOCATE ALL",
		"EXPLAIN SELECT id, city FROM customers WHERE city = 'Istanbul'",
		"SELECT version(), now(), current_database()",
		"SELECT 1 + 2 * 3 - 4 / 2 AS math_val, 'a' || 'b' AS cat_val",
		"SELECT DISTINCT city FROM customers ORDER BY 1 DESC LIMIT 3 OFFSET 1",
		"SELECT c.*, o.order_number FROM customers c LEFT JOIN orders o ON c.id = o.customer_id ORDER BY c.id LIMIT 5",
		"SELECT c.id, o.id FROM customers c RIGHT JOIN orders o ON c.id = o.customer_id LIMIT 5",
		"SELECT c.id, o.id FROM customers c FULL OUTER JOIN orders o ON c.id = o.customer_id LIMIT 5",
		"SELECT c.id, o.id FROM customers c, orders o WHERE c.id = o.customer_id AND c.id BETWEEN 1 AND 5 AND o.id NOT BETWEEN 9000 AND 9999",
		"SELECT id FROM customers WHERE city IN ('Istanbul', 'Ankara') AND tier NOT IN ('unknown') AND full_name LIKE 'Ay%' AND full_name NOT LIKE 'ZZ%' AND email ILIKE '%EXAMPLE%' AND email NOT ILIKE '%NOPE%'",
		"SELECT id, COALESCE(ssn, 'none') AS s, CASE WHEN tier = 'vip' THEN 'high' ELSE 'std' END AS lvl, lower(city), upper(tier), trim(' x '), length(city), substring(city, 1, 3), substring(city, 2) FROM customers WHERE ssn IS NULL OR ssn IS NOT NULL ORDER BY ssn LIMIT 5",
		"SELECT id FROM customers WHERE (tier = 'vip') IS TRUE AND NOT (tier = 'ghost') AND EXISTS (SELECT 1 FROM orders WHERE customer_id = 1) AND id IN (SELECT customer_id FROM orders)",
		"SELECT id, (SELECT COUNT(*) FROM orders) AS total_orders FROM customers LIMIT 2",
		"SELECT city, COUNT(*), COUNT(ssn), SUM(id), AVG(id), MIN(id), MAX(id) FROM customers GROUP BY city",
		"SELECT COUNT(*) FROM customers",
		"WITH vip_c AS (SELECT id, city FROM customers WHERE tier = 'vip') SELECT * FROM vip_c LIMIT 3",
		"SELECT id FROM (SELECT id FROM customers LIMIT 3) sub",
		"SELECT id FROM customers WHERE id = 1 UNION SELECT id FROM customers WHERE id = 1 UNION ALL SELECT id FROM customers WHERE id = 2",
		"SELECT id FROM customers WHERE id <> 999 AND id >= 1 AND id <= 5 AND id > 0 AND id < 10",
		"UPDATE customers SET tier = 'vip' WHERE id = 10",
		"DELETE FROM customers WHERE id = 40",
	}

	for _, q := range queries {
		rows, err := conn.Query(ctx, q)
		if err != nil {
			t.Fatalf("query failed: %s -> %v", q, err)
		}
		for rows.Next() {
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("rows err for %s: %v", q, err)
		}
		rows.Close()
	}

	// Error cases in Simple Query (syntax error, missing table, bad update column)
	for _, bad := range []string{"SELECT FROM WHERE", "SELECT * FROM nonexistent_table", "UPDATE customers SET bad_col = 'x' WHERE id = 1"} {
		if _, err := conn.Exec(ctx, bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
	_ = conn.Close(ctx)

	// Extended Query coverage: Parse/Bind/Describe/Execute/Close + SHOW/EXPLAIN/UPDATE with $1 + error recovery
	extConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("ext connect: %v", err)
	}
	var ver string
	if err := extConn.QueryRow(ctx, "SHOW server_version").Scan(&ver); err != nil {
		t.Fatalf("ext SHOW: %v", err)
	}
	var plan string
	if err := extConn.QueryRow(ctx, "EXPLAIN SELECT id FROM customers WHERE id = $1", 1).Scan(&plan); err != nil {
		t.Fatalf("ext EXPLAIN: %v", err)
	}
	if _, err := extConn.Exec(ctx, "UPDATE orders SET status = $1 WHERE id = $2", "shipped", 1002); err != nil {
		t.Fatalf("ext UPDATE: %v", err)
	}
	if _, err := extConn.Exec(ctx, "DELETE FROM orders WHERE id = $1", 9999); err != nil {
		t.Fatalf("ext DELETE: %v", err)
	}
	if _, err := extConn.Exec(ctx, "SELECT * FROM does_not_exist"); err == nil {
		t.Fatal("expected error for missing table in ext mode")
	}
	// Verify connection recovers cleanly after Sync
	var one int
	if err := extConn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("expected recovery after error, err=%v one=%d", err, one)
	}
	for _, stmt := range []string{
		"SHOW server_encoding",
		"SHOW transaction_isolation",
		"SHOW search_path",
		"SHOW standard_conforming_strings",
		"BEGIN",
		"SAVEPOINT sp1",
		"ROLLBACK",
		"DEALLOCATE ALL",
		"DISCARD ALL",
		"CLOSE ALL",
	} {
		if _, err := extConn.Exec(ctx, stmt); err != nil {
			t.Fatalf("demo utility stmt %q failed: %v", stmt, err)
		}
	}
	if _, err := extConn.Exec(ctx, "CREATE TABLE should_fail (id int)"); err == nil {
		t.Fatal("expected unsupported statement error")
	}
	_ = extConn.Close(ctx)

	cancel()
	srv.Wait()
}
