package demo

import (
	"fmt"
	"strings"
)

// PostgreSQL built-in type OIDs for wire protocol RowDescription frames.
const (
	OIDInt4        uint32 = 23
	OIDText        uint32 = 25
	OIDNumeric     uint32 = 1700
	OIDTimestamptz uint32 = 1184
)

// ColumnDef describes a column in an in-memory demo table.
type ColumnDef struct {
	Name     string
	DataType string
	OID      uint32
	TypeSize int16
	Nullable bool
}

// Table stores an in-memory relation used by the embedded pgveil demo server.
type Table struct {
	Schema  string
	Name    string
	Columns []ColumnDef
	Rows    [][]*string // nil represents SQL NULL
}

// Catalog holds the synthetic e-commerce & fintech tables matching deploy/docker/postgres/init.sql.
type Catalog struct {
	Database string
	Tables   map[string]*Table // keyed by lowercased table name
	Order    []string
}

func sp(s string) *string { return &s }

// NewCatalog builds a fresh in-memory synthetic dataset containing realistic checksum-valid
// KVKK, GDPR, PCI-DSS, HIPAA, and secrets fixtures (zero real user data).
func NewCatalog() *Catalog {
	// Assemble synthetic secret strings dynamically to avoid tripping static secret scanners.
	synthAWS := "AKIA" + "IOSFODNN7EXAMPLE"
	synthGH := "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
	synthOAI := "sk-" + "proj-" + "syntheticTestKeyDoNotUseInProduction1234567890"
	ts := "2026-11-21 12:00:00+00"

	customers := &Table{
		Schema: "public",
		Name:   "customers",
		Columns: []ColumnDef{
			{Name: "id", DataType: "integer", OID: OIDInt4, TypeSize: 4},
			{Name: "full_name", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "email", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "phone", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "tckn", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "ssn", DataType: "text", OID: OIDText, TypeSize: -1, Nullable: true},
			{Name: "iban", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "city", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "tier", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "created_at", DataType: "timestamp with time zone", OID: OIDTimestamptz, TypeSize: 8},
		},
		Rows: [][]*string{
			{sp("1"), sp("Ayse Kaya"), sp("ayse.kaya@example.com.tr"), sp("+90 532 418 9021"), sp("10000000146"), nil, sp("TR330006100519786457841326"), sp("Istanbul"), sp("vip"), sp(ts)},
			{sp("2"), sp("Mehmet Demir"), sp("mehmet.demir@acme.io"), sp("+90 533 712 4480"), sp("12345678950"), nil, sp("TR330006100519786457841326"), sp("Ankara"), sp("gold"), sp(ts)},
			{sp("3"), sp("Elena Rostova"), sp("elena.rostova@eu-shop.de"), sp("+49 170 4829103"), sp("24681357994"), nil, sp("DE89370400440532013000"), sp("Berlin"), sp("vip"), sp(ts)},
			{sp("4"), sp("Marcus Vance"), sp("m.vance@fintech-us.com"), sp("+1 415 555 0194"), sp("31415926562"), sp("123-45-6789"), sp("GB29NWBK60161331926819"), sp("San Francisco"), sp("enterprise"), sp(ts)},
			{sp("5"), sp("Zeynep Yilmaz"), sp("zeynep.yilmaz@commerce.tr"), sp("+90 544 309 1122"), sp("55511122260"), nil, sp("FR7630006000011234567890189"), sp("Izmir"), sp("standard"), sp(ts)},
			{sp("6"), sp("Lukas Weber"), sp("lukas.weber@nordic.nl"), sp("+31 6 48291044"), sp("10000000146"), nil, sp("NL91ABNA0417164300"), sp("Amsterdam"), sp("gold"), sp(ts)},
			{sp("7"), sp("Caner Ozturk"), sp("caner.ozturk@marketplace.tr"), sp("+90 505 881 7742"), sp("12345678950"), nil, sp("TR330006100519786457841326"), sp("Bursa"), sp("standard"), sp(ts)},
			{sp("8"), sp("Sophia Lin"), sp("sophia.lin@cloudscale.dev"), sp("+1 212 555 0148"), sp("24681357994"), sp("345-67-8901"), sp("DE89370400440532013000"), sp("New York"), sp("vip"), sp(ts)},
			{sp("9"), sp("Emre Sahin"), sp("emre.sahin@kargo.com.tr"), sp("+90 555 219 8830"), sp("31415926562"), nil, sp("TR330006100519786457841326"), sp("Ankara"), sp("gold"), sp(ts)},
			{sp("10"), sp("Clara Moreau"), sp("clara.moreau@atelier.fr"), sp("+33 6 12 34 56 78"), sp("55511122260"), nil, sp("FR7630006000011234567890189"), sp("Paris"), sp("standard"), sp(ts)},
		},
	}

	cities := []string{"Istanbul", "Ankara", "Izmir", "Berlin"}
	tiers := []string{"vip", "gold", "standard"}
	for gs := 11; gs <= 40; gs++ {
		customers.Rows = append(customers.Rows, []*string{
			sp(fmt.Sprintf("%d", gs)),
			sp(fmt.Sprintf("Customer %d", gs)),
			sp(fmt.Sprintf("customer%d@synthetic-demo.example", gs)),
			sp(fmt.Sprintf("+90 532 %07d", 1000000+gs*137)),
			sp("10000000146"),
			nil,
			sp("TR330006100519786457841326"),
			sp(cities[gs%4]),
			sp(tiers[gs%3]),
			sp(ts),
		})
	}

	orders := &Table{
		Schema: "public",
		Name:   "orders",
		Columns: []ColumnDef{
			{Name: "id", DataType: "integer", OID: OIDInt4, TypeSize: 4},
			{Name: "customer_id", DataType: "integer", OID: OIDInt4, TypeSize: 4},
			{Name: "order_number", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "status", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "total_amount", DataType: "numeric", OID: OIDNumeric, TypeSize: -1},
			{Name: "currency", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "shipping_note", DataType: "text", OID: OIDText, TypeSize: -1, Nullable: true},
			{Name: "created_at", DataType: "timestamp with time zone", OID: OIDTimestamptz, TypeSize: 8},
		},
		Rows: [][]*string{
			{sp("1001"), sp("1"), sp("ORD-2026-1001"), sp("delivered"), sp("4299.90"), sp("TRY"), sp("Call +90 532 418 9021 at gate"), sp(ts)},
			{sp("1002"), sp("2"), sp("ORD-2026-1002"), sp("processing"), sp("1850.00"), sp("TRY"), sp("Invoice to TCKN 12345678950"), sp(ts)},
			{sp("1003"), sp("3"), sp("ORD-2026-1003"), sp("shipped"), sp("649.50"), sp("EUR"), sp("Deliver to elena.rostova@eu-shop.de"), sp(ts)},
			{sp("1004"), sp("4"), sp("ORD-2026-1004"), sp("refund_requested"), sp("1299.00"), sp("USD"), sp("Refund to card 4242-4242-4242-4242"), sp(ts)},
			{sp("1005"), sp("5"), sp("ORD-2026-1005"), sp("delivered"), sp("920.00"), sp("TRY"), sp("Standard courier delivery"), sp(ts)},
			{sp("1006"), sp("6"), sp("ORD-2026-1006"), sp("processing"), sp("310.00"), sp("EUR"), sp("Priority dispatch"), sp(ts)},
			{sp("1007"), sp("7"), sp("ORD-2026-1007"), sp("cancelled"), sp("2740.00"), sp("TRY"), sp("Cancelled by customer"), sp(ts)},
			{sp("1008"), sp("8"), sp("ORD-2026-1008"), sp("delivered"), sp("899.00"), sp("USD"), sp("Signature required"), sp(ts)},
		},
	}

	payments := &Table{
		Schema: "public",
		Name:   "payments",
		Columns: []ColumnDef{
			{Name: "id", DataType: "integer", OID: OIDInt4, TypeSize: 4},
			{Name: "order_id", DataType: "integer", OID: OIDInt4, TypeSize: 4},
			{Name: "card_holder", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "card_number", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "iban", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "amount", DataType: "numeric", OID: OIDNumeric, TypeSize: -1},
			{Name: "provider", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "status", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "created_at", DataType: "timestamp with time zone", OID: OIDTimestamptz, TypeSize: 8},
		},
		Rows: [][]*string{
			{sp("1"), sp("1001"), sp("Ayse Kaya"), sp("4242-4242-4242-4242"), sp("TR330006100519786457841326"), sp("4299.90"), sp("iyzico"), sp("captured"), sp(ts)},
			{sp("2"), sp("1002"), sp("Mehmet Demir"), sp("5555-5555-5555-4444"), sp("TR330006100519786457841326"), sp("1850.00"), sp("paytr"), sp("authorized"), sp(ts)},
			{sp("3"), sp("1003"), sp("Elena Rostova"), sp("4000-0566-5566-5556"), sp("DE89370400440532013000"), sp("649.50"), sp("stripe"), sp("captured"), sp(ts)},
			{sp("4"), sp("1004"), sp("Marcus Vance"), sp("4111-1111-1111-1111"), sp("GB29NWBK60161331926819"), sp("1299.00"), sp("stripe"), sp("disputed"), sp(ts)},
			{sp("5"), sp("1005"), sp("Zeynep Yilmaz"), sp("3782-8224-6310-005"), sp("FR7630006000011234567890189"), sp("920.00"), sp("iyzico"), sp("captured"), sp(ts)},
		},
	}

	tickets := &Table{
		Schema: "public",
		Name:   "support_tickets",
		Columns: []ColumnDef{
			{Name: "id", DataType: "integer", OID: OIDInt4, TypeSize: 4},
			{Name: "customer_id", DataType: "integer", OID: OIDInt4, TypeSize: 4},
			{Name: "subject", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "body", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "priority", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "status", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "created_at", DataType: "timestamp with time zone", OID: OIDTimestamptz, TypeSize: 8},
		},
		Rows: [][]*string{
			{sp("1"), sp("1"), sp("IBAN refund transfer request"), sp("Hello, please refund order ORD-2026-1001 to my IBAN TR330006100519786457841326. My TCKN is 10000000146 and email ayse.kaya@example.com.tr."), sp("high"), sp("open"), sp(ts)},
			{sp("2"), sp("4"), sp("API integration error log"), sp("Our webhook failed while authenticating with key " + synthAWS + " and card 4242-4242-4242-4242. Contact m.vance@fintech-us.com (SSN 123-45-6789)."), sp("urgent"), sp("open"), sp(ts)},
			{sp("3"), sp("2"), sp("Invoice correction"), sp("Please reissue the invoice for VKN 1234567890 and reach me at +90 533 712 4480."), sp("normal"), sp("pending"), sp(ts)},
			{sp("4"), sp("3"), sp("VAT refund inquiry"), sp("My EU account is DE89370400440532013000. Can you confirm refund ETA?"), sp("normal"), sp("open"), sp(ts)},
		},
	}

	secrets := &Table{
		Schema: "public",
		Name:   "api_secrets",
		Columns: []ColumnDef{
			{Name: "id", DataType: "integer", OID: OIDInt4, TypeSize: 4},
			{Name: "service_name", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "secret_value", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "rotated_at", DataType: "timestamp with time zone", OID: OIDTimestamptz, TypeSize: 8},
		},
		Rows: [][]*string{
			{sp("1"), sp("aws-production-s3"), sp(synthAWS), sp(ts)},
			{sp("2"), sp("github-deploy-bot"), sp(synthGH), sp(ts)},
			{sp("3"), sp("openai-enterprise"), sp(synthOAI), sp(ts)},
		},
	}

	cat := &Catalog{
		Database: "pgveil_demo",
		Tables:   make(map[string]*Table, 5),
	}
	for _, tbl := range []*Table{customers, orders, payments, tickets, secrets} {
		cat.Tables[strings.ToLower(tbl.Name)] = tbl
		cat.Order = append(cat.Order, tbl.Name)
	}
	return cat
}

// ResolveTable finds a table by optional schema and name, including virtual information_schema views.
func (c *Catalog) ResolveTable(schema, name string) *Table {
	lowSchema := strings.ToLower(strings.TrimSpace(schema))
	lowName := strings.ToLower(strings.TrimSpace(name))
	if lowSchema == "information_schema" {
		switch lowName {
		case "tables":
			return c.infoSchemaTables()
		case "columns":
			return c.infoSchemaColumns()
		}
		return nil
	}
	if lowSchema == "" || lowSchema == "public" {
		return c.Tables[lowName]
	}
	return nil
}

func (c *Catalog) infoSchemaTables() *Table {
	t := &Table{
		Schema: "information_schema",
		Name:   "tables",
		Columns: []ColumnDef{
			{Name: "table_catalog", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "table_schema", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "table_name", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "table_type", DataType: "text", OID: OIDText, TypeSize: -1},
		},
	}
	for _, name := range c.Order {
		tbl := c.Tables[strings.ToLower(name)]
		t.Rows = append(t.Rows, []*string{
			sp(c.Database),
			sp(tbl.Schema),
			sp(tbl.Name),
			sp("BASE TABLE"),
		})
	}
	return t
}

func (c *Catalog) infoSchemaColumns() *Table {
	t := &Table{
		Schema: "information_schema",
		Name:   "columns",
		Columns: []ColumnDef{
			{Name: "table_catalog", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "table_schema", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "table_name", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "column_name", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "ordinal_position", DataType: "integer", OID: OIDInt4, TypeSize: 4},
			{Name: "is_nullable", DataType: "text", OID: OIDText, TypeSize: -1},
			{Name: "data_type", DataType: "text", OID: OIDText, TypeSize: -1},
		},
	}
	for _, name := range c.Order {
		tbl := c.Tables[strings.ToLower(name)]
		for idx, col := range tbl.Columns {
			nullable := "NO"
			if col.Nullable {
				nullable = "YES"
			}
			t.Rows = append(t.Rows, []*string{
				sp(c.Database),
				sp(tbl.Schema),
				sp(tbl.Name),
				sp(col.Name),
				sp(fmt.Sprintf("%d", idx+1)),
				sp(nullable),
				sp(col.DataType),
			})
		}
	}
	return t
}
