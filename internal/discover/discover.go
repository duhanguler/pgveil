package discover

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/duhanguler/pgveil/internal/pii"
	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"
)

// Finding describes a discovered sensitive column and its recommended masking rule.
type Finding struct {
	Schema              string         `json:"schema"`
	Table               string         `json:"table"`
	Column              string         `json:"column"`
	DataType            string         `json:"data_type"`
	SampledRows         int            `json:"sampled_rows"`
	MatchedRows         int            `json:"matched_rows"`
	DetectedEntities    map[string]int `json:"detected_entities"`
	CompliancePacks     []string       `json:"compliance_packs"`
	RiskLevel           string         `json:"risk_level"` // CRITICAL, HIGH, MEDIUM
	RecommendedStrategy pii.Strategy   `json:"recommended_strategy"`
	DetectionSource     string         `json:"detection_source"` // content_checksum, column_heuristic, both
	SampleMasked        string         `json:"sample_masked,omitempty"`
}

// Report is the output of scanning a live PostgreSQL database schema for PII & secrets.
type Report struct {
	ScannedAt         time.Time `json:"scanned_at"`
	Database          string    `json:"database"`
	TablesScanned     int       `json:"tables_scanned"`
	ColumnsScanned    int       `json:"columns_scanned"`
	FindingsCount     int       `json:"findings_count"`
	Findings          []Finding `json:"findings"`
	RecommendedTables []string  `json:"recommended_denied_tables,omitempty"`
	GeneratedYAML     string    `json:"generated_yaml"`
}

type colInfo struct {
	schema   string
	table    string
	column   string
	dataType string
}

// Scan connects directly to a PostgreSQL database, samples up to sampleRows per table,
// validates cell contents against all 8 compliance packs, and synthesizes a pgveil policy snippet.
func Scan(ctx context.Context, dsn string, sampleRows int, maskingSecret string) (*Report, error) {
	if sampleRows <= 0 {
		sampleRows = 50
	}
	if sampleRows > 500 {
		sampleRows = 500
	}

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect to PostgreSQL for discovery: %w", err)
	}
	defer conn.Close(context.Background())

	var dbName string
	_ = conn.QueryRow(ctx, "SELECT current_database()").Scan(&dbName)

	rows, err := conn.Query(ctx, `
		SELECT c.table_schema, c.table_name, c.column_name, c.data_type
		FROM information_schema.columns c
		JOIN information_schema.tables t
		  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
		  AND t.table_type = 'BASE TABLE'
		  AND c.table_name NOT LIKE 'pgveil_%'
		ORDER BY c.table_schema, c.table_name, c.ordinal_position
	`)
	if err != nil {
		return nil, fmt.Errorf("query information_schema: %w", err)
	}
	defer rows.Close()

	var cols []colInfo
	tablesSeen := make(map[string]bool)
	for rows.Next() {
		var c colInfo
		if err := rows.Scan(&c.schema, &c.table, &c.column, &c.dataType); err != nil {
			return nil, err
		}
		cols = append(cols, c)
		tablesSeen[c.schema+"."+c.table] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	allPacks := []string{"kvkk", "gdpr", "pci-dss", "hipaa", "lgpd", "pipeda", "uk-gdpr", "secrets"}
	enabled := pii.ResolveEnabledEntities(allPacks)
	masker := pii.NewMasker(maskingSecret)

	var findings []Finding
	deniedTablesSet := make(map[string]bool)

	for _, c := range cols {
		if !isScannableType(c.dataType) {
			continue
		}
		q := fmt.Sprintf(`SELECT %s::text FROM %s.%s WHERE %s IS NOT NULL LIMIT %d`,
			pgx.Identifier{c.column}.Sanitize(),
			pgx.Identifier{c.schema}.Sanitize(),
			pgx.Identifier{c.table}.Sanitize(),
			pgx.Identifier{c.column}.Sanitize(),
			sampleRows,
		)
		qCtx, qCancel := context.WithTimeout(ctx, 5*time.Second)
		sRows, err := conn.Query(qCtx, q)
		if err != nil {
			qCancel()
			continue
		}

		sampled := 0
		matched := 0
		entityCounts := make(map[string]int)
		var sampleMasked string

		for sRows.Next() {
			var val string
			if err := sRows.Scan(&val); err != nil {
				continue
			}
			sampled++
			masked, found := masker.MaskText(val, enabled)
			if len(found) > 0 {
				matched++
				for k, v := range found {
					entityCounts[k] += v
				}
				if sampleMasked == "" {
					if r := []rune(masked); len(r) > 100 {
						masked = string(r[:100]) + "..."
					}
					sampleMasked = masked
				}
			}
		}
		sRows.Close()
		qCancel()

		heurEnt, heurStrat, heurRisk := heuristicFromColumnName(c.column)
		hasContent := len(entityCounts) > 0
		hasHeur := heurEnt != ""

		if !hasContent && !hasHeur {
			continue
		}

		source := "content_checksum"
		if hasContent && hasHeur {
			source = "both"
		} else if hasHeur {
			source = "column_heuristic"
			entityCounts[heurEnt] = sampled
			if sampleMasked == "" {
				sampleMasked = "[heuristic match]"
			}
		}

		packs := packsForEntities(entityCounts)
		strat, risk := recommendStrategyAndRisk(entityCounts, heurStrat, heurRisk)

		// Recommend denying whole secret/credential tables
		lt := strings.ToLower(c.table)
		if strings.Contains(lt, "secret") || strings.Contains(lt, "credential") || strings.Contains(lt, "vault") {
			deniedTablesSet[c.table] = true
		}

		findings = append(findings, Finding{
			Schema:              c.schema,
			Table:               c.table,
			Column:              c.column,
			DataType:            c.dataType,
			SampledRows:         sampled,
			MatchedRows:         matched,
			DetectedEntities:    entityCounts,
			CompliancePacks:     packs,
			RiskLevel:           risk,
			RecommendedStrategy: strat,
			DetectionSource:     source,
			SampleMasked:        sampleMasked,
		})
	}

	deniedTables := make([]string, 0, len(deniedTablesSet))
	for t := range deniedTablesSet {
		deniedTables = append(deniedTables, t)
	}
	sort.Strings(deniedTables)

	genYAML := buildRecommendedYAML(findings, deniedTables)

	return &Report{
		ScannedAt:         time.Now().UTC(),
		Database:          dbName,
		TablesScanned:     len(tablesSeen),
		ColumnsScanned:    len(cols),
		FindingsCount:     len(findings),
		Findings:          findings,
		RecommendedTables: deniedTables,
		GeneratedYAML:     genYAML,
	}, nil
}

func isScannableType(dt string) bool {
	d := strings.ToLower(dt)
	return strings.Contains(d, "char") ||
		strings.Contains(d, "text") ||
		strings.Contains(d, "json") ||
		strings.Contains(d, "inet") ||
		strings.Contains(d, "cidr") ||
		strings.Contains(d, "citext")
}

func heuristicFromColumnName(col string) (entity string, strat pii.Strategy, risk string) {
	c := strings.ToLower(col)
	switch {
	case strings.Contains(c, "password") || strings.Contains(c, "secret") || strings.Contains(c, "api_key") || strings.Contains(c, "private_key"):
		return "secret_column", pii.StrategyRedact, "CRITICAL"
	case strings.Contains(c, "tckn") || strings.Contains(c, "national_id") || strings.Contains(c, "tc_no"):
		return string(pii.EntityTCKN), pii.StrategyPartial, "CRITICAL"
	case strings.Contains(c, "ssn"):
		return string(pii.EntityUSSSN), pii.StrategyRedact, "CRITICAL"
	case strings.Contains(c, "card_number") || strings.Contains(c, "credit_card") || c == "pan":
		return string(pii.EntityCreditCard), pii.StrategyLast4, "CRITICAL"
	case strings.Contains(c, "iban"):
		return string(pii.EntityTRIBAN), pii.StrategyPartial, "HIGH"
	case strings.Contains(c, "email") || strings.Contains(c, "e_mail"):
		return string(pii.EntityEmail), pii.StrategyPartial, "HIGH"
	case strings.Contains(c, "phone") || strings.Contains(c, "mobile"):
		return string(pii.EntityPhoneTR), pii.StrategyPartial, "MEDIUM"
	case c == "full_name" || c == "first_name" || c == "last_name" || c == "card_holder":
		return "person_name", pii.StrategyHash, "MEDIUM"
	default:
		return "", "", ""
	}
}

func packsForEntities(entities map[string]int) []string {
	packSet := make(map[string]bool)
	for ent := range entities {
		switch pii.EntityType(ent) {
		case pii.EntityTCKN, pii.EntityTRIBAN, pii.EntityVKN, pii.EntityPhoneTR:
			packSet["kvkk"] = true
		case pii.EntityEUIBAN, pii.EntityIPv4:
			packSet["gdpr"] = true
		case pii.EntityEmail, pii.EntityPhoneIntl:
			packSet["gdpr"] = true
			packSet["kvkk"] = true
		case pii.EntityCreditCard:
			packSet["pci-dss"] = true
		case pii.EntityUSSSN:
			packSet["hipaa"] = true
		case pii.EntityBRCPF:
			packSet["lgpd"] = true
		case pii.EntityCASIN:
			packSet["pipeda"] = true
		case pii.EntityUKNINO:
			packSet["uk-gdpr"] = true
		case pii.EntityAWSAccessKey, pii.EntityGitHubToken, pii.EntityOpenAIKey, pii.EntityStripeKey, pii.EntitySlackToken, pii.EntityJWT, pii.EntityPrivateKey, pii.EntitySecret:
			packSet["secrets"] = true
		default:
			if ent == "secret_column" {
				packSet["secrets"] = true
			} else if ent == "person_name" {
				packSet["gdpr"] = true
				packSet["kvkk"] = true
			}
		}
	}
	out := make([]string, 0, len(packSet))
	for p := range packSet {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// recommendStrategyAndRisk selects the strictest strategy & risk level deterministically
// (independent of Go map iteration order when multiple entity types appear in one column).
func recommendStrategyAndRisk(entities map[string]int, heurStrat pii.Strategy, heurRisk string) (pii.Strategy, string) {
	has := func(types ...pii.EntityType) bool {
		for _, t := range types {
			if entities[string(t)] > 0 {
				return true
			}
		}
		return false
	}
	if has(pii.EntityPrivateKey, pii.EntityAWSAccessKey, pii.EntityGitHubToken, pii.EntityOpenAIKey, pii.EntityStripeKey, pii.EntitySlackToken, pii.EntityJWT, pii.EntitySecret, pii.EntityUSSSN) {
		return pii.StrategyRedact, "CRITICAL"
	}
	if has(pii.EntityCreditCard) {
		return pii.StrategyLast4, "CRITICAL"
	}
	if has(pii.EntityTCKN, pii.EntityBRCPF, pii.EntityCASIN, pii.EntityUKNINO) {
		return pii.StrategyPartial, "CRITICAL"
	}
	if heurRisk != "" {
		return heurStrat, heurRisk
	}
	if has(pii.EntityTRIBAN, pii.EntityEUIBAN, pii.EntityEmail) {
		return pii.StrategyPartial, "HIGH"
	}
	return pii.StrategyPartial, "MEDIUM"
}

func buildRecommendedYAML(findings []Finding, deniedTables []string) string {
	type colRule struct {
		Column   string       `yaml:"column"`
		Strategy pii.Strategy `yaml:"strategy"`
	}
	seenCols := make(map[string]bool)
	var rules []colRule
	var protected []string

	for _, f := range findings {
		low := strings.ToLower(f.Column)
		// Skip free-text body/note columns from explicit column_rules (handled by auto_detect_pii!)
		if low == "body" || low == "shipping_note" || low == "notes" || low == "description" {
			continue
		}
		if seenCols[low] {
			continue
		}
		seenCols[low] = true
		rules = append(rules, colRule{Column: f.Column, Strategy: f.RecommendedStrategy})
		if f.RiskLevel == "CRITICAL" || f.RiskLevel == "HIGH" {
			protected = append(protected, f.Column)
		}
	}

	snippet := map[string]any{
		"firewall": map[string]any{
			"block_pii_inference": true,
			"protected_columns":   protected,
			"denied_tables":       deniedTables,
		},
		"masking": map[string]any{
			"enabled":         true,
			"auto_detect_pii": true,
			"column_rules":    rules,
		},
	}
	b, _ := yaml.Marshal(snippet)
	return string(b)
}
