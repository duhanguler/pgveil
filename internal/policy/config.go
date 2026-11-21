package policy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/duhanguler/pgveil/internal/pii"
	"gopkg.in/yaml.v3"
)

// RedactedPlaceholder replaces sensitive config secrets in Control Plane API responses.
const RedactedPlaceholder = "__PGVEIL_REDACTED__"

var secretYAMLLineRe = regexp.MustCompile(`(?m)^(\s*(?:upstream_password|masking_secret|admin_token|webhook_url)\s*:\s*)(.+?)(\s*(?:#.*)?)$`)

// Config is the root pgveil runtime and policy configuration.
type Config struct {
	Server         ServerConfig        `yaml:"server" json:"server"`
	Security       SecurityConfig      `yaml:"security" json:"security"`
	Notifications  NotificationsConfig `yaml:"notifications" json:"notifications"`
	Telemetry      TelemetryConfig     `yaml:"telemetry" json:"telemetry"`
	Kafka          KafkaConfig         `yaml:"kafka" json:"kafka"`
	DefaultProfile string              `yaml:"default_profile" json:"default_profile"`
	Profiles       []RoleProfile       `yaml:"profiles" json:"profiles"`
}

type NotificationsConfig struct {
	WebhookURL string `yaml:"webhook_url" json:"webhook_url,omitempty"`
}

type ServerConfig struct {
	ListenAddr       string            `yaml:"listen_addr" json:"listen_addr"`
	AdminAddr        string            `yaml:"admin_addr" json:"admin_addr"`
	UpstreamAddr     string            `yaml:"upstream_addr" json:"upstream_addr"`
	UpstreamUser     string            `yaml:"upstream_user" json:"upstream_user"`
	UpstreamPassword string            `yaml:"upstream_password" json:"upstream_password,omitempty"`
	UpstreamDatabase string            `yaml:"upstream_database" json:"upstream_database"`
	TLS              TLSConfig         `yaml:"tls" json:"tls"`
	UpstreamTLS      UpstreamTLSConfig `yaml:"upstream_tls" json:"upstream_tls"`
}

type UpstreamTLSConfig struct {
	Enabled            bool   `yaml:"enabled" json:"enabled"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
	ServerName         string `yaml:"server_name" json:"server_name"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
}

type SecurityConfig struct {
	MaskingSecret      string   `yaml:"masking_secret" json:"masking_secret,omitempty"`
	AdminToken         string   `yaml:"admin_token" json:"-"`
	HITLDefaultTimeout string   `yaml:"hitl_default_timeout" json:"hitl_default_timeout"`
	CompliancePacks    []string `yaml:"compliance_packs" json:"compliance_packs"`
}

type TelemetryConfig struct {
	ServiceName       string `yaml:"service_name" json:"service_name"`
	PrometheusEnabled bool   `yaml:"prometheus_enabled" json:"prometheus_enabled"`
	OTelEnabled       bool   `yaml:"otel_enabled" json:"otel_enabled"`
	OTelEndpoint      string `yaml:"otel_endpoint" json:"otel_endpoint"`
}

type KafkaConfig struct {
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	Brokers     []string `yaml:"brokers" json:"brokers"`
	AuditTopic  string   `yaml:"audit_topic" json:"audit_topic"`
	AlertsTopic string   `yaml:"alerts_topic" json:"alerts_topic"`
	DLQTopic    string   `yaml:"dlq_topic" json:"dlq_topic"`
	ClientID    string   `yaml:"client_id" json:"client_id"`
}

// RoleProfile defines AST firewall rules and PII masking policies for a matched identity.
type RoleProfile struct {
	Name        string         `yaml:"name" json:"name"`
	Description string         `yaml:"description" json:"description"`
	Mode        string         `yaml:"mode" json:"mode"` // "enforce" (default) or "audit" (shadow dry-run)
	Match       MatchCriteria  `yaml:"match" json:"match"`
	Firewall    FirewallPolicy `yaml:"firewall" json:"firewall"`
	Masking     MaskingPolicy  `yaml:"masking" json:"masking"`

	// Precomputed lookup maps (not serialized)
	colRuleMap      map[string]pii.Strategy `yaml:"-" json:"-"`
	enabledEntities map[pii.EntityType]bool `yaml:"-" json:"-"`
}

// IsAuditOnly returns true when the profile operates in non-blocking shadow/dry-run rollout mode.
func (p *RoleProfile) IsAuditOnly() bool {
	return p != nil && strings.EqualFold(p.Mode, "audit")
}

type MatchCriteria struct {
	ApplicationNames []string `yaml:"application_names" json:"application_names"`
	Users            []string `yaml:"users" json:"users"`
}

type RateLimitPolicy struct {
	MaxQueriesPerMinute int    `yaml:"max_queries_per_minute" json:"max_queries_per_minute"`
	LoopThreshold       int    `yaml:"loop_threshold" json:"loop_threshold"`
	LoopWindow          string `yaml:"loop_window" json:"loop_window"`
}

type FirewallPolicy struct {
	AllowStatements         []string        `yaml:"allow_statements" json:"allow_statements"`
	BlockDDL                bool            `yaml:"block_ddl" json:"block_ddl"`
	BlockMultiStatement     bool            `yaml:"block_multi_statement" json:"block_multi_statement"`
	BlockWriteWithoutWhere  bool            `yaml:"block_write_without_where" json:"block_write_without_where"`
	BlockDangerousFunctions bool            `yaml:"block_dangerous_functions" json:"block_dangerous_functions"`
	BlockSystemCatalogs     bool            `yaml:"block_system_catalogs" json:"block_system_catalogs"`
	BlockPIIInference       bool            `yaml:"block_pii_inference" json:"block_pii_inference"`
	ProtectedColumns        []string        `yaml:"protected_columns" json:"protected_columns"`
	RequireHITLStatements   []string        `yaml:"require_hitl_statements" json:"require_hitl_statements"`
	HITLMode                string          `yaml:"hitl_mode" json:"hitl_mode"`
	HITLTimeout             string          `yaml:"hitl_timeout" json:"hitl_timeout"`
	AllowedTables           []string        `yaml:"allowed_tables" json:"allowed_tables"`
	DeniedTables            []string        `yaml:"denied_tables" json:"denied_tables"`
	MaxRows                 int             `yaml:"max_rows" json:"max_rows"`
	MaxRowsAction           string          `yaml:"max_rows_action" json:"max_rows_action"`
	BlockSelectStarOnPII    bool            `yaml:"block_select_star_on_pii_tables" json:"block_select_star_on_pii_tables"`
	RateLimit               RateLimitPolicy `yaml:"rate_limit" json:"rate_limit"`
}

// LoopWindowDuration returns the parsed runaway-loop detection window.
func (f FirewallPolicy) LoopWindowDuration() time.Duration {
	if f.RateLimit.LoopWindow != "" {
		if d, err := time.ParseDuration(f.RateLimit.LoopWindow); err == nil && d > 0 {
			return d
		}
	}
	return 15 * time.Second
}

type MaskingPolicy struct {
	Enabled         bool         `yaml:"enabled" json:"enabled"`
	AutoDetectPII   bool         `yaml:"auto_detect_pii" json:"auto_detect_pii"`
	CompliancePacks []string     `yaml:"compliance_packs" json:"compliance_packs"`
	ColumnRules     []ColumnRule `yaml:"column_rules" json:"column_rules"`
}

type ColumnRule struct {
	Column   string       `yaml:"column" json:"column"`
	Strategy pii.Strategy `yaml:"strategy" json:"strategy"`
}

// ColumnStrategy returns the explicit masking strategy for a column name, if configured.
func (p *RoleProfile) ColumnStrategy(colName string) pii.Strategy {
	if p == nil || p.colRuleMap == nil {
		return ""
	}
	return p.colRuleMap[strings.ToLower(colName)]
}

// EnabledEntities returns the resolved PII entity map for this profile.
func (p *RoleProfile) EnabledEntities() map[pii.EntityType]bool {
	if p == nil {
		return nil
	}
	return p.enabledEntities
}

// HITLTimeoutDuration parses the HITL timeout with a safe fallback.
func (p *RoleProfile) HITLTimeoutDuration(fallback time.Duration) time.Duration {
	if p != nil && p.Firewall.HITLTimeout != "" {
		if d, err := time.ParseDuration(p.Firewall.HITLTimeout); err == nil && d > 0 {
			return d
		}
	}
	if fallback > 0 {
		return fallback
	}
	return 60 * time.Second
}

// Manager holds the live hot-reloadable configuration and compiled masker.
type Manager struct {
	mu       sync.RWMutex
	cfg      *Config
	rawYAML  string
	filePath string
	masker   *pii.Masker
	version  int64
}

// LoadFile loads, validates, and compiles a pgveil YAML configuration file.
func LoadFile(path string) (*Manager, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	m, err := LoadBytes(data)
	if err != nil {
		return nil, err
	}
	m.filePath = path
	return m, nil
}

// LoadBytes parses YAML bytes into a validated Manager.
func LoadBytes(data []byte) (*Manager, error) {
	cfg, err := parseAndCompile(data)
	if err != nil {
		return nil, err
	}
	return &Manager{
		cfg:     cfg,
		rawYAML: string(data),
		masker:  pii.NewMasker(cfg.Security.MaskingSecret),
		version: 1,
	}, nil
}

// ReloadBytes atomically validates and swaps the active policy configuration.
// Any secret field equal to RedactedPlaceholder preserves the currently active secret so
// Control Plane Policy Studio edits never leak or clobber credentials.
func (m *Manager) ReloadBytes(data []byte) error {
	m.mu.RLock()
	prev := m.cfg
	m.mu.RUnlock()

	cfg, err := parseAndCompileWithPrev(data, prev)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
	m.rawYAML = string(data)
	m.masker = pii.NewMasker(cfg.Security.MaskingSecret)
	m.version++
	return nil
}

// RedactedYAML returns the active YAML with secrets (passwords, HMAC keys, admin tokens, webhooks) redacted.
func (m *Manager) RedactedYAML() (string, int64) {
	m.mu.RLock()
	raw := m.rawYAML
	ver := m.version
	m.mu.RUnlock()
	redacted := secretYAMLLineRe.ReplaceAllStringFunc(raw, func(line string) string {
		parts := secretYAMLLineRe.FindStringSubmatch(line)
		if len(parts) < 4 {
			return line
		}
		val := strings.TrimSpace(strings.Trim(parts[2], `"'`))
		if val == "" {
			return line
		}
		return parts[1] + `"` + RedactedPlaceholder + `"` + parts[3]
	})
	return redacted, ver
}

// BuildDSN constructs a safely URL-encoded PostgreSQL connection URI (handles special characters
// in usernames/passwords, normalizes wildcard bind addresses, and sets sslmode cleanly).
func BuildDSN(addr, user, password, database, appName string, tlsEnabled bool) string {
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		addr = net.JoinHostPort(host, port)
	} else if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	u := &url.URL{
		Scheme: "postgres",
		Host:   addr,
		Path:   "/" + database,
	}
	if user != "" {
		if password != "" {
			u.User = url.UserPassword(user, password)
		} else {
			u.User = url.User(user)
		}
	}
	q := url.Values{}
	if tlsEnabled {
		q.Set("sslmode", "require")
	} else {
		q.Set("sslmode", "disable")
	}
	if appName != "" {
		q.Set("application_name", appName)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// ReloadFile re-reads the configured YAML file from disk (used by SIGHUP).
func (m *Manager) ReloadFile() error {
	m.mu.RLock()
	p := m.filePath
	m.mu.RUnlock()
	if p == "" {
		return errors.New("no config file path associated with manager")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return m.ReloadBytes(data)
}

// Config returns the active immutable snapshot of Config.
func (m *Manager) Config() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// RawYAML returns the active YAML source text and version counter.
func (m *Manager) RawYAML() (string, int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rawYAML, m.version
}

// Masker returns the active compiled PII masker.
func (m *Manager) Masker() *pii.Masker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.masker
}

// MatchProfile resolves the RoleProfile for a PostgreSQL session based on application_name and user.
func (m *Manager) MatchProfile(user, appName string) *RoleProfile {
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	for i := range cfg.Profiles {
		p := &cfg.Profiles[i]
		if matchesAny(appName, p.Match.ApplicationNames) || matchesAny(user, p.Match.Users) {
			return p
		}
	}
	for i := range cfg.Profiles {
		if cfg.Profiles[i].Name == cfg.DefaultProfile {
			return &cfg.Profiles[i]
		}
	}
	if len(cfg.Profiles) > 0 {
		return &cfg.Profiles[0]
	}
	return &RoleProfile{Name: "default"}
}

// GetProfileByName returns a profile directly by name (used by the interactive Playground).
func (m *Manager) GetProfileByName(name string) (*RoleProfile, bool) {
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()
	for i := range cfg.Profiles {
		if strings.EqualFold(cfg.Profiles[i].Name, name) {
			return &cfg.Profiles[i], true
		}
	}
	return nil, false
}

func matchesAny(val string, patterns []string) bool {
	if val == "" {
		return false
	}
	lowVal := strings.ToLower(strings.TrimSpace(val))
	for _, pat := range patterns {
		lowPat := strings.ToLower(strings.TrimSpace(pat))
		if lowPat == "" {
			continue
		}
		if lowPat == "*" || lowPat == lowVal {
			return true
		}
		if ok, _ := filepath.Match(lowPat, lowVal); ok {
			return true
		}
	}
	return false
}

func parseAndCompile(data []byte) (*Config, error) {
	return parseAndCompileWithPrev(data, nil)
}

func parseAndCompileWithPrev(data []byte, prev *Config) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if prev != nil {
		if cfg.Server.UpstreamPassword == RedactedPlaceholder {
			cfg.Server.UpstreamPassword = prev.Server.UpstreamPassword
		}
		if cfg.Security.MaskingSecret == RedactedPlaceholder {
			cfg.Security.MaskingSecret = prev.Security.MaskingSecret
		}
		if cfg.Security.AdminToken == RedactedPlaceholder {
			cfg.Security.AdminToken = prev.Security.AdminToken
		}
		if cfg.Notifications.WebhookURL == RedactedPlaceholder {
			cfg.Notifications.WebhookURL = prev.Notifications.WebhookURL
		}
	}
	applyEnvOverrides(&cfg)
	applyDefaults(&cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	for i := range cfg.Profiles {
		p := &cfg.Profiles[i]
		p.colRuleMap = make(map[string]pii.Strategy, len(p.Masking.ColumnRules))
		for _, r := range p.Masking.ColumnRules {
			p.colRuleMap[strings.ToLower(strings.TrimSpace(r.Column))] = r.Strategy
		}
		packs := p.Masking.CompliancePacks
		if len(packs) == 0 && p.Masking.Enabled {
			packs = cfg.Security.CompliancePacks
		}
		p.enabledEntities = pii.ResolveEnabledEntities(packs)
	}
	return &cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("PGVEIL_LISTEN_ADDR"); v != "" {
		cfg.Server.ListenAddr = v
	}
	if v := os.Getenv("PGVEIL_ADMIN_ADDR"); v != "" {
		cfg.Server.AdminAddr = v
	}
	if v := os.Getenv("PGVEIL_UPSTREAM_ADDR"); v != "" {
		cfg.Server.UpstreamAddr = v
	}
	if v := os.Getenv("PGVEIL_UPSTREAM_USER"); v != "" {
		cfg.Server.UpstreamUser = v
	}
	if v := os.Getenv("PGVEIL_UPSTREAM_PASSWORD"); v != "" {
		cfg.Server.UpstreamPassword = v
	}
	if v := os.Getenv("PGVEIL_UPSTREAM_DATABASE"); v != "" {
		cfg.Server.UpstreamDatabase = v
	}
	if v := os.Getenv("PGVEIL_MASKING_SECRET"); v != "" {
		cfg.Security.MaskingSecret = v
	}
	if v := os.Getenv("PGVEIL_ADMIN_TOKEN"); v != "" {
		cfg.Security.AdminToken = v
	}
	if v := os.Getenv("PGVEIL_KAFKA_ENABLED"); v == "true" || v == "1" {
		cfg.Kafka.Enabled = true
	} else if v == "false" || v == "0" {
		cfg.Kafka.Enabled = false
	}
	if v := os.Getenv("PGVEIL_KAFKA_BROKERS"); v != "" {
		parts := strings.Split(v, ",")
		brokers := make([]string, 0, len(parts))
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				brokers = append(brokers, s)
			}
		}
		if len(brokers) > 0 {
			cfg.Kafka.Brokers = brokers
		}
	}
	if v := os.Getenv("PGVEIL_OTEL_ENABLED"); v == "true" || v == "1" {
		cfg.Telemetry.OTelEnabled = true
	}
	if v := os.Getenv("PGVEIL_OTEL_ENDPOINT"); v != "" {
		cfg.Telemetry.OTelEndpoint = v
	}
	if v := os.Getenv("PGVEIL_ALERT_WEBHOOK"); v != "" {
		cfg.Notifications.WebhookURL = v
	}
	if v := os.Getenv("PGVEIL_UPSTREAM_TLS"); v == "true" || v == "1" {
		cfg.Server.UpstreamTLS.Enabled = true
	}
}

func applyDefaults(cfg *Config) {
	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = ":6432"
	}
	if cfg.Server.AdminAddr == "" {
		cfg.Server.AdminAddr = ":8088"
	}
	if cfg.Server.UpstreamAddr == "" {
		cfg.Server.UpstreamAddr = "127.0.0.1:5432"
	}
	if cfg.Security.HITLDefaultTimeout == "" {
		cfg.Security.HITLDefaultTimeout = "60s"
	}
	if cfg.Telemetry.ServiceName == "" {
		cfg.Telemetry.ServiceName = "pgveil-proxy"
	}
	if cfg.Kafka.AuditTopic == "" {
		cfg.Kafka.AuditTopic = "pgveil.audit.queries"
	}
	if cfg.Kafka.AlertsTopic == "" {
		cfg.Kafka.AlertsTopic = "pgveil.alerts.security"
	}
	if cfg.Kafka.DLQTopic == "" {
		cfg.Kafka.DLQTopic = "pgveil.audit.dlq"
	}
	if cfg.Kafka.ClientID == "" {
		cfg.Kafka.ClientID = "pgveil-proxy"
	}
	for i := range cfg.Profiles {
		if cfg.Profiles[i].Mode == "" {
			cfg.Profiles[i].Mode = "enforce"
		}
		if cfg.Profiles[i].Firewall.MaxRowsAction == "" {
			cfg.Profiles[i].Firewall.MaxRowsAction = "truncate"
		}
		if cfg.Profiles[i].Firewall.HITLMode == "" {
			cfg.Profiles[i].Firewall.HITLMode = "hold"
		}
	}
}

// Validate checks configuration invariants.
func (c *Config) Validate() error {
	if len(c.Profiles) == 0 {
		return errors.New("config must define at least one role profile")
	}
	seen := make(map[string]bool, len(c.Profiles))
	for _, p := range c.Profiles {
		if strings.TrimSpace(p.Name) == "" {
			return errors.New("profile name cannot be empty")
		}
		if seen[p.Name] {
			return fmt.Errorf("duplicate profile name %q", p.Name)
		}
		seen[p.Name] = true
		if p.Mode != "" && p.Mode != "enforce" && p.Mode != "audit" {
			return fmt.Errorf("profile %q: invalid mode %q (must be enforce or audit)", p.Name, p.Mode)
		}
		if p.Firewall.MaxRowsAction != "truncate" && p.Firewall.MaxRowsAction != "block" {
			return fmt.Errorf("profile %q: invalid max_rows_action %q (must be truncate or block)", p.Name, p.Firewall.MaxRowsAction)
		}
		if p.Firewall.HITLMode != "hold" && p.Firewall.HITLMode != "reject" {
			return fmt.Errorf("profile %q: invalid hitl_mode %q (must be hold or reject)", p.Name, p.Firewall.HITLMode)
		}
	}
	if c.DefaultProfile != "" && !seen[c.DefaultProfile] {
		return fmt.Errorf("default_profile %q does not match any defined profile", c.DefaultProfile)
	}
	return nil
}
