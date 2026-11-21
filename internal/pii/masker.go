package pii

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Strategy defines how a detected PII value or sensitive column is transformed.
type Strategy string

const (
	StrategyPartial Strategy = "partial"
	StrategyRedact  Strategy = "redact"
	StrategyLast4   Strategy = "last4"
	StrategyHash    Strategy = "hash"
	StrategyFake    Strategy = "fake"
	StrategyNull    Strategy = "null"
)

// Masker applies deterministic or format-preserving transformations at wire speed.
type Masker struct {
	secret []byte
}

// NewMasker constructs a Masker with the given HMAC secret key for JOIN-preserving pseudonymization.
func NewMasker(secret string) *Masker {
	if secret == "" {
		secret = "pgveil-default-ephemeral-secret"
	}
	return &Masker{secret: []byte(secret)}
}

// Apply transforms a single value according to the requested strategy and optional entity hint.
func (m *Masker) Apply(val string, strategy Strategy, entity EntityType) (string, bool) {
	if val == "" {
		return "", false
	}
	switch strategy {
	case StrategyNull:
		return "", true
	case StrategyRedact:
		if entity != "" {
			return fmt.Sprintf("[REDACTED:%s]", strings.ToUpper(string(entity))), false
		}
		return "[REDACTED]", false
	case StrategyHash:
		return m.deterministicHash(val, entity), false
	case StrategyLast4:
		return maskLast4(val), false
	case StrategyFake:
		return m.deterministicFake(val, entity), false
	case StrategyPartial:
		return maskPartial(val, entity), false
	default:
		return maskPartial(val, entity), false
	}
}

// MaskText scans free-form text for active compliance pack entities and masks every match in-place.
func (m *Masker) MaskText(text string, enabled map[EntityType]bool) (string, map[string]int) {
	matches := Detect(text, enabled)
	if len(matches) == 0 {
		return text, nil
	}

	counts := make(map[string]int, len(matches))
	var b strings.Builder
	b.Grow(len(text) + 16)
	cursor := 0
	for _, match := range matches {
		b.WriteString(text[cursor:match.Start])
		strat := defaultStrategyForEntity(match.Type)
		masked, _ := m.Apply(match.Value, strat, match.Type)
		b.WriteString(masked)
		counts[string(match.Type)]++
		cursor = match.End
	}
	b.WriteString(text[cursor:])
	return b.String(), counts
}

// MaskColumn applies either an explicit column rule or automatic content PII detection.
func (m *Masker) MaskColumn(colName, val string, explicitStrategy Strategy, autoDetect bool, enabled map[EntityType]bool) (masked string, isNull bool, counts map[string]int) {
	if val == "" {
		return val, false, nil
	}
	if explicitStrategy != "" {
		entity := inferEntityFromColumn(colName)
		out, setNull := m.Apply(val, explicitStrategy, entity)
		label := string(entity)
		if label == "" {
			label = "column:" + strings.ToLower(colName)
		}
		return out, setNull, map[string]int{label: 1}
	}
	if autoDetect && len(enabled) > 0 {
		out, found := m.MaskText(val, enabled)
		return out, false, found
	}
	return val, false, nil
}

func defaultStrategyForEntity(t EntityType) Strategy {
	switch t {
	case EntityCreditCard:
		return StrategyLast4
	case EntityPrivateKey, EntityAWSAccessKey, EntityGitHubToken, EntityOpenAIKey, EntityJWT, EntityUSSSN, EntityCASIN, EntityUKNINO:
		return StrategyRedact
	default:
		return StrategyPartial
	}
}

func inferEntityFromColumn(col string) EntityType {
	c := strings.ToLower(col)
	switch {
	case strings.Contains(c, "email") || strings.Contains(c, "e_mail"):
		return EntityEmail
	case strings.Contains(c, "tckn") || strings.Contains(c, "tc_no") || strings.Contains(c, "national_id"):
		return EntityTCKN
	case strings.Contains(c, "vkn") || strings.Contains(c, "tax_id"):
		return EntityVKN
	case strings.Contains(c, "iban"):
		return EntityTRIBAN
	case strings.Contains(c, "card") || strings.Contains(c, "pan"):
		return EntityCreditCard
	case strings.Contains(c, "ssn"):
		return EntityUSSSN
	case strings.Contains(c, "phone") || strings.Contains(c, "mobile") || strings.Contains(c, "tel"):
		return EntityPhoneTR
	case strings.Contains(c, "secret") || strings.Contains(c, "api_key") || strings.Contains(c, "token") || strings.Contains(c, "password"):
		return EntityAWSAccessKey
	default:
		return ""
	}
}

func (m *Masker) deterministicHash(val string, entity EntityType) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(val))
	sum := hex.EncodeToString(mac.Sum(nil))[:12]
	if entity == EntityEmail {
		if idx := strings.LastIndexByte(val, '@'); idx > 0 {
			return fmt.Sprintf("user_%s%s", sum[:8], val[idx:])
		}
	}
	prefix := "tok"
	if entity != "" {
		prefix = string(entity)
	}
	return fmt.Sprintf("%s_%s", prefix, sum)
}

func (m *Masker) deterministicFake(val string, entity EntityType) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(val))
	sum := mac.Sum(nil)
	switch entity {
	case EntityEmail:
		return fmt.Sprintf("user_%x@masked.invalid", sum[:4])
	case EntityPhoneTR:
		num := (uint32(sum[0])<<16 | uint32(sum[1])<<8 | uint32(sum[2])) % 10000000
		return fmt.Sprintf("+90 555 %03d %04d", num/10000, num%10000)
	case EntityIPv4:
		return fmt.Sprintf("198.51.100.%d", int(sum[0])%250+1)
	default:
		return fmt.Sprintf("masked_%x", sum[:5])
	}
}

func maskLast4(val string) string {
	digits := make([]byte, 0, len(val))
	for i := 0; i < len(val); i++ {
		if val[i] >= '0' && val[i] <= '9' {
			digits = append(digits, val[i])
		}
	}
	if len(digits) <= 4 {
		return "****"
	}
	return "****-****-****-" + string(digits[len(digits)-4:])
}

func maskPartial(val string, entity EntityType) string {
	switch entity {
	case EntityEmail:
		if idx := strings.IndexByte(val, '@'); idx > 0 {
			local := val[:idx]
			domain := val[idx:]
			if len(local) <= 1 {
				return "*" + domain
			}
			return local[:1] + "***" + domain
		}
	case EntityTRIBAN, EntityEUIBAN:
		clean := strings.ReplaceAll(strings.ReplaceAll(val, " ", ""), "-", "")
		if len(clean) >= 10 {
			return clean[:4] + " **** **** **** " + clean[len(clean)-4:]
		}
	case EntityTCKN:
		if len(val) == 11 {
			return val[:3] + "******" + val[9:]
		}
	case EntityCreditCard:
		return maskLast4(val)
	case EntityPhoneTR, EntityPhoneIntl:
		if len(val) >= 7 {
			return val[:4] + " *** ** " + val[len(val)-2:]
		}
	case EntityIPv4:
		parts := strings.Split(val, ".")
		if len(parts) == 4 {
			return parts[0] + "." + parts[1] + ".***.***"
		}
	}
	// Generic partial masking preserving small prefix/suffix.
	r := []rune(val)
	switch {
	case len(r) <= 2:
		return "**"
	case len(r) <= 6:
		return string(r[:1]) + strings.Repeat("*", len(r)-2) + string(r[len(r)-1:])
	default:
		return string(r[:2]) + strings.Repeat("*", min(len(r)-4, 8)) + string(r[len(r)-2:])
	}
}
