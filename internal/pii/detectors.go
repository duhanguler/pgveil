package pii

import (
	"regexp"
	"strings"
	"unicode"
)

// EntityType identifies a detected PII or secret category.
type EntityType string

const (
	EntityTCKN         EntityType = "tckn"
	EntityVKN          EntityType = "vkn"
	EntityTRIBAN       EntityType = "tr_iban"
	EntityEUIBAN       EntityType = "eu_iban"
	EntityCreditCard   EntityType = "credit_card"
	EntityUSSSN        EntityType = "us_ssn"
	EntityEmail        EntityType = "email"
	EntityPhoneTR      EntityType = "tr_phone"
	EntityPhoneIntl    EntityType = "phone_intl"
	EntityIPv4         EntityType = "ipv4"
	EntityAWSAccessKey EntityType = "aws_access_key"
	EntityGitHubToken  EntityType = "github_token"
	EntityOpenAIKey    EntityType = "openai_key"
	EntityJWT          EntityType = "jwt_token"
	EntityPrivateKey   EntityType = "private_key"
)

// CompliancePack groups entity detectors by regulatory standard.
type CompliancePack string

const (
	PackGDPR    CompliancePack = "gdpr"
	PackKVKK    CompliancePack = "kvkk"
	PackPCIDSS  CompliancePack = "pci-dss"
	PackHIPAA   CompliancePack = "hipaa"
	PackSecrets CompliancePack = "secrets"
)

// PackEntities maps each compliance pack to its enabled entity types.
var PackEntities = map[CompliancePack][]EntityType{
	PackKVKK: {
		EntityTCKN,
		EntityTRIBAN,
		EntityVKN,
		EntityPhoneTR,
		EntityEmail,
	},
	PackGDPR: {
		EntityEUIBAN,
		EntityEmail,
		EntityPhoneIntl,
		EntityIPv4,
	},
	PackPCIDSS: {
		EntityCreditCard,
	},
	PackHIPAA: {
		EntityUSSSN,
		EntityEmail,
		EntityPhoneIntl,
	},
	PackSecrets: {
		EntityPrivateKey,
		EntityAWSAccessKey,
		EntityGitHubToken,
		EntityOpenAIKey,
		EntityJWT,
	},
}

// Match represents a validated PII or secret span inside a string.
type Match struct {
	Type  EntityType
	Start int
	End   int
	Value string
}

var (
	rePrivateKey   = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	reAWSAccessKey = regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b`)
	reGitHubToken  = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b`)
	reOpenAIKey    = regexp.MustCompile(`\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b`)
	reJWT          = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	reIBAN         = regexp.MustCompile(`\b([A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]){11,30})\b`)
	reCreditCard   = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	reEmail        = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	reUSSSN        = regexp.MustCompile(`\b(\d{3}-\d{2}-\d{4})\b`)
	rePhoneTR      = regexp.MustCompile(`(?:\+90|0090|0)\s*5\d{2}[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b`)
	rePhoneIntl    = regexp.MustCompile(`\+(?:[1-9]\d{0,2})[\s\-]?(?:\(?\d{1,4}\)?[\s\-]?){2,4}\d{2,4}\b`)
	reTCKN         = regexp.MustCompile(`\b([1-9]\d{10})\b`)
	reVKNContext   = regexp.MustCompile(`(?i)\b(?:vkn|vergi(?:\s+kimlik)?(?:\s+no)?|tax\s*id)[:#\s]+(\d{10})\b`)
	reIPv4         = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`)
)

// ibanCountryLengths maps ISO 13616 country codes to exact IBAN character lengths.
var ibanCountryLengths = map[string]int{
	"TR": 26, "DE": 22, "FR": 27, "GB": 22, "NL": 18,
	"ES": 24, "IT": 27, "BE": 16, "AT": 20, "CH": 21,
	"SE": 24, "NO": 15, "DK": 18, "FI": 18, "PL": 28,
	"PT": 25, "IE": 22, "GR": 27, "CZ": 24, "RO": 24,
}

// ValidateTCKN verifies the official 11-digit Turkish National ID (T.C. Kimlik No) checksum.
func ValidateTCKN(raw string) bool {
	if len(raw) != 11 || raw[0] == '0' {
		return false
	}
	var d [11]int
	for i := 0; i < 11; i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return false
		}
		d[i] = int(raw[i] - '0')
	}
	oddSum := d[0] + d[2] + d[4] + d[6] + d[8]
	evenSum := d[1] + d[3] + d[5] + d[7]
	d10 := ((oddSum*7 - evenSum) % 10 + 10) % 10
	if d[9] != d10 {
		return false
	}
	total := 0
	for i := 0; i < 10; i++ {
		total += d[i]
	}
	return d[10] == total%10
}

// ValidateVKN verifies the official 10-digit Turkish Tax Identification Number (Vergi Kimlik No).
func ValidateVKN(raw string) bool {
	if len(raw) != 10 {
		return false
	}
	var d [10]int
	for i := 0; i < 10; i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return false
		}
		d[i] = int(raw[i] - '0')
	}
	sum := 0
	for i := 0; i < 9; i++ {
		v1 := (d[i] + (9 - i)) % 10
		v2 := (v1 * (1 << (9 - i))) % 9
		if v1 != 0 && v2 == 0 {
			v2 = 9
		}
		sum += v2
	}
	check := (10 - (sum % 10)) % 10
	return d[9] == check
}

// ValidateIBAN verifies ISO 13616 length and Mod-97-10 checksum.
func ValidateIBAN(raw string) (valid bool, country string) {
	cleaned := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(raw))
	if len(cleaned) < 15 || len(cleaned) > 34 {
		return false, ""
	}
	cc := cleaned[:2]
	if expected, ok := ibanCountryLengths[cc]; ok && len(cleaned) != expected {
		return false, ""
	}
	// Rearrange: move first 4 chars to the end.
	rearranged := cleaned[4:] + cleaned[:4]
	rem := 0
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			val := int(c-'A') + 10
			rem = (rem*100 + val) % 97
		default:
			return false, ""
		}
	}
	if rem != 1 {
		return false, ""
	}
	return true, cc
}

// ValidateCreditCard checks digit count, major card BIN prefix, and Luhn checksum.
func ValidateCreditCard(raw string) bool {
	digits := make([]int, 0, 19)
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		} else if c != ' ' && c != '-' {
			return false
		}
	}
	n := len(digits)
	if n < 13 || n > 19 {
		return false
	}
	// Reject all-identical digits (e.g. 0000000000000000)
	allSame := true
	for i := 1; i < n; i++ {
		if digits[i] != digits[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return false
	}
	// BIN prefix sanity: Visa (4), Mastercard (51-55, 22-27), Amex (34, 37), Discover/Troy (60, 65, 97)
	first := digits[0]
	firstTwo := digits[0]*10 + digits[1]
	validBIN := first == 4 ||
		(firstTwo >= 51 && firstTwo <= 55) ||
		(firstTwo >= 22 && firstTwo <= 27) ||
		firstTwo == 34 || firstTwo == 37 ||
		firstTwo == 60 || firstTwo == 65 || firstTwo == 97
	if !validBIN {
		return false
	}

	// Luhn checksum
	sum := 0
	double := false
	for i := n - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// ValidateUSSSN verifies US Social Security Number format rules (excludes invalid area/group/serial).
func ValidateUSSSN(raw string) bool {
	if len(raw) != 11 || raw[3] != '-' || raw[6] != '-' {
		return false
	}
	area := raw[0:3]
	group := raw[4:6]
	serial := raw[7:11]
	for _, s := range []string{area, group, serial} {
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
	}
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// ResolveEnabledEntities expands compliance pack names into a set of active EntityTypes.
func ResolveEnabledEntities(packs []string) map[EntityType]bool {
	enabled := make(map[EntityType]bool, 16)
	for _, p := range packs {
		pack := CompliancePack(strings.ToLower(strings.TrimSpace(p)))
		if entities, ok := PackEntities[pack]; ok {
			for _, e := range entities {
				enabled[e] = true
			}
		}
	}
	return enabled
}

// fastWorthScanning performs an O(n) single-pass ASCII hint check to skip regex scanning
// on short/plain values (e.g., "delivered", "Istanbul", "42", "TRY") in nanoseconds.
func fastWorthScanning(s string) bool {
	if len(s) < 6 {
		return false
	}
	digits := 0
	hasAt := false
	hasDash := false
	hasDot := false
	hasUnderscore := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c == '@':
			hasAt = true
		case c == '-':
			hasDash = true
		case c == '.':
			hasDot = true
		case c == '_':
			hasUnderscore = true
		}
	}
	return digits >= 4 || hasAt || hasUnderscore || (hasDash && len(s) >= 15) || (hasDot && digits >= 4)
}

// Detect scans text for all enabled PII & secret entities and returns non-overlapping matches
// sorted by priority (most specific / highest risk first).
func Detect(text string, enabled map[EntityType]bool) []Match {
	if len(enabled) == 0 || !fastWorthScanning(text) {
		return nil
	}

	var candidates []Match
	addMatches := func(re *regexp.Regexp, t EntityType, validator func(string) bool) {
		if !enabled[t] {
			return
		}
		idxs := re.FindAllStringIndex(text, -1)
		for _, idx := range idxs {
			val := text[idx[0]:idx[1]]
			if validator != nil && !validator(val) {
				continue
			}
			candidates = append(candidates, Match{
				Type:  t,
				Start: idx[0],
				End:   idx[1],
				Value: val,
			})
		}
	}

	// 1. High-specificity Secrets first
	if strings.Contains(text, "PRIVATE KEY") {
		addMatches(rePrivateKey, EntityPrivateKey, nil)
	}
	addMatches(reAWSAccessKey, EntityAWSAccessKey, nil)
	if strings.Contains(text, "gh") || strings.Contains(text, "github_pat_") {
		addMatches(reGitHubToken, EntityGitHubToken, nil)
	}
	if strings.Contains(text, "sk-") {
		addMatches(reOpenAIKey, EntityOpenAIKey, nil)
	}
	if strings.Contains(text, "eyJ") {
		addMatches(reJWT, EntityJWT, nil)
	}

	// 2. IBAN (TR & EU)
	if enabled[EntityTRIBAN] || enabled[EntityEUIBAN] {
		idxs := reIBAN.FindAllStringIndex(text, -1)
		for _, idx := range idxs {
			val := text[idx[0]:idx[1]]
			ok, cc := ValidateIBAN(val)
			if !ok {
				continue
			}
			if cc == "TR" && enabled[EntityTRIBAN] {
				candidates = append(candidates, Match{Type: EntityTRIBAN, Start: idx[0], End: idx[1], Value: val})
			} else if cc != "TR" && enabled[EntityEUIBAN] {
				candidates = append(candidates, Match{Type: EntityEUIBAN, Start: idx[0], End: idx[1], Value: val})
			}
		}
	}

	// 3. Credit Card (Luhn + BIN validated)
	addMatches(reCreditCard, EntityCreditCard, ValidateCreditCard)

	// 4. Email
	if strings.ContainsRune(text, '@') {
		addMatches(reEmail, EntityEmail, nil)
	}

	// 5. US SSN
	if strings.ContainsRune(text, '-') {
		addMatches(reUSSSN, EntityUSSSN, ValidateUSSSN)
	}

	// 6. Contextual VKN (10-digit Turkish Tax ID)
	if enabled[EntityVKN] {
		submatches := reVKNContext.FindAllStringSubmatchIndex(text, -1)
		for _, sm := range submatches {
			if len(sm) >= 4 {
				val := text[sm[2]:sm[3]]
				if ValidateVKN(val) {
					candidates = append(candidates, Match{Type: EntityVKN, Start: sm[2], End: sm[3], Value: val})
				}
			}
		}
	}

	// 7. Turkish National ID (TCKN, mod-10 checksum validated)
	addMatches(reTCKN, EntityTCKN, ValidateTCKN)

	// 8. Phone Numbers (TR first, then international)
	addMatches(rePhoneTR, EntityPhoneTR, nil)
	if strings.ContainsRune(text, '+') {
		addMatches(rePhoneIntl, EntityPhoneIntl, func(s string) bool {
			digits := 0
			for _, r := range s {
				if unicode.IsDigit(r) {
					digits++
				}
			}
			return digits >= 9 && digits <= 15
		})
	}

	// 9. IPv4
	if strings.ContainsRune(text, '.') {
		addMatches(reIPv4, EntityIPv4, nil)
	}

	if len(candidates) <= 1 {
		return candidates
	}
	return deduplicateOverlaps(candidates)
}

// deduplicateOverlaps keeps higher-priority (earlier-added) matches and drops overlapping spans.
func deduplicateOverlaps(matches []Match) []Match {
	selected := make([]Match, 0, len(matches))
	for _, m := range matches {
		overlaps := false
		for _, s := range selected {
			if m.Start < s.End && s.Start < m.End {
				overlaps = true
				break
			}
		}
		if !overlaps {
			selected = append(selected, m)
		}
	}
	// Sort by Start offset ascending (insertion sort; tiny N).
	for i := 1; i < len(selected); i++ {
		key := selected[i]
		j := i - 1
		for j >= 0 && selected[j].Start > key.Start {
			selected[j+1] = selected[j]
			j--
		}
		selected[j+1] = key
	}
	return selected
}
