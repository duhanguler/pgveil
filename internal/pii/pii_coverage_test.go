package pii

import (
	"strings"
	"testing"
)

func TestMaskerStrategiesFakeHashNullPartialAndColumnInference(t *testing.T) {
	m := NewMasker("")
	all := ResolveEnabledEntities([]string{"kvkk", "gdpr", "pci-dss", "hipaa", "lgpd", "pipeda", "uk-gdpr", "secrets"})

	if v, n := m.Apply("", StrategyPartial, EntityEmail); v != "" || n {
		t.Fatalf("expected empty value untouched")
	}
	if v, n := m.Apply("abc", StrategyRedact, ""); v != "[REDACTED]" || n {
		t.Fatalf("expected [REDACTED], got %q", v)
	}

	fakeCases := []struct {
		entity EntityType
		val    string
		prefix string
	}{
		{EntityEmail, "ayse@example.com", "@masked.invalid"},
		{EntityPhoneTR, "+90 532 418 9021", "+90 555"},
		{EntityIPv4, "192.168.1.42", "198.51.100."},
		{EntityPhoneIntl, "+1 415 555 0194", "masked_"},
		{EntityTCKN, "10000000146", "masked_"},
		{EntityTRIBAN, "TR330006100519786457841326", "masked_"},
		{EntityEUIBAN, "DE89370400440532013000", "masked_"},
		{EntityCreditCard, "4242-4242-4242-4242", "masked_"},
		{EntityUSSSN, "123-45-6789", "masked_"},
		{EntitySecret, "topsecret", "masked_"},
	}
	for _, tc := range fakeCases {
		got1, _ := m.Apply(tc.val, StrategyFake, tc.entity)
		got2, _ := m.Apply(tc.val, StrategyFake, tc.entity)
		if got1 != got2 || got1 == tc.val || !strings.Contains(got1, tc.prefix) {
			t.Fatalf("StrategyFake(%s): got %q (second=%q)", tc.entity, got1, got2)
		}
	}

	for _, ent := range []EntityType{EntityEmail, EntityTCKN, EntityTRIBAN, EntityEUIBAN, EntitySecret, ""} {
		h1, _ := m.Apply("sample@value.io", StrategyHash, ent)
		h2, _ := m.Apply("sample@value.io", StrategyHash, ent)
		if h1 != h2 || h1 == "sample@value.io" {
			t.Fatalf("StrategyHash(%s) not deterministic: %q vs %q", ent, h1, h2)
		}
	}

	mv, isNull, found := m.MaskColumn("ssn", "123-45-6789", StrategyNull, true, all)
	if !isNull || mv != "" || len(found) == 0 {
		t.Fatalf("expected StrategyNull to set NULL, got mv=%q isNull=%v found=%v", mv, isNull, found)
	}

	if got, _ := m.Apply("ab", StrategyLast4, EntitySecret); got != "****" {
		t.Fatalf("short last4 expected ****, got %q", got)
	}
	if got, _ := m.Apply("1234", StrategyLast4, EntityCreditCard); got != "****" {
		t.Fatalf("4-char last4 expected ****, got %q", got)
	}
	if got, _ := m.Apply("4242424242424242", StrategyLast4, EntityCreditCard); !strings.HasSuffix(got, "4242") {
		t.Fatalf("unexpected last4: %q", got)
	}
	if got, _ := m.Apply("ş@x.tr", StrategyPartial, EntityEmail); got != "*@x.tr" {
		t.Fatalf("unexpected 1-char UTF-8 email partial: %q", got)
	}
	if got, _ := m.Apply("ayse@x.tr", StrategyPartial, EntityEmail); got != "a***@x.tr" {
		t.Fatalf("unexpected email partial: %q", got)
	}
	if got, _ := m.Apply("123", StrategyPartial, EntityTCKN); got != "1*3" {
		t.Fatalf("unexpected short TCKN partial: %q", got)
	}
	if got, _ := m.Apply("TR123", StrategyPartial, EntityTRIBAN); got != "T***3" {
		t.Fatalf("unexpected short IBAN partial: %q", got)
	}
	if got, _ := m.Apply("1234", StrategyPartial, EntityPhoneTR); got != "1**4" {
		t.Fatalf("unexpected short phone partial: %q", got)
	}
	if got, _ := m.Apply("    905321234567", StrategyPartial, EntityPhoneTR); !strings.Contains(got, "*** ** 67") {
		t.Fatalf("unexpected padded phone partial: %q", got)
	}
	if got, _ := m.Apply("10.20.30.40", StrategyPartial, EntityIPv4); got != "10.20.***.***" {
		t.Fatalf("unexpected ipv4 partial: %q", got)
	}
	if got, _ := m.Apply("ab", StrategyPartial, EntitySecret); got != "**" {
		t.Fatalf("unexpected short generic partial: %q", got)
	}
	if got, _ := m.Apply("abcdef", StrategyPartial, EntitySecret); got != "a****f" {
		t.Fatalf("unexpected generic partial: %q", got)
	}
	if got, _ := m.Apply("abcdefghijkl", StrategyPartial, EntitySecret); got != "ab********kl" {
		t.Fatalf("unexpected long generic partial: %q", got)
	}
	if got, _ := m.Apply("val", Strategy("unknown"), EntitySecret); got != "v*l" {
		t.Fatalf("unexpected default fallback strategy: %q", got)
	}

	colHints := []string{
		"email_address", "tckn_no", "national_id", "tc_no", "iban_tr",
		"card_number", "credit_card", "pan", "ssn_num", "phone_number",
		"mobile", "password_hash", "api_key", "secret_value", "vkn_id",
		"client_ip", "ip_address", "other_col",
	}
	for _, col := range colHints {
		out, _, _ := m.MaskColumn(col, "some_sensitive_value_123456", StrategyPartial, false, all)
		if out == "some_sensitive_value_123456" {
			t.Fatalf("expected explicit StrategyPartial on column %q to mask value", col)
		}
	}

	txtOut, _, f2 := m.MaskColumn("notes", "Contact ayse@example.com or 192.168.1.42", "", true, all)
	if len(f2) == 0 || strings.Contains(txtOut, "ayse@example.com") {
		t.Fatalf("expected auto-detect masking, got %q (%v)", txtOut, f2)
	}

	if ValidateTCKN("00000000000") || ValidateTCKN("123") || ValidateTCKN("10000000147") {
		t.Fatal("invalid TCKN passed")
	}
	if ValidateVKN("12345") || ValidateVKN("abcdefghij") {
		t.Fatal("invalid VKN passed")
	}
	if ok1, _ := ValidateIBAN("TR12"); ok1 {
		t.Fatal("invalid IBAN passed")
	}
	if ok2, _ := ValidateIBAN("TR330006100519786457841327"); ok2 {
		t.Fatal("invalid IBAN passed")
	}
	if ValidateCreditCard("1234") || ValidateCreditCard("4242-4242-4242-4243") {
		t.Fatal("invalid card passed")
	}
	if ValidateUSSSN("000-12-3456") || ValidateUSSSN("666-12-3456") || ValidateUSSSN("900-12-3456") || ValidateUSSSN("123-00-4567") || ValidateUSSSN("123-45-0000") {
		t.Fatal("invalid SSN passed")
	}
	if ValidateBRCPF("111.111.111-11") || ValidateBRCPF("123") || ValidateBRCPF("529.982.247-26") {
		t.Fatal("invalid CPF passed")
	}
	if ValidateCASIN("000-000-000") || ValidateCASIN("123") || ValidateCASIN("046-454-287") {
		t.Fatal("invalid SIN passed")
	}
	if ValidateUKNINO("QQ123456C") || ValidateUKNINO("BG123456C") || ValidateUKNINO("AB123") || ValidateUKNINO("AB123456E") {
		t.Fatal("invalid NINO passed")
	}

	synthStripe := "sk_" + "live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz123456"
	synthSlack := "xox" + "b-" + "123456789012-123456789012-aBcDeFgHiJkLmNoPqRsTuVwX"
	synthPEM := "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIE...\n-----END RSA " + "PRIVATE KEY-----"
	synthJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	joined := synthStripe + " " + synthSlack + " " + synthPEM + " " + synthJWT + " 529.982.247-25 130-692-544 QQ123456C AB123456C 192.168.10.20 +49 170 4829103"
	masked, entities := m.MaskText(joined, all)
	if !strings.Contains(masked, "[REDACTED:STRIPE_KEY]") || !strings.Contains(masked, "[REDACTED:SLACK_TOKEN]") || !strings.Contains(masked, "[REDACTED:PRIVATE_KEY]") || !strings.Contains(masked, "[REDACTED:JWT_TOKEN]") {
		t.Fatalf("expected all secret detectors to fire, got: %s (entities=%v)", masked, entities)
	}
}
