package pii

import (
	"strings"
	"testing"
)

func TestValidateTCKN(t *testing.T) {
	valid := []string{"10000000146", "12345678950", "24681357994", "31415926562", "55511122260"}
	for _, v := range valid {
		if !ValidateTCKN(v) {
			t.Errorf("expected valid TCKN %s", v)
		}
	}
	invalid := []string{"00000000000", "10000000147", "12345678901", "12345", "1000000014a", "99999999999"}
	for _, v := range invalid {
		if ValidateTCKN(v) {
			t.Errorf("expected invalid TCKN %s to be rejected (zero false positives)", v)
		}
	}
}

func TestValidateVKN(t *testing.T) {
	// Generate a mathematically valid VKN dynamically and verify validation & rejection.
	base := "123456789"
	sum := 0
	for i := 0; i < 9; i++ {
		d := int(base[i] - '0')
		v1 := (d + (9 - i)) % 10
		v2 := (v1 * (1 << (9 - i))) % 9
		if v1 != 0 && v2 == 0 {
			v2 = 9
		}
		sum += v2
	}
	check := (10 - (sum % 10)) % 10
	validVKN := base + string(rune('0'+check))
	if !ValidateVKN(validVKN) {
		t.Fatalf("expected %s to be valid VKN", validVKN)
	}
	wrongCheck := (check + 1) % 10
	badVKN := base + string(rune('0'+wrongCheck))
	if ValidateVKN(badVKN) {
		t.Fatalf("expected %s to fail VKN checksum", badVKN)
	}
}

func TestValidateIBAN(t *testing.T) {
	cases := []struct {
		iban    string
		wantOK  bool
		wantCC  string
	}{
		{"TR330006100519786457841326", true, "TR"},
		{"TR33 0006 1005 1978 6457 8413 26", true, "TR"},
		{"DE89370400440532013000", true, "DE"},
		{"FR7630006000011234567890189", true, "FR"},
		{"GB29NWBK60161331926819", true, "GB"},
		{"NL91ABNA0417164300", true, "NL"},
		{"TR330006100519786457841327", false, ""}, // corrupted checksum
		{"TR3300061005197864578413", false, ""},   // wrong length
	}
	for _, tc := range cases {
		ok, cc := ValidateIBAN(tc.iban)
		if ok != tc.wantOK || cc != tc.wantCC {
			t.Errorf("ValidateIBAN(%q) = (%v, %q), want (%v, %q)", tc.iban, ok, cc, tc.wantOK, tc.wantCC)
		}
	}
}

func TestValidateCreditCard(t *testing.T) {
	valid := []string{"4242-4242-4242-4242", "5555-5555-5555-4444", "4000-0566-5566-5556", "3782-8224-6310-005"}
	for _, cc := range valid {
		if !ValidateCreditCard(cc) {
			t.Errorf("expected valid Luhn card %s", cc)
		}
	}
	invalid := []string{"4242-4242-4242-4243", "0000-0000-0000-0000", "1234-5678-9012-3456", "411111"}
	for _, cc := range invalid {
		if ValidateCreditCard(cc) {
			t.Errorf("expected invalid card %s to be rejected", cc)
		}
	}
}

func TestMaskTextMultiCompliance(t *testing.T) {
	masker := NewMasker("test-secret-key")
	enabled := ResolveEnabledEntities([]string{"kvkk", "gdpr", "pci-dss", "hipaa", "secrets"})

	input := "Refund to IBAN TR330006100519786457841326, TCKN 10000000146, Card 4242-4242-4242-4242, Email ayse.kaya@example.com.tr, Key AKIAIOSFODNN7EXAMPLE, SSN 123-45-6789."
	out, counts := masker.MaskText(input, enabled)

	for _, leaked := range []string{"TR330006100519786457841326", "10000000146", "4242-4242-4242-4242", "ayse.kaya@example.com.tr", "AKIAIOSFODNN7EXAMPLE", "123-45-6789"} {
		if strings.Contains(out, leaked) {
			t.Errorf("PII leaked in masked output! leaked=%q output=%q", leaked, out)
		}
	}
	if counts[string(EntityTRIBAN)] != 1 || counts[string(EntityTCKN)] != 1 || counts[string(EntityCreditCard)] != 1 || counts[string(EntityEmail)] != 1 || counts[string(EntityAWSAccessKey)] != 1 || counts[string(EntityUSSSN)] != 1 {
		t.Errorf("unexpected entity counts: %+v", counts)
	}
}

func TestDeterministicHashPreservesJoins(t *testing.T) {
	m := NewMasker("stable-join-key")
	a, _ := m.Apply("ayse.kaya@example.com.tr", StrategyHash, EntityEmail)
	b, _ := m.Apply("ayse.kaya@example.com.tr", StrategyHash, EntityEmail)
	c, _ := m.Apply("mehmet.demir@acme.io", StrategyHash, EntityEmail)
	if a != b {
		t.Fatalf("expected deterministic pseudonymization: %q != %q", a, b)
	}
	if a == c {
		t.Fatalf("expected distinct hashes for distinct emails")
	}
	if !strings.HasSuffix(a, "@example.com.tr") {
		t.Fatalf("expected email hash to preserve domain, got %q", a)
	}
}

func BenchmarkMaskFreeTextWithPII(b *testing.B) {
	m := NewMasker("bench-key")
	enabled := ResolveEnabledEntities([]string{"kvkk", "gdpr", "pci-dss", "hipaa", "secrets"})
	text := "Hello, please refund order ORD-2026-1001 to my IBAN TR330006100519786457841326. My TCKN is 10000000146 and email ayse.kaya@example.com.tr."
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.MaskText(text, enabled)
	}
}

func BenchmarkMaskCleanCellFastPath(b *testing.B) {
	m := NewMasker("bench-key")
	enabled := ResolveEnabledEntities([]string{"kvkk", "gdpr", "pci-dss", "hipaa", "secrets"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.MaskText("delivered", enabled)
	}
}

func BenchmarkMaskExplicitColumn(b *testing.B) {
	m := NewMasker("bench-key")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = m.MaskColumn("tckn", "10000000146", StrategyPartial, false, nil)
	}
}
