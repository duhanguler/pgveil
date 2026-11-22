package jwtauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/duhanguler/pgveil/internal/policy"
)

func signHS256(secret string, hdr, claims map[string]any) string {
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(in))
	return in + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func signRS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	cb, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func signES256(t *testing.T, priv *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid})
	cb, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	var raw [64]byte
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return in + "." + base64.RawURLEncoding.EncodeToString(raw[:])
}

func TestVerifierHS256PrivilegeEscalationAndAPIKeys(t *testing.T) {
	cfgYAML := `
mcp:
  http_enabled: true
  auth:
    enabled: true
    jwt_secret: "unit-test-hs256-key"
    issuer: "https://auth.example.internal"
    audience: "pgveil-mcp"
    role_claim: "role"
    api_keys:
      - name: "ci-runner"
        token: "pgv_static_ci_token_123"
        profile: "tenant_tr"
        claims:
          city: "Istanbul"
          tenant_id: "42"
default_profile: ai_agent
profiles:
  - name: ai_agent
    masking:
      enabled: true
    firewall:
      allow_statements: ["SELECT"]
  - name: tenant_tr
    masking:
      enabled: true
    firewall:
      allow_statements: ["SELECT"]
  - name: admin
    masking:
      enabled: false
    firewall:
      allow_statements: ["*"]
`
	mgr, err := policy.LoadBytes([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(mgr)
	ctx := context.Background()

	// 1. Static API key succeeds with mapped claims
	id1, err := v.AuthenticateHeader(ctx, "Bearer pgv_static_ci_token_123", "ai_agent")
	if err != nil || id1.AuthMethod != "api_key" || id1.Profile != "tenant_tr" || id1.Claims["city"] != "Istanbul" {
		t.Fatalf("static API key failed: id=%+v err=%v", id1, err)
	}

	// 2. Valid HS256 JWT with array audience & numeric/bool claims
	now := time.Now().Unix()
	validTok := signHS256("unit-test-hs256-key", map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{
		"sub":       "agent-007",
		"iss":       "https://auth.example.internal",
		"aud":       []string{"other", "pgveil-mcp"},
		"exp":       now + 300,
		"nbf":       now - 10,
		"role":      "tenant_tr",
		"city":      "Ankara",
		"org_id":    99,
		"is_active": true,
	})
	id2, err := v.AuthenticateHeader(ctx, "Bearer "+validTok, "ai_agent")
	if err != nil || id2.Subject != "agent-007" || id2.Profile != "tenant_tr" || id2.Claims["org_id"] != "99" || id2.Claims["is_active"] != "true" {
		t.Fatalf("HS256 verify failed: id=%+v err=%v", id2, err)
	}

	// 3. Privilege escalation via role_claim="admin" MUST fail closed
	adminTok := signHS256("unit-test-hs256-key", map[string]any{"alg": "HS256"}, map[string]any{
		"sub":  "attacker",
		"iss":  "https://auth.example.internal",
		"aud":  "pgveil-mcp",
		"exp":  now + 300,
		"role": "admin",
	})
	if _, err := v.AuthenticateHeader(ctx, "Bearer "+adminTok, "ai_agent"); !errors.Is(err, ErrProfileNotPermitted) {
		t.Fatalf("expected ErrProfileNotPermitted on admin escalation, got %v", err)
	}

	// 4. Reject alg=none, expired, future nbf, wrong issuer, wrong audience, bad signature, missing header
	noneTok := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`)) + ".sig"
	if _, err := v.AuthenticateHeader(ctx, "Bearer "+noneTok, "ai_agent"); !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("expected ErrUnsupportedAlg for alg=none, got %v", err)
	}
	expTok := signHS256("unit-test-hs256-key", map[string]any{"alg": "HS256"}, map[string]any{
		"sub": "x", "iss": "https://auth.example.internal", "aud": "pgveil-mcp", "exp": now - 120,
	})
	if _, err := v.AuthenticateHeader(ctx, "Bearer "+expTok, "ai_agent"); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken, got %v", err)
	}
	nbfTok := signHS256("unit-test-hs256-key", map[string]any{"alg": "HS256"}, map[string]any{
		"sub": "x", "iss": "https://auth.example.internal", "aud": "pgveil-mcp", "nbf": now + 300,
	})
	if _, err := v.AuthenticateHeader(ctx, "Bearer "+nbfTok, "ai_agent"); !errors.Is(err, ErrTokenNotYetValid) {
		t.Fatalf("expected ErrTokenNotYetValid, got %v", err)
	}
	wrongIss := signHS256("unit-test-hs256-key", map[string]any{"alg": "HS256"}, map[string]any{
		"sub": "x", "iss": "https://evil.example", "aud": "pgveil-mcp", "exp": now + 300,
	})
	if _, err := v.AuthenticateHeader(ctx, "Bearer "+wrongIss, "ai_agent"); err == nil {
		t.Fatal("expected issuer mismatch error")
	}
	wrongAud := signHS256("unit-test-hs256-key", map[string]any{"alg": "HS256"}, map[string]any{
		"sub": "x", "iss": "https://auth.example.internal", "aud": "wrong", "exp": now + 300,
	})
	if _, err := v.AuthenticateHeader(ctx, "Bearer "+wrongAud, "ai_agent"); err == nil {
		t.Fatal("expected audience mismatch error")
	}
	if _, err := v.AuthenticateHeader(ctx, "", "ai_agent"); !errors.Is(err, ErrMissingToken) {
		t.Fatalf("expected ErrMissingToken, got %v", err)
	}
}

func TestVerifierRS256ES256JWKSStampedeAndKeyConfusion(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var xBuf, yBuf [32]byte
	ecPriv.PublicKey.X.FillBytes(xBuf[:])
	ecPriv.PublicKey.Y.FillBytes(yBuf[:])
	eBytes := []byte{0x01, 0x00, 0x01} // 65537

	var jwksHits atomic.Int32
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksHits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"use": "sig",
					"kid": "rsa-1",
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(rsaPriv.PublicKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(eBytes),
				},
				{
					"kty": "EC",
					"use": "sig",
					"kid": "ec-1",
					"crv": "P-256",
					"alg": "ES256",
					"x":   base64.RawURLEncoding.EncodeToString(xBuf[:]),
					"y":   base64.RawURLEncoding.EncodeToString(yBuf[:]),
				},
			},
		})
	}))
	defer jwksSrv.Close()

	cfgYAML := `
mcp:
  http_enabled: true
  auth:
    enabled: true
    jwks_url: "` + jwksSrv.URL + `"
    allowed_profiles: ["ai_agent"]
default_profile: ai_agent
profiles:
  - name: ai_agent
    masking:
      enabled: true
    firewall:
      allow_statements: ["SELECT"]
`
	mgr, err := policy.LoadBytes([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(mgr)
	ctx := context.Background()
	now := time.Now().Unix()

	// 1. RS256 via JWKS
	rsTok := signRS256(t, rsaPriv, "rsa-1", map[string]any{"sub": "rsa-user", "exp": now + 300, "city": "Izmir"})
	idRS, err := v.VerifyToken(ctx, rsTok, "ai_agent")
	if err != nil || idRS.Subject != "rsa-user" || idRS.Claims["city"] != "Izmir" {
		t.Fatalf("RS256 JWKS failed: id=%+v err=%v", idRS, err)
	}

	// 2. ES256 via JWKS (warm cache -> 0 extra HTTP fetches!)
	esTok := signES256(t, ecPriv, "ec-1", map[string]any{"sub": "ec-user", "exp": now + 300})
	idES, err := v.VerifyToken(ctx, esTok, "ai_agent")
	if err != nil || idES.Subject != "ec-user" {
		t.Fatalf("ES256 JWKS failed: id=%+v err=%v", idES, err)
	}

	// 3. Key-confusion attack: HS256 token MUST be rejected when JWTSecret is empty!
	confused := signHS256("anything", map[string]any{"alg": "HS256"}, map[string]any{"sub": "evil", "exp": now + 300})
	if _, err := v.VerifyToken(ctx, confused, "ai_agent"); !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("expected HS256 key-confusion rejection, got %v", err)
	}

	// 4. 50-goroutine concurrent unknown-kid flood -> JWKS server MUST NOT be hammered (hits stay == 1 due to 30s cooldown!)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			badKid := signRS256(t, rsaPriv, "unknown-kid", map[string]any{"sub": "flood", "exp": now + 300})
			_, _ = v.VerifyToken(ctx, badKid, "ai_agent")
		}(i)
	}
	wg.Wait()
	if hits := jwksHits.Load(); hits != 1 {
		t.Fatalf("expected JWKS stampede protection to cap fetches at 1, got %d", hits)
	}

	// 5. Non-HTTPS non-loopback JWKS URL rejected (SSRF protection)
	if err := validateJWKSURL("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Fatal("expected SSRF non-HTTPS jwks_url rejection")
	}

	// 6. Direct PEM public key verification
	pubDER, _ := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	pemMgr, err := policy.LoadBytes([]byte(`
mcp:
  auth:
    enabled: true
    public_key_pem: |
      ` + strings.ReplaceAll(strings.TrimSpace(pubPEM), "\n", "\n      ") + `
profiles:
  - name: ai_agent
    masking:
      enabled: true
`))
	if err != nil {
		t.Fatal(err)
	}
	vPEM := NewVerifier(pemMgr)
	if _, err := vPEM.VerifyToken(ctx, esTok, "ai_agent"); err != nil {
		t.Fatalf("PEM ES256 verify failed: %v", err)
	}

	// 7. Disabled auth fast-path, PKCS1 RSA PEM, allowed_profiles rejection, and malformed tokens
	disabledMgr, _ := policy.LoadBytes([]byte("profiles:\n  - name: ai_agent\n    masking:\n      enabled: true\n"))
	idAnon, err := NewVerifier(disabledMgr).AuthenticateHeader(ctx, "", "ai_agent")
	if err != nil || idAnon.AuthMethod != "anonymous" {
		t.Fatalf("expected anonymous when auth disabled, got %+v %v", idAnon, err)
	}

	pkcs1PEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&rsaPriv.PublicKey)}))
	rsaPEMMgr, err := policy.LoadBytes([]byte("mcp:\n  auth:\n    enabled: true\n    allowed_profiles: [\"ai_agent\"]\n    public_key_pem: |\n      " + strings.ReplaceAll(strings.TrimSpace(pkcs1PEM), "\n", "\n      ") + "\nprofiles:\n  - name: ai_agent\n    masking:\n      enabled: true\n  - name: analyst\n    masking:\n      enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	vRSA := NewVerifier(rsaPEMMgr)
	if _, err := vRSA.VerifyToken(ctx, rsTok, "ai_agent"); err != nil {
		t.Fatalf("PKCS1 RSA PEM verify failed: %v", err)
	}
	notAllowedRole := signRS256(t, rsaPriv, "rsa-1", map[string]any{"sub": "u", "exp": now + 300, "role": "analyst"})
	if _, err := vRSA.VerifyToken(ctx, notAllowedRole, "ai_agent"); !errors.Is(err, ErrProfileNotPermitted) {
		t.Fatalf("expected allowed_profiles rejection, got %v", err)
	}
	for _, malformed := range []string{"only_one_part", "a.b.!!!", "!!!.b.c", "a.!!!.c"} {
		if _, err := vRSA.VerifyToken(ctx, malformed, "ai_agent"); err == nil {
			t.Fatalf("expected error on malformed token %q", malformed)
		}
	}
}
