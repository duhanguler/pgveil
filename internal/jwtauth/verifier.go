package jwtauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/duhanguler/pgveil/internal/policy"
)

const (
	clockSkewTolerance    = 30 * time.Second
	jwksDefaultTTL        = 5 * time.Minute
	jwksMinRefreshBackoff = 30 * time.Second
	maxJWKSBodyBytes      = 256 * 1024 // 256 KiB cap against memory exhaustion
)

var (
	ErrMissingToken        = errors.New("missing Bearer token")
	ErrInvalidToken        = errors.New("invalid or malformed Bearer token")
	ErrExpiredToken        = errors.New("token has expired")
	ErrTokenNotYetValid    = errors.New("token is not yet valid (nbf)")
	ErrUnsupportedAlg      = errors.New("unsupported or disallowed JWT signing algorithm")
	ErrProfileNotPermitted = errors.New("requested profile is not permitted for dynamic token routing")
)

// VerifiedIdentity represents a cryptographically verified MCP caller and its flattened claims.
type VerifiedIdentity struct {
	Subject    string            `json:"subject"`
	Profile    string            `json:"profile,omitempty"`
	Claims     map[string]string `json:"claims,omitempty"`
	AuthMethod string            `json:"auth_method"` // "jwt", "api_key", "anonymous"
}

type hashedAPIKey struct {
	name       string
	digest     [32]byte
	profile    string
	claims     map[string]string
}

// Verifier authenticates Bearer tokens (HS256, RS256, ES256, JWKS, and static API keys)
// and enforces allowed_profiles privilege-escalation guards.
type Verifier struct {
	policyMgr  *policy.Manager
	httpClient *http.Client

	jwksMu        sync.Mutex
	jwksURL       string
	jwksKeys      map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	jwksFetchedAt time.Time
	jwksExpiresAt time.Time
	refreshMu     sync.Mutex // coalesces concurrent unknown-kid JWKS fetches
}

func NewVerifier(policyMgr *policy.Manager) *Verifier {
	return &Verifier{
		policyMgr: policyMgr,
		httpClient: &http.Client{
			Timeout: 4 * time.Second,
		},
		jwksKeys: make(map[string]any),
	}
}

// AuthenticateHeader verifies an HTTP Authorization header according to the active MCPAuthConfig.
func (v *Verifier) AuthenticateHeader(ctx context.Context, authHeader string, fallbackProfile string) (VerifiedIdentity, error) {
	cfg := v.policyMgr.Config()
	authCfg := cfg.MCP.Auth
	if !authCfg.Enabled {
		return VerifiedIdentity{
			Subject:    "anonymous",
			Profile:    fallbackProfile,
			AuthMethod: "anonymous",
		}, nil
	}

	raw := strings.TrimSpace(authHeader)
	if !strings.HasPrefix(raw, "Bearer ") && !strings.HasPrefix(raw, "bearer ") {
		return VerifiedIdentity{}, ErrMissingToken
	}
	tok := strings.TrimSpace(raw[7:])
	if tok == "" {
		return VerifiedIdentity{}, ErrMissingToken
	}
	return v.VerifyToken(ctx, tok, fallbackProfile)
}

// VerifyToken validates either a static API key or a signed JWT (HS256 / RS256 / ES256).
func (v *Verifier) VerifyToken(ctx context.Context, token string, fallbackProfile string) (VerifiedIdentity, error) {
	cfg := v.policyMgr.Config()
	authCfg := cfg.MCP.Auth

	// 1. Constant-time SHA-256 comparison against configured static API keys
	if len(authCfg.APIKeys) > 0 {
		tokSum := sha256.Sum256([]byte(token))
		for _, ak := range authCfg.APIKeys {
			if ak.Token == "" {
				continue
			}
			akSum := sha256.Sum256([]byte(ak.Token))
			if subtle.ConstantTimeCompare(tokSum[:], akSum[:]) == 1 {
				prof := ak.Profile
				if prof == "" {
					prof = fallbackProfile
				}
				claims := make(map[string]string, len(ak.Claims))
				for k, val := range ak.Claims {
					claims[k] = val
				}
				sub := ak.Name
				if sub == "" {
					sub = "apikey"
				}
				return VerifiedIdentity{
					Subject:    "apikey:" + sub,
					Profile:    prof,
					Claims:     claims,
					AuthMethod: "api_key",
				}, nil
			}
		}
	}

	// 2. Signed JWT (header.payload.signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return VerifiedIdentity{}, ErrInvalidToken
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return VerifiedIdentity{}, ErrInvalidToken
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return VerifiedIdentity{}, ErrInvalidToken
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sigBytes) == 0 {
		return VerifiedIdentity{}, ErrInvalidToken
	}

	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return VerifiedIdentity{}, ErrInvalidToken
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	if err := v.verifySignature(ctx, hdr.Alg, hdr.Kid, signingInput, sigBytes, authCfg); err != nil {
		return VerifiedIdentity{}, err
	}

	var rawClaims map[string]any
	if err := json.Unmarshal(payloadBytes, &rawClaims); err != nil {
		return VerifiedIdentity{}, ErrInvalidToken
	}

	now := time.Now()
	// Validate exp (if present, or require exp when issuer/JWKS is configured)
	if expVal, hasExp := rawClaims["exp"]; hasExp {
		expSec, ok := toInt64(expVal)
		if !ok {
			return VerifiedIdentity{}, ErrInvalidToken
		}
		if now.After(time.Unix(expSec, 0).Add(clockSkewTolerance)) {
			return VerifiedIdentity{}, ErrExpiredToken
		}
	}
	// Validate nbf
	if nbfVal, hasNbf := rawClaims["nbf"]; hasNbf {
		nbfSec, ok := toInt64(nbfVal)
		if !ok {
			return VerifiedIdentity{}, ErrInvalidToken
		}
		if now.Add(clockSkewTolerance).Before(time.Unix(nbfSec, 0)) {
			return VerifiedIdentity{}, ErrTokenNotYetValid
		}
	}
	// Validate issuer
	if authCfg.Issuer != "" {
		iss, _ := rawClaims["iss"].(string)
		if iss != authCfg.Issuer {
			return VerifiedIdentity{}, fmt.Errorf("%w: issuer mismatch", ErrInvalidToken)
		}
	}
	// Validate audience (string or []any)
	if authCfg.Audience != "" {
		if !matchesAudience(rawClaims["aud"], authCfg.Audience) {
			return VerifiedIdentity{}, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
		}
	}

	flat := flattenClaims(rawClaims)
	sub := flat["sub"]
	if sub == "" {
		sub = "jwt-anonymous"
	}

	resolvedProfile := fallbackProfile
	roleClaimKey := authCfg.RoleClaim
	if roleClaimKey == "" {
		roleClaimKey = "role"
	}
	if claimedRole := strings.TrimSpace(flat[roleClaimKey]); claimedRole != "" {
		if err := v.checkProfilePermitted(claimedRole, cfg); err != nil {
			return VerifiedIdentity{}, err
		}
		resolvedProfile = claimedRole
	}

	return VerifiedIdentity{
		Subject:    sub,
		Profile:    resolvedProfile,
		Claims:     flat,
		AuthMethod: "jwt",
	}, nil
}

func (v *Verifier) checkProfilePermitted(profileName string, cfg *policy.Config) error {
	prof, ok := findProfile(cfg, profileName)
	if !ok {
		return fmt.Errorf("%w: unknown profile %q", ErrProfileNotPermitted, profileName)
	}
	// Explicit allowlist check when configured
	if len(cfg.MCP.Auth.AllowedProfiles) > 0 {
		for _, allowed := range cfg.MCP.Auth.AllowedProfiles {
			if strings.EqualFold(allowed, prof.Name) {
				return nil
			}
		}
		return fmt.Errorf("%w: profile %q is not in mcp.auth.allowed_profiles", ErrProfileNotPermitted, profileName)
	}
	// Default privilege-escalation guard: never allow dynamic JWT claims to select an unmasked
	// or wildcard-statement admin profile unless explicitly listed in allowed_profiles.
	for _, st := range prof.Firewall.AllowStatements {
		if strings.TrimSpace(st) == "*" {
			return fmt.Errorf("%w: wildcard profile %q requires explicit listing in mcp.auth.allowed_profiles", ErrProfileNotPermitted, prof.Name)
		}
	}
	if !prof.Masking.Enabled {
		return fmt.Errorf("%w: unmasked profile %q requires explicit listing in mcp.auth.allowed_profiles", ErrProfileNotPermitted, prof.Name)
	}
	return nil
}

func findProfile(cfg *policy.Config, name string) (*policy.RoleProfile, bool) {
	for i := range cfg.Profiles {
		if strings.EqualFold(cfg.Profiles[i].Name, name) {
			return &cfg.Profiles[i], true
		}
	}
	return nil, false
}

func (v *Verifier) verifySignature(ctx context.Context, alg, kid string, signingInput, sig []byte, authCfg policy.MCPAuthConfig) error {
	switch alg {
	case "HS256":
		// Prevent RSA/ECDSA -> HS256 key-confusion attacks: HS256 is ONLY permitted when JWTSecret is explicitly set.
		if authCfg.JWTSecret == "" {
			return fmt.Errorf("%w: HS256 not enabled", ErrUnsupportedAlg)
		}
		mac := hmac.New(sha256.New, []byte(authCfg.JWTSecret))
		mac.Write(signingInput)
		if !hmac.Equal(sig, mac.Sum(nil)) {
			return ErrInvalidToken
		}
		return nil

	case "RS256":
		pub, err := v.resolvePublicKey(ctx, kid, authCfg)
		if err != nil {
			return err
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: key type mismatch for RS256", ErrInvalidToken)
		}
		sum := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, sum[:], sig); err != nil {
			return ErrInvalidToken
		}
		return nil

	case "ES256":
		if len(sig) != 64 {
			return ErrInvalidToken
		}
		pub, err := v.resolvePublicKey(ctx, kid, authCfg)
		if err != nil {
			return err
		}
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok || ecPub.Curve != elliptic.P256() {
			return fmt.Errorf("%w: key type mismatch for ES256", ErrInvalidToken)
		}
		sum := sha256.Sum256(signingInput)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:64])
		if !ecdsa.Verify(ecPub, sum[:], r, s) {
			return ErrInvalidToken
		}
		return nil

	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedAlg, alg)
	}
}

func (v *Verifier) resolvePublicKey(ctx context.Context, kid string, authCfg policy.MCPAuthConfig) (any, error) {
	if strings.TrimSpace(authCfg.PublicKeyPEM) != "" {
		return parsePEMPublicKey(authCfg.PublicKeyPEM)
	}
	if strings.TrimSpace(authCfg.JWKSURL) != "" {
		return v.lookupJWKSKey(ctx, authCfg.JWKSURL, kid)
	}
	return nil, fmt.Errorf("%w: no public key or jwks_url configured", ErrUnsupportedAlg)
}

func parsePEMPublicKey(pemStr string) (any, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("%w: invalid public_key_pem", ErrInvalidToken)
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert.PublicKey, nil
	}
	if rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return rsaPub, nil
	}
	return nil, fmt.Errorf("%w: unsupported public key format", ErrInvalidToken)
}

func validateJWKSURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid jwks_url %q", rawURL)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host == "127.0.0.1" || host == "localhost" || host == "::1" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("jwks_url must use https (http allowed only on loopback for local testing)")
}

func (v *Verifier) lookupJWKSKey(ctx context.Context, jwksURL, kid string) (any, error) {
	if err := validateJWKSURL(jwksURL); err != nil {
		return nil, err
	}
	now := time.Now()

	v.jwksMu.Lock()
	if v.jwksURL == jwksURL && now.Before(v.jwksExpiresAt) {
		if key, ok := findKeyInMap(v.jwksKeys, kid); ok {
			v.jwksMu.Unlock()
			return key, nil
		}
		// Unknown kid while cache is warm: check cooldown before hitting network
		if now.Sub(v.jwksFetchedAt) < jwksMinRefreshBackoff {
			v.jwksMu.Unlock()
			return nil, fmt.Errorf("%w: unknown key id %q", ErrInvalidToken, kid)
		}
	}
	v.jwksMu.Unlock()

	// Coalesce concurrent refreshes so unknown-kid bursts trigger at most 1 HTTP GET
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	now = time.Now()
	v.jwksMu.Lock()
	if v.jwksURL == jwksURL && now.Sub(v.jwksFetchedAt) < jwksMinRefreshBackoff {
		key, ok := findKeyInMap(v.jwksKeys, kid)
		v.jwksMu.Unlock()
		if ok {
			return key, nil
		}
		return nil, fmt.Errorf("%w: unknown key id %q", ErrInvalidToken, kid)
	}
	v.jwksMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS: unexpected HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}

	parsedKeys, err := parseJWKSet(body)
	if err != nil {
		return nil, err
	}

	v.jwksMu.Lock()
	v.jwksURL = jwksURL
	v.jwksKeys = parsedKeys
	v.jwksFetchedAt = time.Now()
	v.jwksExpiresAt = v.jwksFetchedAt.Add(jwksDefaultTTL)
	key, ok := findKeyInMap(v.jwksKeys, kid)
	v.jwksMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown key id %q", ErrInvalidToken, kid)
	}
	return key, nil
}

func findKeyInMap(m map[string]any, kid string) (any, bool) {
	if kid != "" {
		k, ok := m[kid]
		return k, ok
	}
	if len(m) == 1 {
		for _, k := range m {
			return k, true
		}
	}
	return nil, false
}

type jwkEntry struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parseJWKSet(data []byte) (map[string]any, error) {
	var doc struct {
		Keys []jwkEntry `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode JWKS JSON: %w", err)
	}
	out := make(map[string]any, len(doc.Keys))
	for i, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		kid := k.Kid
		if kid == "" {
			kid = fmt.Sprintf("__idx_%d", i)
		}
		switch k.Kty {
		case "RSA":
			nb, err1 := base64.RawURLEncoding.DecodeString(k.N)
			eb, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil || len(nb) == 0 || len(eb) == 0 {
				continue
			}
			eInt := 0
			for _, b := range eb {
				eInt = (eInt << 8) | int(b)
			}
			if eInt <= 1 {
				continue
			}
			out[kid] = &rsa.PublicKey{
				N: new(big.Int).SetBytes(nb),
				E: eInt,
			}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			xb, err1 := base64.RawURLEncoding.DecodeString(k.X)
			yb, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil || len(xb) != 32 || len(yb) != 32 {
				continue
			}
			x := new(big.Int).SetBytes(xb)
			y := new(big.Int).SetBytes(yb)
			if !elliptic.P256().IsOnCurve(x, y) {
				continue
			}
			out[kid] = &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			}
		}
	}
	return out, nil
}

func toInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case int64:
		return x, true
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	default:
		return 0, false
	}
}

func matchesAudience(audClaim any, expected string) bool {
	switch a := audClaim.(type) {
	case string:
		return a == expected
	case []any:
		for _, item := range a {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

func flattenClaims(raw map[string]any) map[string]string {
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		switch val := v.(type) {
		case string:
			out[k] = val
		case float64:
			if val == float64(int64(val)) {
				out[k] = strconv.FormatInt(int64(val), 10)
			} else {
				out[k] = strconv.FormatFloat(val, 'f', -1, 64)
			}
		case bool:
			out[k] = strconv.FormatBool(val)
		}
	}
	return out
}
