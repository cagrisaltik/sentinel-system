package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type testCredentialStore map[string]string

func (s testCredentialStore) PasswordHash(_ context.Context, username string) (string, error) {
	hash, ok := s[username]
	if !ok {
		return "", sql.ErrNoRows
	}
	return hash, nil
}

func testApp(t *testing.T, config Config) (*AnalystApp, string) {
	t.Helper()
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		t.Fatal(err)
	}
	password := base64.RawURLEncoding.EncodeToString(passwordBytes)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	app, err := newAnalystApp(nil, testCredentialStore{"analyst": string(hash)}, config)
	if err != nil {
		t.Fatal(err)
	}
	return app, password
}

func testConfig() Config {
	return Config{
		WebDir: "../../web/analyst", SessionTTL: time.Hour,
		LoginMaxAttempts: 5, LoginIdentityMaxAttempts: 3, LoginAccountMaxAttempts: 10, LoginWindow: 10 * time.Minute, LoginBlockTime: 15 * time.Minute,
		APIMaxRequests: 240, APIWindow: time.Minute,
	}
}

func performRequest(handler http.Handler, method, target, body, remoteAddr string, token string, tlsEnabled bool) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.RemoteAddr = remoteAddr
	if token != "" {
		request.AddCookie(&http.Cookie{Name: analystCookieName, Value: token})
	}
	if tlsEnabled {
		request.TLS = &tls.ConnectionState{}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestSessionTokensAreRandomAndHave32BytesOfEntropy(t *testing.T) {
	first, err := generateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 32 || first == second {
		t.Fatalf("expected distinct 256-bit session tokens; got %q and %q", first, second)
	}
}

func TestRequiredStartupConfigurationFailsClosed(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("Analyst config should require TLS certificate and key paths")
	}
	if _, err := openDatabase(""); err == nil {
		t.Fatal("Analyst should require DATABASE_URL")
	}
}

func TestSessionExpiryInvalidTokenAndCleanup(t *testing.T) {
	now := time.Now()
	store := newSessionStore(time.Minute)
	token, err := store.create("analyst", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.get(token, now.Add(59*time.Second)); !ok {
		t.Fatal("session should be valid before its expiry")
	}
	if _, ok := store.get(token, now.Add(time.Minute)); ok {
		t.Fatal("session should expire at its expiry time")
	}
	if _, ok := store.get("not-a-session", now); ok {
		t.Fatal("unknown token should not be accepted")
	}
	other, err := store.create("analyst", now)
	if err != nil {
		t.Fatal(err)
	}
	store.cleanup(now.Add(time.Minute))
	if _, ok := store.get(other, now.Add(time.Minute)); ok {
		t.Fatal("cleanup should remove expired sessions")
	}
}

func TestValidLoginSetsSecureCookieAndRotatesSession(t *testing.T) {
	app, password := testApp(t, testConfig())
	oldToken, err := app.sessions.create("analyst", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(LoginRequest{Username: "analyst", Password: password})
	response := performRequest(app.Handler(), http.MethodPost, "/api/login", string(body), "192.0.2.1:1234", oldToken, true)
	if response.Code != http.StatusOK {
		t.Fatalf("login returned %d: %s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != analystCookieName || cookie.Value == "" || cookie.Value == oldToken {
		t.Fatal("login should issue a fresh session cookie")
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.MaxAge != int(time.Hour.Seconds()) {
		t.Fatalf("unexpected cookie security settings: %#v", cookie)
	}
	if _, ok := app.sessions.get(oldToken, time.Now()); ok {
		t.Fatal("pre-login session should be revoked")
	}
	if _, ok := app.sessions.get(cookie.Value, time.Now()); !ok {
		t.Fatal("new login session should be stored")
	}
	if strings.Contains(response.Body.String(), cookie.Value) {
		t.Fatal("session token must not be returned in the response body")
	}
}

func TestUnknownUserAndWrongPasswordHaveSameResponse(t *testing.T) {
	app, _ := testApp(t, testConfig())
	handler := app.Handler()
	unknown, _ := json.Marshal(LoginRequest{Username: "missing-user", Password: "bad password"})
	wrong, _ := json.Marshal(LoginRequest{Username: "analyst", Password: "bad password"})
	unknownResponse := performRequest(handler, http.MethodPost, "/api/login", string(unknown), "192.0.2.2:1234", "", true)
	wrongResponse := performRequest(handler, http.MethodPost, "/api/login", string(wrong), "192.0.2.3:1234", "", true)
	if unknownResponse.Code != http.StatusUnauthorized || wrongResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expected generic 401 responses, got %d and %d", unknownResponse.Code, wrongResponse.Code)
	}
	if unknownResponse.Body.String() != wrongResponse.Body.String() || !strings.Contains(unknownResponse.Body.String(), "invalid credentials") {
		t.Fatalf("login responses disclose account existence: %q vs %q", unknownResponse.Body.String(), wrongResponse.Body.String())
	}
}

func TestLoginRejectsMalformedAndOversizedJSON(t *testing.T) {
	app, _ := testApp(t, testConfig())
	malformed := performRequest(app.Handler(), http.MethodPost, "/api/login", `{"username":`, "192.0.2.4:1234", "", true)
	if malformed.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON returned %d, want 400", malformed.Code)
	}
	oversizedBody := `{"username":"analyst","password":"` + strings.Repeat("x", maxLoginBodyBytes) + `"}`
	oversized := performRequest(app.Handler(), http.MethodPost, "/api/login", oversizedBody, "192.0.2.5:1234", "", true)
	if oversized.Code != http.StatusBadRequest {
		t.Fatalf("oversized JSON returned %d, want 400", oversized.Code)
	}
}

func TestProtectedAPIRequiresValidSession(t *testing.T) {
	app, _ := testApp(t, testConfig())
	handler := app.Handler()
	for _, path := range []string{"/api", "/api/agents", "/api/chart", "/api/table", "/api/targets", "/api/export", "/api/not-registered"} {
		response := performRequest(handler, http.MethodGet, path, "", "192.0.2.6:1234", "", true)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("%s returned %d without a session, want 401", path, response.Code)
		}
	}
	expired, err := app.sessions.create("analyst", time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	response := performRequest(handler, http.MethodGet, "/api/agents", "", "192.0.2.7:1234", expired, true)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expired session returned %d, want 401", response.Code)
	}
}

func TestLogoutDeletesServerSessionAndExpiresCookie(t *testing.T) {
	app, _ := testApp(t, testConfig())
	token, err := app.sessions.create("analyst", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response := performRequest(app.Handler(), http.MethodPost, "/api/logout", "", "192.0.2.8:1234", token, true)
	if response.Code != http.StatusNoContent {
		t.Fatalf("logout returned %d, want 204", response.Code)
	}
	if _, ok := app.sessions.get(token, time.Now()); ok {
		t.Fatal("logout should remove the server-side session")
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != analystCookieName || cookies[0].MaxAge >= 0 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("logout did not expire the secure cookie: %#v", cookies)
	}
}

func TestLoginRateLimiterTriggersCooldownAndCleanup(t *testing.T) {
	now := time.Now()
	limiter := newLoginRateLimiter(2, 2, 2, time.Minute, 30*time.Second)
	keys := []string{"ip:192.0.2.10", "identity:192.0.2.10\x00analyst", "account:analyst"}
	limiter.failure(keys, now)
	if limiter.blocked(keys, now.Add(time.Second)) {
		t.Fatal("one failure should not block login")
	}
	limiter.failure(keys, now.Add(2*time.Second))
	if !limiter.blocked(keys, now.Add(3*time.Second)) {
		t.Fatal("limit should trigger cooldown")
	}
	if limiter.blocked(keys, now.Add(33*time.Second)) {
		t.Fatal("login should be allowed after cooldown expires")
	}
	limiter.cleanup(now.Add(3 * time.Minute))
	limiter.mu.Lock()
	remaining := len(limiter.entries)
	limiter.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected stale login entries to be cleaned, found %d", remaining)
	}
}

func TestRepeatedFailedLoginIsRateLimited(t *testing.T) {
	config := testConfig()
	config.LoginMaxAttempts = 2
	app, _ := testApp(t, config)
	handler := app.Handler()
	body, _ := json.Marshal(LoginRequest{Username: "analyst", Password: "wrong password"})
	for i := 0; i < 2; i++ {
		response := performRequest(handler, http.MethodPost, "/api/login", string(body), "192.0.2.11:1234", "", true)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("failed login %d returned %d, want 401", i+1, response.Code)
		}
	}
	response := performRequest(handler, http.MethodPost, "/api/login", string(body), "192.0.2.11:1234", "", true)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited login returned %d, want 429", response.Code)
	}
}

func TestUsernameAndIPCombinationHasItsOwnLimit(t *testing.T) {
	config := testConfig()
	config.LoginIdentityMaxAttempts = 2
	app, _ := testApp(t, config)
	handler := app.Handler()
	body, _ := json.Marshal(LoginRequest{Username: "analyst", Password: "wrong password"})
	for i := 0; i < 2; i++ {
		response := performRequest(handler, http.MethodPost, "/api/login", string(body), "192.0.2.14:1234", "", true)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("failed login %d returned %d, want 401", i+1, response.Code)
		}
	}
	blocked := performRequest(handler, http.MethodPost, "/api/login", string(body), "192.0.2.14:1234", "", true)
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("identity limited login returned %d, want 429", blocked.Code)
	}
	otherUser, _ := json.Marshal(LoginRequest{Username: "other", Password: "wrong password"})
	response := performRequest(handler, http.MethodPost, "/api/login", string(otherUser), "192.0.2.14:1234", "", true)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("different identity should still be below the IP limit, got %d", response.Code)
	}
}

func TestRequestRateLimiterWindowAndCleanup(t *testing.T) {
	now := time.Now()
	limiter := newRequestRateLimiter(2, time.Minute)
	if !limiter.allow("ip", now) || !limiter.allow("ip", now.Add(time.Second)) || limiter.allow("ip", now.Add(2*time.Second)) {
		t.Fatal("request limit should allow two requests and reject the third")
	}
	if !limiter.allow("ip", now.Add(time.Minute)) {
		t.Fatal("request limit should reset after its window")
	}
	limiter.cleanup(now.Add(4 * time.Minute))
	if len(limiter.entries) != 0 {
		t.Fatal("stale API limiter entry was not cleaned")
	}
}

func TestAPIRequestLimitIsAppliedBeforeEndpointDispatch(t *testing.T) {
	config := testConfig()
	config.APIMaxRequests = 1
	app, _ := testApp(t, config)
	token, err := app.sessions.create("analyst", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	first := performRequest(handler, http.MethodGet, "/api/unknown", "", "192.0.2.12:1234", token, true)
	second := performRequest(handler, http.MethodGet, "/api/unknown", "", "192.0.2.12:1234", token, true)
	if first.Code != http.StatusNotFound || second.Code != http.StatusTooManyRequests {
		t.Fatalf("expected endpoint dispatch then API limit, got %d and %d", first.Code, second.Code)
	}
}

func TestSecurityHeadersAndHTTPSOnlyHSTS(t *testing.T) {
	check := func(t *testing.T, tlsEnabled bool) *httptest.ResponseRecorder {
		t.Helper()
		handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		return performRequest(handler, http.MethodGet, "/", "", "192.0.2.13:1234", "", tlsEnabled)
	}
	plain := check(t, false)
	secure := check(t, true)
	for _, response := range []*httptest.ResponseRecorder{plain, secure} {
		for name, expected := range map[string]string{
			"Content-Security-Policy": "default-src 'self'",
			"X-Frame-Options":         "DENY",
			"X-Content-Type-Options":  "nosniff",
			"Referrer-Policy":         "strict-origin-when-cross-origin",
			"Permissions-Policy":      "camera=(), microphone=(), geolocation=()",
		} {
			if !strings.Contains(response.Header().Get(name), expected) {
				t.Errorf("%s header %q does not contain %q", name, response.Header().Get(name), expected)
			}
		}
		csp := response.Header().Get("Content-Security-Policy")
		if strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
			t.Errorf("CSP permits unsafe script execution: %s", csp)
		}
	}
	if plain.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS must not be sent over plaintext HTTP")
	}
	if secure.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("HSTS should be sent for HTTPS")
	}
}

func TestChartRejectsInvalidQueryParameters(t *testing.T) {
	app, _ := testApp(t, testConfig())
	for _, path := range []string{"/api/chart?mode=week", "/api/chart?agent=bad%20agent"} {
		request := httptest.NewRequest(http.MethodGet, path, bytes.NewReader(nil))
		response := httptest.NewRecorder()
		app.handleChart(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s returned %d, want 400", path, response.Code)
		}
	}
}

func TestPrepareMySQLDSNRequiresVerifiedTLSTCP(t *testing.T) {
	secureDSN := "analyst:secret@tcp(db.example.test:3306)/sentinel?tls=true"
	prepared, err := prepareMySQLDSN(secureDSN, "")
	if err != nil {
		t.Fatalf("verified TLS DSN was rejected: %v", err)
	}
	parsed, err := mysql.ParseDSN(prepared)
	if err != nil {
		t.Fatalf("prepared DSN could not be parsed: %v", err)
	}
	if parsed.TLS == nil || parsed.TLS.InsecureSkipVerify || parsed.TLS.RootCAs == nil || parsed.TLS.MinVersion != tls.VersionTLS12 {
		t.Fatalf("prepared DSN does not use certificate-verified TLS: %#v", parsed.TLS)
	}

	for name, dsn := range map[string]string{
		"tls false":          "analyst:secret@tcp(db.example.test:3306)/sentinel?tls=false",
		"skip verify":        "analyst:secret@tcp(db.example.test:3306)/sentinel?tls=skip-verify",
		"preferred":          "analyst:secret@tcp(db.example.test:3306)/sentinel?tls=preferred",
		"missing TLS":        "analyst:secret@tcp(db.example.test:3306)/sentinel",
		"plaintext fallback": "analyst:secret@tcp(db.example.test:3306)/sentinel?tls=true&allowFallbackToPlaintext=true",
		"malformed DSN":      "not a valid DSN",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := prepareMySQLDSN(dsn, "")
			if err == nil {
				t.Fatal("insecure or malformed TCP DSN was accepted")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), dsn) {
				t.Fatalf("error exposes DSN credentials or contents: %v", err)
			}
		})
	}
}

func TestPrepareMySQLDSNAllowsLocalUnixSocket(t *testing.T) {
	dsn := "analyst:secret@unix(/var/run/mysqld/mysqld.sock)/sentinel"
	prepared, err := prepareMySQLDSN(dsn, "")
	if err != nil {
		t.Fatalf("local Unix socket should not require TLS: %v", err)
	}
	parsed, err := mysql.ParseDSN(prepared)
	if err != nil || parsed.Net != "unix" || parsed.TLS != nil {
		t.Fatalf("Unix socket transport was changed unexpectedly: %#v, %v", parsed, err)
	}
}

func TestPrepareMySQLDSNAcceptsPrivateCAWithoutDisablingVerification(t *testing.T) {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Sentinel test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "db.example.test"},
		DNSNames: []string{"db.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCertificate, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	caFile := t.TempDir() + string(os.PathSeparator) + "mysql-ca.pem"
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}

	prepared, err := prepareMySQLDSN("analyst:secret@tcp(db.example.test:3306)/sentinel?tls=true", caFile)
	if err != nil {
		t.Fatalf("verified TLS configuration with private CA was rejected: %v", err)
	}
	parsed, err := mysql.ParseDSN(prepared)
	if err != nil {
		t.Fatalf("prepared private-CA DSN could not be parsed: %v", err)
	}
	if parsed.TLS == nil || parsed.TLS.InsecureSkipVerify || parsed.TLS.RootCAs == nil || parsed.TLS.ServerName != "db.example.test" {
		t.Fatalf("private-CA TLS config does not verify the server identity: %#v", parsed.TLS)
	}
	if _, err := leafCertificate.Verify(x509.VerifyOptions{
		DNSName: "db.example.test", CurrentTime: now, Roots: parsed.TLS.RootCAs,
	}); err != nil {
		t.Fatalf("configured CA does not verify its valid server certificate: %v", err)
	}
	if _, err := leafCertificate.Verify(x509.VerifyOptions{
		DNSName: "wrong.example.test", CurrentTime: now, Roots: parsed.TLS.RootCAs,
	}); err == nil {
		t.Fatal("private-CA TLS config accepted a certificate with the wrong hostname")
	}
}

func TestTrustedProxyCIDRParsing(t *testing.T) {
	networks, err := parseTrustedProxyCIDRs("10.20.0.0/16, 2001:db8:abcd::/48")
	if err != nil || len(networks) != 2 {
		t.Fatalf("valid IPv4/IPv6 proxy CIDRs rejected: %#v, %v", networks, err)
	}
	if !networks[0].Contains(net.ParseIP("10.20.5.1")) || !networks[1].Contains(net.ParseIP("2001:db8:abcd::5")) {
		t.Fatal("parsed trusted CIDRs do not contain expected proxy addresses")
	}
	for _, invalid := range []string{",", "10.0.0.0/8,", "10.0.0.0/8,,192.0.2.0/24", "not-a-cidr", "10.0.0.1/8", "10.0.0.0/8,10.0.0.0/8"} {
		if _, err := parseTrustedProxyCIDRs(invalid); err == nil {
			t.Errorf("invalid proxy CIDR configuration %q was accepted", invalid)
		}
	}
}

func TestClientIPUsesOnlyTrustedForwardedChain(t *testing.T) {
	noProxyApp, _ := testApp(t, testConfig())
	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.RemoteAddr = "192.0.2.10:1234"
	direct.Header.Set("X-Forwarded-For", "198.51.100.10")
	if got := noProxyApp.clientIP(direct); got != "192.0.2.10" {
		t.Fatalf("untrusted forwarded header changed client IP to %q", got)
	}

	trusted, err := parseTrustedProxyCIDRs("10.20.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	config := testConfig()
	config.TrustedProxyCIDRs = trusted
	proxyApp, _ := testApp(t, config)

	forwarded := httptest.NewRequest(http.MethodGet, "/", nil)
	forwarded.RemoteAddr = "10.20.1.2:443"
	forwarded.Header.Add("X-Forwarded-For", "203.0.113.99, 192.0.2.25")
	forwarded.Header.Add("X-Forwarded-For", "10.20.1.1")
	if got := proxyApp.clientIP(forwarded); got != "192.0.2.25" {
		t.Fatalf("proxy chain returned %q, want nearest untrusted address 192.0.2.25", got)
	}

	malformed := httptest.NewRequest(http.MethodGet, "/", nil)
	malformed.RemoteAddr = "10.20.1.2:443"
	malformed.Header.Set("X-Forwarded-For", "192.0.2.25, invalid-address")
	if got := proxyApp.clientIP(malformed); got != "10.20.1.2" {
		t.Fatalf("malformed forwarded chain should fall back to direct peer, got %q", got)
	}

	untrustedPeer := httptest.NewRequest(http.MethodGet, "/", nil)
	untrustedPeer.RemoteAddr = "192.0.2.10:1234"
	untrustedPeer.Header.Set("X-Forwarded-For", "203.0.113.77")
	if got := proxyApp.clientIP(untrustedPeer); got != "192.0.2.10" {
		t.Fatalf("untrusted peer spoofed forwarded IP %q", got)
	}
}

func TestClientIPHandlesTrustedIPv6ProxyAndMalformedRemote(t *testing.T) {
	trusted, err := parseTrustedProxyCIDRs("2001:db8:1::/64")
	if err != nil {
		t.Fatal(err)
	}
	config := testConfig()
	config.TrustedProxyCIDRs = trusted
	app, _ := testApp(t, config)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "[2001:db8:1::2]:443"
	request.Header.Set("X-Forwarded-For", "2001:db8:ffff::10, 2001:db8:1::1")
	if got := app.clientIP(request); got != "2001:db8:ffff::10" {
		t.Fatalf("trusted IPv6 forwarding returned %q", got)
	}

	directIPv6 := httptest.NewRequest(http.MethodGet, "/", nil)
	directIPv6.RemoteAddr = "[2001:db8:ffff::10]:1234"
	if got := app.clientIP(directIPv6); got != "2001:db8:ffff::10" {
		t.Fatalf("direct IPv6 peer parsed as %q", got)
	}

	badRemote := httptest.NewRequest(http.MethodGet, "/", nil)
	badRemote.RemoteAddr = "invalid-peer"
	badRemote.Header.Set("X-Forwarded-For", "198.51.100.99")
	if got := app.clientIP(badRemote); got != "invalid-peer" {
		t.Fatalf("invalid direct peer should not trust forwarded header, got %q", got)
	}
}

func TestUsernameFailureLimitAppliesAcrossSourceIPs(t *testing.T) {
	config := testConfig()
	config.LoginMaxAttempts = 10
	config.LoginIdentityMaxAttempts = 10
	config.LoginAccountMaxAttempts = 2
	app, _ := testApp(t, config)
	handler := app.Handler()
	body, _ := json.Marshal(LoginRequest{Username: "analyst", Password: "wrong password"})
	for _, ip := range []string{"192.0.2.31:1234", "192.0.2.32:1234"} {
		response := performRequest(handler, http.MethodPost, "/api/login", string(body), ip, "", true)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("initial wrong-password response from %s was %d, want 401", ip, response.Code)
		}
	}
	response := performRequest(handler, http.MethodPost, "/api/login", string(body), "192.0.2.33:1234", "", true)
	if response.Code != http.StatusTooManyRequests || response.Body.String() != "too many login attempts\n" {
		t.Fatalf("cross-IP account throttling returned %d %q", response.Code, response.Body.String())
	}
}

func TestInvalidPasswordShapeDoesNotConsumeAccountFailureBudget(t *testing.T) {
	config := testConfig()
	config.LoginMaxAttempts = 10
	config.LoginIdentityMaxAttempts = 10
	config.LoginAccountMaxAttempts = 2
	app, _ := testApp(t, config)
	handler := app.Handler()
	emptyPassword, _ := json.Marshal(LoginRequest{Username: "analyst", Password: ""})
	for _, ip := range []string{"192.0.2.34:1234", "192.0.2.35:1234"} {
		response := performRequest(handler, http.MethodPost, "/api/login", string(emptyPassword), ip, "", true)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("empty-password response was %d, want generic 401", response.Code)
		}
	}
	wrongPassword, _ := json.Marshal(LoginRequest{Username: "analyst", Password: "well-formed but wrong"})
	response := performRequest(handler, http.MethodPost, "/api/login", string(wrongPassword), "192.0.2.36:1234", "", true)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid password shape consumed the account failure budget, got %d", response.Code)
	}
}

func TestLoginRateLimiterHasBoundedStateAndCleansIt(t *testing.T) {
	now := time.Now()
	limiter := newLoginRateLimiter(2, 2, 2, time.Minute, time.Minute)
	limiter.maxEntries = 3
	blockedKeys := []string{"ip:192.0.2.40", "identity:192.0.2.40\x00unknown-a", "account:unknown-a"}
	limiter.failure(blockedKeys, now)
	limiter.failure(blockedKeys, now.Add(time.Second))
	if len(limiter.entries) != 3 {
		t.Fatalf("expected three limiter entries, got %d", len(limiter.entries))
	}
	newKeys := []string{"ip:192.0.2.41", "identity:192.0.2.41\x00unknown-b", "account:unknown-b"}
	if !limiter.blocked(newKeys, now.Add(time.Second)) {
		t.Fatal("new keys should be denied when all bounded limiter entries are cooling down")
	}
	limiter.failure(newKeys, now.Add(time.Second))
	if len(limiter.entries) != 3 {
		t.Fatalf("limiter exceeded its state bound: %d entries", len(limiter.entries))
	}
	limiter.cleanup(now.Add(3 * time.Minute))
	if len(limiter.entries) != 0 {
		t.Fatalf("cleanup should remove expired entries, found %d", len(limiter.entries))
	}

	rotating := newLoginRateLimiter(5, 5, 5, time.Minute, time.Minute)
	rotating.maxEntries = 3
	rotating.failure([]string{"ip:192.0.2.42", "identity:192.0.2.42\x00old", "account:old"}, now)
	if rotating.blocked(newKeys, now.Add(time.Second)) {
		t.Fatal("limiter should evict old unblocked keys instead of denying a new identity")
	}
	rotating.failure(newKeys, now.Add(time.Second))
	if len(rotating.entries) > rotating.maxEntries {
		t.Fatalf("limiter exceeded its state bound after eviction: %d entries", len(rotating.entries))
	}
}

func TestDashboardVendorAssetsAreLocalAndServedWithCSP(t *testing.T) {
	app, _ := testApp(t, testConfig())
	token, err := app.sessions.create("analyst", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	index := performRequest(handler, http.MethodGet, "/", "", "192.0.2.50:1234", token, true)
	if index.Code != http.StatusOK {
		t.Fatalf("dashboard returned %d, want 200", index.Code)
	}
	for _, required := range []string{"/assets/apexcharts.min.js", "/assets/gridjs.min.js", "/assets/gridjs.min.css"} {
		if !strings.Contains(index.Body.String(), required) {
			t.Errorf("dashboard does not reference local asset %q", required)
		}
	}
	if strings.Contains(index.Body.String(), "cdn.jsdelivr.net") || strings.Contains(index.Body.String(), "unpkg.com") {
		t.Fatal("dashboard still references a third-party JavaScript or CSS CDN")
	}
	csp := index.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "cdn.jsdelivr.net") || strings.Contains(csp, "unpkg.com") {
		t.Fatalf("CSP does not constrain scripts to local assets: %s", csp)
	}
	for _, path := range []string{"/assets/apexcharts.min.js", "/assets/gridjs.min.js", "/assets/gridjs.min.css"} {
		response := performRequest(handler, http.MethodGet, path, "", "192.0.2.50:1234", token, true)
		if response.Code != http.StatusOK {
			t.Errorf("local vendor asset %s returned %d", path, response.Code)
		}
	}
}
