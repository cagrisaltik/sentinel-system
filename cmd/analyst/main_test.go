package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		LoginMaxAttempts: 5, LoginIdentityMaxAttempts: 3, LoginWindow: 10 * time.Minute, LoginBlockTime: 15 * time.Minute,
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
	limiter := newLoginRateLimiter(2, 2, time.Minute, 30*time.Second)
	keys := []string{"ip:192.0.2.10", "identity:192.0.2.10\x00analyst"}
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
