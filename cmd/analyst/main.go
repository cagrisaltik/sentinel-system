package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

const (
	analystCookieName = "analyst_session"
	maxLoginBodyBytes = 16 * 1024
	maxQueryDuration  = 5 * time.Second
)

type Config struct {
	Port                     string
	TLSCertFile              string
	TLSKeyFile               string
	WebDir                   string
	SessionTTL               time.Duration
	LoginMaxAttempts         int
	LoginIdentityMaxAttempts int
	LoginAccountMaxAttempts  int
	LoginWindow              time.Duration
	LoginBlockTime           time.Duration
	APIMaxRequests           int
	APIWindow                time.Duration
	TrustedProxyCIDRs        []*net.IPNet
}

func loadConfig() (Config, error) {
	port := strings.TrimSpace(os.Getenv("ANALYST_PORT"))
	if port == "" {
		port = "3000"
	}
	portNumber := 0
	if _, err := fmt.Sscanf(port, "%d", &portNumber); err != nil || portNumber < 1 || portNumber > 65535 || fmt.Sprint(portNumber) != port {
		return Config{}, errors.New("ANALYST_PORT must be a valid TCP port")
	}

	certFile := strings.TrimSpace(os.Getenv("TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("TLS_KEY_FILE"))
	if certFile == "" || keyFile == "" {
		return Config{}, errors.New("TLS_CERT_FILE and TLS_KEY_FILE are required")
	}

	sessionHours, err := positiveEnvInt("SESSION_TTL_HOURS", 24, 1, 8760)
	if err != nil {
		return Config{}, err
	}
	loginMax, err := positiveEnvInt("LOGIN_MAX_ATTEMPTS", 5, 1, 100)
	if err != nil {
		return Config{}, err
	}
	identityMax, err := positiveEnvInt("LOGIN_IDENTITY_MAX_ATTEMPTS", 3, 1, 100)
	if err != nil {
		return Config{}, err
	}
	accountMax, err := positiveEnvInt("LOGIN_ACCOUNT_MAX_ATTEMPTS", 10, 1, 1000)
	if err != nil {
		return Config{}, err
	}
	loginWindowMinutes, err := positiveEnvInt("LOGIN_WINDOW_MINUTES", 10, 1, 1440)
	if err != nil {
		return Config{}, err
	}
	loginBlockMinutes, err := positiveEnvInt("LOGIN_BLOCK_MINUTES", 15, 1, 1440)
	if err != nil {
		return Config{}, err
	}
	apiLimit, err := positiveEnvInt("API_RATE_LIMIT_PER_MINUTE", 240, 1, 100000)
	if err != nil {
		return Config{}, err
	}
	trustedProxyCIDRs, err := parseTrustedProxyCIDRs(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return Config{}, err
	}
	webDir := strings.TrimSpace(os.Getenv("ANALYST_WEB_DIR"))
	if webDir == "" {
		webDir = filepath.Join("web", "analyst")
	}

	return Config{
		Port:                     port,
		TLSCertFile:              certFile,
		TLSKeyFile:               keyFile,
		WebDir:                   webDir,
		SessionTTL:               time.Duration(sessionHours) * time.Hour,
		LoginMaxAttempts:         loginMax,
		LoginIdentityMaxAttempts: identityMax,
		LoginAccountMaxAttempts:  accountMax,
		LoginWindow:              time.Duration(loginWindowMinutes) * time.Minute,
		LoginBlockTime:           time.Duration(loginBlockMinutes) * time.Minute,
		APIMaxRequests:           apiLimit,
		APIWindow:                time.Minute,
		TrustedProxyCIDRs:        trustedProxyCIDRs,
	}, nil
}

func parseTrustedProxyCIDRs(value string) ([]*net.IPNet, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	entries := strings.Split(value, ",")
	networks := make([]*net.IPNet, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, errors.New("TRUSTED_PROXY_CIDRS contains an empty entry")
		}
		ip, network, err := net.ParseCIDR(entry)
		if err != nil || !ip.Equal(network.IP) {
			return nil, errors.New("TRUSTED_PROXY_CIDRS must contain canonical CIDRs")
		}
		if _, ok := seen[network.String()]; ok {
			return nil, errors.New("TRUSTED_PROXY_CIDRS contains a duplicate CIDR")
		}
		seen[network.String()] = struct{}{}
		networks = append(networks, network)
	}
	return networks, nil
}

func positiveEnvInt(name string, fallback, minimum, maximum int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	var parsed int
	if _, err := fmt.Sscanf(value, "%d", &parsed); err != nil || parsed < minimum || parsed > maximum || fmt.Sprint(parsed) != value {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, minimum, maximum)
	}
	return parsed, nil
}

func openDatabase(dsn string) (*sql.DB, error) {
	configuredDSN, err := prepareMySQLDSN(dsn, os.Getenv("DATABASE_TLS_CA_FILE"))
	if err != nil {
		return nil, err
	}
	database, err := sql.Open("mysql", configuredDSN)
	if err != nil {
		return nil, errors.New("MySQL connection could not be configured")
	}
	database.SetMaxOpenConns(10)
	database.SetMaxIdleConns(5)
	database.SetConnMaxLifetime(30 * time.Minute)
	database.SetConnMaxIdleTime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, errors.New("MySQL is unavailable")
	}
	return database, nil
}

const analystDatabaseTLSConfigPrefix = "analyst-verified-db-"

func prepareMySQLDSN(dsn, caFile string) (string, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return "", errors.New("DATABASE_URL is required")
	}
	config, err := mysql.ParseDSN(dsn)
	if err != nil {
		return "", errors.New("MySQL connection configuration is invalid")
	}
	if config.AllowFallbackToPlaintext {
		return "", errors.New("MySQL plaintext fallback is not allowed")
	}
	if config.Net == "unix" {
		if config.TLSConfig != "" && config.TLSConfig != "false" {
			return "", errors.New("MySQL TLS configuration is invalid for a Unix socket")
		}
		return config.FormatDSN(), nil
	}
	if config.TLSConfig != "true" {
		return "", errors.New("network MySQL requires verified TLS configuration")
	}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		if caFile == "" {
			return "", errors.New("MySQL TLS trust roots are unavailable")
		}
		roots = x509.NewCertPool()
	}
	var caPEM []byte
	if caFile != "" {
		caPEM, err = os.ReadFile(caFile)
		if err != nil || !roots.AppendCertsFromPEM(caPEM) {
			return "", errors.New("MySQL TLS CA configuration is invalid")
		}
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	caFingerprint := sha256.Sum256(caPEM)
	tlsConfigName := analystDatabaseTLSConfigPrefix + fmt.Sprintf("%x", caFingerprint[:8])
	if err := mysql.RegisterTLSConfig(tlsConfigName, tlsConfig); err != nil {
		return "", errors.New("MySQL TLS configuration could not be registered")
	}
	config.TLS = nil
	config.TLSConfig = tlsConfigName
	return config.FormatDSN(), nil
}

func verifyDatabaseSchema(database *sql.DB) error {
	if database == nil {
		return errors.New("database is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, query := range []string{
		"SELECT 1 FROM users LIMIT 0",
		"SELECT 1 FROM logs LIMIT 0",
	} {
		rows, err := database.QueryContext(ctx, query)
		if err != nil {
			return errors.New("required MySQL schema is unavailable")
		}
		if err := rows.Close(); err != nil {
			return errors.New("required MySQL schema could not be verified")
		}
	}
	return nil
}

type credentialStore interface {
	PasswordHash(context.Context, string) (string, error)
}

type mysqlCredentialStore struct{ db *sql.DB }

func (s mysqlCredentialStore) PasswordHash(ctx context.Context, username string) (string, error) {
	if s.db == nil {
		return "", errors.New("database unavailable")
	}
	var hash string
	err := s.db.QueryRowContext(ctx,
		"SELECT password_hash FROM users WHERE username = ?", username,
	).Scan(&hash)
	return hash, err
}

type Session struct {
	Username string
	Expires  time.Time
}

type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]Session
	ttl      time.Duration
}

func newSessionStore(ttl time.Duration) *sessionStore {
	return &sessionStore{sessions: make(map[string]Session), ttl: ttl}
}

func generateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (s *sessionStore) create(username string, now time.Time) (string, error) {
	token, err := generateSessionToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.sessions[token] = Session{Username: username, Expires: now.Add(s.ttl)}
	s.mu.Unlock()
	return token, nil
}

func (s *sessionStore) get(token string, now time.Time) (Session, bool) {
	s.mu.RLock()
	session, ok := s.sessions[token]
	s.mu.RUnlock()
	if !ok {
		return Session{}, false
	}
	if !now.Before(session.Expires) {
		s.delete(token)
		return Session{}, false
	}
	return session, true
}

func (s *sessionStore) delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

func (s *sessionStore) cleanup(now time.Time) {
	s.mu.Lock()
	for token, session := range s.sessions {
		if !now.Before(session.Expires) {
			delete(s.sessions, token)
		}
	}
	s.mu.Unlock()
}

type loginAttempt struct {
	count       int
	firstSeen   time.Time
	blockedTill time.Time
	lastSeen    time.Time
}

type loginRateLimiter struct {
	mu            sync.Mutex
	entries       map[string]*loginAttempt
	limit         int
	identityLimit int
	accountLimit  int
	maxEntries    int
	window        time.Duration
	cooldown      time.Duration
}

const maxLoginRateLimitEntries = 20000

func newLoginRateLimiter(limit, identityLimit, accountLimit int, window, cooldown time.Duration) *loginRateLimiter {
	return &loginRateLimiter{
		entries: make(map[string]*loginAttempt), limit: limit, identityLimit: identityLimit,
		accountLimit: accountLimit, maxEntries: maxLoginRateLimitEntries, window: window, cooldown: cooldown,
	}
}

func (l *loginRateLimiter) blocked(keys []string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	blocked := false
	missing := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		entry, ok := l.entries[key]
		if !ok {
			missing[key] = struct{}{}
			continue
		}
		entry.lastSeen = now
		if now.Before(entry.blockedTill) {
			blocked = true
			continue
		}
		if now.Sub(entry.firstSeen) >= l.window {
			entry.count = 0
			entry.firstSeen = now
			entry.blockedTill = time.Time{}
		}
	}
	if !l.makeRoomLocked(len(missing), keys, now) {
		blocked = true
	}
	return blocked
}

func (l *loginRateLimiter) failure(keys []string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	missing := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if _, ok := l.entries[key]; !ok {
			missing[key] = struct{}{}
		}
	}
	if !l.makeRoomLocked(len(missing), keys, now) {
		return
	}
	for _, key := range keys {
		entry, ok := l.entries[key]
		if !ok {
			entry = &loginAttempt{firstSeen: now}
			l.entries[key] = entry
		}
		if now.Sub(entry.firstSeen) >= l.window {
			entry.count = 0
			entry.firstSeen = now
			entry.blockedTill = time.Time{}
		}
		entry.count++
		entry.lastSeen = now
		limit := l.limit
		if strings.HasPrefix(key, "identity:") {
			limit = l.identityLimit
		} else if strings.HasPrefix(key, "account:") {
			limit = l.accountLimit
		}
		if entry.count >= limit {
			entry.blockedTill = now.Add(l.cooldown)
		}
	}
}

func (l *loginRateLimiter) makeRoomLocked(required int, preserve []string, now time.Time) bool {
	if required > l.maxEntries {
		return false
	}
	preserved := make(map[string]struct{}, len(preserve))
	for _, key := range preserve {
		preserved[key] = struct{}{}
	}
	for len(l.entries)+required > l.maxEntries {
		oldestKey := ""
		var oldestSeen time.Time
		for key, entry := range l.entries {
			if _, keep := preserved[key]; keep || now.Before(entry.blockedTill) {
				continue
			}
			if oldestKey == "" || entry.lastSeen.Before(oldestSeen) {
				oldestKey = key
				oldestSeen = entry.lastSeen
			}
		}
		if oldestKey == "" {
			return false
		}
		delete(l.entries, oldestKey)
	}
	return true
}

func (l *loginRateLimiter) cleanup(now time.Time) {
	l.mu.Lock()
	for key, entry := range l.entries {
		if !now.Before(entry.blockedTill) && now.Sub(entry.lastSeen) > l.window+l.cooldown {
			delete(l.entries, key)
		}
	}
	l.mu.Unlock()
}

type requestWindow struct {
	started  time.Time
	lastSeen time.Time
	count    int
}

type requestRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*requestWindow
	limit   int
	window  time.Duration
}

func newRequestRateLimiter(limit int, window time.Duration) *requestRateLimiter {
	return &requestRateLimiter{entries: make(map[string]*requestWindow), limit: limit, window: window}
}

func (l *requestRateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[key]
	if !ok {
		l.entries[key] = &requestWindow{started: now, lastSeen: now, count: 1}
		return true
	}
	entry.lastSeen = now
	if now.Sub(entry.started) >= l.window {
		entry.started = now
		entry.count = 0
	}
	if entry.count >= l.limit {
		return false
	}
	entry.count++
	return true
}

func (l *requestRateLimiter) cleanup(now time.Time) {
	l.mu.Lock()
	for key, entry := range l.entries {
		if now.Sub(entry.lastSeen) > 2*l.window {
			delete(l.entries, key)
		}
	}
	l.mu.Unlock()
}

type ChartData struct {
	Label string  `json:"label"`
	Value float64 `json:"value"`
}

type TableData struct {
	Agent   string  `json:"agent"`
	Target  string  `json:"target"`
	AvgPing float64 `json:"avg_ping"`
	MaxPing float64 `json:"max_ping"`
	Success int     `json:"success"`
	Fail    int     `json:"fail"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AnalystApp struct {
	db                *sql.DB
	credentials       credentialStore
	sessions          *sessionStore
	loginLimiter      *loginRateLimiter
	apiLimiter        *requestRateLimiter
	dummyPasswordHash []byte
	config            Config
}

func newAnalystApp(db *sql.DB, credentials credentialStore, config Config) (*AnalystApp, error) {
	randomPassword := make([]byte, 32)
	if _, err := rand.Read(randomPassword); err != nil {
		return nil, errors.New("could not initialize credential verification")
	}
	dummyHash, err := bcrypt.GenerateFromPassword(randomPassword, bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New("could not initialize credential verification")
	}
	if credentials == nil {
		credentials = mysqlCredentialStore{db: db}
	}
	return &AnalystApp{
		db:                db,
		credentials:       credentials,
		sessions:          newSessionStore(config.SessionTTL),
		loginLimiter:      newLoginRateLimiter(config.LoginMaxAttempts, config.LoginIdentityMaxAttempts, config.LoginAccountMaxAttempts, config.LoginWindow, config.LoginBlockTime),
		apiLimiter:        newRequestRateLimiter(config.APIMaxRequests, config.APIWindow),
		dummyPasswordHash: dummyHash,
		config:            config,
	}, nil
}

func (a *AnalystApp) Handler() http.Handler {
	protectedAPI := http.NewServeMux()
	protectedAPI.HandleFunc("/api/logout", a.handleLogout)
	protectedAPI.HandleFunc("/api/agents", a.handleAgents)
	protectedAPI.HandleFunc("/api/chart", a.handleChart)
	protectedAPI.HandleFunc("/api/table", a.handleTable)

	mux := http.NewServeMux()
	mux.Handle("/api/login", a.loginRateLimit(http.HandlerFunc(a.handleLogin)))
	mux.Handle("/api", a.apiRateLimit(a.authMiddleware(protectedAPI)))
	mux.Handle("/api/", a.apiRateLimit(a.authMiddleware(protectedAPI)))
	mux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, http.MethodGet, http.MethodHead)
			return
		}
		http.ServeFile(w, r, filepath.Join(a.config.WebDir, "login.html"))
	})
	for _, asset := range []string{"login.css", "login.js"} {
		asset := asset
		mux.HandleFunc("/assets/"+asset, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				methodNotAllowed(w, http.MethodGet, http.MethodHead)
				return
			}
			http.ServeFile(w, r, filepath.Join(a.config.WebDir, "assets", asset))
		})
	}
	files := http.FileServer(http.Dir(a.config.WebDir))
	mux.Handle("/", a.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, http.MethodGet, http.MethodHead)
			return
		}
		files.ServeHTTP(w, r)
	})))

	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; script-src-attr 'none'; style-src 'self' https://fonts.googleapis.com; style-src-attr 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func methodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (a *AnalystApp) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(analystCookieName)
		if err != nil {
			a.unauthorized(w, r)
			return
		}
		if _, ok := a.sessions.get(cookie.Value, time.Now()); !ok {
			log.Print("security event: invalid session")
			a.unauthorized(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *AnalystApp) unauthorized(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
		log.Print("security event: authentication failure")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/login.html", http.StatusSeeOther)
}

func (a *AnalystApp) clientIP(r *http.Request) string {
	peer := remotePeerIP(r.RemoteAddr)
	if peer == nil {
		if r.RemoteAddr == "" {
			return "unknown"
		}
		return r.RemoteAddr
	}
	if !ipInNetworks(peer, a.config.TrustedProxyCIDRs) {
		return peer.String()
	}

	forwarded := r.Header.Values("X-Forwarded-For")
	if len(forwarded) == 0 {
		return peer.String()
	}
	var chain []net.IP
	for _, header := range forwarded {
		for _, value := range strings.Split(header, ",") {
			ip := net.ParseIP(strings.TrimSpace(value))
			if ip == nil {
				return peer.String()
			}
			chain = append(chain, ip)
		}
	}
	if len(chain) == 0 {
		return peer.String()
	}

	client := peer
	for index := len(chain) - 1; index >= 0; index-- {
		if !ipInNetworks(client, a.config.TrustedProxyCIDRs) {
			break
		}
		client = chain[index]
	}
	return client.String()
}

func remotePeerIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.Trim(remoteAddr, "[]"))
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *AnalystApp) loginRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := a.clientIP(r)
		if a.loginLimiter.blocked([]string{"ip:" + ip}, time.Now()) {
			log.Print("security event: login rate limit")
			http.Error(w, "too many login attempts", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *AnalystApp) apiRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.apiLimiter.allow(a.clientIP(r), time.Now()) {
			log.Print("security event: API rate limit")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, maxBytes int64, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func (a *AnalystApp) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var creds LoginRequest
	if err := decodeJSONBody(w, r, maxLoginBodyBytes, &creds); err != nil {
		a.loginLimiter.failure([]string{"ip:" + a.clientIP(r)}, time.Now())
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	creds.Username = strings.TrimSpace(creds.Username)
	ip := a.clientIP(r)
	keys := []string{"ip:" + ip}
	validUsername := creds.Username != "" && len(creds.Username) <= 100 && !hasControlCharacter(creds.Username)
	if validUsername {
		normalizedUsername := strings.ToLower(creds.Username)
		keys = append(keys, "identity:"+ip+"\x00"+normalizedUsername, "account:"+normalizedUsername)
	}
	if a.loginLimiter.blocked(keys, time.Now()) {
		log.Print("security event: login rate limit")
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	if !validUsername || len(creds.Password) == 0 || len(creds.Password) > 72 {
		failureKeys := keys
		if validUsername {
			failureKeys = keys[:len(keys)-1]
		}
		a.loginLimiter.failure(failureKeys, time.Now())
		log.Print("security event: login failure")
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	storedHash, err := a.credentials.PasswordHash(r.Context(), creds.Username)
	if errors.Is(err, sql.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword(a.dummyPasswordHash, []byte(creds.Password))
		a.loginLimiter.failure(keys, time.Now())
		log.Print("security event: login failure")
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Print("analyst credential lookup failed")
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password)) != nil {
		a.loginLimiter.failure(keys, time.Now())
		log.Print("security event: login failure")
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if existing, err := r.Cookie(analystCookieName); err == nil {
		a.sessions.delete(existing.Value)
	}
	token, err := a.sessions.create(creds.Username, time.Now())
	if err != nil {
		log.Print("analyst session creation failed")
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: analystCookieName, Value: token, Path: "/",
		Expires: time.Now().Add(a.config.SessionTTL), MaxAge: int(a.config.SessionTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	log.Print("security event: login success")
	w.WriteHeader(http.StatusOK)
}

func hasControlCharacter(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func (a *AnalystApp) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if cookie, err := r.Cookie(analystCookieName); err == nil {
		a.sessions.delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: analystCookieName, Value: "", Path: "/", MaxAge: -1,
		Expires: time.Unix(1, 0), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (a *AnalystApp) handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), maxQueryDuration)
	defer cancel()
	rows, err := a.db.QueryContext(ctx, "SELECT DISTINCT agent FROM logs ORDER BY agent")
	if err != nil {
		log.Print("analyst database query failed: agents")
		writeJSON(w, []string{})
		return
	}
	defer rows.Close()
	agents := make([]string, 0)
	for rows.Next() {
		var agent string
		if err := rows.Scan(&agent); err != nil {
			log.Print("analyst database result failed: agents")
			writeJSON(w, []string{})
			return
		}
		agents = append(agents, agent)
	}
	if err := rows.Err(); err != nil {
		log.Print("analyst database result failed: agents")
		writeJSON(w, []string{})
		return
	}
	writeJSON(w, agents)
}

var analystAgentNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

func (a *AnalystApp) handleChart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "hour"
	}
	if mode != "hour" && mode != "day" {
		http.Error(w, "invalid mode", http.StatusBadRequest)
		return
	}
	agent := r.URL.Query().Get("agent")
	if agent == "null" || agent == "undefined" {
		agent = ""
	}
	if agent != "" && !analystAgentNamePattern.MatchString(agent) {
		http.Error(w, "invalid agent", http.StatusBadRequest)
		return
	}
	timeFormat := "%Y-%m-%d %H:00"
	if mode == "day" {
		timeFormat = "%Y-%m-%d"
	}
	query := `SELECT DATE_FORMAT(created_at, ?) AS label,
		AVG(CAST(REPLACE(latency, 'ms', '') AS DECIMAL(10,3))) AS val
		FROM logs WHERE 1=1`
	args := []any{timeFormat}
	if agent != "" {
		query += " AND agent = ?"
		args = append(args, agent)
	}
	query += " GROUP BY label ORDER BY label DESC LIMIT 24"

	ctx, cancel := context.WithTimeout(r.Context(), maxQueryDuration)
	defer cancel()
	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		log.Print("analyst database query failed: chart")
		writeJSON(w, []ChartData{})
		return
	}
	defer rows.Close()
	data := make([]ChartData, 0)
	for rows.Next() {
		var item ChartData
		if err := rows.Scan(&item.Label, &item.Value); err != nil {
			log.Print("analyst database result failed: chart")
			writeJSON(w, []ChartData{})
			return
		}
		data = append(data, item)
	}
	if err := rows.Err(); err != nil {
		log.Print("analyst database result failed: chart")
		writeJSON(w, []ChartData{})
		return
	}
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
	writeJSON(w, data)
}

func (a *AnalystApp) handleTable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), maxQueryDuration)
	defer cancel()
	rows, err := a.db.QueryContext(ctx, `
		SELECT agent, target,
			COALESCE(AVG(CAST(REPLACE(latency, 'ms', '') AS DECIMAL(10,3))), 0),
			COALESCE(MAX(CAST(REPLACE(latency, 'ms', '') AS DECIMAL(10,3))), 0),
			SUM(CASE WHEN status = 200 THEN 1 ELSE 0 END) AS success,
			SUM(CASE WHEN status <> 200 THEN 1 ELSE 0 END) AS fail
		FROM logs
		GROUP BY agent, target`)
	if err != nil {
		log.Print("analyst database query failed: table")
		writeJSON(w, []TableData{})
		return
	}
	defer rows.Close()
	table := make([]TableData, 0)
	for rows.Next() {
		var item TableData
		if err := rows.Scan(&item.Agent, &item.Target, &item.AvgPing, &item.MaxPing, &item.Success, &item.Fail); err != nil {
			log.Print("analyst database result failed: table")
			writeJSON(w, []TableData{})
			return
		}
		table = append(table, item)
	}
	if err := rows.Err(); err != nil {
		log.Print("analyst database result failed: table")
		writeJSON(w, []TableData{})
		return
	}
	writeJSON(w, table)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Print("analyst JSON response could not be encoded")
	}
}

func (a *AnalystApp) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			a.sessions.cleanup(now)
			a.loginLimiter.cleanup(now)
			a.apiLimiter.cleanup(now)
		}
	}
}

func main() {
	_ = godotenv.Load()
	config, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	if strings.TrimSpace(os.Getenv("DATABASE_URL")) == "" {
		log.Fatal("DATABASE_URL is required")
	}
	certificate, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		log.Fatal("Analyst TLS certificate or key could not be loaded")
	}
	database, err := openDatabase(os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	if err := verifyDatabaseSchema(database); err != nil {
		_ = database.Close()
		log.Fatal("Analyst MySQL schema is not ready")
	}
	app, err := newAnalystApp(database, nil, config)
	if err != nil {
		_ = database.Close()
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              ":" + config.Port,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 * 1024,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
		},
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		_ = database.Close()
		log.Fatal("Analyst HTTPS listener could not start")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go app.cleanupLoop(ctx)
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.ServeTLS(listener, "", "")
	}()
	log.Printf("Analyst HTTPS server started on port %s", config.Port)

	select {
	case <-ctx.Done():
		log.Print("Analyst shutdown started")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Print("Analyst HTTP shutdown timed out")
			_ = server.Close()
		}
	case err := <-serveErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Print("Analyst HTTPS server stopped unexpectedly")
		}
	}
	_ = database.Close()
	log.Print("Analyst server stopped")
}
