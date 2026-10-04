package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cagrisaltik/sentinel-system/internal/models"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/xuri/excelize/v2"
	"github.com/youmark/pkcs8"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

type Config struct {
	Host string
	Port string

	TLSCertFile  string
	TLSKeyFile   string
	ClientCAFile string

	AllowedOrigins map[string]bool

	MaxWSConnections int

	SessionTTL time.Duration

	LoginMaxAttempts int
	LoginWindow      time.Duration
	LoginBlockTime   time.Duration
}

var cfg Config

// -----------------------------------------------------------------------------
// WebSocket clients
// -----------------------------------------------------------------------------

type AgentConnection struct {
	Name string
	Conn *websocket.Conn

	WriteMu sync.Mutex

	LastSeenMu sync.RWMutex
	LastSeen   time.Time
}

var (
	clients   = make(map[string]*AgentConnection)
	clientsMu sync.RWMutex

	activeWSConnections int64
	tasksMu             sync.Mutex
	pendingTasks        = make(map[string]*pendingTask)
)

type pendingTask struct {
	Agent     string
	Target    string
	ExpiresAt time.Time
	Reported  bool
	Reporting bool
}

func claimReport(taskID, agentName, target string, now time.Time) bool {
	if !validTaskID(taskID) {
		return false
	}
	tasksMu.Lock()
	defer tasksMu.Unlock()
	task, ok := pendingTasks[taskID]
	if !ok || task.Reported || task.Reporting || task.Agent != agentName || task.Target != target || !now.Before(task.ExpiresAt) {
		return false
	}
	task.Reporting = true
	return true
}

func validTaskID(taskID string) bool {
	if len(taskID) != 36 {
		return false
	}
	id, err := uuid.Parse(taskID)
	return err == nil && id.String() == strings.ToLower(taskID)
}

func createPendingTask(taskID, agentName, target string, expiresAt, now time.Time) bool {
	if !validTaskID(taskID) || !expiresAt.After(now) {
		return false
	}
	tasksMu.Lock()
	defer tasksMu.Unlock()

	for id, task := range pendingTasks {
		if !now.Before(task.ExpiresAt) || task.Reported {
			delete(pendingTasks, id)
		}
	}
	if _, exists := pendingTasks[taskID]; exists {
		return false
	}
	for _, task := range pendingTasks {
		if task.Agent == agentName && task.Target == target {
			return false
		}
	}
	pendingTasks[taskID] = &pendingTask{Agent: agentName, Target: target, ExpiresAt: expiresAt}
	return true
}

func finishReport(taskID string, success bool) {
	tasksMu.Lock()
	defer tasksMu.Unlock()
	if task, ok := pendingTasks[taskID]; ok {
		task.Reporting = false
		if success {
			task.Reported = true
		}
	}
}

func validAgentMessageType(messageType string) bool {
	return messageType == "REPORT"
}

const maxReportTimeLength = 128

func validReportTelemetry(msg models.Command, currentAgentName string) bool {
	return msg.Agent == currentAgentName &&
		(msg.Status == 200 || msg.Status == 500) &&
		msg.CPU >= 0 && msg.CPU <= 100 &&
		msg.RAM >= 0 && msg.RAM <= 100 &&
		msg.Disk >= 0 && msg.Disk <= 100 &&
		len(msg.Time) <= maxReportTimeLength
}

// -----------------------------------------------------------------------------
// Sessions
// -----------------------------------------------------------------------------

type Session struct {
	Username string
	Expires  time.Time
}

var (
	sessions   = make(map[string]Session)
	sessionsMu sync.RWMutex
)

// -----------------------------------------------------------------------------
// Login rate limiting
// -----------------------------------------------------------------------------

type LoginAttempt struct {
	Count       int
	FirstSeen   time.Time
	BlockedTill time.Time
}

var (
	loginAttempts   = make(map[string]*LoginAttempt)
	loginAttemptsMu sync.Mutex
)

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

type LogEntry struct {
	ID        int     `json:"id"`
	Target    string  `json:"target"`
	Status    int     `json:"status"`
	Latency   string  `json:"latency"`
	Agent     string  `json:"agent"`
	CreatedAt string  `json:"created_at"`
	CPU       float64 `json:"cpu"`
	RAM       float64 `json:"ram"`
	Disk      float64 `json:"disk"`
}

type TargetTask struct {
	ID        int    `json:"id"`
	AgentName string `json:"agent_name"`
	TargetURL string `json:"target_url"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

var agentNameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

func validAgentName(name string) bool {
	return agentNameRegex.MatchString(name)
}

func validTarget(target string) bool {
	target = strings.TrimSpace(target)

	if target == "" || len(target) > 2048 {
		return false
	}

	for _, r := range target {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			strings.ContainsRune(".:-_/?!&%#[]@+,~=;", r) {
			continue
		}

		return false
	}

	return true
}

// -----------------------------------------------------------------------------
// Environment
// -----------------------------------------------------------------------------

func loadConfig() {
	cfg.Host = getEnv("COMMANDER_HOST", "0.0.0.0")
	cfg.Port = getEnv("COMMANDER_PORT", "8080")

	cfg.TLSCertFile = os.Getenv("COMMANDER_TLS_CERT")
	cfg.TLSKeyFile = os.Getenv("COMMANDER_TLS_KEY")
	cfg.ClientCAFile = os.Getenv("COMMANDER_CLIENT_CA")

	cfg.MaxWSConnections = getEnvInt("MAX_WS_CONNECTIONS", 100)

	cfg.SessionTTL =
		time.Duration(
			getEnvInt("SESSION_TTL_HOURS", 24),
		) * time.Hour

	cfg.LoginMaxAttempts =
		getEnvInt("LOGIN_MAX_ATTEMPTS", 5)

	cfg.LoginWindow =
		time.Duration(
			getEnvInt("LOGIN_WINDOW_MINUTES", 10),
		) * time.Minute

	cfg.LoginBlockTime =
		time.Duration(
			getEnvInt("LOGIN_BLOCK_MINUTES", 15),
		) * time.Minute

	cfg.AllowedOrigins = make(map[string]bool)

	origins := os.Getenv("ALLOWED_ORIGINS")
	log.Println("🔥 RAW ALLOWED_ORIGINS =", origins)
	if origins == "" {
		cfg.AllowedOrigins["https://commander.sentinel.test:8080"] = true

		cfg.AllowedOrigins["http://commander.sentinel.test:8080"] = true

		cfg.AllowedOrigins["https://localhost:8080"] = true
		cfg.AllowedOrigins["http://localhost:8080"] = true

		cfg.AllowedOrigins["https://127.0.0.1:8080"] = true
		cfg.AllowedOrigins["http://127.0.0.1:8080"] = true
	} else {
		for _, origin := range strings.Split(origins, ",") {
			origin = strings.TrimSpace(origin)

			if origin != "" {
				cfg.AllowedOrigins[origin] = true
			}
		}
	}
	log.Println("========== ALLOWED ORIGINS ==========")

	for origin := range cfg.AllowedOrigins {
		log.Println("CONFIG:", origin)
	}

	log.Println("=====================================")

	log.Println("🔥 FINAL ALLOWED ORIGINS:")

	for origin := range cfg.AllowedOrigins {
		log.Println("   ->", origin)
	}
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))

	if value == "" {
		return fallback
	}

	return value
}

func getEnvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))

	if value == "" {
		return fallback
	}

	n, err := strconv.Atoi(value)

	if err != nil || n <= 0 {
		return fallback
	}

	return n
}

func requireMTLSSetting(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "1", "true", "yes", "on":
		return nil
	case "0", "false", "no", "off":
		return fmt.Errorf("Commander requires mTLS and does not allow disabling it")
	default:
		return fmt.Errorf("MTLS_REQUIRED must be true when set")
	}
}

// -----------------------------------------------------------------------------
// Database - MySQL
// -----------------------------------------------------------------------------

func initDB() {
	connStr := strings.TrimSpace(
		os.Getenv("DATABASE_URL"),
	)

	if connStr == "" {
		log.Fatal(
			"DATABASE_URL is not set. Configure the MySQL connection.",
		)
	}

	var err error

	db, err = sql.Open("mysql", connStr)

	if err != nil {
		log.Fatal(
			"Could not configure the MySQL connection:",
			err,
		)
	}

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	if err = db.Ping(); err != nil {
		log.Fatal(
			"MySQL connection failed:",
			err,
		)
	}

	ensureDatabaseSchema()

	fmt.Println("🗄️ MySQL: Connection established.")
	fmt.Println("🐘 Commander: Database is ready.")
}

func loadTLSCertificate(certFile, keyFile, keyPassword string) (tls.Certificate, error) {
	// Read the certificate and private key files first.
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("Could not read TLS certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("Could not read TLS private key: %w", err)
	}

	// Find the private key block in the PEM data.
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return tls.Certificate{}, errors.New("TLS private key is not valid PEM")
	}

	var privateKey any

	switch keyBlock.Type {
	case "ENCRYPTED PRIVATE KEY":
		// PKCS#8 encrypted private key.
		if keyPassword == "" {
			return tls.Certificate{}, errors.New(
				"TLS private key is encrypted, but TLS_KEY_PASSWORD is not set",
			)
		}

		privateKey, err = pkcs8.ParsePKCS8PrivateKey(
			keyBlock.Bytes,
			[]byte(keyPassword),
		)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf(
				"Could not decrypt the encrypted TLS private key: %w",
				err,
			)
		}

	default:
		// Support unencrypted PKCS#8, RSA, and EC keys.
		privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)

		if err != nil {
			// PKCS#1 RSA key ihtimali.
			if rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); rsaErr == nil {
				privateKey = rsaKey
			} else if ecKey, ecErr := x509.ParseECPrivateKey(keyBlock.Bytes); ecErr == nil {
				privateKey = ecKey
			} else {
				return tls.Certificate{}, fmt.Errorf(
					"Could not parse TLS private key: %w",
					err,
				)
			}
		}
	}

	// Convert the certificate chain to the format expected by TLS.
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return tls.Certificate{}, errors.New(
			"TLS certificate is not valid PEM",
		)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"Could not parse TLS certificate: %w",
			err,
		)
	}

	// Create a tls.Certificate.
	tlsCert := tls.Certificate{
		Certificate: [][]byte{
			cert.Raw,
		},
		PrivateKey: privateKey,
	}

	// If the certificate file contains an intermediate chain,
	// append the remaining PEM blocks to the certificate chain.
	remaining := certPEM
	_, remaining = pem.Decode(remaining)

	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			chainCert, parseErr := x509.ParseCertificate(block.Bytes)
			if parseErr != nil {
				return tls.Certificate{}, fmt.Errorf(
					"Could not parse TLS certificate chain: %w",
					parseErr,
				)
			}

			tlsCert.Certificate = append(
				tlsCert.Certificate,
				chainCert.Raw,
			)
		}

		remaining = rest
	}

	return tlsCert, nil
}

// -----------------------------------------------------------------------------
// Database schema verification
// -----------------------------------------------------------------------------

func ensureDatabaseSchema() {
	queries := []string{

		`
		CREATE TABLE IF NOT EXISTS users (
			id INT UNSIGNED NOT NULL AUTO_INCREMENT,
			username VARCHAR(100) NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

			PRIMARY KEY (id),
			UNIQUE KEY uq_users_username (username)
		) ENGINE=InnoDB
		DEFAULT CHARACTER SET utf8mb4
		COLLATE utf8mb4_unicode_ci;
		`,

		`
		CREATE TABLE IF NOT EXISTS targets (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			agent_name VARCHAR(100) NOT NULL,
			target_url VARCHAR(2048) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

			PRIMARY KEY (id),
			INDEX idx_targets_agent (agent_name)
		) ENGINE=InnoDB
		DEFAULT CHARACTER SET utf8mb4
		COLLATE utf8mb4_unicode_ci;
		`,

		`
		CREATE TABLE IF NOT EXISTS logs (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			target VARCHAR(2048) NOT NULL,
			status INT NOT NULL,
			latency VARCHAR(50) NOT NULL,
			agent VARCHAR(100) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			cpu DECIMAL(5,2) NOT NULL DEFAULT 0,
			ram DECIMAL(5,2) NOT NULL DEFAULT 0,
			disk DECIMAL(5,2) NOT NULL DEFAULT 0,

			PRIMARY KEY (id),
			INDEX idx_logs_created_at (created_at),
			INDEX idx_logs_agent (agent)
		) ENGINE=InnoDB
		DEFAULT CHARACTER SET utf8mb4
		COLLATE utf8mb4_unicode_ci;
		`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			log.Fatal(
				"MySQL schema creation/verification failed:",
				err,
			)
		}
	}

	var userCount int

	err := db.QueryRow(
		"SELECT COUNT(*) FROM users",
	).Scan(&userCount)

	if err != nil {
		log.Fatal(
			"Could not read user records:",
			err,
		)
	}

	if userCount == 0 {
		createInitialAdmin()
	}
}

func createInitialAdmin() {
	defaultUser := getEnv(
		"ADMIN_INIT_USER",
		"admin",
	)

	defaultPass := strings.TrimSpace(
		os.Getenv("ADMIN_INIT_PASS"),
	)

	if defaultPass == "" {
		log.Fatal(
			"The users table is empty and ADMIN_INIT_PASS is not set.",
		)
	}

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(defaultPass),
		bcrypt.DefaultCost,
	)

	if err != nil {
		log.Fatal(
			"Could not hash the admin password:",
			err,
		)
	}

	_, err = db.Exec(
		`
		INSERT INTO users
			(username, password_hash)
		VALUES
			(?, ?)
		`,
		defaultUser,
		string(hash),
	)

	if err != nil {
		log.Fatal(
			"Could not create the admin user:",
			err,
		)
	}

	fmt.Println(
		"🔑 Initial user created:",
		defaultUser,
	)
}

// -----------------------------------------------------------------------------
// Session
// -----------------------------------------------------------------------------

func generateSessionToken() (string, error) {
	buf := make([]byte, 32)

	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func createSession(username string) (string, error) {
	token, err := generateSessionToken()

	if err != nil {
		return "", err
	}

	sessionsMu.Lock()

	sessions[token] = Session{
		Username: username,
		Expires:  time.Now().Add(cfg.SessionTTL),
	}

	sessionsMu.Unlock()

	return token, nil
}

func getSession(token string) (Session, bool) {
	sessionsMu.RLock()

	session, ok := sessions[token]

	sessionsMu.RUnlock()

	if !ok {
		return Session{}, false
	}

	if time.Now().After(session.Expires) {
		sessionsMu.Lock()

		delete(
			sessions,
			token,
		)

		sessionsMu.Unlock()

		return Session{}, false
	}

	return session, true
}

func deleteSession(token string) {
	sessionsMu.Lock()

	delete(
		sessions,
		token,
	)

	sessionsMu.Unlock()
}

func sessionCleanup() {
	ticker := time.NewTicker(10 * time.Minute)

	go func() {
		for range ticker.C {
			now := time.Now()

			sessionsMu.Lock()

			for token, session := range sessions {
				if now.After(session.Expires) {
					delete(
						sessions,
						token,
					)
				}
			}

			sessionsMu.Unlock()
		}
	}()
}

// -----------------------------------------------------------------------------
// Security headers
// -----------------------------------------------------------------------------

func securityHeaders(
	w http.ResponseWriter,
	isHTTPS bool,
) {
	w.Header().Set(
		"X-Frame-Options",
		"DENY",
	)

	w.Header().Set(
		"X-Content-Type-Options",
		"nosniff",
	)

	w.Header().Set(
		"Referrer-Policy",
		"strict-origin-when-cross-origin",
	)

	w.Header().Set(
		"Permissions-Policy",
		"camera=(), microphone=(), geolocation=()",
	)

	w.Header().Set(
		"Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "+
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "+
			"img-src 'self' data:; "+
			"connect-src 'self' wss://commander.sentinel.test:8080; "+
			"font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com; "+
			"object-src 'none'; "+
			"base-uri 'self'; "+
			"frame-ancestors 'none'",
	)

	if isHTTPS {
		w.Header().Set(
			"Strict-Transport-Security",
			"max-age=31536000; includeSubDomains",
		)
	}
}

// -----------------------------------------------------------------------------
// Authentication middleware
// -----------------------------------------------------------------------------

func authMiddleware(
	next http.HandlerFunc,
) http.HandlerFunc {

	return func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		securityHeaders(
			w,
			r.TLS != nil,
		)

		if r.URL.Path == "/api/login" ||
			r.URL.Path == "/login.html" {

			next(w, r)
			return
		}

		cookie, err := r.Cookie(
			"session_token",
		)

		if err != nil {
			if strings.HasPrefix(
				r.URL.Path,
				"/api/",
			) {
				http.Error(
					w,
					"Yetkisiz",
					http.StatusUnauthorized,
				)

				return
			}

			http.Redirect(
				w,
				r,
				"/login.html",
				http.StatusSeeOther,
			)

			return
		}

		if _, ok := getSession(
			cookie.Value,
		); !ok {

			if strings.HasPrefix(
				r.URL.Path,
				"/api/",
			) {
				http.Error(
					w,
					"Session is invalid or expired",
					http.StatusUnauthorized,
				)

				return
			}

			http.Redirect(
				w,
				r,
				"/login.html",
				http.StatusSeeOther,
			)

			return
		}

		next(w, r)
	}
}

// -----------------------------------------------------------------------------
// Login rate limiting
// -----------------------------------------------------------------------------

func getClientIP(
	r *http.Request,
) string {

	host, _, err := net.SplitHostPort(
		r.RemoteAddr,
	)

	if err == nil {
		return host
	}

	return r.RemoteAddr
}

func loginAllowed(ip string) bool {
	now := time.Now()

	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()

	entry, exists := loginAttempts[ip]

	if !exists {
		loginAttempts[ip] = &LoginAttempt{
			Count:     0,
			FirstSeen: now,
		}

		return true
	}

	if entry.BlockedTill.After(now) {
		return false
	}

	if now.Sub(entry.FirstSeen) >
		cfg.LoginWindow {

		entry.Count = 0
		entry.FirstSeen = now
		entry.BlockedTill = time.Time{}
	}

	return true
}

func recordLoginFailure(ip string) {
	now := time.Now()

	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()

	entry, exists := loginAttempts[ip]

	if !exists {
		entry = &LoginAttempt{
			FirstSeen: now,
		}

		loginAttempts[ip] = entry
	}

	if now.Sub(entry.FirstSeen) >
		cfg.LoginWindow {

		entry.Count = 0
		entry.FirstSeen = now
	}

	entry.Count++

	if entry.Count >=
		cfg.LoginMaxAttempts {

		entry.BlockedTill =
			now.Add(cfg.LoginBlockTime)
	}
}

func recordLoginSuccess(ip string) {
	loginAttemptsMu.Lock()

	delete(
		loginAttempts,
		ip,
	)

	loginAttemptsMu.Unlock()
}

// -----------------------------------------------------------------------------
// Login
// -----------------------------------------------------------------------------

func handleLogin(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		http.Error(
			w,
			"Method Not Allowed",
			http.StatusMethodNotAllowed,
		)

		return
	}

	ip := getClientIP(r)

	if !loginAllowed(ip) {
		http.Error(
			w,
			"Too many failed login attempts.",
			http.StatusTooManyRequests,
		)

		return
	}

	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		16*1024,
	)

	var creds LoginRequest

	if err := json.NewDecoder(
		r.Body,
	).Decode(&creds); err != nil {

		http.Error(
			w,
			"Invalid data",
			http.StatusBadRequest,
		)

		return
	}

	creds.Username =
		strings.TrimSpace(
			creds.Username,
		)

	if creds.Username == "" ||
		len(creds.Username) > 128 ||
		len(creds.Password) > 256 {

		recordLoginFailure(ip)

		http.Error(
			w,
			"Login failed",
			http.StatusUnauthorized,
		)

		return
	}

	var storedHash string

	err := db.QueryRow(
		`
		SELECT password_hash
		FROM users
		WHERE username = ?
		`,
		creds.Username,
	).Scan(&storedHash)

	if err != nil ||
		bcrypt.CompareHashAndPassword(
			[]byte(storedHash),
			[]byte(creds.Password),
		) != nil {

		recordLoginFailure(ip)

		time.Sleep(
			500 * time.Millisecond,
		)

		http.Error(
			w,
			"Login failed",
			http.StatusUnauthorized,
		)

		return
	}

	recordLoginSuccess(ip)

	sessionToken, err :=
		createSession(creds.Username)

	if err != nil {
		http.Error(
			w,
			"Could not create session",
			http.StatusInternalServerError,
		)

		return
	}

	isSecure :=
		r.TLS != nil ||
			strings.EqualFold(
				os.Getenv("COOKIE_SECURE"),
				"true",
			)

	http.SetCookie(
		w,
		&http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  time.Now().Add(cfg.SessionTTL),
			MaxAge:   int(cfg.SessionTTL.Seconds()),
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   isSecure,
		},
	)

	w.WriteHeader(http.StatusOK)
}

// -----------------------------------------------------------------------------
// Logout
// -----------------------------------------------------------------------------

func handleLogout(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {

		http.Error(
			w,
			"Method Not Allowed",
			http.StatusMethodNotAllowed,
		)

		return
	}

	cookie, err :=
		r.Cookie("session_token")

	if err == nil {
		deleteSession(cookie.Value)
	}

	http.SetCookie(
		w,
		&http.Cookie{
			Name:     "session_token",
			Value:    "",
			Expires:  time.Unix(1, 0),
			MaxAge:   -1,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil,
		},
	)

	http.Redirect(
		w,
		r,
		"/login.html",
		http.StatusSeeOther,
	)
}

// -----------------------------------------------------------------------------
// Scheduler
// -----------------------------------------------------------------------------

func startTaskScheduler() {
	ticker := time.NewTicker(
		5 * time.Second,
	)

	go func() {
		for range ticker.C {

			rows, err := db.Query(
				`
				SELECT agent_name, target_url
				FROM targets
				`,
			)

			if err != nil {
				log.Println(
					"Scheduler DB error:",
					err,
				)

				continue
			}

			for rows.Next() {
				var (
					agentName string
					targetURL string
				)

				if err := rows.Scan(
					&agentName,
					&targetURL,
				); err != nil {
					continue
				}

				clientsMu.RLock()

				agent, exists :=
					clients[agentName]

				clientsMu.RUnlock()

				if !exists ||
					agent == nil {
					continue
				}

				now := time.Now().UTC()
				taskID := uuid.NewString()
				expiresAt := now.Add(30 * time.Second)
				if !createPendingTask(taskID, agentName, targetURL, expiresAt, now) {
					continue
				}

				agent.WriteMu.Lock()

				_ = agent.Conn.SetWriteDeadline(
					time.Now().Add(5 * time.Second),
				)

				err := agent.Conn.WriteJSON(
					models.Command{
						Type:      "PING_REQUEST",
						TaskID:    taskID,
						Agent:     agentName,
						Target:    targetURL,
						IssuedAt:  now.Format(time.RFC3339Nano),
						ExpiresAt: expiresAt.Format(time.RFC3339Nano),
					},
				)

				agent.WriteMu.Unlock()

				if err != nil {
					tasksMu.Lock()
					delete(pendingTasks, taskID)
					tasksMu.Unlock()
					log.Printf(
						"Agent %s write error: %v",
						agentName,
						err,
					)
				}
			}

			rows.Close()
		}
	}()
}

// -----------------------------------------------------------------------------
// Targets
// -----------------------------------------------------------------------------

func handleTargets(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	switch r.Method {

	case http.MethodGet:

		rows, err := db.Query(
			`
			SELECT id, agent_name, target_url
			FROM targets
			`,
		)

		if err != nil {
			http.Error(
				w,
				"Could not retrieve data",
				http.StatusInternalServerError,
			)

			return
		}

		defer rows.Close()

		tasks :=
			make([]TargetTask, 0)

		for rows.Next() {
			var t TargetTask

			if err := rows.Scan(
				&t.ID,
				&t.AgentName,
				&t.TargetURL,
			); err != nil {
				continue
			}

			tasks = append(
				tasks,
				t,
			)
		}

		if err := rows.Err(); err != nil {
			http.Error(
				w,
				"Could not read data",
				http.StatusInternalServerError,
			)

			return
		}

		_ = json.NewEncoder(
			w,
		).Encode(tasks)

	case http.MethodPost:

		r.Body = http.MaxBytesReader(
			w,
			r.Body,
			32*1024,
		)

		var t TargetTask

		if err := json.NewDecoder(
			r.Body,
		).Decode(&t); err != nil {

			http.Error(
				w,
				"Invalid data",
				http.StatusBadRequest,
			)

			return
		}

		t.AgentName =
			strings.TrimSpace(
				t.AgentName,
			)

		t.TargetURL =
			strings.TrimSpace(
				t.TargetURL,
			)

		if !validAgentName(
			t.AgentName,
		) {
			http.Error(
				w,
				"Invalid agent name",
				http.StatusBadRequest,
			)

			return
		}

		if !validTarget(
			t.TargetURL,
		) {
			http.Error(
				w,
				"Invalid target",
				http.StatusBadRequest,
			)

			return
		}

		_, err := db.Exec(
			`
			INSERT INTO targets
				(agent_name, target_url)
			VALUES
				(?, ?)
			`,
			t.AgentName,
			t.TargetURL,
		)

		if err != nil {
			log.Println(
				"DB Error:",
				err,
			)

			http.Error(
				w,
				"Could not save record",
				http.StatusInternalServerError,
			)

			return
		}

		w.WriteHeader(
			http.StatusCreated,
		)

	case http.MethodDelete:

		idStr :=
			r.URL.Query().Get("id")

		id, err :=
			strconv.Atoi(idStr)

		if err != nil ||
			id <= 0 {

			http.Error(
				w,
				"Invalid ID",
				http.StatusBadRequest,
			)

			return
		}

		result, err := db.Exec(
			`
			DELETE FROM targets
			WHERE id = ?
			`,
			id,
		)

		if err != nil {
			http.Error(
				w,
				"Could not delete record",
				http.StatusInternalServerError,
			)

			return
		}

		affected, _ :=
			result.RowsAffected()

		if affected == 0 {
			http.Error(
				w,
				"Record not found",
				http.StatusNotFound,
			)

			return
		}

		w.WriteHeader(
			http.StatusOK,
		)

	default:

		http.Error(
			w,
			"Method Not Allowed",
			http.StatusMethodNotAllowed,
		)
	}
}

// -----------------------------------------------------------------------------
// History
// -----------------------------------------------------------------------------

func getHistory(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	hoursStr :=
		strings.TrimSpace(
			r.URL.Query().Get("hours"),
		)

	queryBase := `
		SELECT id, target, status, latency, agent,
		       created_at, cpu, ram, disk
		FROM logs
	`

	var (
		rows *sql.Rows
		err  error
	)

	if hoursStr != "" {

		hours, parseErr :=
			strconv.Atoi(hoursStr)

		if parseErr != nil ||
			hours <= 0 ||
			hours > 8760 {

			http.Error(
				w,
				"Invalid hours value",
				http.StatusBadRequest,
			)

			return
		}

		cutoff :=
			time.Now().Add(
				-time.Duration(hours) * time.Hour,
			)

		rows, err = db.Query(
			queryBase+`
			WHERE created_at >= ?
			ORDER BY id DESC
			`,
			cutoff,
		)

	} else {

		rows, err = db.Query(
			queryBase + `
			ORDER BY id DESC
			LIMIT 200
			`,
		)
	}

	if err != nil {
		http.Error(
			w,
			"Could not retrieve data",
			http.StatusInternalServerError,
		)

		return
	}

	defer rows.Close()

	history :=
		make([]LogEntry, 0)

	for rows.Next() {

		var e LogEntry
		var createdAt time.Time

		if err := rows.Scan(
			&e.ID,
			&e.Target,
			&e.Status,
			&e.Latency,
			&e.Agent,
			&createdAt,
			&e.CPU,
			&e.RAM,
			&e.Disk,
		); err != nil {
			continue
		}

		e.CreatedAt =
			createdAt.Format(
				time.RFC3339,
			)

		history = append(
			history,
			e,
		)
	}

	if err := rows.Err(); err != nil {

		http.Error(
			w,
			"Could not read data",
			http.StatusInternalServerError,
		)

		return
	}

	_ = json.NewEncoder(
		w,
	).Encode(history)
}

// -----------------------------------------------------------------------------
// Active agents
// -----------------------------------------------------------------------------

func handleActiveAgents(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	clientsMu.RLock()
	defer clientsMu.RUnlock()

	activeList :=
		make([]string, 0, len(clients))

	for name := range clients {
		activeList = append(
			activeList,
			name,
		)
	}

	_ = json.NewEncoder(
		w,
	).Encode(activeList)
}

// -----------------------------------------------------------------------------
// Export
// -----------------------------------------------------------------------------

func handleExport(
	w http.ResponseWriter,
	r *http.Request,
) {
	rows, err := db.Query(`
		SELECT id, target, status, latency, agent,
		       created_at, cpu, ram, disk
		FROM logs
		ORDER BY id DESC
		LIMIT 1000
	`)

	if err != nil {
		http.Error(
			w,
			"Error",
			http.StatusInternalServerError,
		)

		return
	}

	defer rows.Close()

	f := excelize.NewFile()

	sheetName :=
		"Sentinel Report"

	if err := f.SetSheetName(
		"Sheet1",
		sheetName,
	); err != nil {

		http.Error(
			w,
			"Could not create Excel file",
			http.StatusInternalServerError,
		)

		return
	}

	titleStyle, _ := f.NewStyle(
		&excelize.Style{
			Font: &excelize.Font{
				Bold:  true,
				Size:  20,
				Color: "#1F4E78",
			},
			Alignment: &excelize.Alignment{
				Horizontal: "center",
			},
		},
	)

	headerStyle, _ := f.NewStyle(
		&excelize.Style{
			Font: &excelize.Font{
				Bold:  true,
				Color: "#FFFFFF",
			},
			Fill: excelize.Fill{
				Type:    "pattern",
				Color:   []string{"#1F4E78"},
				Pattern: 1,
			},
			Alignment: &excelize.Alignment{
				Horizontal: "center",
			},
		},
	)

	centerStyle, _ := f.NewStyle(
		&excelize.Style{
			Alignment: &excelize.Alignment{
				Horizontal: "center",
			},
		},
	)

	badStyle, _ := f.NewStyle(
		&excelize.Style{
			Font: &excelize.Font{
				Color: "#DC2626",
				Bold:  true,
			},
			Alignment: &excelize.Alignment{
				Horizontal: "center",
			},
		},
	)

	goodStyle, _ := f.NewStyle(
		&excelize.Style{
			Font: &excelize.Font{
				Color: "#16A34A",
				Bold:  true,
			},
			Alignment: &excelize.Alignment{
				Horizontal: "center",
			},
		},
	)

	warnStyle, _ := f.NewStyle(
		&excelize.Style{
			Font: &excelize.Font{
				Color: "#EA580C",
				Bold:  true,
			},
			Alignment: &excelize.Alignment{
				Horizontal: "center",
			},
		},
	)

	_ = f.MergeCell(
		sheetName,
		"A1",
		"I1",
	)

	_ = f.SetCellValue(
		sheetName,
		"A1",
		"SENTINEL SYSTEM REPORT",
	)

	_ = f.SetCellStyle(
		sheetName,
		"A1",
		"I1",
		titleStyle,
	)

	_ = f.SetRowHeight(
		sheetName,
		1,
		40,
	)

	headers := []string{
		"ID",
		"Time",
		"Agent",
		"Target",
		"Status",
		"Latency",
		"CPU %",
		"RAM %",
		"Disk %",
	}

	cols := []string{
		"A",
		"B",
		"C",
		"D",
		"E",
		"F",
		"G",
		"H",
		"I",
	}

	for i, h := range headers {

		cell :=
			fmt.Sprintf(
				"%s2",
				cols[i],
			)

		_ = f.SetCellValue(
			sheetName,
			cell,
			h,
		)

		_ = f.SetCellStyle(
			sheetName,
			cell,
			cell,
			headerStyle,
		)
	}

	rowIdx := 3

	for rows.Next() {

		var (
			id             int
			status         int
			target         string
			latency        string
			agent          string
			createdAt      time.Time
			cpu, ram, disk float64
		)

		if err := rows.Scan(
			&id,
			&target,
			&status,
			&latency,
			&agent,
			&createdAt,
			&cpu,
			&ram,
			&disk,
		); err != nil {
			continue
		}

		formattedTime :=
			createdAt.Format(
				"2006-01-02 15:04:05",
			)

		values := []any{
			id,
			formattedTime,
			agent,
			target,
			status,
			latency,
			fmt.Sprintf("%.1f", cpu),
			fmt.Sprintf("%.1f", ram),
			fmt.Sprintf("%.1f", disk),
		}

		for i, value := range values {

			cell :=
				fmt.Sprintf(
					"%s%d",
					cols[i],
					rowIdx,
				)

			_ = f.SetCellValue(
				sheetName,
				cell,
				value,
			)
		}

		_ = f.SetCellStyle(
			sheetName,
			fmt.Sprintf("A%d", rowIdx),
			fmt.Sprintf("I%d", rowIdx),
			centerStyle,
		)

		statusCell :=
			fmt.Sprintf("E%d", rowIdx)

		if status == 200 {

			_ = f.SetCellStyle(
				sheetName,
				statusCell,
				statusCell,
				goodStyle,
			)

		} else {

			_ = f.SetCellStyle(
				sheetName,
				statusCell,
				statusCell,
				badStyle,
			)
		}

		latStr :=
			strings.TrimSuffix(
				latency,
				"ms",
			)

		latVal, _ :=
			strconv.Atoi(latStr)

		latCell :=
			fmt.Sprintf(
				"F%d",
				rowIdx,
			)

		if latVal > 300 {

			_ = f.SetCellStyle(
				sheetName,
				latCell,
				latCell,
				badStyle,
			)

		} else if latVal > 100 {

			_ = f.SetCellStyle(
				sheetName,
				latCell,
				latCell,
				warnStyle,
			)

		} else {

			_ = f.SetCellStyle(
				sheetName,
				latCell,
				latCell,
				goodStyle,
			)
		}

		rowIdx++
	}

	_ = f.SetColWidth(
		sheetName,
		"B",
		"B",
		20,
	)

	_ = f.SetColWidth(
		sheetName,
		"C",
		"D",
		25,
	)

	w.Header().Set(
		"Content-Type",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	)

	w.Header().Set(
		"Content-Disposition",
		"attachment; filename=sentinel_report.xlsx",
	)

	if err := f.Write(w); err != nil {
		log.Println(
			"Excel response error:",
			err,
		)
	}
}

// -----------------------------------------------------------------------------
// WebSocket origin
// -----------------------------------------------------------------------------

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,

	CheckOrigin: func(r *http.Request) bool {

		origin := strings.TrimSpace(r.Header.Get("Origin"))

		log.Println("🔎 Received Origin:", origin)

		for allowed := range cfg.AllowedOrigins {
			log.Println("🔎 Allowed Origin:", allowed)
		}

		if cfg.AllowedOrigins[origin] {
			log.Println("✅ Origin accepted:", origin)
			return true
		}

		log.Println("⚠️ Blocked WebSocket Origin:", origin)

		return false
	},
}

// -----------------------------------------------------------------------------
// Client certificate identity
// -----------------------------------------------------------------------------

func validateClientCertificate(
	r *http.Request,
	agentName string,
) bool {

	if r.TLS == nil ||
		len(r.TLS.PeerCertificates) == 0 {
		return false
	}

	cert :=
		r.TLS.PeerCertificates[0]

	for _, dnsName := range cert.DNSNames {

		if dnsName == agentName ||
			dnsName ==
				agentName+".sentinel.test" {

			return true
		}
	}

	for _, uri := range cert.URIs {

		if uri.String() == "spiffe://sentinel.test/"+agentName {

			return true
		}
	}

	return false
}

// -----------------------------------------------------------------------------
// WebSocket connection limiting
// -----------------------------------------------------------------------------

func acquireWSConnection() bool {
	for {

		current :=
			atomic.LoadInt64(
				&activeWSConnections,
			)

		if current >=
			int64(cfg.MaxWSConnections) {

			return false
		}

		if atomic.CompareAndSwapInt64(
			&activeWSConnections,
			current,
			current+1,
		) {
			return true
		}
	}
}

func releaseWSConnection() {
	atomic.AddInt64(
		&activeWSConnections,
		-1,
	)
}

// -----------------------------------------------------------------------------
// WebSocket heartbeat
// -----------------------------------------------------------------------------

const (
	wsWriteWait  = 10 * time.Second
	wsPongWait   = 60 * time.Second
	wsPingPeriod = 30 * time.Second

	maxMessageSize = 64 * 1024
)

// -----------------------------------------------------------------------------
// WebSocket handler
// -----------------------------------------------------------------------------

func handleConnections(
	w http.ResponseWriter,
	r *http.Request,
) {
	securityHeaders(
		w,
		r.TLS != nil,
	)

	if !acquireWSConnection() {

		http.Error(
			w,
			"WebSocket connection limit reached",
			http.StatusServiceUnavailable,
		)

		return
	}

	defer releaseWSConnection()

	// -------------------------------------------------------------------------
	// Legacy development authentication
	// -------------------------------------------------------------------------

	// -------------------------------------------------------------------------
	// TLS / mTLS
	// -------------------------------------------------------------------------

	if r.TLS == nil {
		http.Error(w, "TLS is required", http.StatusUpgradeRequired)
		return
	}
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "A client certificate is required", http.StatusUnauthorized)
		return
	}

	ws, err :=
		upgrader.Upgrade(
			w,
			r,
			nil,
		)

	if err != nil {
		log.Println(
			"WebSocket upgrade error:",
			err,
		)

		return
	}

	defer ws.Close()

	ws.SetReadLimit(
		maxMessageSize,
	)

	_ = ws.SetReadDeadline(
		time.Now().Add(wsPongWait),
	)

	ws.SetPongHandler(
		func(string) error {
			return ws.SetReadDeadline(
				time.Now().Add(wsPongWait),
			)
		},
	)

	var (
		currentAgentName string
		agentConn        *AgentConnection
	)
	var agentConnMu sync.RWMutex

	done := make(chan struct{})

	defer close(done)

	// -------------------------------------------------------------------------
	// Heartbeat
	// -------------------------------------------------------------------------

	go func() {

		ticker :=
			time.NewTicker(
				wsPingPeriod,
			)

		defer ticker.Stop()

		for {

			select {

			case <-ticker.C:

				agentConnMu.RLock()
				registeredAgentConn := agentConn
				agentConnMu.RUnlock()
				if registeredAgentConn == nil {
					continue
				}

				registeredAgentConn.WriteMu.Lock()

				_ = ws.SetWriteDeadline(
					time.Now().Add(
						wsWriteWait,
					),
				)

				err :=
					ws.WriteControl(
						websocket.PingMessage,
						nil,
						time.Now().Add(
							wsWriteWait,
						),
					)

				registeredAgentConn.WriteMu.Unlock()

				if err != nil {
					return
				}

			case <-done:
				return
			}
		}
	}()

	// -------------------------------------------------------------------------
	// Message loop
	// -------------------------------------------------------------------------

messageLoop:
	for {

		var msg models.Command

		err :=
			ws.ReadJSON(&msg)

		if err != nil {

			if !errors.Is(
				err,
				io.EOF,
			) {

				log.Printf(
					"WebSocket closed (%s): %v",
					currentAgentName,
					err,
				)
			}

			break
		}

		// ---------------------------------------------------------------------
		// REGISTER
		// ---------------------------------------------------------------------

		if msg.Type == "REGISTER" {
			if currentAgentName != "" {
				break
			}

			agentName :=
				strings.TrimSpace(
					msg.Agent,
				)

			if !validAgentName(
				agentName,
			) {

				log.Println(
					"⛔ Invalid agent name:",
					agentName,
				)

				break
			}

			if !validateClientCertificate(
				r,
				agentName,
			) {

				log.Printf(
					"⛔ Agent certificate identity mismatch: %s",
					agentName,
				)

				break
			}

			clientsMu.Lock()

			if existing, exists :=
				clients[agentName]; exists {

				clientsMu.Unlock()

				if existing != nil &&
					existing.Conn != ws {

					log.Printf(
						"⛔ Duplicate agent rejected: %s",
						agentName,
					)
				}

				break
			}

			registeredAgentConn := &AgentConnection{
				Name:     agentName,
				Conn:     ws,
				LastSeen: time.Now(),
			}

			clients[agentName] =
				registeredAgentConn

			clientsMu.Unlock()

			agentConnMu.Lock()
			agentConn = registeredAgentConn
			agentConnMu.Unlock()

			currentAgentName =
				agentName

			log.Printf(
				"🔵 Agent connected: %s",
				currentAgentName,
			)

			continue
		}

		// ---------------------------------------------------------------------
		// Registration required
		// ---------------------------------------------------------------------

		if currentAgentName == "" ||
			agentConn == nil {

			log.Println(
				"⛔ Message received before REGISTER",
			)

			break
		}

		// ---------------------------------------------------------------------
		// Agent identity protection
		agentConn.LastSeenMu.Lock()

		agentConn.LastSeen =
			time.Now()

		agentConn.LastSeenMu.Unlock()

		// ---------------------------------------------------------------------
		// REPORT
		// ---------------------------------------------------------------------

		if !validAgentMessageType(msg.Type) {
			log.Printf("Unknown agent message type %q; closing connection", msg.Type)
			break messageLoop
		}

		switch msg.Type {
		case "REPORT":

			if len(msg.Target) > 2048 ||
				len(msg.Time) > maxReportTimeLength {

				log.Println(
					"⛔ REPORT message is too large",
				)

				continue
			}

			target := strings.TrimSpace(msg.Target)

			if target != msg.Target || !validTarget(target) {

				log.Println(
					"⛔ Invalid REPORT target:",
					target,
				)

				continue
			}
			if !validReportTelemetry(msg, currentAgentName) {
				log.Printf("Invalid REPORT agent or telemetry: agent=%s status=%d", currentAgentName, msg.Status)
				continue
			}

			if !validTaskID(msg.TaskID) {
				log.Printf("Invalid REPORT task_id: %q", msg.TaskID)
				continue
			}
			if !claimReport(msg.TaskID, currentAgentName, target, time.Now()) {
				log.Printf("REPORT task authorization failed: agent=%s task_id=%s", currentAgentName, msg.TaskID)
				continue
			}

			_, err :=
				db.Exec(
					`
					INSERT INTO logs
						(target,
						 status,
						 latency,
						 agent,
						 created_at,
						 cpu,
						 ram,
						 disk)
					VALUES
						(?, ?, ?, ?, ?, ?, ?, ?)
					`,
					target,
					msg.Status,
					msg.Time,
					currentAgentName,
					time.Now(),
					msg.CPU,
					msg.RAM,
					msg.Disk,
				)

			if err != nil {
				finishReport(msg.TaskID, false)
				log.Println(
					"Log DB Error:",
					err,
				)
			} else {
				finishReport(msg.TaskID, true)
			}
		}
	}

	// -------------------------------------------------------------------------
	// Cleanup
	// -------------------------------------------------------------------------

	if currentAgentName != "" {

		clientsMu.Lock()

		if existing, ok :=
			clients[currentAgentName]; ok {

			if existing != nil &&
				existing.Conn == ws {

				delete(
					clients,
					currentAgentName,
				)
			}
		}

		clientsMu.Unlock()

		log.Printf(
			"🔴 Agent disconnected: %s",
			currentAgentName,
		)
	}
}

// -----------------------------------------------------------------------------
// TLS
// -----------------------------------------------------------------------------

func loadClientCAPool() (
	*x509.CertPool,
	error,
) {

	if cfg.ClientCAFile == "" {

		return nil,
			fmt.Errorf(
				"COMMANDER_CLIENT_CA is not set",
			)
	}

	caData, err :=
		os.ReadFile(
			cfg.ClientCAFile,
		)

	if err != nil {

		return nil,
			fmt.Errorf(
				"Could not read client CA: %w",
				err,
			)
	}

	pool :=
		x509.NewCertPool()

	if !pool.AppendCertsFromPEM(
		caData,
	) {

		return nil,
			fmt.Errorf(
				"Could not parse client CA certificate",
			)
	}

	return pool, nil
}

func buildTLSConfig() (
	*tls.Config,
	error,
) {

	if cfg.TLSCertFile == "" ||
		cfg.TLSKeyFile == "" {

		return nil,
			fmt.Errorf(
				"TLS certificate/key are not configured",
			)
	}

	keyPassword := os.Getenv("TLS_KEY_PASSWORD")

	cert, err := loadTLSCertificate(
		cfg.TLSCertFile,
		cfg.TLSKeyFile,
		keyPassword,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"Could not load TLS certificate: %w",
			err,
		)
	}

	tlsConfig :=
		&tls.Config{
			MinVersion: tls.VersionTLS13,

			Certificates: []tls.Certificate{
				cert,
			},

			PreferServerCipherSuites: true,
		}

	clientCAs, err := loadClientCAPool()
	if err != nil {
		return nil, err
	}
	tlsConfig.ClientCAs = clientCAs
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

	return tlsConfig, nil
}

// -----------------------------------------------------------------------------
// HTTP server
// -----------------------------------------------------------------------------

func buildHTTPServer() *http.Server {
	webDir :=
		filepath.Join(
			"..",
			"..",
			"web",
			"commander",
		)

	mux :=
		http.NewServeMux()

	mux.HandleFunc(
		"/api/login",
		handleLogin,
	)

	mux.HandleFunc(
		"/api/logout",
		handleLogout,
	)

	mux.HandleFunc(
		"/ws",
		handleConnections,
	)

	mux.HandleFunc(
		"/login.html",
		func(
			w http.ResponseWriter,
			r *http.Request,
		) {

			securityHeaders(
				w,
				r.TLS != nil,
			)

			http.ServeFile(
				w,
				r,
				filepath.Join(
					webDir,
					"login.html",
				),
			)
		},
	)

	mux.HandleFunc(
		"/api/history",
		authMiddleware(
			getHistory,
		),
	)

	mux.HandleFunc(
		"/api/targets",
		authMiddleware(
			handleTargets,
		),
	)

	mux.HandleFunc(
		"/api/agents",
		authMiddleware(
			handleActiveAgents,
		),
	)

	mux.HandleFunc(
		"/api/export",
		authMiddleware(
			handleExport,
		),
	)

	fs :=
		http.FileServer(
			http.Dir(
				webDir,
			),
		)

	mux.HandleFunc(
		"/",
		authMiddleware(
			func(
				w http.ResponseWriter,
				r *http.Request,
			) {

				securityHeaders(
					w,
					r.TLS != nil,
				)

				fs.ServeHTTP(
					w,
					r,
				)
			},
		),
	)

	return &http.Server{
		Addr: cfg.Host +
			":" +
			cfg.Port,

		Handler: requestLogger(mux),

		ReadHeaderTimeout: 10 * time.Second,

		ReadTimeout: 30 * time.Second,

		IdleTimeout: 120 * time.Second,

		MaxHeaderBytes: 32 * 1024,
	}
}

// -----------------------------------------------------------------------------
// HTTP logging
// -----------------------------------------------------------------------------

func requestLogger(
	next http.Handler,
) http.Handler {

	return http.HandlerFunc(
		func(
			w http.ResponseWriter,
			r *http.Request,
		) {

			start :=
				time.Now()

			next.ServeHTTP(
				w,
				r,
			)

			log.Printf(
				"%s %s %s",
				r.Method,
				r.URL.Path,
				time.Since(start),
			)
		},
	)
}

// -----------------------------------------------------------------------------
// Graceful shutdown
// -----------------------------------------------------------------------------

func shutdownOnSignal(
	server *http.Server,
) {

	stop :=
		make(chan os.Signal, 1)

	signal.Notify(
		stop,
		syscall.SIGINT,
		syscall.SIGTERM,
	)

	<-stop

	log.Println(
		"🛑 Commander is shutting down...",
	)

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			10*time.Second,
		)

	defer cancel()

	_ = server.Shutdown(ctx)

	if db != nil {
		_ = db.Close()
	}

	log.Println(
		"Commander has shut down.",
	)
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println(".env not found; using environment variables.")
	}

	if err := requireMTLSSetting(os.Getenv("MTLS_REQUIRED")); err != nil {
		log.Fatal(err)
	}
	loadConfig()
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" || cfg.ClientCAFile == "" {
		log.Fatal("Commander mTLS requires COMMANDER_TLS_CERT, COMMANDER_TLS_KEY, and COMMANDER_CLIENT_CA")
	}

	fmt.Println("======================================")
	fmt.Println(" SENTINEL COMMANDER")
	fmt.Println(" Security Hardened Build")
	fmt.Println("======================================")

	initDB()
	sessionCleanup()
	startTaskScheduler()

	server := buildHTTPServer()
	go shutdownOnSignal(server)

	tlsConfig, err := buildTLSConfig()
	if err != nil {
		log.Fatal("TLS configuration error:", err)
	}
	server.TLSConfig = tlsConfig

	fmt.Println("🔐 TLS: ACTIVE")
	fmt.Println("🔒 Minimum TLS: 1.3")
	fmt.Println("🛡️ mTLS: ACTIVE")
	fmt.Println("🗄️ Database: MySQL")
	fmt.Println("🌐 Commander:", "https://"+cfg.Host+":"+cfg.Port)

	ln, err := tls.Listen("tcp", cfg.Host+":"+cfg.Port, tlsConfig)
	if err != nil {
		log.Fatal("Could not create TLS listener:", err)
	}
	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("HTTPS server error:", err)
	}
}
