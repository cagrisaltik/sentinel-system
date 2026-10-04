package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cagrisaltik/sentinel-system/internal/models"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/youmark/pkcs8"
)

// SECURITY: Command injection protection
// Only domain- or IP-like targets are allowed.
var targetRegex = regexp.MustCompile(`^[a-zA-Z0-9.:\_-]+$`)

var (
	seenTasksMu sync.Mutex
	seenTasks   = make(map[string]time.Time)
)

const maxTaskLifetime = 60 * time.Second

const (
	maxMessageSize = 64 * 1024
	wsReadWait     = 60 * time.Second
	wsWriteWait    = 5 * time.Second
)

var agentNameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

type scoutConfig struct {
	commanderURL   string
	caFile         string
	agentName      string
	clientCertFile string
	clientKeyFile  string
	keyPassword    string
}

func loadScoutConfig() (scoutConfig, error) {
	cfg := scoutConfig{
		commanderURL:   strings.TrimSpace(os.Getenv("COMMANDER_URL")),
		caFile:         strings.TrimSpace(os.Getenv("TLS_CA_FILE")),
		agentName:      strings.TrimSpace(os.Getenv("AGENT_NAME")),
		clientCertFile: strings.TrimSpace(os.Getenv("TLS_CLIENT_CERT")),
		clientKeyFile:  strings.TrimSpace(os.Getenv("TLS_CLIENT_KEY")),
		keyPassword:    os.Getenv("TLS_CLIENT_KEY_PASSWORD"),
	}

	for _, required := range []struct{ name, value string }{
		{"COMMANDER_URL", cfg.commanderURL},
		{"TLS_CA_FILE", cfg.caFile},
		{"AGENT_NAME", cfg.agentName},
		{"TLS_CLIENT_CERT", cfg.clientCertFile},
		{"TLS_CLIENT_KEY", cfg.clientKeyFile},
	} {
		if required.value == "" {
			return scoutConfig{}, fmt.Errorf("%s must be set", required.name)
		}
	}

	commanderURL, err := url.Parse(cfg.commanderURL)
	if err != nil || commanderURL.Scheme != "wss" || commanderURL.Hostname() == "" || commanderURL.User != nil || commanderURL.RawQuery != "" || commanderURL.Fragment != "" || (commanderURL.Path != "" && commanderURL.Path != "/") {
		return scoutConfig{}, fmt.Errorf("COMMANDER_URL must be a wss URL with a hostname and no path, query, or fragment")
	}
	if !agentNameRegex.MatchString(cfg.agentName) {
		return scoutConfig{}, fmt.Errorf("AGENT_NAME must be 1-64 letters, numbers, dots, underscores, or hyphens")
	}
	return cfg, nil
}

func validTaskID(taskID string) bool {
	if len(taskID) != 36 {
		return false
	}
	id, err := uuid.Parse(taskID)
	return err == nil && id.String() == strings.ToLower(taskID)
}

func safeTarget(target string) bool {
	if target == "" || len(target) > 253 || strings.TrimSpace(target) != target || !targetRegex.MatchString(target) {
		return false
	}
	if net.ParseIP(target) != nil {
		return true
	}
	for _, label := range strings.Split(target, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func claimTask(taskID string, issuedAt, expiresAt, now time.Time) bool {
	if !validTaskID(taskID) || !expiresAt.After(now) || !expiresAt.After(issuedAt) || issuedAt.After(now) || expiresAt.Sub(issuedAt) > maxTaskLifetime {
		return false
	}
	seenTasksMu.Lock()
	defer seenTasksMu.Unlock()
	for id, expiry := range seenTasks {
		if !now.Before(expiry) {
			delete(seenTasks, id)
		}
	}
	if _, exists := seenTasks[taskID]; exists {
		return false
	}
	seenTasks[taskID] = expiresAt
	return true
}

func authorizePing(msg models.Command, agentName string, now time.Time) bool {
	if msg.Type != "PING_REQUEST" || msg.Agent != agentName || !targetRegex.MatchString(msg.Target) || !safeTarget(msg.Target) {
		return false
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, msg.IssuedAt)
	if err != nil {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, msg.ExpiresAt)
	if err != nil {
		return false
	}
	return claimTask(msg.TaskID, issuedAt, expiresAt, now)
}

func configureScoutWebSocket(conn *websocket.Conn, readWait time.Duration) error {
	conn.SetReadLimit(maxMessageSize)
	if err := conn.SetReadDeadline(time.Now().Add(readWait)); err != nil {
		return err
	}

	defaultPingHandler := conn.PingHandler()
	conn.SetPingHandler(func(appData string) error {
		if err := defaultPingHandler(appData); err != nil {
			return err
		}
		return conn.SetReadDeadline(time.Now().Add(readWait))
	})
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(readWait))
	})

	return nil
}

func writeScoutJSON(conn *websocket.Conn, message any) error {
	if err := conn.SetWriteDeadline(time.Now().Add(wsWriteWait)); err != nil {
		return err
	}
	return conn.WriteJSON(message)
}

func getSystemStats() (float64, float64, float64) {
	c, _ := cpu.Percent(0, false)
	v, _ := mem.VirtualMemory()
	d, _ := disk.Usage("/")

	cpuVal := 0.0

	if len(c) > 0 {
		cpuVal = c[0]
	}

	return cpuVal, v.UsedPercent, d.UsedPercent
}

func loadClientCertificate(certFile, keyFile, password string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"Could not read client certificate: %w",
			err,
		)
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"Could not read client private key: %w",
			err,
		)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return tls.Certificate{}, fmt.Errorf(
			"Could not parse private key PEM",
		)
	}

	var privateKey any

	switch keyBlock.Type {

	case "ENCRYPTED PRIVATE KEY":
		if password == "" {
			return tls.Certificate{}, fmt.Errorf(
				"TLS client key is encrypted, but TLS_CLIENT_KEY_PASSWORD is not set",
			)
		}

		privateKey, err =
			pkcs8.ParsePKCS8PrivateKey(
				keyBlock.Bytes,
				[]byte(password),
			)

		if err != nil {
			return tls.Certificate{}, fmt.Errorf(
				"Could not decrypt encrypted client private key: %w",
				err,
			)
		}

	case "PRIVATE KEY":
		privateKey, err =
			x509.ParsePKCS8PrivateKey(
				keyBlock.Bytes,
			)

		if err != nil {
			return tls.Certificate{}, fmt.Errorf(
				"Could not parse PKCS#8 private key: %w",
				err,
			)
		}

	case "EC PRIVATE KEY":
		privateKey, err =
			x509.ParseECPrivateKey(
				keyBlock.Bytes,
			)

		if err != nil {
			return tls.Certificate{}, fmt.Errorf(
				"Could not parse EC private key: %w",
				err,
			)
		}

	default:
		return tls.Certificate{}, fmt.Errorf(
			"Unsupported private key type: %s",
			keyBlock.Type,
		)
	}

	// Verify that the Scout certificate public key and
	// private key actually match.
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return tls.Certificate{}, fmt.Errorf(
			"Could not parse client certificate PEM",
		)
	}

	x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"Could not parse client certificate: %w",
			err,
		)
	}

	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf(
			"client private key is not the expected ECDSA key",
		)
	}

	certPublicKey, ok := x509Cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf(
			"client certificate does not contain the expected ECDSA public key",
		)
	}

	if certPublicKey.X.Cmp(ecKey.PublicKey.X) != 0 ||
		certPublicKey.Y.Cmp(ecKey.PublicKey.Y) != 0 {
		return tls.Certificate{}, fmt.Errorf(
			"client certificate does not match the private key",
		)
	}

	// tls.X509KeyPair does not accept encrypted keys.
	// Construct the Certificate and PrivateKey directly instead.
	return tls.Certificate{
		Certificate: [][]byte{
			x509Cert.Raw,
		},
		PrivateKey: privateKey,
		Leaf:       x509Cert,
	}, nil
}

func main() {
	// ============================================================
	// CONFIGURATION
	// ============================================================
	_ = godotenv.Load()
	config, err := loadScoutConfig()
	if err != nil {
		log.Fatal("Scout security configuration is invalid:", err)
	}
	serverURL := config.commanderURL
	caFile := config.caFile
	agentName := config.agentName

	// Security:
	// No hard-coded or fallback Agent Secret is used.

	// ============================================================
	// TLS / CA
	// ============================================================

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatal("Could not read CA certificate:", err)
	}

	rootCAs := x509.NewCertPool()

	if !rootCAs.AppendCertsFromPEM(caPEM) {
		log.Fatal("Could not load CA certificate:", caFile)
	}

	// ============================================================
	// mTLS CLIENT CERTIFICATE
	// ============================================================

	clientCert, err := loadClientCertificate(
		config.clientCertFile,
		config.clientKeyFile,
		config.keyPassword,
	)

	if err != nil {
		log.Fatal("Could not load mTLS client certificate:", err)
	}

	log.Printf("🔐 mTLS client certificate is ready: %s", agentName)

	// ============================================================
	// TLS CONFIGURATION
	// ============================================================

	tlsConfig := &tls.Config{
		// TLS 1.3 only
		MinVersion: tls.VersionTLS13,

		// Trust the Sentinel Root CA.
		RootCAs: rootCAs,

		// Verify the SAN on the Commander certificate.
		ServerName: "commander.sentinel.test",

		// Never disable hostname verification.
		InsecureSkipVerify: false,

		// Scout-01 client certificate.
		// Present this certificate when Commander requests mTLS.
		// It is sent during the TLS handshake.
		Certificates: []tls.Certificate{
			clientCert,
		},
	}

	// ============================================================
	// WEBSOCKET URL
	// ============================================================

	u := strings.TrimRight(serverURL, "/") + "/ws"

	fmt.Printf(
		"Connecting to %s (Agent: %s)\n",
		u,
		agentName,
	)

	// ============================================================
	// RECONNECT LOOP
	// ============================================================

	for {
		// --------------------------------------------------------
		// SECURITY HEADERS
		// --------------------------------------------------------

		headers := http.Header{}

		// This must match the Origin check on Commander.
		headers.Set(
			"Origin",
			"https://commander.sentinel.test:8080",
		)

		// --------------------------------------------------------
		// WEBSOCKET DIALER
		// --------------------------------------------------------

		dialer := websocket.Dialer{
			TLSClientConfig: tlsConfig,

			// Do not wait forever if the connection cannot be established.
			HandshakeTimeout: 10 * time.Second,
		}

		c, _, err := dialer.Dial(u, headers)

		if err != nil {
			log.Println(
				"Connection failed; retrying in 5 seconds:",
				err,
			)

			time.Sleep(5 * time.Second)
			continue
		}

		fmt.Println("✅ Connected to Commander.")

		// --------------------------------------------------------
		// REGISTER
		// --------------------------------------------------------

		if err := configureScoutWebSocket(c, wsReadWait); err != nil {
			log.Println("Could not set WebSocket read deadline:", err)
			c.Close()
			time.Sleep(2 * time.Second)
			continue
		}

		err = writeScoutJSON(c, models.Command{
			Type:  "REGISTER",
			Agent: agentName,
		})

		if err != nil {
			log.Println("Could not send REGISTER:", err)
			c.Close()

			time.Sleep(2 * time.Second)
			continue
		}

		fmt.Println("🛰️ Scout sent registration:", agentName)

		// --------------------------------------------------------
		// COMMAND LOOP
		// --------------------------------------------------------

		func() {
			defer c.Close()

			for {
				var msg models.Command

				err := c.ReadJSON(&msg)

				if err != nil {
					log.Println(
						"Connection lost:",
						err,
					)

					return
				}

				if msg.Type != "PING_REQUEST" {
					log.Printf("Rejected unknown Commander message type: %q", msg.Type)
					return
				}

				// ------------------------------------------------
				// PING COMMAND
				// ------------------------------------------------

				if msg.Type == "PING_REQUEST" {
					if !authorizePing(msg, agentName, time.Now()) {
						log.Printf("Rejected invalid, expired, or duplicate task: %s", msg.TaskID)
						continue
					}

					fmt.Printf(
						"🎯 Task: %s\n",
						msg.Target,
					)

					// Security:
					// To reduce command injection risk,
					// validate the target against the allowlist.
					start := time.Now()

					var cmd *exec.Cmd

					if runtime.GOOS == "windows" {
						cmd = exec.Command(
							"ping",
							"-n",
							"1",
							"-w",
							"2000",
							msg.Target,
						)
					} else {
						cmd = exec.Command(
							"ping",
							"-c",
							"1",
							"-W",
							"2",
							msg.Target,
						)
					}

					err := cmd.Run()

					duration := time.Since(start)

					status := 200

					if err != nil {
						status = 500
					}

					// ------------------------------------------------
					// SYSTEM STATS
					// ------------------------------------------------

					cpuUse, ramUse, diskUse := getSystemStats()

					// ------------------------------------------------
					// REPORT
					// ------------------------------------------------

					resp := models.Command{
						Type:   "REPORT",
						TaskID: msg.TaskID,
						Target: msg.Target,
						Status: status,
						Time: fmt.Sprintf(
							"%dms",
							duration.Milliseconds(),
						),
						Agent: agentName,
						CPU:   cpuUse,
						RAM:   ramUse,
						Disk:  diskUse,
					}

					if err := writeScoutJSON(c, resp); err != nil {
						log.Println(
							"Could not send report:",
							err,
						)

						return
					}
				}
			}
		}()

		// --------------------------------------------------------
		// RECONNECT DELAY
		// --------------------------------------------------------

		time.Sleep(2 * time.Second)
	}
}
