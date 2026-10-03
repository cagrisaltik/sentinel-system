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

// GÜVENLİK: Command Injection Koruması
// Yalnızca domain/IP benzeri hedeflere izin verilir.
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
	if msg.Type != "PING_ISTEGI" || msg.Agent != agentName || !targetRegex.MatchString(msg.Target) || !safeTarget(msg.Target) {
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
			"client certificate okunamadı: %w",
			err,
		)
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"client private key okunamadı: %w",
			err,
		)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return tls.Certificate{}, fmt.Errorf(
			"private key PEM olarak parse edilemedi",
		)
	}

	var privateKey any

	switch keyBlock.Type {

	case "ENCRYPTED PRIVATE KEY":
		if password == "" {
			return tls.Certificate{}, fmt.Errorf(
				"TLS client key şifreli ancak TLS_CLIENT_KEY_PASSWORD ayarlanmamış",
			)
		}

		privateKey, err =
			pkcs8.ParsePKCS8PrivateKey(
				keyBlock.Bytes,
				[]byte(password),
			)

		if err != nil {
			return tls.Certificate{}, fmt.Errorf(
				"şifreli client private key çözülemedi: %w",
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
				"PKCS#8 private key parse edilemedi: %w",
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
				"EC private key parse edilemedi: %w",
				err,
			)
		}

	default:
		return tls.Certificate{}, fmt.Errorf(
			"desteklenmeyen private key tipi: %s",
			keyBlock.Type,
		)
	}

	// Scout sertifikasının public key'i ile
	// private key'in gerçekten eşleştiğini kontrol et.
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return tls.Certificate{}, fmt.Errorf(
			"client certificate PEM olarak parse edilemedi",
		)
	}

	x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"client certificate parse edilemedi: %w",
			err,
		)
	}

	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf(
			"client private key beklenen ECDSA anahtar değil",
		)
	}

	certPublicKey, ok := x509Cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf(
			"client certificate beklenen ECDSA anahtar değil",
		)
	}

	if certPublicKey.X.Cmp(ecKey.PublicKey.X) != 0 ||
		certPublicKey.Y.Cmp(ecKey.PublicKey.Y) != 0 {
		return tls.Certificate{}, fmt.Errorf(
			"client certificate ile private key eşleşmiyor",
		)
	}

	// tls.X509KeyPair encrypted key kabul etmez.
	// Bunun yerine Certificate ve PrivateKey'i doğrudan oluşturuyoruz.
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

	// Güvenlik:
	// Artık hardcoded/fallback Agent Secret kullanılmıyor.

	// ============================================================
	// TLS / CA
	// ============================================================

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatal("CA sertifikası okunamadı:", err)
	}

	rootCAs := x509.NewCertPool()

	if !rootCAs.AppendCertsFromPEM(caPEM) {
		log.Fatal("CA sertifikası yüklenemedi:", caFile)
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
		log.Fatal("mTLS client sertifikası yüklenemedi:", err)
	}

	log.Printf("🔐 mTLS client sertifikası hazır: %s", agentName)

	// ============================================================
	// TLS CONFIGURATION
	// ============================================================

	tlsConfig := &tls.Config{
		// Yalnızca TLS 1.3
		MinVersion: tls.VersionTLS13,

		// Sentinel Root CA'ya güven.
		RootCAs: rootCAs,

		// Commander sertifikasının SAN değerini doğrula.
		ServerName: "commander.sentinel.test",

		// Hostname doğrulamasını kesinlikle kapatma.
		InsecureSkipVerify: false,

		// Scout-01 client certificate.
		// Commander mTLS istediğinde bu sertifika
		// TLS handshake sırasında sunulacak.
		Certificates: []tls.Certificate{
			clientCert,
		},
	}

	// ============================================================
	// WEBSOCKET URL
	// ============================================================

	u := strings.TrimRight(serverURL, "/") + "/ws"

	fmt.Printf(
		"🔌 Bağlanıyor: %s (Agent: %s)\n",
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

		// Commander tarafındaki Origin kontrolüyle eşleşmeli.
		headers.Set(
			"Origin",
			"https://commander.sentinel.test:8080",
		)

		// --------------------------------------------------------
		// WEBSOCKET DIALER
		// --------------------------------------------------------

		dialer := websocket.Dialer{
			TLSClientConfig: tlsConfig,

			// Bağlantı kurulamazsa sonsuza kadar bekleme.
			HandshakeTimeout: 10 * time.Second,
		}

		c, _, err := dialer.Dial(u, headers)

		if err != nil {
			log.Println(
				"Bağlantı hatası, 5sn sonra tekrar denenecek:",
				err,
			)

			time.Sleep(5 * time.Second)
			continue
		}

		fmt.Println("✅ Commander bağlantısı kuruldu.")

		// --------------------------------------------------------
		// REGISTER
		// --------------------------------------------------------

		if err := configureScoutWebSocket(c, wsReadWait); err != nil {
			log.Println("WebSocket read deadline ayarlanamadı:", err)
			c.Close()
			time.Sleep(2 * time.Second)
			continue
		}

		err = writeScoutJSON(c, models.Command{
			Type:  "REGISTER",
			Agent: agentName,
		})

		if err != nil {
			log.Println("REGISTER gönderilemedi:", err)
			c.Close()

			time.Sleep(2 * time.Second)
			continue
		}

		fmt.Println("🛰️ Scout kayıt gönderdi:", agentName)

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
						"Bağlantı koptu:",
						err,
					)

					return
				}

				if msg.Type != "PING_ISTEGI" {
					log.Printf("Bilinmeyen Commander mesaj tipi reddedildi: %q", msg.Type)
					return
				}

				// ------------------------------------------------
				// PING COMMAND
				// ------------------------------------------------

				if msg.Type == "PING_ISTEGI" {
					if !authorizePing(msg, agentName, time.Now()) {
						log.Printf("Geçersiz, süresi dolmuş veya yinelenen görev reddedildi: %s", msg.TaskID)
						continue
					}

					fmt.Printf(
						"🎯 Görev: %s\n",
						msg.Target,
					)

					// Güvenlik:
					// Command injection riskini azaltmak için
					// hedef whitelist kontrolü.
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
						Type:   "RAPOR",
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
							"Rapor gönderilemedi:",
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
