package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cagrisaltik/sentinel-system/internal/models"
	"github.com/gorilla/websocket"
)

func main() {
	agentName := os.Getenv("AGENT_NAME")
	if agentName == "" {
		agentName = "Bilinmeyen-Asker"
	}
	serverHost := os.Getenv("SERVER_HOST")
	if serverHost == "" {
		serverHost = "localhost:8080"
	}
	serverURL := fmt.Sprintf("ws://%s/ws", serverHost)

	fmt.Printf("🛡️ Scout [%s] başlatılıyor -> %s\n", agentName, serverURL)

	for {
		connectAndListen(serverURL, agentName)
		fmt.Println("⚠️ Bağlantı koptu, 5 saniye içinde tekrar deneniyor...")
		time.Sleep(5 * time.Second)
	}
}

func connectAndListen(url, agentName string) {
	c, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		log.Println("❌ Sunucuya bağlanılamadı:", err)
		return
	}
	defer c.Close()

	// 1. KAYIT OL
	c.WriteJSON(models.Command{Type: "REGISTER", Agent: agentName})
	fmt.Println("✅ Kayıt başarılı. Görev bekleniyor...")

	// 2. EMİR DİNLE
	for {
		var cmd models.Command
		err := c.ReadJSON(&cmd)
		if err != nil {
			return
		}

		if cmd.Type == "PING_ISTEGI" {
			target := strings.TrimSpace(cmd.Target)
			fmt.Printf("⚡ Görev: %s\n", target)

			var status int
			var duration time.Duration
			var errCheck error

			// --- ZEKİ MOD SEÇİCİ ---
			if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
				// MOD 1: HTTP İSTEĞİ
				status, duration, errCheck = checkHTTP(target)
			} else if strings.Contains(target, ":") {
				// MOD 2: PORT KONTROLÜ (Telnet benzeri)
				// Örn: 1.1.1.1:53 veya google.com:443
				status, duration, errCheck = checkPort(target)
			} else {
				// MOD 3: PING (ICMP)
				// Örn: 1.1.1.1 veya google.com
				status, duration, errCheck = checkPing(target)
			}

			// Hata varsa konsola bas
			if errCheck != nil {
				fmt.Println("❌ Hata:", errCheck)
				// Ping başarısızsa status 0 veya 500 dönebiliriz
				if status == 0 {
					status = 500
				}
			}

			// Raporu gönder
			c.WriteJSON(models.Command{
				Type: "RAPOR", Target: target, Status: status,
				Time: fmt.Sprintf("%dms", duration.Milliseconds()), Agent: agentName,
			})
		}
	}
}

// --- YARDIMCI FONKSİYONLAR ---

// 1. HTTP KONTROLÜ (SSL Hatasını Yoksayar)
func checkHTTP(target string) (int, time.Duration, error) {
	// SSL Sertifika hatalarını (x509) yoksaymak için özel Transport
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	start := time.Now()
	resp, err := client.Get(target)
	duration := time.Since(start)

	if err != nil {
		return 0, duration, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, duration, nil
}

// 2. PORT KONTROLÜ (TCP Connect)
func checkPort(target string) (int, time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	duration := time.Since(start)

	if err != nil {
		return 500, duration, err // Bağlanamadı
	}
	defer conn.Close()
	return 200, duration, nil // Bağlandı (200 OK mantığı)
}

// 3. PING KONTROLÜ (OS Ping Komutu)
func checkPing(target string) (int, time.Duration, error) {
	start := time.Now()
	// Linux/Alpine ping komutu: -c 1 (1 paket), -W 1 (1 saniye bekle)
	cmd := exec.Command("ping", "-c", "1", "-W", "1", target)

	err := cmd.Run()
	duration := time.Since(start)

	if err != nil {
		return 500, duration, err // Ping gitmedi
	}
	return 200, duration, nil // Ping gitti
}
