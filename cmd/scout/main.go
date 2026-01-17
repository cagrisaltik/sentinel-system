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

	// Donanım kütüphaneleri
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
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

	c.WriteJSON(models.Command{Type: "REGISTER", Agent: agentName})
	fmt.Println("✅ Kayıt başarılı. Görev bekleniyor...")

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

			if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
				status, duration, errCheck = checkHTTP(target)
			} else if strings.Contains(target, ":") {
				status, duration, errCheck = checkPort(target)
			} else {
				status, duration, errCheck = checkPing(target)
			}

			if errCheck != nil {
				fmt.Println("❌ Hata:", errCheck)
				if status == 0 {
					status = 500
				}
			}

			// --- YENİ: SİSTEM BİLGİLERİNİ TOPLA ---
			cpuUsage, _ := cpu.Percent(0, false)
			vMem, _ := mem.VirtualMemory()
			dStat, _ := disk.Usage("/")

			currentCPU := 0.0
			if len(cpuUsage) > 0 {
				currentCPU = cpuUsage[0]
			}
			// ---------------------------------------

			c.WriteJSON(models.Command{
				Type: "RAPOR", Target: target, Status: status,
				Time: fmt.Sprintf("%dms", duration.Milliseconds()), Agent: agentName,

				// Donanım verilerini pakete ekle
				CPU:  currentCPU,
				RAM:  vMem.UsedPercent,
				Disk: dStat.UsedPercent,
			})
		}
	}
}

// --- YARDIMCI FONKSİYONLAR (Aynı kalıyor) ---
func checkHTTP(target string) (int, time.Duration, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
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

func checkPort(target string) (int, time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	duration := time.Since(start)
	if err != nil {
		return 500, duration, err
	}
	defer conn.Close()
	return 200, duration, nil
}

func checkPing(target string) (int, time.Duration, error) {
	start := time.Now()
	cmd := exec.Command("ping", "-c", "1", "-W", "1", target)
	err := cmd.Run()
	duration := time.Since(start)
	if err != nil {
		return 500, duration, err
	}
	return 200, duration, nil
}
