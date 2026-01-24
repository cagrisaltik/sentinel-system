package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"time"

	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

// GÜVENLİK: Command Injection Koruması (Sadece geçerli Domain/IP)
var targetRegex = regexp.MustCompile(`^[a-zA-Z0-9.:_-]+$`)

type Command struct {
	Type   string  `json:"type"`
	Target string  `json:"target"`
	Status int     `json:"status"`
	Time   string  `json:"time"`
	Agent  string  `json:"agent"`
	CPU    float64 `json:"cpu"`
	RAM    float64 `json:"ram"`
	Disk   float64 `json:"disk"`
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

func main() {
	serverHost := os.Getenv("SERVER_HOST")
	agentName := os.Getenv("AGENT_NAME")
	agentSecret := os.Getenv("AGENT_SECRET") // Şifreyi Env'den al

	if serverHost == "" {
		serverHost = "localhost:8080"
	}
	if agentName == "" {
		agentName = "Unknown-Agent"
	}
	// Şifre yoksa varsayılanı kullan (Test için)
	if agentSecret == "" {
		agentSecret = "gizli-ajan-sifresi-123"
	}

	u := fmt.Sprintf("ws://%s/ws", serverHost)
	fmt.Printf("🔌 Bağlanıyor: %s (Agent: %s)\n", u, agentName)

	for {
		// --- GÜVENLİK HEADERLARI ---
		headers := http.Header{}
		// 1. Origin Kontrolü İçin
		headers.Add("Origin", "http://localhost")
		// 2. Kimlik Doğrulama (Secret Token) İçin
		headers.Add("X-Agent-Secret", agentSecret)
		// ---------------------------

		dialer := websocket.Dialer{}
		c, _, err := dialer.Dial(u, headers)

		if err != nil {
			log.Println("Bağlantı hatası (401 Yetkisiz olabilir), 5sn sonra tekrar denenecek:", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Kayıt Ol
		c.WriteJSON(Command{Type: "REGISTER", Agent: agentName})

		// Komut Dinle
		func() {
			defer c.Close()
			for {
				var msg Command
				err := c.ReadJSON(&msg)
				if err != nil {
					log.Println("Bağlantı koptu:", err)
					return
				}

				if msg.Type == "PING_ISTEGI" {
					fmt.Printf("🎯 Görev: %s\n", msg.Target)

					// Güvenlik: Hedef Kontrolü
					if !targetRegex.MatchString(msg.Target) {
						fmt.Println("⚠️ BLOKLANDI: Geçersiz Hedef ->", msg.Target)
						continue
					}

					start := time.Now()
					var cmd *exec.Cmd

					if runtime.GOOS == "windows" {
						cmd = exec.Command("ping", "-n", "1", "-w", "2000", msg.Target)
					} else {
						cmd = exec.Command("ping", "-c", "1", "-W", "2", msg.Target)
					}

					err := cmd.Run()
					duration := time.Since(start)

					status := 200
					if err != nil {
						status = 500
					}

					cpuUse, ramUse, diskUse := getSystemStats()

					resp := Command{
						Type:   "RAPOR",
						Target: msg.Target,
						Status: status,
						Time:   fmt.Sprintf("%dms", duration.Milliseconds()),
						Agent:  agentName,
						CPU:    cpuUse,
						RAM:    ramUse,
						Disk:   diskUse,
					}
					c.WriteJSON(resp)
				}
			}
		}()
		time.Sleep(2 * time.Second)
	}
}
