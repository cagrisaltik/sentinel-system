package main

import (
	"fmt"
	"log"
	"net/http" // Header eklemek için gerekli
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

// GÜVENLİK: Sadece geçerli Domain/IP (Command Injection Koruması)
var targetRegex = regexp.MustCompile(`^[a-zA-Z0-9.:_-]+$`)

type Command struct {
	Type   string  `json:"type"`
	Target string  `json:"target"`
	Status int     `json:"status"`
	Time   string  `json:"time"` // Latency yerine Time (Commander ile uyumlu)
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

	if serverHost == "" {
		serverHost = "localhost:8080"
	}
	if agentName == "" {
		agentName = "Unknown-Agent"
	}

	u := fmt.Sprintf("ws://%s/ws", serverHost)
	fmt.Printf("🔌 Bağlanıyor: %s (Agent: %s)\n", u, agentName)

	for {
		// --- GÜVENLİK DÜZELTMESİ BURADA ---
		// Commander artık Origin kontrolü yapıyor.
		// Biz de sahte bir "Origin" başlığı ekleyerek güvenlik kontrolünü geçiyoruz.
		headers := http.Header{}
		headers.Add("Origin", "http://localhost")

		dialer := websocket.Dialer{}
		c, _, err := dialer.Dial(u, headers)
		// ---------------------------------

		if err != nil {
			log.Println("Bağlantı hatası, 5sn sonra tekrar denenecek:", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Kayıt Ol
		c.WriteJSON(Command{Type: "REGISTER", Agent: agentName})

		// Komut Dinle
		// Hata olduğunda fonksiyon dışına çıkıp yeniden bağlanması için label kullanımı
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
						fmt.Println("⚠️ BLOKLANDI: Geçersiz Hedef Formatı ->", msg.Target)
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

					// Sonucu Raporla (Time alanını kullanıyoruz)
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

		time.Sleep(2 * time.Second) // Döngü çok hızlı dönmesin diye bekleme
	}
}
