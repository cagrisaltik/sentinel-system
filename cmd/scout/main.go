package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cagrisaltik/Sentinel/internal/models"
	"github.com/gorilla/websocket"
)

func main() {
	// Ajan ismini al
	agentName := os.Getenv("AGENT_NAME")
	if agentName == "" {
		agentName = "Bilinmeyen-Asker"
	}

	// Sunucu adresini dinamik al
	serverHost := os.Getenv("SERVER_HOST")
	if serverHost == "" {
		serverHost = "localhost:8080"
	}
	serverURL := fmt.Sprintf("ws://%s/ws", serverHost)

	fmt.Printf("🛡️ Scout [%s] sunucuya bağlanıyor: %s ...\n", agentName, serverURL)

	// Yeniden bağlanma döngüsü (Reconnection logic)
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

	fmt.Println("✅ Bağlantı başarılı! Emir bekleniyor.")

	for {
		var cmd models.Command
		err := c.ReadJSON(&cmd)
		if err != nil {
			return
		}

		if cmd.Type == "PING_ISTEGI" {
			fmt.Printf("⚡ Görev: %s -> %s\n", agentName, cmd.Target)

			start := time.Now()
			resp, err := http.Get(cmd.Target)
			duration := time.Since(start)

			status := 0
			if err != nil {
				fmt.Println("❌ Hata:", err)
				status = 500
			} else {
				status = resp.StatusCode
				resp.Body.Close()
			}

			// Raporu hazırla (İmzalı)
			rapor := models.Command{
				Type:   "RAPOR",
				Target: cmd.Target,
				Status: status,
				Time:   fmt.Sprintf("%dms", duration.Milliseconds()),
				Agent:  agentName, // İMZA BURADA
			}

			c.WriteJSON(rapor)
			fmt.Printf("📤 Rapor yollandı: %d | %s\n", status, duration)
		}
	}
}
