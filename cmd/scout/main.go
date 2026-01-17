package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cagrisaltik/Sentinel/internal/models" // Import yoluna dikkat!
	"github.com/gorilla/websocket"
)

func main() {
	agentName := os.Getenv("AGENT_NAME")
	if agentName == "" {
		agentName = "Bilinmeyen-Asker"
	}

	serverURL := "ws://localhost:8080/ws"
	fmt.Printf("🛡️ Scout [%s] sunucuya bağlanıyor...\n", agentName)

	c, _, err := websocket.DefaultDialer.Dial(serverURL, nil)
	if err != nil {
		log.Fatal("Bağlantı hatası:", err)
	}
	defer c.Close()

	// --- DİNLEME DÖNGÜSÜ ---
	for {
		// 1. Komutandan emir bekle
		var cmd models.Command
		err := c.ReadJSON(&cmd) // Gelen JSON'ı oku
		if err != nil {
			log.Println("Bağlantı koptu:", err)
			return
		}

		// 2. Eğer emir "PING_ISTEGI" ise göreve çık
		if cmd.Type == "PING_ISTEGI" {
			fmt.Printf("⚡ Görev Alındı: %s hedefine gidiliyor...\n", cmd.Target)

			// Ölçüme başla
			start := time.Now()
			resp, err := http.Get(cmd.Target)
			duration := time.Since(start)

			status := 0
			if err != nil {
				fmt.Println("❌ Hedefe ulaşılamadı:", err)
				status = 500
			} else {
				status = resp.StatusCode
				resp.Body.Close()
			}

			// 3. Raporu hazırla ve geri gönder
			rapor := models.Command{
				Type:   "RAPOR",
				Target: cmd.Target,
				Status: status,
				Time:   fmt.Sprintf("%dms", duration.Milliseconds()),
			}

			c.WriteJSON(rapor)
			fmt.Printf("✅ Rapor Gönderildi: %d | %s\n", status, duration)
		}
	}
}
