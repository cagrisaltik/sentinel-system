package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
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

	fmt.Printf("🛡️ Scout [%s] başlatılıyor...\n", agentName)

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

	// --- 1. ADIM: KİMLİK BEYANI (REGISTER) ---
	// Bağlanır bağlanmaz "Ben geldim" de
	regMsg := models.Command{
		Type:  "REGISTER",
		Agent: agentName,
	}
	if err := c.WriteJSON(regMsg); err != nil {
		log.Println("Kayıt mesajı atılamadı:", err)
		return
	}
	fmt.Println("✅ Sunucuya kayıt olundu. Emir bekleniyor...")

	// --- 2. ADIM: EMİR DİNLEME ---
	for {
		var cmd models.Command
		err := c.ReadJSON(&cmd)
		if err != nil {
			return
		}

		if cmd.Type == "PING_ISTEGI" {
			fmt.Printf("⚡ Görev Geldi: %s -> %s\n", agentName, cmd.Target)

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

			// Cevabı gönder
			rapor := models.Command{
				Type:   "RAPOR",
				Target: cmd.Target,
				Status: status,
				Time:   fmt.Sprintf("%dms", duration.Milliseconds()),
				Agent:  agentName,
			}
			c.WriteJSON(rapor)
		}
	}
}
