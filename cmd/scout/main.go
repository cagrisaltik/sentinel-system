package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings" // YENİ: Metin işleme kütüphanesi
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
	fmt.Println("✅ Kayıt başarılı. Emir bekleniyor...")

	// 2. EMİR DİNLE
	for {
		var cmd models.Command
		err := c.ReadJSON(&cmd)
		if err != nil {
			return
		}

		if cmd.Type == "PING_ISTEGI" {
			// --- YENİ EKLENEN KISIM: IP/URL DÜZELTME ---
			target := cmd.Target
			// Eğer başında http:// veya https:// yoksa, varsayılan olarak http:// ekle
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				target = "http://" + target
			}
			// ---------------------------------------------

			fmt.Printf("⚡ Görev: %s\n", target)

			start := time.Now()
			// Artık düzeltilmiş 'target' değişkenini kullanıyoruz
			resp, err := http.Get(target)

			duration := time.Since(start)
			status := 0
			if err != nil {
				fmt.Println("❌ Hata:", err) // Hatayı konsola bas ama durma
				status = 500
			} else {
				status = resp.StatusCode
				resp.Body.Close()
			}

			// Raporu gönder (Orijinal hedef adını koruyarak veya düzelterek gönderebilirsin)
			c.WriteJSON(models.Command{
				Type: "RAPOR", Target: target, Status: status, // Raporlarken 'target' (http eklenmiş halini) yolluyoruz
				Time: fmt.Sprintf("%dms", duration.Milliseconds()), Agent: agentName,
			})
		}
	}
}
