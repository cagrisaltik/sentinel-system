package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cagrisaltik/Sentinel/internal/models"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ws.Close()

	fmt.Println("🔵 Ajan bağlandı! Görev emri veriliyor...")

	// --- GÖREV DÖNGÜSÜ (Arka Planda) ---
	go func() {
		for {
			time.Sleep(5 * time.Second) // 5 saniyede bir emir ver

			gorev := models.Command{
				Type:   "PING_ISTEGI",
				Target: "https://www.google.com",
			}

			fmt.Println("📤 Emir gönderildi: Google kontrolü")
			if err := ws.WriteJSON(gorev); err != nil {
				break
			}
		}
	}()

	// --- RAPOR DİNLEME DÖNGÜSÜ ---
	for {
		var rapor models.Command
		err := ws.ReadJSON(&rapor)
		if err != nil {
			fmt.Println("🔴 Ajan koptu.")
			break
		}

		if rapor.Type == "RAPOR" {
			fmt.Printf("📊 RAPOR GELDİ -> Hedef: %s | Durum: %d | Hız: %s\n",
				rapor.Target, rapor.Status, rapor.Time)
		}
	}
}

func main() {
	fmt.Println("🚀 Commander 8080 portunda...")
	http.HandleFunc("/ws", handleConnections)
	http.ListenAndServe(":8080", nil)
}
