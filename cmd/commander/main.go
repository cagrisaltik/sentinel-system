package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cagrisaltik/Sentinel/internal/models"
	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite" // SQLite sürücüsü
)

var db *sql.DB

// Veritabanı kurulumu
func initDB() {
	var err error
	// 'sentinel.db' adında bir dosya oluşturur
	db, err = sql.Open("sqlite", "sentinel.db")
	if err != nil {
		log.Fatal(err)
	}

	// Tabloyu oluştur (Eğer yoksa)
	query := `
	CREATE TABLE IF NOT EXISTS logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT,
		status INTEGER,
		latency TEXT,
		created_at DATETIME
	);`
	_, err = db.Exec(query)
	if err != nil {
		log.Fatal("Tablo oluşturulamadı:", err)
	}
	fmt.Println("💾 Veritabanı bağlantısı hazır.")
}

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

	// --- GÖREV VERME (Arka Planda) ---
	go func() {
		for {
			time.Sleep(10 * time.Second) // 10 saniyede bir
			gorev := models.Command{
				Type:   "PING_ISTEGI",
				Target: "https://www.google.com",
			}
			if err := ws.WriteJSON(gorev); err != nil {
				break
			}
		}
	}()

	// --- RAPOR DİNLEME VE KAYDETME ---
	for {
		var rapor models.Command
		err := ws.ReadJSON(&rapor)
		if err != nil {
			fmt.Println("🔴 Ajan koptu.")
			break
		}

		if rapor.Type == "RAPOR" {
			// 1. Ekrana Yaz
			fmt.Printf("📊 RAPOR -> %s | %s\n", rapor.Target, rapor.Time)

			// 2. Veritabanına Kaydet
			_, err := db.Exec("INSERT INTO logs (target, status, latency, created_at) VALUES (?, ?, ?, ?)",
				rapor.Target, rapor.Status, rapor.Time, time.Now())

			if err != nil {
				fmt.Println("❌ Kayıt hatası:", err)
			} else {
				fmt.Println("💾 Veri kaydedildi.")
			}
		}
	}
}

func main() {
	initDB() // Veritabanını başlat

	fmt.Println("🚀 Commander 8080 portunda...")
	http.HandleFunc("/ws", handleConnections)

	// Sunucuyu başlat
	log.Fatal(http.ListenAndServe(":8080", nil))
}
