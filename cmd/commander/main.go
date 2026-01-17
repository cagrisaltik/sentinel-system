package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cagrisaltik/Sentinel/internal/models"
	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"
)

var db *sql.DB

// API Response Yapısı
type LogEntry struct {
	ID        int    `json:"id"`
	Target    string `json:"target"`
	Status    int    `json:"status"`
	Latency   string `json:"latency"`
	Agent     string `json:"agent"` // YENİ ALAN
	CreatedAt string `json:"created_at"`
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "sentinel.db")
	if err != nil {
		log.Fatal(err)
	}

	// Tabloya 'agent' sütunu eklendi
	query := `CREATE TABLE IF NOT EXISTS logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT,
		status INTEGER,
		latency TEXT,
		agent TEXT, 
		created_at DATETIME
	);`
	if _, err := db.Exec(query); err != nil {
		log.Fatal("Tablo hatası:", err)
	}
	fmt.Println("💾 Veritabanı hazır (Agent destekli).")
}

func getHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Agent bilgisini de çekiyoruz
	rows, err := db.Query("SELECT id, target, status, latency, agent, created_at FROM logs ORDER BY id DESC LIMIT 50")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var history []LogEntry
	for rows.Next() {
		var e LogEntry
		rows.Scan(&e.ID, &e.Target, &e.Status, &e.Latency, &e.Agent, &e.CreatedAt)
		history = append(history, e)
	}
	// Boşsa null yerine boş array dön
	if history == nil {
		history = []LogEntry{}
	}
	json.NewEncoder(w).Encode(history)
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ws.Close()

	// Görev Döngüsü
	go func() {
		for {
			time.Sleep(10 * time.Second)
			ws.WriteJSON(models.Command{Type: "PING_ISTEGI", Target: "https://www.google.com"})
		}
	}()

	// Dinleme Döngüsü
	for {
		var rapor models.Command
		if err := ws.ReadJSON(&rapor); err != nil {
			break
		}

		if rapor.Type == "RAPOR" {
			fmt.Printf("📊 [%s] RAPOR -> %s | %s\n", rapor.Agent, rapor.Target, rapor.Time)

			// Agent ismini de kaydediyoruz
			_, err := db.Exec("INSERT INTO logs (target, status, latency, agent, created_at) VALUES (?, ?, ?, ?, ?)",
				rapor.Target, rapor.Status, rapor.Time, rapor.Agent, time.Now())

			if err != nil {
				fmt.Println("❌ DB Hatası:", err)
			}
		}
	}
}

func main() {
	initDB()
	http.HandleFunc("/ws", handleConnections)
	http.HandleFunc("/api/history", getHistory)
	http.Handle("/", http.FileServer(http.Dir("./web")))

	fmt.Println("🚀 Commander v2.0 Aktif (Port 8080)...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
