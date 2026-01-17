package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/cagrisaltik/sentinel-system/internal/models"
	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"
)

var db *sql.DB

// --- BAĞLI AJANLARI YÖNETMEK İÇİN ---
var (
	clients   = make(map[string]*websocket.Conn) // AjanIsmi -> Websocket
	clientsMu sync.Mutex                         // Haritayı korumak için kilit
)

// --- VERİ MODELLERİ ---
type LogEntry struct {
	ID        int    `json:"id"`
	Target    string `json:"target"`
	Status    int    `json:"status"`
	Latency   string `json:"latency"`
	Agent     string `json:"agent"`
	CreatedAt string `json:"created_at"`
}

type TargetTask struct {
	ID        int    `json:"id"`
	AgentName string `json:"agent_name"`
	TargetURL string `json:"target_url"`
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "sentinel.db")
	if err != nil {
		log.Fatal(err)
	}

	// Log tablosu
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT, status INTEGER, latency TEXT, agent TEXT, created_at DATETIME
	);`)

	// YENİ: Hedefler Tablosu (Görev Listesi)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		agent_name TEXT,
		target_url TEXT
	);`)

	if err != nil {
		log.Fatal("Tablo hatası:", err)
	}
	fmt.Println("💾 Veritabanı ve Görev Sistemi hazır.")
}

// --- GÖREV DAĞITICI (SCHEDULER) ---
func startTaskScheduler() {
	ticker := time.NewTicker(5 * time.Second) // 5 saniyede bir görevleri dağıt
	go func() {
		for range ticker.C {
			// 1. Veritabanından tüm görevleri çek
			rows, err := db.Query("SELECT agent_name, target_url FROM targets")
			if err != nil {
				fmt.Println("Görev okuma hatası:", err)
				continue
			}

			// 2. Her görevi ilgili ajana yolla
			for rows.Next() {
				var agentName, targetUrl string
				rows.Scan(&agentName, &targetUrl)

				clientsMu.Lock()
				conn, exists := clients[agentName]
				clientsMu.Unlock()

				if exists {
					// Ajan bağlıysa emri gönder
					cmd := models.Command{
						Type:   "PING_ISTEGI",
						Target: targetUrl,
					}
					if err := conn.WriteJSON(cmd); err != nil {
						fmt.Printf("⚠️ %s ajanına emir gidemedi.\n", agentName)
						// Bağlantı kopmuş olabilir, listeden silmek handleConnections'ın işi
					}
				}
			}
			rows.Close()
		}
	}()
}

// --- API: YENİ GÖREV EKLEME / SİLME ---
func handleTargets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		rows, _ := db.Query("SELECT id, agent_name, target_url FROM targets")
		defer rows.Close()
		var tasks []TargetTask
		for rows.Next() {
			var t TargetTask
			rows.Scan(&t.ID, &t.AgentName, &t.TargetURL)
			tasks = append(tasks, t)
		}
		if tasks == nil {
			tasks = []TargetTask{}
		}
		json.NewEncoder(w).Encode(tasks)

	} else if r.Method == "POST" {
		var t TargetTask
		json.NewDecoder(r.Body).Decode(&t)
		db.Exec("INSERT INTO targets (agent_name, target_url) VALUES (?, ?)", t.AgentName, t.TargetURL)
		w.WriteHeader(http.StatusCreated)

	} else if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		db.Exec("DELETE FROM targets WHERE id = ?", id)
		w.WriteHeader(http.StatusOK)
	}
}

func getHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rows, _ := db.Query("SELECT id, target, status, latency, agent, created_at FROM logs ORDER BY id DESC LIMIT 50")
	defer rows.Close()
	var history []LogEntry
	for rows.Next() {
		var e LogEntry
		rows.Scan(&e.ID, &e.Target, &e.Status, &e.Latency, &e.Agent, &e.CreatedAt)
		history = append(history, e)
	}
	if history == nil {
		history = []LogEntry{}
	}
	json.NewEncoder(w).Encode(history)
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	var currentAgentName string

	for {
		var msg models.Command
		err := ws.ReadJSON(&msg)
		if err != nil {
			// Bağlantı koptuysa listeden sil
			if currentAgentName != "" {
				clientsMu.Lock()
				delete(clients, currentAgentName)
				clientsMu.Unlock()
				fmt.Printf("🔴 %s bağlantısı koptu.\n", currentAgentName)
			}
			break
		}

		// --- 1. KAYIT İŞLEMİ ---
		if msg.Type == "REGISTER" {
			currentAgentName = msg.Agent
			clientsMu.Lock()
			clients[currentAgentName] = ws
			clientsMu.Unlock()
			fmt.Printf("🔵 Ajan Kaydedildi: %s\n", currentAgentName)
		}

		// --- 2. RAPOR İŞLEMİ ---
		if msg.Type == "RAPOR" {
			_, err := db.Exec("INSERT INTO logs (target, status, latency, agent, created_at) VALUES (?, ?, ?, ?, ?)",
				msg.Target, msg.Status, msg.Time, msg.Agent, time.Now().UTC())
			if err != nil {
				fmt.Println("DB Error:", err)
			}
		}
	}
}

func main() {
	initDB()
	startTaskScheduler() // Görev dağıtıcıyı başlat

	http.HandleFunc("/ws", handleConnections)
	http.HandleFunc("/api/history", getHistory)
	http.HandleFunc("/api/targets", handleTargets) // Yeni Endpoint
	http.Handle("/", http.FileServer(http.Dir("./web")))

	fmt.Println("🚀 Commander v3.0 (Dynamic Targets) Aktif...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
