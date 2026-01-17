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
var (
	clients   = make(map[string]*websocket.Conn)
	clientsMu sync.Mutex
)

// Modeller
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

	db.Exec(`CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, status INTEGER, latency TEXT, agent TEXT, created_at DATETIME);`)
	db.Exec(`CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_name TEXT, target_url TEXT);`)
	fmt.Println("💾 Veritabanı ve Görev Sistemi hazır.")
}

func startTaskScheduler() {
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			rows, err := db.Query("SELECT agent_name, target_url FROM targets")
			if err != nil {
				continue
			}

			for rows.Next() {
				var agentName, targetUrl string
				rows.Scan(&agentName, &targetUrl)

				clientsMu.Lock()
				conn, exists := clients[agentName]
				clientsMu.Unlock()

				if exists {
					conn.WriteJSON(models.Command{Type: "PING_ISTEGI", Target: targetUrl})
				}
			}
			rows.Close()
		}
	}()
}

// --- YENİ EKLENEN FONKSİYON: AKTİF AJANLARI LİSTELE ---
func handleActiveAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	clientsMu.Lock()
	defer clientsMu.Unlock()

	var activeList []string
	for name := range clients {
		activeList = append(activeList, name)
	}

	// Eğer hiç ajan yoksa boş liste dön
	if activeList == nil {
		activeList = []string{}
	}

	json.NewEncoder(w).Encode(activeList)
}

// -------------------------------------------------------

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
			if currentAgentName != "" {
				clientsMu.Lock()
				delete(clients, currentAgentName)
				clientsMu.Unlock()
			}
			break
		}
		if msg.Type == "REGISTER" {
			currentAgentName = msg.Agent
			clientsMu.Lock()
			clients[currentAgentName] = ws
			clientsMu.Unlock()
			fmt.Printf("🔵 Ajan Kayıt: %s\n", currentAgentName)
		}
		if msg.Type == "RAPOR" {
			db.Exec("INSERT INTO logs (target, status, latency, agent, created_at) VALUES (?, ?, ?, ?, ?)",
				msg.Target, msg.Status, msg.Time, msg.Agent, time.Now().UTC())
		}
	}
}

func main() {
	initDB()
	startTaskScheduler()

	http.HandleFunc("/ws", handleConnections)
	http.HandleFunc("/api/history", getHistory)
	http.HandleFunc("/api/targets", handleTargets)
	http.HandleFunc("/api/agents", handleActiveAgents) // YENİ ROTA

	http.Handle("/", http.FileServer(http.Dir("./web")))
	fmt.Println("🚀 Commander v3.1 (Agent List) Aktif...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
