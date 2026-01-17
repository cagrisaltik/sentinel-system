package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv" // YENİ: String çevirmek için
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
	ID        int     `json:"id"`
	Target    string  `json:"target"`
	Status    int     `json:"status"`
	Latency   string  `json:"latency"`
	Agent     string  `json:"agent"`
	CreatedAt string  `json:"created_at"`
	CPU       float64 `json:"cpu"`
	RAM       float64 `json:"ram"`
	Disk      float64 `json:"disk"`
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

	query := `CREATE TABLE IF NOT EXISTS logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT, status INTEGER, latency TEXT, agent TEXT, created_at DATETIME,
		cpu REAL, ram REAL, disk REAL
	);`
	db.Exec(query)
	db.Exec(`CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_name TEXT, target_url TEXT);`)
	fmt.Println("💾 Veritabanı (Analytics Ready) hazır.")
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

func handleActiveAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	clientsMu.Lock()
	defer clientsMu.Unlock()
	var activeList []string
	for name := range clients {
		activeList = append(activeList, name)
	}
	if activeList == nil {
		activeList = []string{}
	}
	json.NewEncoder(w).Encode(activeList)
}

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

// --- GÜNCELLENEN FONKSİYON: TARİH FİLTRESİ ---
func getHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// URL parametresini kontrol et: ?hours=24 gibi
	hoursStr := r.URL.Query().Get("hours")

	var rows *sql.Rows
	var err error

	if hoursStr != "" {
		// Eğer saat filtresi varsa: O saatten öncekileri getir
		// Not: SQLite 'datetime' fonksiyonu ile zaman hesabı
		// SQL Enjeksiyonuna karşı parametre kullanıyoruz (?) ancak interval string birleştirme SQLite'da trickli olabilir.
		// Basitlik için Go tarafında zamanı hesaplayıp gönderelim.

		hours, _ := strconv.Atoi(hoursStr)
		cutoff := time.Now().Add(time.Duration(-hours) * time.Hour).Format("2006-01-02 15:04:05")

		// Zaman kısıtlı sorgu
		rows, err = db.Query(`SELECT id, target, status, latency, agent, created_at, cpu, ram, disk 
							  FROM logs WHERE created_at >= ? ORDER BY id ASC`, cutoff)
	} else {
		// Varsayılan: Son 50 kayıt (Canlı izleme için)
		rows, err = db.Query(`SELECT id, target, status, latency, agent, created_at, cpu, ram, disk 
							  FROM logs ORDER BY id DESC LIMIT 50`)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var history []LogEntry
	for rows.Next() {
		var e LogEntry
		rows.Scan(&e.ID, &e.Target, &e.Status, &e.Latency, &e.Agent, &e.CreatedAt, &e.CPU, &e.RAM, &e.Disk)
		history = append(history, e)
	}
	if history == nil {
		history = []LogEntry{}
	}
	json.NewEncoder(w).Encode(history)
}

// ----------------------------------------------

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
			db.Exec("INSERT INTO logs (target, status, latency, agent, created_at, cpu, ram, disk) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
				msg.Target, msg.Status, msg.Time, msg.Agent, time.Now().UTC(), msg.CPU, msg.RAM, msg.Disk)
		}
	}
}

func main() {
	initDB()
	startTaskScheduler()
	http.HandleFunc("/ws", handleConnections)
	http.HandleFunc("/api/history", getHistory)
	http.HandleFunc("/api/targets", handleTargets)
	http.HandleFunc("/api/agents", handleActiveAgents)
	http.Handle("/", http.FileServer(http.Dir("./web")))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
