package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings" // String işlemleri için gerekli
	"sync"
	"time"

	"github.com/cagrisaltik/sentinel-system/internal/models"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"         // PostgreSQL sürücüsü
	"github.com/xuri/excelize/v2" // Excel kütüphanesi
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
	// Varsayılan bağlantı
	connStr := "postgres://sentinel:[REDACTED]@sentineld-db:5432/sentineldb?sslmode=disable"
	if val := os.Getenv("DATABASE_URL"); val != "" {
		connStr = val
	}

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Commander DB Erişim Hatası:", err)
	}

	// Tabloları oluştur (PostgreSQL Syntax)
	queryLogs := `CREATE TABLE IF NOT EXISTS logs (
		id SERIAL PRIMARY KEY,
		target TEXT,
		status INTEGER,
		latency TEXT,
		agent TEXT,
		created_at TIMESTAMP,
		cpu REAL, ram REAL, disk REAL
	);`
	queryTargets := `CREATE TABLE IF NOT EXISTS targets (
		id SERIAL PRIMARY KEY,
		agent_name TEXT,
		target_url TEXT
	);`

	if _, err := db.Exec(queryLogs); err != nil {
		log.Fatal(err)
	}
	if _, err := db.Exec(queryTargets); err != nil {
		log.Fatal(err)
	}

	fmt.Println("🐘 Commander: PostgreSQL Veritabanı Hazır.")
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
		// PostgreSQL: $1, $2
		db.Exec("INSERT INTO targets (agent_name, target_url) VALUES ($1, $2)", t.AgentName, t.TargetURL)
		w.WriteHeader(http.StatusCreated)
	} else if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		// PostgreSQL: $1
		db.Exec("DELETE FROM targets WHERE id = $1", id)
		w.WriteHeader(http.StatusOK)
	}
}

func getHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	hoursStr := r.URL.Query().Get("hours")
	var rows *sql.Rows
	var err error

	queryBase := `SELECT id, target, status, latency, agent, created_at, cpu, ram, disk FROM logs`

	if hoursStr != "" {
		hours, _ := strconv.Atoi(hoursStr)
		cutoff := time.Now().Add(time.Duration(-hours) * time.Hour)
		// PostgreSQL: $1
		rows, err = db.Query(queryBase+` WHERE created_at >= $1 ORDER BY id DESC`, cutoff)
	} else {
		rows, err = db.Query(queryBase + ` ORDER BY id DESC LIMIT 200`)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var history []LogEntry
	for rows.Next() {
		var e LogEntry
		var createdAt time.Time
		rows.Scan(&e.ID, &e.Target, &e.Status, &e.Latency, &e.Agent, &createdAt, &e.CPU, &e.RAM, &e.Disk)
		e.CreatedAt = createdAt.Format(time.RFC3339)
		history = append(history, e)
	}
	if history == nil {
		history = []LogEntry{}
	}
	json.NewEncoder(w).Encode(history)
}

// --- RENKLİ EXCEL RAPORLAMA ---
func handleExport(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, target, status, latency, agent, created_at, cpu, ram, disk FROM logs ORDER BY id DESC LIMIT 1000")
	if err != nil {
		http.Error(w, "Veritabanı hatası", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	f := excelize.NewFile()
	sheetName := "Sentinel Raporu"
	f.SetSheetName("Sheet1", sheetName)

	// Stiller
	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Size: 20, Color: "#1F4E78"},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "#FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#1F4E78"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	centerStyle, _ := f.NewStyle(&excelize.Style{Alignment: &excelize.Alignment{Horizontal: "center"}})
	badStyle, _ := f.NewStyle(&excelize.Style{Font: &excelize.Font{Color: "#DC2626", Bold: true}, Alignment: &excelize.Alignment{Horizontal: "center"}})
	goodStyle, _ := f.NewStyle(&excelize.Style{Font: &excelize.Font{Color: "#16A34A", Bold: true}, Alignment: &excelize.Alignment{Horizontal: "center"}})
	warnStyle, _ := f.NewStyle(&excelize.Style{Font: &excelize.Font{Color: "#EA580C", Bold: true}, Alignment: &excelize.Alignment{Horizontal: "center"}})

	// Başlıklar
	f.MergeCell(sheetName, "A1", "I1")
	f.SetCellValue(sheetName, "A1", "SENTINEL SİSTEM RAPORU")
	f.SetCellStyle(sheetName, "A1", "I1", titleStyle)
	f.SetRowHeight(sheetName, 1, 40)

	headers := []string{"ID", "Zaman", "Ajan", "Hedef", "Durum", "Gecikme", "CPU %", "RAM %", "Disk %"}
	columns := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I"}
	for i, h := range headers {
		cell := fmt.Sprintf("%s2", columns[i])
		f.SetCellValue(sheetName, cell, h)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}

	rowIdx := 3
	for rows.Next() {
		var id, status int
		var target, latency, agent string
		var createdAt time.Time
		var cpu, ram, disk float64

		rows.Scan(&id, &target, &status, &latency, &agent, &createdAt, &cpu, &ram, &disk)
		formattedTime := createdAt.Format("2006-01-02 15:04:05")

		f.SetCellValue(sheetName, fmt.Sprintf("A%d", rowIdx), id)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", rowIdx), formattedTime)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", rowIdx), agent)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", rowIdx), target)
		f.SetCellValue(sheetName, fmt.Sprintf("E%d", rowIdx), status)
		f.SetCellValue(sheetName, fmt.Sprintf("F%d", rowIdx), latency)
		f.SetCellValue(sheetName, fmt.Sprintf("G%d", rowIdx), fmt.Sprintf("%.1f", cpu))
		f.SetCellValue(sheetName, fmt.Sprintf("H%d", rowIdx), fmt.Sprintf("%.1f", ram))
		f.SetCellValue(sheetName, fmt.Sprintf("I%d", rowIdx), fmt.Sprintf("%.1f", disk))

		// Renklendirme
		f.SetCellStyle(sheetName, fmt.Sprintf("A%d", rowIdx), fmt.Sprintf("I%d", rowIdx), centerStyle)

		// Durum Kontrolü (Hata varsa Kırmızı)
		statusCell := fmt.Sprintf("E%d", rowIdx)
		if status == 200 {
			f.SetCellStyle(sheetName, statusCell, statusCell, goodStyle)
		} else {
			f.SetCellStyle(sheetName, statusCell, statusCell, badStyle)
		}

		// Ping Kontrolü
		latStr := strings.TrimSuffix(latency, "ms")
		latVal, _ := strconv.Atoi(latStr)
		latCell := fmt.Sprintf("F%d", rowIdx)
		if latVal > 300 {
			f.SetCellStyle(sheetName, latCell, latCell, badStyle)
		} else if latVal > 100 {
			f.SetCellStyle(sheetName, latCell, latCell, warnStyle)
		} else {
			f.SetCellStyle(sheetName, latCell, latCell, goodStyle)
		}

		// CPU Kontrolü
		cpuCell := fmt.Sprintf("G%d", rowIdx)
		if cpu > 80.0 {
			f.SetCellStyle(sheetName, cpuCell, cpuCell, badStyle)
		}

		rowIdx++
	}

	// Genişlikler
	f.SetColWidth(sheetName, "B", "B", 20)
	f.SetColWidth(sheetName, "C", "D", 25)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=sentinel_rapor.xlsx")
	w.Header().Set("Content-Transfer-Encoding", "binary")
	f.WriteTo(w)
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
			// PostgreSQL: $1...$8
			_, err := db.Exec("INSERT INTO logs (target, status, latency, agent, created_at, cpu, ram, disk) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
				msg.Target, msg.Status, msg.Time, msg.Agent, time.Now(), msg.CPU, msg.RAM, msg.Disk)
			if err != nil {
				fmt.Println("Log Insert Error:", err)
			}
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
	http.HandleFunc("/api/export", handleExport)
	http.Handle("/", http.FileServer(http.Dir("./web/commander")))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
