package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq"
)

var db *sql.DB

type AnalyticsData struct {
	Label string  `json:"label"` // 2024-01-20 14:00 gibi
	Value float64 `json:"value"` // Ortalama Gecikme
}

type TableRow struct {
	Target  string  `json:"target"`
	AvgPing float64 `json:"avg_ping"`
	MaxPing int     `json:"max_ping"`
	Success int     `json:"success"`
	Fail    int     `json:"fail"`
}

func initDB() {
	var err error

	// HATALI OLAN KISIM BURASIYDI, DÜZELTİLDİ:
	// Varsayılan bağlantı cümlesi (Docker içindeki isimle)
	connStr := "postgres://sentinel:[REDACTED]@sentineld-db:5432/sentineldb?sslmode=disable"

	// Eğer environment variable ile gelirse onu kullan (Production için)
	if val := os.Getenv("DATABASE_URL"); val != "" {
		connStr = val
	}

	// Sürücü adı artık "postgres"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Analyst DB'ye ulaşamadı:", err)
	}

	fmt.Println("📊 Analyst, PostgreSQL veritabanına bağlandı.")
}

// Grafik Verisi (Saatlik veya Günlük Gruplama)
func handleChartData(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	agent := r.URL.Query().Get("agent")

	var query string
	// POSTGRES TARİH FONKSİYONU: to_char
	if mode == "day" {
		query = `SELECT to_char(created_at, 'YYYY-MM-DD') as time_group, AVG(CAST(REPLACE(latency, 'ms', '') AS INTEGER)) 
                 FROM logs WHERE agent LIKE $1 GROUP BY time_group ORDER BY time_group ASC`
	} else {
		// Saatlik
		query = `SELECT to_char(created_at, 'YYYY-MM-DD HH24:00') as time_group, AVG(CAST(REPLACE(latency, 'ms', '') AS INTEGER)) 
                 FROM logs WHERE agent LIKE $1 GROUP BY time_group ORDER BY time_group ASC`
	}

	// SQLite '?' kullanır, Postgres '$1' kullanır.
	searchAgent := "%"
	if agent != "" {
		searchAgent = agent
	}

	rows, err := db.Query(query, searchAgent)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var data []AnalyticsData
	for rows.Next() {
		var d AnalyticsData
		rows.Scan(&d.Label, &d.Value)
		data = append(data, d)
	}

	if data == nil {
		data = []AnalyticsData{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// Tablo Verisi (Tableau Tarzı Özet)
func handleTableData(w http.ResponseWriter, r *http.Request) {
	// Son 24 saatin özeti
	query := `
		SELECT 
			target,
			AVG(CAST(replace(latency, 'ms', '') AS INTEGER)) as avg_ping,
			MAX(CAST(replace(latency, 'ms', '') AS INTEGER)) as max_ping,
			SUM(CASE WHEN status = 200 THEN 1 ELSE 0 END) as success,
			SUM(CASE WHEN status != 200 THEN 1 ELSE 0 END) as fail
		FROM logs
		GROUP BY target
	`
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var tableData []TableRow
	for rows.Next() {
		var t TableRow
		rows.Scan(&t.Target, &t.AvgPing, &t.MaxPing, &t.Success, &t.Fail)
		tableData = append(tableData, t)
	}
	if tableData == nil {
		tableData = []TableRow{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tableData)
}

func handleAgents(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query("SELECT DISTINCT agent FROM logs")
	defer rows.Close()
	var agents []string
	for rows.Next() {
		var a string
		rows.Scan(&a)
		agents = append(agents, a)
	}
	if agents == nil {
		agents = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agents)
}

func main() {
	initDB()
	http.HandleFunc("/api/chart", handleChartData)
	http.HandleFunc("/api/table", handleTableData)
	http.HandleFunc("/api/agents", handleAgents)

	// Arayüz dosyalarını sun
	http.Handle("/", http.FileServer(http.Dir("./web/analyst")))

	fmt.Println("📊 Sentinel Analyst 3000 portunda çalışıyor...")
	log.Fatal(http.ListenAndServe(":3000", nil))
}
