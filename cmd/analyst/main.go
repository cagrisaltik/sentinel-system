package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	_ "modernc.org/sqlite"
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
	// _journal_mode=WAL çok önemli! İki uygulama aynı anda dosyayı okuyabilsin diye.
	db, err = sql.Open("sqlite", "/root/sentinel.db?_journal_mode=WAL")
	if err != nil {
		log.Fatal(err)
	}
}

// Grafik Verisi (Saatlik veya Günlük Gruplama)
func handleChartData(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode") // 'hour' veya 'day'
	agent := r.URL.Query().Get("agent")

	var query string
	// SQLite'da zaman formatlama ve gruplama
	if mode == "day" {
		query = `SELECT strftime('%Y-%m-%d', created_at) as time_group, AVG(CAST(replace(latency, 'ms', '') AS INTEGER)) 
				 FROM logs WHERE agent LIKE ? GROUP BY time_group ORDER BY time_group ASC`
	} else {
		// Varsayılan: Saatlik
		query = `SELECT strftime('%Y-%m-%d %H:00', created_at) as time_group, AVG(CAST(replace(latency, 'ms', '') AS INTEGER)) 
				 FROM logs WHERE agent LIKE ? GROUP BY time_group ORDER BY time_group ASC`
	}

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
