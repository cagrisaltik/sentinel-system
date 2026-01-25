package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var (
	sessions   = make(map[string]string)
	sessionsMu sync.Mutex
)

// --- MODELLER (HTML'in beklediği formatlar) ---
type ChartData struct {
	Label string  `json:"label"`
	Value float64 `json:"value"`
}

type TableData struct {
	Agent   string  `json:"agent"`
	Target  string  `json:"target"`
	AvgPing float64 `json:"avg_ping"`
	MaxPing int     `json:"max_ping"`
	Success int     `json:"success"`
	Fail    int     `json:"fail"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// --- VERİTABANI BAĞLANTISI ---
func initDB() {
	var err error
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Println("⚠️ DATABASE_URL yok, varsayılan kullanılıyor.")
		connStr = "postgres://sentinel:gizlisifre@localhost:5432/sentineldb?sslmode=disable"
	}

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	if err = db.Ping(); err != nil {
		log.Fatal("DB Bağlantı Hatası:", err)
	}
	fmt.Println("📊 Analyst: Veritabanı ve Grafik Motoru Hazır.")
}

// --- GÜVENLİK MIDDLEWARE ---
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Login sayfasına ve statik varlıklara izin ver
		if r.URL.Path == "/api/login" || r.URL.Path == "/login.html" || r.URL.Path == "/assets/style.css" {
			next(w, r)
			return
		}

		c, err := r.Cookie("analyst_session")
		if err != nil {
			http.Redirect(w, r, "/login.html", http.StatusSeeOther)
			return
		}

		sessionsMu.Lock()
		_, ok := sessions[c.Value]
		sessionsMu.Unlock()

		if !ok {
			http.Redirect(w, r, "/login.html", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// --- LOGIN HANDLERS ---
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Geçersiz veri", 400)
		return
	}

	var storedHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = $1", creds.Username).Scan(&storedHash)

	if err != nil || bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password)) != nil {
		time.Sleep(1 * time.Second)
		http.Error(w, "Giriş başarısız", 401)
		return
	}

	token := uuid.New().String()
	sessionsMu.Lock()
	sessions[token] = creds.Username
	sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name: "analyst_session", Value: token, Expires: time.Now().Add(24 * time.Hour), Path: "/", HttpOnly: true,
	})
	w.WriteHeader(200)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("analyst_session"); err == nil {
		sessionsMu.Lock()
		delete(sessions, c.Value)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "analyst_session", MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/login.html", http.StatusSeeOther)
}

// --- GRAFİK VE TABLO HANDLERLARI (YENİ KISIM) ---

// 1. /api/agents (Dropdown listesini doldurur)
func handleAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rows, err := db.Query("SELECT DISTINCT agent FROM logs ORDER BY agent")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var agents []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err == nil {
			agents = append(agents, a)
		}
	}
	json.NewEncoder(w).Encode(agents)
}

// 2. /api/chart (ApexCharts verisini hazırlar)
func handleChart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	mode := r.URL.Query().Get("mode")
	agent := r.URL.Query().Get("agent")

	// Basit zaman gruplaması (Saatlik veya Günlük)
	timeFormat := "YYYY-MM-DD HH24:00"
	if mode == "day" {
		timeFormat = "YYYY-MM-DD"
	}

	query := fmt.Sprintf(`
		SELECT to_char(timestamp, '%s') as label, AVG(latency) as val 
		FROM logs 
		WHERE 1=1 %s 
		GROUP BY label 
		ORDER BY label DESC LIMIT 24`, timeFormat, "")

	var rows *sql.Rows
	var err error

	if agent != "" && agent != "undefined" {
		query = fmt.Sprintf(`
			SELECT to_char(timestamp, '%s') as label, AVG(latency) as val 
			FROM logs 
			WHERE agent = $1 
			GROUP BY label 
			ORDER BY label DESC LIMIT 24`, timeFormat)
		rows, err = db.Query(query, agent)
	} else {
		rows, err = db.Query(query)
	}

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var data []ChartData
	for rows.Next() {
		var d ChartData
		rows.Scan(&d.Label, &d.Value)
		data = append(data, d)
	}
	// Grafiğin soldan sağa akması için ters çevir
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}

	json.NewEncoder(w).Encode(data)
}

// 3. /api/table (Grid.js tablosunu doldurur)
func handleTable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Postgres Filter Syntax Kullanımı
	rows, err := db.Query(`
		SELECT 
			agent, 
			target, 
			COALESCE(AVG(latency),0), 
			COALESCE(MAX(latency),0), 
			COUNT(*) FILTER (WHERE status = 200) as success, 
			COUNT(*) FILTER (WHERE status != 200) as fail
		FROM logs 
		GROUP BY agent, target
	`)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var table []TableData
	for rows.Next() {
		var t TableData
		rows.Scan(&t.Agent, &t.Target, &t.AvgPing, &t.MaxPing, &t.Success, &t.Fail)
		table = append(table, t)
	}
	json.NewEncoder(w).Encode(table)
}

func main() {
	_ = godotenv.Load()
	initDB()

	// Statik Dosyalar
	fs := http.FileServer(http.Dir("./web/analyst"))

	// Login & Logout
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)

	// --- YENİ ENDPOINTLER ---
	http.HandleFunc("/api/agents", authMiddleware(handleAgents))
	http.HandleFunc("/api/chart", authMiddleware(handleChart))
	http.HandleFunc("/api/table", authMiddleware(handleTable))

	// HTML Sayfaları
	http.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./web/analyst/login.html")
	})

	// Ana Handler
	http.HandleFunc("/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login.html" {
			http.ServeFile(w, r, "./web/analyst/login.html")
			return
		}
		fs.ServeHTTP(w, r)
	}))

	port := os.Getenv("ANALYST_PORT")
	if port == "" {
		port = "3000"
	}

	fmt.Printf("🛡️ Analyst: Gelişmiş Grafik Modu Aktif (Port %s)\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
