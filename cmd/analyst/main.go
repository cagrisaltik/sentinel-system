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

// --- MODELLER ---
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

	// DB'ye ulaşana kadar bekle (Retry Logic)
	for i := 0; i < 5; i++ {
		if err = db.Ping(); err == nil {
			fmt.Println("📊 Analyst: Veritabanı bağlantısı BAŞARILI.")
			return
		}
		fmt.Println("⏳ DB bekleniyor...", err)
		time.Sleep(2 * time.Second)
	}
	log.Fatal("DB Bağlantı Hatası:", err)
}

// --- GÜVENLİK MIDDLEWARE ---
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Login ve statiklere izin ver
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

// --- LOGIN İŞLEMLERİ ---
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Geçersiz veri", 400)
		return
	}

	var storedHash string
	// Şifre kontrolü
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

// --- API ENDPOINTLERİ (DÜZELTİLMİŞ SQL SORGULARI) ---

// 1. /api/agents
func handleAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// 'agent' kolonu yoksa hatayı logla
	rows, err := db.Query("SELECT DISTINCT agent FROM logs ORDER BY agent")
	if err != nil {
		log.Println("SQL Hatası (Agents):", err)
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

// 2. /api/chart (DÜZELTME: 'timestamp' yerine 'created_at' kullanıldı)
func handleChart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	mode := r.URL.Query().Get("mode")
	agent := r.URL.Query().Get("agent")

	timeFormat := "YYYY-MM-DD HH24:00"
	if mode == "day" {
		timeFormat = "YYYY-MM-DD"
	}

	// DİKKAT: Burada kolon adı 'created_at' olarak değiştirildi.
	// Eğer veritabanında hala 'timestamp' ise burayı değiştirmen gerekebilir.
	baseQuery := fmt.Sprintf(`
		SELECT to_char(created_at, '%s') as label, AVG(latency) as val 
		FROM logs 
		WHERE 1=1 `, timeFormat)

	groupBy := " GROUP BY label ORDER BY label DESC LIMIT 24"

	var rows *sql.Rows
	var err error

	if agent != "" && agent != "null" && agent != "undefined" {
		rows, err = db.Query(baseQuery+" AND agent = $1"+groupBy, agent)
	} else {
		rows, err = db.Query(baseQuery + groupBy)
	}

	if err != nil {
		log.Println("SQL Hatası (Chart):", err) // Hatayı Docker loglarında görmek için
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
	// Grafiği ters çevir (Eskiden yeniye)
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}

	json.NewEncoder(w).Encode(data)
}

// 3. /api/table
func handleTable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

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
		log.Println("SQL Hatası (Table):", err)
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

	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/agents", authMiddleware(handleAgents))
	http.HandleFunc("/api/chart", authMiddleware(handleChart))
	http.HandleFunc("/api/table", authMiddleware(handleTable))

	http.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./web/analyst/login.html")
	})

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

	fmt.Printf("🛡️ Analyst: Gelişmiş Mod Aktif (Port %s)\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
