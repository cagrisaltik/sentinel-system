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
	sessionsMu sync.Mutex // Eşzamanlı erişim hatası olmasın diye kilit
)

// --- MODELLER ---
type LogStats struct {
	TotalPings   int     `json:"total_pings"`
	SuccessRate  float64 `json:"success_rate"`
	AvgLatency   float64 `json:"avg_latency"`
	ActiveAgents int     `json:"active_agents"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// --- VERİTABANI ---
func initDB() {
	var err error
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Println("UYARI: DATABASE_URL yok, varsayılan kullanılıyor.")
		connStr = "postgres://sentinel:gizlisifre@localhost:5432/sentineldb?sslmode=disable"
	}

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	if err = db.Ping(); err != nil {
		log.Fatal("Analyst DB'ye bağlanamadı:", err)
	}
	fmt.Println("📊 Analyst: Veritabanı bağlantısı başarılı (Users tablosu kullanılıyor).")
}

// --- GÜVENLİK MIDDLEWARE ---
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Güvenlik Başlıkları
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Login sayfasına izin ver
		if r.URL.Path == "/api/login" || r.URL.Path == "/login.html" || r.URL.Path == "/assets/style.css" {
			next(w, r)
			return
		}

		// Cookie Kontrolü
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
		http.Error(w, "Geçersiz veri", http.StatusBadRequest)
		return
	}

	var storedHash string
	// Commander ile AYNI kullanıcı tablosunu sorguluyoruz
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = $1", creds.Username).Scan(&storedHash)

	if err != nil || bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password)) != nil {
		time.Sleep(1 * time.Second) // Brute-force önlemi
		http.Error(w, "Giriş başarısız", http.StatusUnauthorized)
		return
	}

	sessionToken := uuid.New().String()
	sessionsMu.Lock()
	sessions[sessionToken] = creds.Username
	sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "analyst_session",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusOK)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("analyst_session")
	if err == nil {
		sessionsMu.Lock()
		delete(sessions, c.Value)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "analyst_session", Value: "", Expires: time.Now(), Path: "/"})
	http.Redirect(w, r, "/login.html", http.StatusSeeOther)
}

// --- API ---
func getStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var stats LogStats
	// Basit bir istatistik sorgusu
	err := db.QueryRow(`
		SELECT 
			COUNT(*) as total,
			COALESCE(AVG(CASE WHEN status = 200 THEN 100.0 ELSE 0.0 END), 0) as success_rate,
			COUNT(DISTINCT agent) as agents
		FROM logs
	`).Scan(&stats.TotalPings, &stats.SuccessRate, &stats.ActiveAgents)

	if err != nil {
		http.Error(w, "Veri hatası", 500)
		return
	}
	stats.AvgLatency = 45.0 // Şimdilik dummy veya hesaplanabilir
	json.NewEncoder(w).Encode(stats)
}

func main() {
	_ = godotenv.Load()
	initDB()

	// Statik Dosyalar
	fs := http.FileServer(http.Dir("./web/analyst"))

	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/stats", authMiddleware(getStats))

	// Özel Login Sayfası Yönlendirmesi
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

	fmt.Printf("🛡️ Analyst: Login Ekranlı Modda Başlatıldı (Port %s)\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
