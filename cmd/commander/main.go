package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cagrisaltik/sentinel-system/internal/models"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/xuri/excelize/v2"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var (
	clients   = make(map[string]*websocket.Conn)
	clientsMu sync.Mutex
	sessions  = make(map[string]string)
)

// GÜVENLİK: Sıkı URL ve İsim Doğrulama Regex'i
// İzin verilenler: Harfler, rakamlar, nokta, tire, alt çizgi, iki nokta (port için), slash (path için)
var strictInputRegex = regexp.MustCompile(`^[a-zA-Z0-9.:_/-]+$`)

// --- MODELLER ---
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
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// --- VERİTABANI BAŞLATMA ---
func initDB() {
	var err error
	// GÜVENLİK FİX: Hardcoded şifre kaldırıldı.
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		// Fallback (Sadece geliştirme ortamı için)
		log.Println("UYARI: DATABASE_URL ayarlanmamış, varsayılan değer kullanılıyor.")
		connStr = "postgres://sentinel:Cagri1183@sentineld-db:5432/sentineldb?sslmode=disable"
	}

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("DB Erişim Hatası:", err)
	}

	// Tabloları oluştur
	queries := []string{
		`CREATE TABLE IF NOT EXISTS logs (id SERIAL PRIMARY KEY, target TEXT, status INTEGER, latency TEXT, agent TEXT, created_at TIMESTAMP, cpu REAL, ram REAL, disk REAL);`,
		`CREATE TABLE IF NOT EXISTS targets (id SERIAL PRIMARY KEY, agent_name TEXT, target_url TEXT);`,
		`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);`,
	}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			log.Println("Tablo oluşturma hatası:", err)
		}
	}

	// Varsayılan Kullanıcı
	var userCount int
	err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if err == nil && userCount == 0 {
		defaultUser := "admin"
		defaultPass := "admin123"

		// Eğer env'den geliyorsa onu kullan
		if envPass := os.Getenv("ADMIN_INIT_PASS"); envPass != "" {
			defaultPass = envPass
		}

		hash, _ := bcrypt.GenerateFromPassword([]byte(defaultPass), bcrypt.DefaultCost)
		db.Exec("INSERT INTO users (username, password_hash) VALUES ($1, $2)", defaultUser, string(hash))
		fmt.Println("🔑 İlk Kullanıcı Oluşturuldu: admin")
	}
	fmt.Println("🐘 Commander: Sistem Hazır.")
}

// --- GÜVENLİK MIDDLEWARE ---
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Güvenlik Başlıkları
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		if r.URL.Path == "/api/login" || r.URL.Path == "/login.html" {
			next(w, r)
			return
		}
		c, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login.html", http.StatusSeeOther)
			return
		}
		if _, ok := sessions[c.Value]; !ok {
			http.Redirect(w, r, "/login.html", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// --- LOGIN ---
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Geçersiz veri", http.StatusBadRequest)
		return
	}

	var storedHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = $1", creds.Username).Scan(&storedHash)

	// Timing Attack Önlemi
	if err != nil || bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password)) != nil {
		time.Sleep(1 * time.Second)
		http.Error(w, "Giriş başarısız", http.StatusUnauthorized)
		return
	}

	sessionToken := uuid.New().String()
	sessions[sessionToken] = creds.Username

	// Production'da Secure: true olmalı
	isSecure := false
	if os.Getenv("ENV") == "production" {
		isSecure = true
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecure,
	})
	w.WriteHeader(http.StatusOK)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err == nil {
		delete(sessions, c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", Expires: time.Now(), Path: "/"})
	http.Redirect(w, r, "/login.html", http.StatusSeeOther)
}

// --- GÖREV ZAMANLAYICI ---
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

// --- TARGETS ---
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
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			http.Error(w, "Geçersiz veri", http.StatusBadRequest)
			return
		}

		// GÜVENLİK FİX: Validasyon
		if strings.TrimSpace(t.AgentName) == "" || strings.TrimSpace(t.TargetURL) == "" {
			http.Error(w, "Boş alan bırakılamaz", http.StatusBadRequest)
			return
		}
		if !strictInputRegex.MatchString(t.TargetURL) {
			http.Error(w, "Geçersiz URL formatı! (Sadece harf, rakam, nokta, tire)", http.StatusBadRequest)
			return
		}
		if strings.Contains(t.AgentName, "<") || strings.Contains(t.AgentName, ">") {
			http.Error(w, "Geçersiz karakter", http.StatusBadRequest)
			return
		}

		_, err := db.Exec("INSERT INTO targets (agent_name, target_url) VALUES ($1, $2)", t.AgentName, t.TargetURL)
		if err != nil {
			log.Println("DB Error:", err)
			http.Error(w, "Kayıt hatası", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	} else if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		db.Exec("DELETE FROM targets WHERE id = $1", id)
		w.WriteHeader(http.StatusOK)
	}
}

// --- HISTORY ---
func getHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	hoursStr := r.URL.Query().Get("hours")
	var rows *sql.Rows
	var err error
	queryBase := `SELECT id, target, status, latency, agent, created_at, cpu, ram, disk FROM logs`

	if hoursStr != "" {
		// strconv hata kontrolü eklenebilir ama basit tutuyoruz
		rows, err = db.Query(queryBase+` WHERE created_at >= NOW() - INTERVAL '1 hour' * $1 ORDER BY id DESC`, hoursStr)
	} else {
		rows, err = db.Query(queryBase + ` ORDER BY id DESC LIMIT 200`)
	}

	if err != nil {
		http.Error(w, "Veri çekilemedi", 500)
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

// --- ACTIVE AGENTS ---
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

// --- EXCEL EXPORT ---
func handleExport(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, target, status, latency, agent, created_at, cpu, ram, disk FROM logs ORDER BY id DESC LIMIT 1000")
	if err != nil {
		http.Error(w, "Hata", 500)
		return
	}
	defer rows.Close()

	f := excelize.NewFile()
	sheetName := "Sentinel Raporu"
	f.SetSheetName("Sheet1", sheetName)

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

	f.MergeCell(sheetName, "A1", "I1")
	f.SetCellValue(sheetName, "A1", "SENTINEL SİSTEM RAPORU")
	f.SetCellStyle(sheetName, "A1", "I1", titleStyle)
	f.SetRowHeight(sheetName, 1, 40)

	headers := []string{"ID", "Zaman", "Ajan", "Hedef", "Durum", "Gecikme", "CPU %", "RAM %", "Disk %"}
	cols := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I"}
	for i, h := range headers {
		cell := fmt.Sprintf("%s2", cols[i])
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

		f.SetCellStyle(sheetName, fmt.Sprintf("A%d", rowIdx), fmt.Sprintf("I%d", rowIdx), centerStyle)

		statusCell := fmt.Sprintf("E%d", rowIdx)
		if status == 200 {
			f.SetCellStyle(sheetName, statusCell, statusCell, goodStyle)
		} else {
			f.SetCellStyle(sheetName, statusCell, statusCell, badStyle)
		}

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
		rowIdx++
	}

	f.SetColWidth(sheetName, "B", "B", 20)
	f.SetColWidth(sheetName, "C", "D", 25)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=sentinel_rapor.xlsx")
	f.WriteTo(w)
}

// --- WEBSOCKET ---
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// GÜVENLİK FİX: Origin Kontrolü
		origin := r.Header.Get("Origin")

		// Localhost veya 127.0.0.1'e izin ver
		if strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") {
			return true
		}

		fmt.Println("⚠️ Bloklanan Origin:", origin)
		return false
	},
}

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
			if strings.Contains(msg.Agent, "<") || strings.Contains(msg.Agent, ">") {
				ws.Close()
				break
			}
			currentAgentName = msg.Agent
			clientsMu.Lock()
			clients[currentAgentName] = ws
			clientsMu.Unlock()
			fmt.Printf("🔵 Ajan: %s\n", currentAgentName)
		}

		if msg.Type == "RAPOR" {
			// Temizlik
			cleanTarget := strings.ReplaceAll(msg.Target, "<", "")
			cleanTarget = strings.ReplaceAll(cleanTarget, ">", "")
			cleanTime := strings.ReplaceAll(msg.Time, "<", "")
			cleanTime = strings.ReplaceAll(cleanTime, ">", "")

			_, err := db.Exec("INSERT INTO logs (target, status, latency, agent, created_at, cpu, ram, disk) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
				cleanTarget, msg.Status, cleanTime, msg.Agent, time.Now(), msg.CPU, msg.RAM, msg.Disk)
			if err != nil {
				log.Println("Log Error:", err)
			}
		}
	}
}

func main() {

	_ = godotenv.Load()
	initDB()
	startTaskScheduler()

	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/ws", handleConnections)
	http.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./web/commander/login.html")
	})

	http.HandleFunc("/api/history", authMiddleware(getHistory))
	http.HandleFunc("/api/targets", authMiddleware(handleTargets))
	http.HandleFunc("/api/agents", authMiddleware(handleActiveAgents))
	http.HandleFunc("/api/export", authMiddleware(handleExport))

	fs := http.FileServer(http.Dir("./web/commander"))
	http.HandleFunc("/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login.html" {
			fs.ServeHTTP(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	}))

	fmt.Println("🔒 Commander: Güvenli Modda Başlatıldı (Port 8080)")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
