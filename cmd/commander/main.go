package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cagrisaltik/sentinel-system/internal/models"
	"github.com/google/uuid" //Rastgele ve benzersiz token için
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"         // PostgreSQL Driver
	"github.com/xuri/excelize/v2" // Excel Export
	"golang.org/x/crypto/bcrypt"  // Şifre Hashleme
)

var db *sql.DB
var (
	clients   = make(map[string]*websocket.Conn)
	clientsMu sync.Mutex
	sessions  = make(map[string]string) // SessionToken -> Username (Basit Session Yönetimi)
)

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
	// Varsayılan bağlantı (Docker içi)
	connStr := "postgres://sentinel:[REDACTED]@sentineld-db:5432/sentineldb?sslmode=disable"

	// Eğer Environment'tan gelirse onu kullan
	if val := os.Getenv("DATABASE_URL"); val != "" {
		connStr = val
	}

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("DB Erişim Hatası:", err)
	}

	// 1. Log Tablosu
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS logs (
		id SERIAL PRIMARY KEY,
		target TEXT,
		status INTEGER,
		latency TEXT,
		agent TEXT,
		created_at TIMESTAMP,
		cpu REAL, ram REAL, disk REAL
	);`)
	if err != nil {
		log.Println("Logs tablosu hatası:", err)
	}

	// 2. Hedefler Tablosu
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS targets (
		id SERIAL PRIMARY KEY,
		agent_name TEXT,
		target_url TEXT
	);`)
	if err != nil {
		log.Println("Targets tablosu hatası:", err)
	}

	// 3. Kullanıcılar Tablosu (Şifreli)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL
	);`)
	if err != nil {
		log.Fatal("Users tablosu oluşturulamadı:", err)
	}

	// 4. Varsayılan Kullanıcı (admin / [REDACTED]) Kontrolü
	var userCount int
	err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if err == nil && userCount == 0 {
		defaultUser := "admin"
		defaultPass := "[REDACTED]" // Varsayılan şifre
		hash, _ := bcrypt.GenerateFromPassword([]byte(defaultPass), bcrypt.DefaultCost)

		_, err := db.Exec("INSERT INTO users (username, password_hash) VALUES ($1, $2)", defaultUser, string(hash))
		if err != nil {
			log.Println("Default user oluşturulamadı:", err)
		} else {
			fmt.Println("🔑 İlk Kullanıcı Oluşturuldu: admin / [REDACTED]")
		}
	}

	fmt.Println("🐘 Commander: PostgreSQL Veritabanı ve Auth Sistemi Hazır.")
}

// --- GÜVENLİK KATMANI (MIDDLEWARE) ---
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Public endpointlere izin ver
		if r.URL.Path == "/api/login" || r.URL.Path == "/login.html" {
			next(w, r)
			return
		}

		c, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login.html", http.StatusSeeOther)
			return
		}

		// Session geçerli mi?
		if _, ok := sessions[c.Value]; !ok {
			http.Redirect(w, r, "/login.html", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

// --- LOGIN HANDLERS ---
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds LoginRequest
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Geçersiz veri", http.StatusBadRequest)
		return
	}

	var storedHash string
	err = db.QueryRow("SELECT password_hash FROM users WHERE username = $1", creds.Username).Scan(&storedHash)
	if err != nil {
		// Güvenlik İpucu: "Kullanıcı bulunamadı" demek yerine genel hata verilir ki hacker kullanıcı adını doğrulayamasın.
		time.Sleep(1 * time.Second) // Timing Attack önlemi (Cevabı bilerek geciktiriyoruz)
		http.Error(w, "Giriş başarısız", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password))
	if err != nil {
		time.Sleep(1 * time.Second) // Şifre denemesini yavaşlat
		http.Error(w, "Giriş başarısız", http.StatusUnauthorized)
		return
	}

	// 1. GÜVENLİK GÜNCELLEMESİ: UUID Kullan (Tahmin edilemez)
	sessionToken := uuid.New().String()
	sessions[sessionToken] = creds.Username

	// 2. GÜVENLİK GÜNCELLEMESİ: Secure Cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: time.Now().Add(24 * time.Hour),
		Path:    "/",
		// Bu ikisi ÇOK ÖNEMLİ:
		HttpOnly: true,                    // Javascript bu çerezi okuyamaz (XSS koruması)
		SameSite: http.SameSiteStrictMode, // Başka siteden gelen istekte çerez gitmez (CSRF koruması)
		// Secure: true,                 // Sadece HTTPS'de çalışır (Localhost testinde false kalsın, sunucuda true yapmalısın)
	})
	w.WriteHeader(http.StatusOK)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err == nil {
		delete(sessions, c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now(),
		Path:    "/",
	})
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

// --- API ENDPOINTLERİ ---

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
		err := json.NewDecoder(r.Body).Decode(&t)
		if err != nil {
			http.Error(w, "Geçersiz veri formatı", http.StatusBadRequest)
			return
		}

		// --- GÜVENLİK KONTROLLERİ (XSS & VALIDATION) ---

		// 1. Boş Alan Kontrolü
		if strings.TrimSpace(t.AgentName) == "" || strings.TrimSpace(t.TargetURL) == "" {
			http.Error(w, "Ajan adı ve Hedef URL boş olamaz", http.StatusBadRequest)
			return
		}

		// 2. XSS Koruması (HTML Taglerini Yasakla)
		// Eğer URL içinde < veya > varsa reddet.
		if strings.Contains(t.TargetURL, "<") || strings.Contains(t.TargetURL, ">") ||
			strings.Contains(t.AgentName, "<") || strings.Contains(t.AgentName, ">") {
			http.Error(w, "Güvenlik Uyarısı: HTML karakterleri (<, >) kullanılamaz!", http.StatusBadRequest)
			return
		}
		// ------------------------------------------------

		// Veritabanına Kayıt (PostgreSQL $1, $2 kullanarak SQL Injection'ı zaten engelliyoruz)
		_, err = db.Exec("INSERT INTO targets (agent_name, target_url) VALUES ($1, $2)", t.AgentName, t.TargetURL)
		if err != nil {
			http.Error(w, "Veritabanı hatası", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)

	} else if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "ID gerekli", http.StatusBadRequest)
			return
		}

		// ID'ye göre sil ($1 parametresi ile)
		_, err := db.Exec("DELETE FROM targets WHERE id = $1", id)
		if err != nil {
			http.Error(w, "Silme işlemi başarısız", http.StatusInternalServerError)
			return
		}
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

// --- EXCEL EXPORT (RENKLİ) ---
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

		// Renklendirme ve Stillendirme
		f.SetCellStyle(sheetName, fmt.Sprintf("A%d", rowIdx), fmt.Sprintf("I%d", rowIdx), centerStyle)

		statusCell := fmt.Sprintf("E%d", rowIdx)
		if status == 200 {
			f.SetCellStyle(sheetName, statusCell, statusCell, goodStyle)
		} else {
			f.SetCellStyle(sheetName, statusCell, statusCell, badStyle)
		}

		// Latency Renklendirme
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

		// CPU Renklendirme
		cpuCell := fmt.Sprintf("G%d", rowIdx)
		if cpu > 80.0 {
			f.SetCellStyle(sheetName, cpuCell, cpuCell, badStyle)
		}

		rowIdx++
	}

	f.SetColWidth(sheetName, "B", "B", 20)
	f.SetColWidth(sheetName, "C", "D", 25)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=sentinel_rapor.xlsx")
	w.Header().Set("Content-Transfer-Encoding", "binary")
	f.WriteTo(w)
}

// --- WEBSOCKET ---
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Sadece kendi sunucumuzdan (localhost veya sunucu IP'si) gelen isteklere izin ver
		origin := r.Header.Get("Origin")

		// Geliştirme ortamı (Localhost) için izin ver
		if strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") {
			return true
		}

		// PROD: Sunucunun IP adresini veya Domainini buraya yazmalısın!
		// Örn: if strings.Contains(origin, "192.168.1.50") { return true }

		// Şimdilik test için true bırakıyoruz ama riskli olduğunu bil!
		// Doğrusu yukarıdaki gibi IP kontrolü yapmaktır.
		return true
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
			// Güvenlik: Ajan Adı Kontrolü
			if strings.Contains(msg.Agent, "<") || strings.Contains(msg.Agent, ">") {
				fmt.Println("⚠️ SALDIRI TESPİTİ: Ajan adında illegal karakterler!")
				ws.Close()
				break
			}

			currentAgentName = msg.Agent
			clientsMu.Lock()
			clients[currentAgentName] = ws
			clientsMu.Unlock()
			fmt.Printf("🔵 Ajan Kayıt: %s\n", currentAgentName)
		}

		if msg.Type == "RAPOR" {
			// --- DÜZELTME BURADA YAPILDI ---

			// 1. Target Temizliği
			cleanTarget := strings.ReplaceAll(msg.Target, "<", "")
			cleanTarget = strings.ReplaceAll(cleanTarget, ">", "")

			// 2. Latency (Time) Temizliği
			// DİKKAT: Burada 'msg.Latency' yerine 'msg.Time' kullanıyoruz!
			cleanLatency := strings.ReplaceAll(msg.Time, "<", "")
			cleanLatency = strings.ReplaceAll(cleanLatency, ">", "")

			// -------------------------------

			_, err := db.Exec("INSERT INTO logs (target, status, latency, agent, created_at, cpu, ram, disk) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
				cleanTarget, msg.Status, cleanLatency, msg.Agent, time.Now(), msg.CPU, msg.RAM, msg.Disk)
			if err != nil {
				fmt.Println("Log Insert Error:", err)
			}
		}
	}
}

// --- ANA FONKSİYON ---
func main() {
	initDB()
	startTaskScheduler()

	// Public Routes (Middleware YOK)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/ws", handleConnections) // Ajanlar auth olmadan bağlanıyor (şimdilik)

	// Login Sayfasını Sunma
	http.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./web/commander/login.html")
	})

	// Protected Routes (Middleware VAR)
	http.HandleFunc("/api/history", authMiddleware(getHistory))
	http.HandleFunc("/api/targets", authMiddleware(handleTargets))
	http.HandleFunc("/api/agents", authMiddleware(handleActiveAgents))
	http.HandleFunc("/api/export", authMiddleware(handleExport))

	// Statik Dosyalar (Korumalı)
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
