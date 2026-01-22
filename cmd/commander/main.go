package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv" // YENİ: String çevirmek için
	"strings"
	"sync"
	"time"

	"github.com/cagrisaltik/sentinel-system/internal/models"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"github.com/xuri/excelize/v2"
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
	// Ortam değişkenlerinden bilgileri al, yoksa varsayılanı kullan
	connStr := "postgres://sentinel:gizlisifre@sentineld-db:5432/sentineldb?sslmode=disable"

	// Eğer docker run -e DB_URL="..." ile verirsek onu kullanırız
	if os.Getenv("DATABASE_URL") != "" {
		connStr = os.Getenv("DATABASE_URL")
	}

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Bağlantıyı test et
	if err = db.Ping(); err != nil {
		log.Fatal("Veritabanına ulaşılamadı:", err)
	}

	// --- TABLO OLUŞTURMA (Postgres Syntax) ---
	// SQLite'daki AUTOINCREMENT yerine SERIAL kullanıyoruz
	// DATETIME yerine TIMESTAMP kullanıyoruz

	queryLogs := `CREATE TABLE IF NOT EXISTS logs (
        id SERIAL PRIMARY KEY,
        target TEXT,
        status INTEGER,
        latency TEXT,
        agent TEXT,
        created_at TIMESTAMP,
        cpu REAL,
        ram REAL,
        disk REAL
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

	fmt.Println("🐘 PostgreSQL Bağlantısı Hazır.")
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
							  FROM logs ORDER BY id DESC LIMIT 200`)
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

			if err != nil {
				fmt.Println("❌ KRİTİK VERİTABANI HATASI:", err)
			} else {
				fmt.Printf("✅ Kayıt Başarılı: %s (%d)\n", msg.Target, msg.Status)
			}
		}
	}
}

// --- EXCEL RAPORLAMA MOTORU ---
// --- EXCEL RAPORLAMA MOTORU (RENKLİ SÜRÜM) ---
func handleExport(w http.ResponseWriter, r *http.Request) {
	// 1. Verileri Çek
	rows, err := db.Query("SELECT id, target, status, latency, agent, created_at, cpu, ram, disk FROM logs ORDER BY id DESC LIMIT 1000")
	if err != nil {
		http.Error(w, "Veritabanı hatası", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// 2. Excel Dosyasını Oluştur
	f := excelize.NewFile()
	sheetName := "Sentinel Raporu"
	f.SetSheetName("Sheet1", sheetName)

	// --- STİLLERİ OLUŞTUR ---
	// Başlık Stili
	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Size: 20, Color: "#1F4E78"},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	// Tablo Başlığı Stili
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "#FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#1F4E78"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	// Normal Veri Stili (Ortalanmış)
	centerStyle, _ := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})

	// --- RENK STİLLERİ (Conditonal Formatting) ---
	// Kötü Durum (Kırmızı Yazı & Kalın) - Hata veya Yüksek Ping için
	badStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Color: "#DC2626", Bold: true}, // Kırmızı
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	// İyi Durum (Yeşil Yazı)
	goodStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Color: "#16A34A", Bold: true}, // Yeşil
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	// Uyarı Durumu (Turuncu Yazı) - Yüksek CPU/RAM için
	warnStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Color: "#EA580C", Bold: true}, // Turuncu
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})

	// 3. Başlık Satırı
	f.MergeCell(sheetName, "A1", "I1")
	f.SetCellValue(sheetName, "A1", "SENTINEL SİSTEM RAPORU")
	f.SetCellStyle(sheetName, "A1", "I1", titleStyle)
	f.SetRowHeight(sheetName, 1, 40)

	// 4. Tablo Başlıkları
	headers := []string{"ID", "Zaman", "Ajan", "Hedef", "Durum", "Gecikme", "CPU %", "RAM %", "Disk %"}
	columns := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I"}
	for i, h := range headers {
		cell := fmt.Sprintf("%s2", columns[i])
		f.SetCellValue(sheetName, cell, h)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}

	// 5. Verileri Doldur ve Renklendir
	rowIdx := 3
	for rows.Next() {
		var id, status int
		var target, latency, agent, createdAt string
		var cpu, ram, disk float64

		rows.Scan(&id, &target, &status, &latency, &agent, &createdAt, &cpu, &ram, &disk)

		t, _ := time.Parse(time.RFC3339, createdAt)
		formattedTime := t.Format("2006-01-02 15:04:05")

		// Hücrelere Veriyi Yaz
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", rowIdx), id)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", rowIdx), formattedTime)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", rowIdx), agent)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", rowIdx), target)
		f.SetCellValue(sheetName, fmt.Sprintf("E%d", rowIdx), status)
		f.SetCellValue(sheetName, fmt.Sprintf("F%d", rowIdx), latency)
		f.SetCellValue(sheetName, fmt.Sprintf("G%d", rowIdx), fmt.Sprintf("%.1f", cpu))
		f.SetCellValue(sheetName, fmt.Sprintf("H%d", rowIdx), fmt.Sprintf("%.1f", ram))
		f.SetCellValue(sheetName, fmt.Sprintf("I%d", rowIdx), fmt.Sprintf("%.1f", disk))

		// --- RENKLENDİRME MANTIĞI ---

		// 1. Varsayılan Stil (Hepsine uygula, sonra özelleri ez)
		f.SetCellStyle(sheetName, fmt.Sprintf("A%d", rowIdx), fmt.Sprintf("I%d", rowIdx), centerStyle)

		// 2. STATUS KONTROLÜ (Sütun E)
		statusCell := fmt.Sprintf("E%d", rowIdx)
		if status == 200 {
			f.SetCellStyle(sheetName, statusCell, statusCell, goodStyle) // Yeşil
		} else {
			f.SetCellStyle(sheetName, statusCell, statusCell, badStyle) // Kırmızı
		}

		// 3. GECİKME (LATENCY) KONTROLÜ (Sütun F)
		// "56ms" stringini sayıya çevirmemiz lazım

		// Not: Bu importları dosyanın en üstüne eklemelisin, burada logic gösteriyorum:
		latStr := strings.TrimSuffix(latency, "ms")
		latVal, _ := strconv.Atoi(latStr)
		latCell := fmt.Sprintf("F%d", rowIdx)

		if latVal > 300 {
			f.SetCellStyle(sheetName, latCell, latCell, badStyle) // 300ms üstü Kırmızı
		} else if latVal > 100 {
			f.SetCellStyle(sheetName, latCell, latCell, warnStyle) // 100ms üstü Turuncu
		} else {
			f.SetCellStyle(sheetName, latCell, latCell, goodStyle) // Düşük ping Yeşil
		}

		// 4. DONANIM KONTROLÜ (CPU - Sütun G)
		cpuCell := fmt.Sprintf("G%d", rowIdx)
		if cpu > 80.0 {
			f.SetCellStyle(sheetName, cpuCell, cpuCell, badStyle)
		} else if cpu > 50.0 {
			f.SetCellStyle(sheetName, cpuCell, cpuCell, warnStyle)
		}

		rowIdx++
	}

	// 6. Sütun Genişlikleri
	f.SetColWidth(sheetName, "B", "B", 20)
	f.SetColWidth(sheetName, "C", "C", 25)
	f.SetColWidth(sheetName, "D", "D", 30)
	f.SetColWidth(sheetName, "F", "I", 12)

	// 7. İndirt
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=sentinel_renkli_rapor.xlsx")
	w.Header().Set("Content-Transfer-Encoding", "binary")
	f.WriteTo(w)
}

func main() {
	initDB()
	startTaskScheduler()
	http.HandleFunc("/ws", handleConnections)
	http.HandleFunc("/api/history", getHistory)
	http.HandleFunc("/api/targets", handleTargets)
	http.HandleFunc("/api/export", handleExport) // YENİ: Excel İndirme Linki
	http.HandleFunc("/api/agents", handleActiveAgents)
	http.Handle("/", http.FileServer(http.Dir("./web")))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
