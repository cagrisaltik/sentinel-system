package models

// Hem Ajanın hem Komutanın kullanacağı ortak mesaj yapısı
type Command struct {
	Type      string `json:"type"` // Mesaj tipi: "PING_ISTEGI", "RAPOR"
	TaskID    string `json:"task_id,omitempty"`
	Target    string `json:"target"` // Hedef: "google.com"
	Status    int    `json:"status"` // Sonuç kodu: 200, 404, 500
	Time      string `json:"time"`   // Gecikme süresi: "45ms"
	Agent     string `json:"agent"`  // Agent Adı:  Agent-İzmir_Konak_POP
	IssuedAt  string `json:"issued_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`

	// --- YENİ EKLENEN DONANIM BİLGİLERİ ---
	CPU  float64 `json:"cpu"`  // Yüzde kaç işlemci kullanılıyor?
	RAM  float64 `json:"ram"`  // Yüzde kaç RAM dolu?
	Disk float64 `json:"disk"` // Disk doluluk oranı
}
