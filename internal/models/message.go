package models

// Hem Ajanın hem Komutanın kullanacağı ortak mesaj yapısı
type Command struct {
	Type   string `json:"type"`   // Mesaj tipi: "PING_ISTEGI", "RAPOR"
	Target string `json:"target"` // Hedef: "google.com"
	Status int    `json:"status"` // Sonuç kodu: 200, 404, 500
	Time   string `json:"time"`   // Gecikme süresi: "45ms"
	Agent  string `json:"agent"`  // Agent Adı:  Agent-İzmir_Konak_POP
}
