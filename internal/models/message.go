package models

// Shared message structure used by both agents and Commander
type Command struct {
	Type      string `json:"type"` // Message type: "PING_REQUEST", "REPORT"
	TaskID    string `json:"task_id,omitempty"`
	Target    string `json:"target"` // Target: "google.com"
	Status    int    `json:"status"` // Result code: 200, 404, or 500
	Time      string `json:"time"`   // Latency: "45ms"
	Agent     string `json:"agent"`  // Agent name: Agent-Izmir_Konak_POP
	IssuedAt  string `json:"issued_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`

	// --- ADDED SYSTEM METRICS ---
	CPU  float64 `json:"cpu"`  // CPU utilization percentage.
	RAM  float64 `json:"ram"`  // RAM utilization percentage.
	Disk float64 `json:"disk"` // Disk utilization percentage
}
