package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cagrisaltik/sentinel-system/internal/models"
)

const scoutTaskID = "550e8400-e29b-41d4-a716-446655440000"

func validPing(now time.Time) models.Command {
	return models.Command{
		Type:      "PING_REQUEST",
		TaskID:    scoutTaskID,
		Agent:     "scout-1",
		Target:    "example.com",
		IssuedAt:  now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano),
	}
}

func resetSeenTasks() {
	seenTasksMu.Lock()
	seenTasks = make(map[string]time.Time)
	seenTasksMu.Unlock()
}

func TestAuthorizePingUsesModelsCommand(t *testing.T) {
	resetSeenTasks()
	now := time.Now().UTC()
	if !authorizePing(validPing(now), "scout-1", now) {
		t.Fatal("valid UUID task was rejected")
	}
}

func TestAuthorizePingRejectsInvalidTaskIDsAndAgent(t *testing.T) {
	now := time.Now().UTC()
	for _, taskID := range []string{"", "task", "550e8400e29b41d4a716446655440000"} {
		msg := validPing(now)
		msg.TaskID = taskID
		if authorizePing(msg, "scout-1", now) {
			t.Errorf("invalid task_id %q accepted", taskID)
		}
	}

	msg := validPing(now)
	msg.Agent = "scout-2"
	if authorizePing(msg, "scout-1", now) {
		t.Fatal("task for another agent was accepted")
	}
}

func TestAuthorizePingRejectsMalformedTimestamps(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		name   string
		mutate func(*models.Command)
	}{
		{name: "issued_at", mutate: func(msg *models.Command) { msg.IssuedAt = "invalid" }},
		{name: "expires_at", mutate: func(msg *models.Command) { msg.ExpiresAt = "invalid" }},
	} {
		msg := validPing(now)
		test.mutate(&msg)
		if authorizePing(msg, "scout-1", now) {
			t.Errorf("malformed %s accepted", test.name)
		}
	}
}

func TestClaimTaskRejectsInvalidTimestampsAndLifetime(t *testing.T) {
	now := time.Now().UTC()
	if claimTask(scoutTaskID, now.Add(time.Second), now.Add(20*time.Second), now) {
		t.Fatal("future issued_at accepted")
	}
	if claimTask("550e8400-e29b-41d4-a716-446655440001", now.Add(-time.Minute), now.Add(-time.Second), now) {
		t.Fatal("expired task accepted")
	}
	if claimTask("550e8400-e29b-41d4-a716-446655440002", now, now.Add(maxTaskLifetime+time.Second), now) {
		t.Fatal("excessive task lifetime accepted")
	}
	if claimTask("550e8400-e29b-41d4-a716-446655440003", now, now, now) {
		t.Fatal("expires_at equal to issued_at accepted")
	}
}

func TestClaimTaskRejectsDuplicateTask(t *testing.T) {
	resetSeenTasks()
	now := time.Now().UTC()
	if !claimTask(scoutTaskID, now, now.Add(20*time.Second), now) || claimTask(scoutTaskID, now, now.Add(20*time.Second), now) {
		t.Fatal("duplicate task claim accepted")
	}
}

func TestSafeTargetRejectsShellSyntax(t *testing.T) {
	for _, target := range []string{"example.com;whoami", "$(whoami)", "example.com&x", "-bad.example", "a..example"} {
		if safeTarget(target) {
			t.Errorf("unsafe target accepted: %q", target)
		}
	}
	for _, target := range []string{"192.0.2.1", "2001:db8::1", "example.com", "agent-01.internal.example"} {
		if !safeTarget(target) {
			t.Errorf("valid IP/domain rejected: %q", target)
		}
	}
}

func TestLoadScoutConfigFailsClosedAndRequiresWSS(t *testing.T) {
	values := map[string]string{
		"COMMANDER_URL":   "wss://commander.sentinel.test:8080",
		"TLS_CA_FILE":     "ca.pem",
		"AGENT_NAME":      "scout-1",
		"TLS_CLIENT_CERT": "client.crt",
		"TLS_CLIENT_KEY":  "client.key",
	}
	for name, value := range values {
		t.Setenv(name, value)
	}
	t.Setenv("TLS_CLIENT_KEY_PASSWORD", "")
	for name, value := range values {
		t.Setenv(name, "")
		if _, err := loadScoutConfig(); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("missing %s was not rejected specifically: %v", name, err)
		}
		t.Setenv(name, value)
	}

	t.Setenv("COMMANDER_URL", "https://commander.sentinel.test:8080")
	if _, err := loadScoutConfig(); err == nil {
		t.Fatal("non-WebSocket TLS URL accepted")
	}
	t.Setenv("COMMANDER_URL", "wss://commander.sentinel.test:8080")
	cfg, err := loadScoutConfig()
	if err != nil {
		t.Fatalf("valid Scout configuration rejected: %v", err)
	}
	if cfg.agentName != "scout-1" {
		t.Fatalf("loaded agent name = %q, want scout-1", cfg.agentName)
	}
	t.Setenv("AGENT_NAME", "scout;1")
	if _, err := loadScoutConfig(); err == nil {
		t.Fatal("invalid agent name accepted")
	}
}

func TestLoadClientCertificateRejectsMismatchedKey(t *testing.T) {
	tempDir := t.TempDir()
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "scout-1"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &certKey.PublicKey, certKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(tempDir, "client.crt")
	keyPath := filepath.Join(tempDir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadClientCertificate(certPath, keyPath, ""); err == nil {
		t.Fatal("mismatched client certificate and key accepted")
	}
}
