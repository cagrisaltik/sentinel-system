package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const validReportTaskID = "550e8400-e29b-41d4-a716-446655440000"
const validReportFingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestAuthorizeReport(t *testing.T) {
	now := time.Now()
	reset := func() {
		tasksMu.Lock()
		pendingTasks = map[string]*pendingTask{
			validReportTaskID: {Agent: "scout-1", CertificateFingerprint: validReportFingerprint, Target: "example.com", ExpiresAt: now.Add(time.Minute)},
		}
		tasksMu.Unlock()
	}

	t.Run("wrong task id", func(t *testing.T) {
		reset()
		if claimReport("550e8400-e29b-41d4-a716-446655440001", "scout-1", validReportFingerprint, "example.com", now) {
			t.Fatal("unknown task_id was authorized")
		}
	})
	t.Run("wrong target", func(t *testing.T) {
		reset()
		if claimReport(validReportTaskID, "scout-1", validReportFingerprint, "other.example", now) {
			t.Fatal("wrong target was authorized")
		}
	})
	t.Run("wrong agent", func(t *testing.T) {
		reset()
		if claimReport(validReportTaskID, "scout-2", validReportFingerprint, "example.com", now) {
			t.Fatal("wrong agent was authorized")
		}
	})
	t.Run("wrong certificate fingerprint", func(t *testing.T) {
		reset()
		if claimReport(validReportTaskID, "scout-1", strings.Repeat("b", 64), "example.com", now) {
			t.Fatal("report from another certificate identity was authorized")
		}
	})
	t.Run("duplicate report", func(t *testing.T) {
		reset()
		if !claimReport(validReportTaskID, "scout-1", validReportFingerprint, "example.com", now) {
			t.Fatal("task report must be accepted once")
		}
		finishReport(validReportTaskID, true)
		if claimReport(validReportTaskID, "scout-1", validReportFingerprint, "example.com", now) {
			t.Fatal("duplicate report accepted")
		}
	})
	t.Run("DB failure permits retry and does not report success", func(t *testing.T) {
		reset()
		if !claimReport(validReportTaskID, "scout-1", validReportFingerprint, "example.com", now) {
			t.Fatal("initial claim failed")
		}
		finishReport(validReportTaskID, false)
		if pendingTasks[validReportTaskID].Reported {
			t.Fatal("failed DB insert marked report successful")
		}
		if !claimReport(validReportTaskID, "scout-1", validReportFingerprint, "example.com", now) {
			t.Fatal("retry was not permitted")
		}
	})
	t.Run("concurrent claim rejected", func(t *testing.T) {
		reset()
		if !claimReport(validReportTaskID, "scout-1", validReportFingerprint, "example.com", now) || claimReport(validReportTaskID, "scout-1", validReportFingerprint, "example.com", now) {
			t.Fatal("second claim accepted")
		}
	})
	t.Run("unknown message type", func(t *testing.T) {
		if validAgentMessageType("UNRECOGNIZED") {
			t.Fatal("unknown message type was accepted")
		}
	})
}

func TestTaskIDValidation(t *testing.T) {
	if !validTaskID(validReportTaskID) || !validTaskID("550E8400-E29B-41D4-A716-446655440000") {
		t.Fatal("valid UUID task_id rejected")
	}
	for _, taskID := range []string{"", "task-1", "550e8400e29b41d4a716446655440000", "{550e8400-e29b-41d4-a716-446655440000}"} {
		if validTaskID(taskID) {
			t.Fatalf("invalid task_id accepted: %q", taskID)
		}
	}
}

func TestCreatePendingTaskRejectsDuplicateAgentTarget(t *testing.T) {
	tasksMu.Lock()
	pendingTasks = make(map[string]*pendingTask)
	tasksMu.Unlock()
	now := time.Now()
	if !createPendingTask(validReportTaskID, "scout-1", validReportFingerprint, "example.com", now.Add(time.Minute), now) {
		t.Fatal("initial task was not created")
	}
	if createPendingTask("550e8400-e29b-41d4-a716-446655440001", "scout-1", validReportFingerprint, "example.com", now.Add(time.Minute), now) {
		t.Fatal("duplicate active task for agent and target was created")
	}
	if !createPendingTask("550e8400-e29b-41d4-a716-446655440002", "scout-2", strings.Repeat("b", 64), "example.com", now.Add(time.Minute), now) {
		t.Fatal("different agent should be allowed to use the same target")
	}
}

func TestHandleLogoutOnlyAcceptsPost(t *testing.T) {
	getResponse := httptest.NewRecorder()
	handleLogout(getResponse, httptest.NewRequest(http.MethodGet, "/api/logout", nil))
	if getResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout status = %d, want %d", getResponse.Code, http.StatusMethodNotAllowed)
	}

	postResponse := httptest.NewRecorder()
	handleLogout(postResponse, httptest.NewRequest(http.MethodPost, "/api/logout", nil))
	if postResponse.Code != http.StatusSeeOther {
		t.Fatalf("POST logout status = %d, want %d", postResponse.Code, http.StatusSeeOther)
	}
}

func TestWebSocketOriginRejectsEmptyAndUnknown(t *testing.T) {
	previous := cfg.AllowedOrigins
	cfg.AllowedOrigins = map[string]bool{"https://commander.sentinel.test:8080": true}
	defer func() { cfg.AllowedOrigins = previous }()

	for _, test := range []struct {
		origin string
		want   bool
	}{
		{origin: "https://commander.sentinel.test:8080", want: true},
		{origin: "", want: false},
		{origin: "https://attacker.example", want: false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/ws", nil)
		if test.origin != "" {
			req.Header.Set("Origin", test.origin)
		}
		if got := upgrader.CheckOrigin(req); got != test.want {
			t.Errorf("CheckOrigin(%q) = %t, want %t", test.origin, got, test.want)
		}
	}
}

func TestRequireMTLSSetting(t *testing.T) {
	for _, value := range []string{"", "true", "1"} {
		if err := requireMTLSSetting(value); err != nil {
			t.Errorf("requireMTLSSetting(%q) returned error: %v", value, err)
		}
	}
	for _, value := range []string{"false", "0", "invalid"} {
		if err := requireMTLSSetting(value); err == nil {
			t.Errorf("requireMTLSSetting(%q) accepted insecure or invalid value", value)
		}
	}
}
