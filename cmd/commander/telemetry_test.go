package main

import (
	"testing"

	"github.com/cagrisaltik/sentinel-system/internal/models"
)

func validTelemetryReport() models.Command {
	return models.Command{
		Type:   "REPORT",
		Status: 200,
		Time:   "45ms",
		Agent:  "scout-1",
		CPU:    25,
		RAM:    50,
		Disk:   75,
	}
}

func TestValidReportTelemetry(t *testing.T) {
	if !validReportTelemetry(validTelemetryReport(), "scout-1") {
		t.Fatal("valid telemetry was rejected")
	}

	failedReport := validTelemetryReport()
	failedReport.Status = 500
	if !validReportTelemetry(failedReport, "scout-1") {
		t.Fatal("Scout's failure status was rejected")
	}
}

func TestReportTelemetryRejectsOutOfRangePercentages(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*models.Command)
	}{
		{name: "CPU below zero", mutate: func(msg *models.Command) { msg.CPU = -0.01 }},
		{name: "CPU above one hundred", mutate: func(msg *models.Command) { msg.CPU = 100.01 }},
		{name: "RAM below zero", mutate: func(msg *models.Command) { msg.RAM = -0.01 }},
		{name: "RAM above one hundred", mutate: func(msg *models.Command) { msg.RAM = 100.01 }},
		{name: "Disk below zero", mutate: func(msg *models.Command) { msg.Disk = -0.01 }},
		{name: "Disk above one hundred", mutate: func(msg *models.Command) { msg.Disk = 100.01 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msg := validTelemetryReport()
			test.mutate(&msg)
			if validReportTelemetry(msg, "scout-1") {
				t.Fatal("out-of-range percentage was accepted")
			}
		})
	}
}

func TestReportTelemetryRejectsMismatchedAgent(t *testing.T) {
	msg := validTelemetryReport()
	msg.Agent = "scout-2"
	if validReportTelemetry(msg, "scout-1") {
		t.Fatal("REPORT for a different agent was accepted")
	}
}

func TestReportTelemetryRejectsUnknownStatus(t *testing.T) {
	msg := validTelemetryReport()
	msg.Status = 404
	if validReportTelemetry(msg, "scout-1") {
		t.Fatal("status not produced by Scout was accepted")
	}
}

func TestReportTelemetryPreservesTimeLengthLimit(t *testing.T) {
	msg := validTelemetryReport()
	msg.Time = string(make([]byte, maxReportTimeLength+1))
	if validReportTelemetry(msg, "scout-1") {
		t.Fatal("overlong Time value was accepted")
	}
}
