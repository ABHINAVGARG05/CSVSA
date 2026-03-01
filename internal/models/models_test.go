package models

import (
	"testing"
	"time"
)

func TestSeverityWeight(t *testing.T) {
	tests := []struct {
		severity Severity
		expected int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{SeverityUnknown, 0},
		{Severity("INVALID"), 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			if got := tt.severity.Weight(); got != tt.expected {
				t.Errorf("Severity(%q).Weight() = %d, want %d", tt.severity, got, tt.expected)
			}
		})
	}
}

func TestSeverityIsValid(t *testing.T) {
	validSeverities := []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityUnknown,
	}

	for _, s := range validSeverities {
		if !s.IsValid() {
			t.Errorf("Severity(%q).IsValid() = false, want true", s)
		}
	}

	invalidSeverities := []Severity{
		Severity("INVALID"),
		Severity(""),
		Severity("critical"), // lowercase should be invalid
	}

	for _, s := range invalidSeverities {
		if s.IsValid() {
			t.Errorf("Severity(%q).IsValid() = true, want false", s)
		}
	}
}

func TestVulnerabilityKey(t *testing.T) {
	v := &Vulnerability{
		CVE:              "CVE-2021-44228",
		Package:          "log4j-core",
		InstalledVersion: "2.14.1",
		Severity:         SeverityCritical,
		Scanner:          "trivy",
	}

	expected := "CVE-2021-44228|log4j-core|2.14.1"
	if got := v.Key(); got != expected {
		t.Errorf("Vulnerability.Key() = %q, want %q", got, expected)
	}
}

func TestScanResultCountBySeverity(t *testing.T) {
	result := &ScanResult{
		Vulnerabilities: []Vulnerability{
			{CVE: "CVE-1", Severity: SeverityCritical},
			{CVE: "CVE-2", Severity: SeverityCritical},
			{CVE: "CVE-3", Severity: SeverityHigh},
			{CVE: "CVE-4", Severity: SeverityMedium},
			{CVE: "CVE-5", Severity: SeverityLow},
			{CVE: "CVE-6", Severity: SeverityLow},
			{CVE: "CVE-7", Severity: SeverityLow},
		},
	}

	counts := result.CountBySeverity()

	expected := map[Severity]int{
		SeverityCritical: 2,
		SeverityHigh:     1,
		SeverityMedium:   1,
		SeverityLow:      3,
	}

	for sev, expectedCount := range expected {
		if counts[sev] != expectedCount {
			t.Errorf("CountBySeverity()[%s] = %d, want %d", sev, counts[sev], expectedCount)
		}
	}
}

func TestConsensusResultSuccessfulScanners(t *testing.T) {
	result := &ConsensusResult{
		ScanResults: []ScanResult{
			{Scanner: "trivy", Success: true},
			{Scanner: "grype", Success: true},
			{Scanner: "snyk", Success: false},
		},
	}

	if got := result.SuccessfulScanners(); got != 2 {
		t.Errorf("SuccessfulScanners() = %d, want 2", got)
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 5*time.Minute {
		t.Errorf("DefaultConfig().Timeout = %v, want 5m", config.Timeout)
	}

	if len(config.Scanners) != 0 {
		t.Errorf("DefaultConfig().Scanners should be empty, got %v", config.Scanners)
	}

	if len(config.OutputFormat) != 1 || config.OutputFormat[0] != "table" {
		t.Errorf("DefaultConfig().OutputFormat = %v, want [table]", config.OutputFormat)
	}

	if config.Verbose {
		t.Error("DefaultConfig().Verbose should be false")
	}

	if config.FailOnVulnerability {
		t.Error("DefaultConfig().FailOnVulnerability should be false")
	}
}
