package cli

import (
	"testing"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected models.Severity
	}{
		{"CRITICAL", models.SeverityCritical},
		{"high", models.SeverityHigh},
		{"Medium", models.SeverityMedium},
		{"low", models.SeverityLow},
		{"unknown", models.SeverityUnknown},
		{"", models.SeverityUnknown},
	}

	for _, tt := range tests {
		got := parseSeverity(tt.input)
		if got != tt.expected {
			t.Errorf("parseSeverity(%q) = %s, want %s", tt.input, got, tt.expected)
		}
	}
}

func TestCountKEV(t *testing.T) {
	vulns := []models.Vulnerability{
		{CVE: "CVE-1", KEV: &models.KEVInfo{IsKEV: true}},
		{CVE: "CVE-2", KEV: &models.KEVInfo{IsKEV: false}},
		{CVE: "CVE-3"},
	}

	if got := countKEV(vulns); got != 1 {
		t.Errorf("countKEV() = %d, want 1", got)
	}
}

func TestFilterConsensusResult(t *testing.T) {
	result := &models.ConsensusResult{
		Consensus: []models.Vulnerability{
			{CVE: "CVE-1", Severity: models.SeverityHigh, KEV: &models.KEVInfo{IsKEV: true}},
			{CVE: "CVE-2", Severity: models.SeverityLow},
		},
		UniqueFindings: map[string][]models.Vulnerability{
			"trivy": {
				{CVE: "CVE-3", Severity: models.SeverityMedium, KEV: &models.KEVInfo{IsKEV: true}},
			},
			"grype": {
				{CVE: "CVE-4", Severity: models.SeverityLow},
			},
		},
		AllVulnerabilities: []models.Vulnerability{
			{CVE: "CVE-1", Severity: models.SeverityHigh, KEV: &models.KEVInfo{IsKEV: true}},
			{CVE: "CVE-2", Severity: models.SeverityLow},
			{CVE: "CVE-3", Severity: models.SeverityMedium, KEV: &models.KEVInfo{IsKEV: true}},
			{CVE: "CVE-4", Severity: models.SeverityLow},
		},
	}

	filterConsensusResult(result, models.SeverityHigh)

	if len(result.Consensus) != 1 {
		t.Errorf("Consensus count = %d, want 1", len(result.Consensus))
	}
	if len(result.AllVulnerabilities) != 1 {
		t.Errorf("AllVulnerabilities count = %d, want 1", len(result.AllVulnerabilities))
	}
	if result.OverlapPercentage != 100 {
		t.Errorf("OverlapPercentage = %.2f, want 100", result.OverlapPercentage)
	}
	if result.Statistics.KEVConsensusCount != 1 {
		t.Errorf("KEVConsensusCount = %d, want 1", result.Statistics.KEVConsensusCount)
	}
	if result.Statistics.KEVCount != 1 {
		t.Errorf("KEVCount = %d, want 1", result.Statistics.KEVCount)
	}
}

func TestFilterConsensusResultEmpty(t *testing.T) {
	result := &models.ConsensusResult{
		Consensus: []models.Vulnerability{
			{CVE: "CVE-1", Severity: models.SeverityLow},
		},
		AllVulnerabilities: []models.Vulnerability{
			{CVE: "CVE-1", Severity: models.SeverityLow},
		},
	}

	filterConsensusResult(result, models.SeverityCritical)

	if len(result.AllVulnerabilities) != 0 {
		t.Errorf("AllVulnerabilities count = %d, want 0", len(result.AllVulnerabilities))
	}
	if result.OverlapPercentage != 0 {
		t.Errorf("OverlapPercentage = %.2f, want 0", result.OverlapPercentage)
	}
}
