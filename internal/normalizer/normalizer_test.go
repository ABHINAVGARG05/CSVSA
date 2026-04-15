package normalizer

import (
	"reflect"
	"testing"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

func TestNormalizeSeverity(t *testing.T) {
	n := NewNormalizer()

	tests := []struct {
		input    string
		expected models.Severity
	}{
		{"CRITICAL", models.SeverityCritical},
		{"critical", models.SeverityCritical},
		{"CRIT", models.SeverityCritical},
		{"HIGH", models.SeverityHigh},
		{"high", models.SeverityHigh},
		{"H", models.SeverityHigh},
		{"MEDIUM", models.SeverityMedium},
		{"MODERATE", models.SeverityMedium},
		{"MED", models.SeverityMedium},
		{"LOW", models.SeverityLow},
		{"NEGLIGIBLE", models.SeverityLow},
		{"INFO", models.SeverityLow},
		{"UNKNOWN", models.SeverityUnknown},
		{"", models.SeverityUnknown},
		{"RANDOM", models.SeverityUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := n.normalizeSeverity(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeSeverity(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNormalizeCVE(t *testing.T) {
	n := NewNormalizer()

	tests := []struct {
		input    string
		expected string
	}{
		{"CVE-2021-44228", "CVE-2021-44228"},
		{"cve-2021-44228", "CVE-2021-44228"},
		{"  CVE-2021-44228  ", "CVE-2021-44228"},
		{"GHSA-abc-123", "GHSA-ABC-123"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := n.normalizeCVE(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeCVE(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsValidVulnerability(t *testing.T) {
	n := NewNormalizer()

	tests := []struct {
		name     string
		vuln     models.Vulnerability
		expected bool
	}{
		{
			name: "valid vulnerability",
			vuln: models.Vulnerability{
				CVE:     "CVE-2021-44228",
				Package: "log4j",
			},
			expected: true,
		},
		{
			name: "missing CVE",
			vuln: models.Vulnerability{
				Package: "log4j",
			},
			expected: false,
		},
		{
			name: "missing package",
			vuln: models.Vulnerability{
				CVE: "CVE-2021-44228",
			},
			expected: false,
		},
		{
			name:     "empty vulnerability",
			vuln:     models.Vulnerability{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := n.isValidVulnerability(tt.vuln)
			if got != tt.expected {
				t.Errorf("isValidVulnerability() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDeduplicate(t *testing.T) {
	n := NewNormalizer()

	vulns := []models.Vulnerability{
		{
			CVE:              "CVE-2021-0001",
			Package:          "pkg1",
			InstalledVersion: "1.0.0",
			Scanner:          "trivy",
			Title:            "Title from Trivy",
		},
		{
			CVE:              "CVE-2021-0001",
			Package:          "pkg1",
			InstalledVersion: "1.0.0",
			Scanner:          "grype",
			Title:            "Title from Grype",
			Description:      "Detailed description", // More complete
		},
		{
			CVE:              "CVE-2021-0002",
			Package:          "pkg2",
			InstalledVersion: "2.0.0",
			Scanner:          "trivy",
		},
	}

	result := n.deduplicate(vulns)

	if len(result) != 2 {
		t.Errorf("Expected 2 vulnerabilities after dedup, got %d", len(result))
	}

	// Check that the more complete entry was kept
	for _, v := range result {
		if v.CVE == "CVE-2021-0001" {
			if v.Description != "Detailed description" {
				t.Error("Should have kept the more complete entry")
			}
		}
	}
}

func TestNormalizeResults(t *testing.T) {
	n := NewNormalizer()

	results := []models.ScanResult{
		{
			Scanner: "trivy",
			Success: true,
			Vulnerabilities: []models.Vulnerability{
				{
					CVE:              "CVE-2021-0001",
					Package:          "pkg1",
					InstalledVersion: "1.0.0",
					Severity:         models.SeverityCritical,
					Scanner:          "trivy",
				},
				{
					CVE:              "CVE-2021-0002",
					Package:          "pkg2",
					InstalledVersion: "2.0.0",
					Severity:         models.SeverityLow,
					Scanner:          "trivy",
				},
			},
		},
		{
			Scanner: "grype",
			Success: true,
			Vulnerabilities: []models.Vulnerability{
				{
					CVE:              "CVE-2021-0001",
					Package:          "pkg1",
					InstalledVersion: "1.0.0",
					Severity:         models.SeverityCritical,
					Scanner:          "grype",
				},
				{
					CVE:              "CVE-2021-0003",
					Package:          "pkg3",
					InstalledVersion: "3.0.0",
					Severity:         models.SeverityMedium,
					Scanner:          "grype",
				},
			},
		},
		{
			Scanner: "failed",
			Success: false, // Should be skipped
			Vulnerabilities: []models.Vulnerability{
				{CVE: "CVE-SHOULD-NOT-APPEAR"},
			},
		},
	}

	normalized := n.NormalizeResults(results)

	// Should have 3 unique vulnerabilities (deduped)
	if len(normalized) != 3 {
		t.Errorf("Expected 3 vulnerabilities, got %d", len(normalized))
	}

	// Should be sorted by severity (CRITICAL first)
	if normalized[0].Severity != models.SeverityCritical {
		t.Error("First vulnerability should be CRITICAL severity")
	}

	// Should not include failed scanner results
	for _, v := range normalized {
		if v.CVE == "CVE-SHOULD-NOT-APPEAR" {
			t.Error("Should not include vulnerabilities from failed scanner")
		}
	}
}

func TestFilterBySeverity(t *testing.T) {
	n := NewNormalizer()

	vulns := []models.Vulnerability{
		{CVE: "CVE-1", Severity: models.SeverityCritical},
		{CVE: "CVE-2", Severity: models.SeverityHigh},
		{CVE: "CVE-3", Severity: models.SeverityMedium},
		{CVE: "CVE-4", Severity: models.SeverityLow},
	}

	tests := []struct {
		minSeverity   models.Severity
		expectedCount int
	}{
		{models.SeverityCritical, 1},
		{models.SeverityHigh, 2},
		{models.SeverityMedium, 3},
		{models.SeverityLow, 4},
		{models.SeverityUnknown, 4},
	}

	for _, tt := range tests {
		t.Run(string(tt.minSeverity), func(t *testing.T) {
			filtered := n.FilterBySeverity(vulns, tt.minSeverity)
			if len(filtered) != tt.expectedCount {
				t.Errorf("FilterBySeverity(%s) returned %d, want %d",
					tt.minSeverity, len(filtered), tt.expectedCount)
			}
		})
	}
}

func TestMergeVulnerabilities(t *testing.T) {
	n := NewNormalizer()

	results := []models.ScanResult{
		{
			Scanner: "trivy",
			Success: true,
			Vulnerabilities: []models.Vulnerability{
				{CVE: "CVE-1", Package: "pkg1", InstalledVersion: "1.0", Severity: models.SeverityHigh, Scanner: "trivy"},
			},
		},
		{
			Scanner: "grype",
			Success: true,
			Vulnerabilities: []models.Vulnerability{
				{CVE: "CVE-1", Package: "pkg1", InstalledVersion: "1.0", Severity: models.SeverityHigh, Scanner: "grype"},
				{CVE: "CVE-2", Package: "pkg2", InstalledVersion: "2.0", Severity: models.SeverityLow, Scanner: "grype"},
			},
		},
	}

	merged := n.MergeVulnerabilities(results)
	if len(merged) != 2 {
		t.Errorf("expected 2 merged keys, got %d", len(merged))
	}

	key := "CVE-1|pkg1|1.0"
	if len(merged[key]) != 2 {
		t.Errorf("expected 2 entries for %s, got %d", key, len(merged[key]))
	}
}

func TestGroupByPackage(t *testing.T) {
	n := NewNormalizer()
	vulns := []models.Vulnerability{
		{CVE: "CVE-1", Package: "pkg1"},
		{CVE: "CVE-2", Package: "pkg1"},
		{CVE: "CVE-3", Package: "pkg2"},
	}

	groups := n.GroupByPackage(vulns)
	if len(groups) != 2 {
		t.Errorf("expected 2 package groups, got %d", len(groups))
	}
	if len(groups["pkg1"]) != 2 {
		t.Errorf("expected 2 vulns for pkg1, got %d", len(groups["pkg1"]))
	}
}

func TestGroupByScanner(t *testing.T) {
	n := NewNormalizer()
	vulns := []models.Vulnerability{
		{CVE: "CVE-1", Scanner: "trivy"},
		{CVE: "CVE-2", Scanner: "trivy"},
		{CVE: "CVE-3", Scanner: "grype"},
	}

	groups := n.GroupByScanner(vulns)
	if len(groups) != 2 {
		t.Errorf("expected 2 scanner groups, got %d", len(groups))
	}
	if len(groups["trivy"]) != 2 {
		t.Errorf("expected 2 vulns for trivy, got %d", len(groups["trivy"]))
	}
}

func TestGroupBySeverity(t *testing.T) {
	n := NewNormalizer()

	vulns := []models.Vulnerability{
		{CVE: "CVE-1", Severity: models.SeverityCritical},
		{CVE: "CVE-2", Severity: models.SeverityCritical},
		{CVE: "CVE-3", Severity: models.SeverityHigh},
		{CVE: "CVE-4", Severity: models.SeverityMedium},
	}

	groups := n.GroupBySeverity(vulns)

	if len(groups[models.SeverityCritical]) != 2 {
		t.Errorf("Expected 2 CRITICAL, got %d", len(groups[models.SeverityCritical]))
	}

	if len(groups[models.SeverityHigh]) != 1 {
		t.Errorf("Expected 1 HIGH, got %d", len(groups[models.SeverityHigh]))
	}

	if len(groups[models.SeverityMedium]) != 1 {
		t.Errorf("Expected 1 MEDIUM, got %d", len(groups[models.SeverityMedium]))
	}
}

func TestNormalizeReferences(t *testing.T) {
	n := NewNormalizer()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty",
			input:    []string{},
			expected: nil,
		},
		{
			name:     "nil",
			input:    nil,
			expected: nil,
		},
		{
			name:     "with duplicates",
			input:    []string{"http://example.com", "http://example.com", "http://other.com"},
			expected: []string{"http://example.com", "http://other.com"},
		},
		{
			name:     "with whitespace",
			input:    []string{"  http://example.com  ", "", "http://other.com"},
			expected: []string{"http://example.com", "http://other.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := n.normalizeReferences(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("normalizeReferences() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCompletenessScore(t *testing.T) {
	n := NewNormalizer()

	minimal := models.Vulnerability{
		CVE:     "CVE-2021-0001",
		Package: "pkg1",
	}

	complete := models.Vulnerability{
		CVE:              "CVE-2021-0001",
		Package:          "pkg1",
		InstalledVersion: "1.0.0",
		FixedVersion:     "1.0.1",
		Severity:         models.SeverityHigh,
		Title:            "A vulnerability",
		Description:      "Detailed description",
		References:       []string{"http://example.com"},
	}

	minScore := n.completenessScore(minimal)
	completeScore := n.completenessScore(complete)

	if completeScore <= minScore {
		t.Errorf("Complete vuln score (%d) should be > minimal score (%d)",
			completeScore, minScore)
	}
}
