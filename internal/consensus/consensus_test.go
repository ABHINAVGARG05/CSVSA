package consensus

import (
	"testing"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

// Helper to create test vulnerabilities
func makeVuln(cve, pkg, version string, severity models.Severity, scanner string) models.Vulnerability {
	return models.Vulnerability{
		CVE:              cve,
		Package:          pkg,
		InstalledVersion: version,
		Severity:         severity,
		Scanner:          scanner,
	}
}

// Helper to create test scan result
func makeScanResult(scanner string, success bool, vulns ...models.Vulnerability) models.ScanResult {
	return models.ScanResult{
		Scanner:         scanner,
		Success:         success,
		Vulnerabilities: vulns,
	}
}

func TestAnalyzeConsensus(t *testing.T) {
	analyzer := NewAnalyzer()

	// Create test data:
	// CVE-1: Found by both Trivy and Grype (consensus)
	// CVE-2: Found only by Trivy (unique to Trivy)
	// CVE-3: Found only by Grype (unique to Grype)

	trivyResult := makeScanResult("trivy", true,
		makeVuln("CVE-2021-0001", "pkg1", "1.0.0", models.SeverityCritical, "trivy"),
		makeVuln("CVE-2021-0002", "pkg2", "2.0.0", models.SeverityHigh, "trivy"),
	)

	grypeResult := makeScanResult("grype", true,
		makeVuln("CVE-2021-0001", "pkg1", "1.0.0", models.SeverityCritical, "grype"),
		makeVuln("CVE-2021-0003", "pkg3", "3.0.0", models.SeverityMedium, "grype"),
	)

	results := []models.ScanResult{trivyResult, grypeResult}
	consensus := analyzer.Analyze("test-image:latest", results)

	// Verify basic structure
	if consensus.Target != "test-image:latest" {
		t.Errorf("Target = %s, want test-image:latest", consensus.Target)
	}

	if len(consensus.Scanners) != 2 {
		t.Errorf("Scanners count = %d, want 2", len(consensus.Scanners))
	}

	// Verify consensus (should be CVE-2021-0001 only)
	if len(consensus.Consensus) != 1 {
		t.Errorf("Consensus count = %d, want 1", len(consensus.Consensus))
	}

	if len(consensus.Consensus) > 0 && consensus.Consensus[0].CVE != "CVE-2021-0001" {
		t.Errorf("Consensus CVE = %s, want CVE-2021-0001", consensus.Consensus[0].CVE)
	}

	// Verify unique findings
	if len(consensus.UniqueFindings["trivy"]) != 1 {
		t.Errorf("Trivy unique count = %d, want 1", len(consensus.UniqueFindings["trivy"]))
	}

	if len(consensus.UniqueFindings["grype"]) != 1 {
		t.Errorf("Grype unique count = %d, want 1", len(consensus.UniqueFindings["grype"]))
	}

	// Verify all vulnerabilities
	if len(consensus.AllVulnerabilities) != 3 {
		t.Errorf("All vulns count = %d, want 3", len(consensus.AllVulnerabilities))
	}

	// Verify overlap percentage (1 consensus / 3 total = 33.33%)
	expectedOverlap := 100.0 / 3.0 // ~33.33%
	if consensus.OverlapPercentage < expectedOverlap-1 || consensus.OverlapPercentage > expectedOverlap+1 {
		t.Errorf("Overlap = %.2f%%, want ~%.2f%%", consensus.OverlapPercentage, expectedOverlap)
	}
}

func TestAnalyzeWithFailedScanner(t *testing.T) {
	analyzer := NewAnalyzer()

	trivyResult := makeScanResult("trivy", true,
		makeVuln("CVE-2021-0001", "pkg1", "1.0.0", models.SeverityCritical, "trivy"),
	)

	// Failed scanner should be ignored
	grypeResult := makeScanResult("grype", false,
		makeVuln("CVE-2021-0002", "pkg2", "2.0.0", models.SeverityHigh, "grype"),
	)

	results := []models.ScanResult{trivyResult, grypeResult}
	consensus := analyzer.Analyze("test-image:latest", results)

	// Only trivy should be counted
	if len(consensus.Scanners) != 1 {
		t.Errorf("Scanners count = %d, want 1", len(consensus.Scanners))
	}

	// With only one scanner, all vulns are "consensus"
	if len(consensus.Consensus) != 1 {
		t.Errorf("Consensus count = %d, want 1", len(consensus.Consensus))
	}
}

func TestAnalyzePerfectConsensus(t *testing.T) {
	analyzer := NewAnalyzer()

	// Both scanners find exactly the same vulnerabilities
	sharedVulns := []models.Vulnerability{
		makeVuln("CVE-2021-0001", "pkg1", "1.0.0", models.SeverityCritical, ""),
		makeVuln("CVE-2021-0002", "pkg2", "2.0.0", models.SeverityHigh, ""),
	}

	trivyVulns := make([]models.Vulnerability, len(sharedVulns))
	grypeVulns := make([]models.Vulnerability, len(sharedVulns))
	for i, v := range sharedVulns {
		trivyVulns[i] = v
		trivyVulns[i].Scanner = "trivy"
		grypeVulns[i] = v
		grypeVulns[i].Scanner = "grype"
	}

	results := []models.ScanResult{
		makeScanResult("trivy", true, trivyVulns...),
		makeScanResult("grype", true, grypeVulns...),
	}

	consensus := analyzer.Analyze("test-image:latest", results)

	// 100% overlap expected
	if consensus.OverlapPercentage != 100.0 {
		t.Errorf("Overlap = %.2f%%, want 100%%", consensus.OverlapPercentage)
	}

	// All vulns should be in consensus
	if len(consensus.Consensus) != 2 {
		t.Errorf("Consensus count = %d, want 2", len(consensus.Consensus))
	}

	// No unique findings
	if len(consensus.UniqueFindings["trivy"]) != 0 {
		t.Errorf("Trivy unique count = %d, want 0", len(consensus.UniqueFindings["trivy"]))
	}

	if len(consensus.UniqueFindings["grype"]) != 0 {
		t.Errorf("Grype unique count = %d, want 0", len(consensus.UniqueFindings["grype"]))
	}
}

func TestAnalyzeNoConsensus(t *testing.T) {
	analyzer := NewAnalyzer()

	// Scanners find completely different vulnerabilities
	trivyResult := makeScanResult("trivy", true,
		makeVuln("CVE-2021-0001", "pkg1", "1.0.0", models.SeverityCritical, "trivy"),
		makeVuln("CVE-2021-0002", "pkg2", "2.0.0", models.SeverityHigh, "trivy"),
	)

	grypeResult := makeScanResult("grype", true,
		makeVuln("CVE-2021-0003", "pkg3", "3.0.0", models.SeverityMedium, "grype"),
		makeVuln("CVE-2021-0004", "pkg4", "4.0.0", models.SeverityLow, "grype"),
	)

	results := []models.ScanResult{trivyResult, grypeResult}
	consensus := analyzer.Analyze("test-image:latest", results)

	// 0% overlap expected
	if consensus.OverlapPercentage != 0.0 {
		t.Errorf("Overlap = %.2f%%, want 0%%", consensus.OverlapPercentage)
	}

	// No consensus
	if len(consensus.Consensus) != 0 {
		t.Errorf("Consensus count = %d, want 0", len(consensus.Consensus))
	}

	// All findings are unique
	if len(consensus.UniqueFindings["trivy"]) != 2 {
		t.Errorf("Trivy unique count = %d, want 2", len(consensus.UniqueFindings["trivy"]))
	}

	if len(consensus.UniqueFindings["grype"]) != 2 {
		t.Errorf("Grype unique count = %d, want 2", len(consensus.UniqueFindings["grype"]))
	}
}

func TestConfidenceCalculation(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name          string
		scannerCount  int
		foundByCount  int
		expectedLevel models.ConfidenceLevel
	}{
		{"all scanners", 3, 3, models.ConfidenceHigh},
		{"majority", 3, 2, models.ConfidenceMedium},
		{"minority", 3, 1, models.ConfidenceLow},
		{"single scanner all", 1, 1, models.ConfidenceHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			occ := &VulnerabilityOccurrence{
				Count: tt.foundByCount,
			}

			score := analyzer.CalculateConfidence(occ, tt.scannerCount)

			if score.Level != tt.expectedLevel {
				t.Errorf("Confidence = %v, want %v", score.Level, tt.expectedLevel)
			}
		})
	}
}

func TestComputeStatistics(t *testing.T) {
	analyzer := NewAnalyzer()

	trivyResult := makeScanResult("trivy", true,
		makeVuln("CVE-2021-0001", "pkg1", "1.0.0", models.SeverityCritical, "trivy"),
		makeVuln("CVE-2021-0002", "pkg2", "2.0.0", models.SeverityHigh, "trivy"),
	)

	grypeResult := makeScanResult("grype", true,
		makeVuln("CVE-2021-0001", "pkg1", "1.0.0", models.SeverityCritical, "grype"),
		makeVuln("CVE-2021-0003", "pkg3", "3.0.0", models.SeverityMedium, "grype"),
	)

	results := []models.ScanResult{trivyResult, grypeResult}
	consensusResult := analyzer.Analyze("test-image:latest", results)
	stats := analyzer.ComputeStatistics(consensusResult)

	if stats.TotalVulnerabilities != 3 {
		t.Errorf("TotalVulnerabilities = %d, want 3", stats.TotalVulnerabilities)
	}

	if stats.ConsensusCount != 1 {
		t.Errorf("ConsensusCount = %d, want 1", stats.ConsensusCount)
	}

	if stats.UniqueCount["trivy"] != 1 {
		t.Errorf("Trivy unique = %d, want 1", stats.UniqueCount["trivy"])
	}

	if stats.UniqueCount["grype"] != 1 {
		t.Errorf("Grype unique = %d, want 1", stats.UniqueCount["grype"])
	}
}

func TestSortBySeverity(t *testing.T) {
	vulns := []models.Vulnerability{
		makeVuln("CVE-3", "pkg", "1.0", models.SeverityLow, "test"),
		makeVuln("CVE-1", "pkg", "1.0", models.SeverityCritical, "test"),
		makeVuln("CVE-2", "pkg", "1.0", models.SeverityHigh, "test"),
		makeVuln("CVE-4", "pkg", "1.0", models.SeverityMedium, "test"),
	}

	sortBySeverity(vulns)

	expectedOrder := []string{"CVE-1", "CVE-2", "CVE-4", "CVE-3"}
	for i, v := range vulns {
		if v.CVE != expectedOrder[i] {
			t.Errorf("Position %d: got %s, want %s", i, v.CVE, expectedOrder[i])
		}
	}
}

func TestAgreementMatrix(t *testing.T) {
	analyzer := NewAnalyzer()

	// CVE-1: Found by trivy and grype
	// CVE-2: Found only by trivy
	// CVE-3: Found only by grype

	results := []models.ScanResult{
		makeScanResult("trivy", true,
			makeVuln("CVE-2021-0001", "pkg1", "1.0.0", models.SeverityCritical, "trivy"),
			makeVuln("CVE-2021-0002", "pkg2", "2.0.0", models.SeverityHigh, "trivy"),
		),
		makeScanResult("grype", true,
			makeVuln("CVE-2021-0001", "pkg1", "1.0.0", models.SeverityCritical, "grype"),
			makeVuln("CVE-2021-0003", "pkg3", "3.0.0", models.SeverityMedium, "grype"),
		),
	}

	matrix := analyzer.computeAgreementMatrix(results)

	// Trivy found 2 vulns total
	if matrix["trivy"]["trivy"] != 2 {
		t.Errorf("trivy-trivy agreement = %d, want 2", matrix["trivy"]["trivy"])
	}

	// Grype found 2 vulns total
	if matrix["grype"]["grype"] != 2 {
		t.Errorf("grype-grype agreement = %d, want 2", matrix["grype"]["grype"])
	}

	// Both found 1 vuln in common
	if matrix["trivy"]["grype"] != 1 {
		t.Errorf("trivy-grype agreement = %d, want 1", matrix["trivy"]["grype"])
	}

	// Matrix should be symmetric
	if matrix["grype"]["trivy"] != matrix["trivy"]["grype"] {
		t.Error("Agreement matrix should be symmetric")
	}
}

func TestEmptyResults(t *testing.T) {
	analyzer := NewAnalyzer()

	// Test with no results
	result := analyzer.Analyze("test-image:latest", []models.ScanResult{})

	if len(result.Consensus) != 0 {
		t.Errorf("Consensus should be empty, got %d", len(result.Consensus))
	}

	if result.OverlapPercentage != 0 {
		t.Errorf("Overlap should be 0%%, got %.2f%%", result.OverlapPercentage)
	}
}

func TestMergeReferences(t *testing.T) {
	refs1 := []string{"http://a.com", "http://b.com"}
	refs2 := []string{"http://b.com", "http://c.com"}

	merged := mergeReferences(refs1, refs2)

	if len(merged) != 3 {
		t.Errorf("Merged refs count = %d, want 3", len(merged))
	}

	// Check all refs are present
	refSet := make(map[string]bool)
	for _, ref := range merged {
		refSet[ref] = true
	}

	expected := []string{"http://a.com", "http://b.com", "http://c.com"}
	for _, exp := range expected {
		if !refSet[exp] {
			t.Errorf("Missing reference: %s", exp)
		}
	}
}
