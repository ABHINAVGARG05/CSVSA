// Package tests contains integration tests for the CSVSA tool.
// These tests verify that all components work together correctly.
//
// Integration Test Strategy:
// 1. Use real scanner JSON output files as test fixtures
// 2. Test the full pipeline: parsing -> normalizing -> consensus -> reporting
// 3. Verify cross-scanner vulnerability matching
// 4. Test edge cases and error handling
package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ABHINAVGARG05/CSVSA/internal/consensus"
	"github.com/ABHINAVGARG05/CSVSA/internal/models"
	"github.com/ABHINAVGARG05/CSVSA/internal/normalizer"
	"github.com/ABHINAVGARG05/CSVSA/internal/report"
	"github.com/ABHINAVGARG05/CSVSA/internal/scanner"
)

// testDataPath returns the path to test data files.
func testDataPath(t *testing.T, filename string) string {
	t.Helper()
	return filepath.Join("testdata", filename)
}

// loadTestData reads a test data file and returns its contents.
func loadTestData(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(testDataPath(t, filename))
	if err != nil {
		t.Fatalf("failed to load test data %s: %v", filename, err)
	}
	return data
}

// TestTrivyOutputParsing verifies that Trivy JSON output is correctly parsed.
func TestTrivyOutputParsing(t *testing.T) {
	data := loadTestData(t, "trivy_output.json")

	trivyScanner := scanner.NewTrivyScanner()
	vulns, err := trivyScanner.ParseOutputForTest(data)
	if err != nil {
		t.Fatalf("failed to parse Trivy output: %v", err)
	}

	// Verify expected vulnerabilities
	if len(vulns) != 4 {
		t.Errorf("expected 4 vulnerabilities, got %d", len(vulns))
	}

	// Check for specific CVEs
	cveMap := make(map[string]models.Vulnerability)
	for _, v := range vulns {
		cveMap[v.CVE] = v
	}

	// Verify CVE-2023-5363 (HIGH)
	if v, ok := cveMap["CVE-2023-5363"]; ok {
		if v.Package != "libssl3" {
			t.Errorf("CVE-2023-5363: expected package libssl3, got %s", v.Package)
		}
		if v.Severity != models.SeverityHigh {
			t.Errorf("CVE-2023-5363: expected severity HIGH, got %s", v.Severity)
		}
		if v.InstalledVersion != "3.1.2-r0" {
			t.Errorf("CVE-2023-5363: expected version 3.1.2-r0, got %s", v.InstalledVersion)
		}
	} else {
		t.Error("CVE-2023-5363 not found in parsed output")
	}

	// Verify CVE-2024-0727 (LOW)
	if v, ok := cveMap["CVE-2024-0727"]; ok {
		if v.Severity != models.SeverityLow {
			t.Errorf("CVE-2024-0727: expected severity LOW, got %s", v.Severity)
		}
	} else {
		t.Error("CVE-2024-0727 not found in parsed output")
	}
}

// TestGrypeOutputParsing verifies that Grype JSON output is correctly parsed.
func TestGrypeOutputParsing(t *testing.T) {
	data := loadTestData(t, "grype_output.json")

	grypeScanner := scanner.NewGrypeScanner()
	vulns, err := grypeScanner.ParseOutputForTest(data)
	if err != nil {
		t.Fatalf("failed to parse Grype output: %v", err)
	}

	// Verify expected vulnerabilities
	if len(vulns) != 3 {
		t.Errorf("expected 3 vulnerabilities, got %d", len(vulns))
	}

	// Check for specific CVEs
	cveMap := make(map[string]models.Vulnerability)
	for _, v := range vulns {
		cveMap[v.CVE] = v
	}

	// Verify CVE-2023-44487 (CRITICAL - unique to Grype in our test data)
	if v, ok := cveMap["CVE-2023-44487"]; ok {
		if v.Package != "nghttp2-libs" {
			t.Errorf("CVE-2023-44487: expected package nghttp2-libs, got %s", v.Package)
		}
		if v.Severity != models.SeverityCritical {
			t.Errorf("CVE-2023-44487: expected severity CRITICAL, got %s", v.Severity)
		}
	} else {
		t.Error("CVE-2023-44487 not found in parsed output")
	}

	// Verify CVE-2023-5363 (shared with Trivy)
	if v, ok := cveMap["CVE-2023-5363"]; ok {
		if v.Scanner != "grype" {
			t.Errorf("CVE-2023-5363: expected scanner grype, got %s", v.Scanner)
		}
	} else {
		t.Error("CVE-2023-5363 not found in parsed output")
	}
}

// TestFullPipelineIntegration tests the complete scan -> normalize -> consensus -> report pipeline.
func TestFullPipelineIntegration(t *testing.T) {
	// Load test data
	trivyData := loadTestData(t, "trivy_output.json")
	grypeData := loadTestData(t, "grype_output.json")

	// Parse scanner outputs
	trivyScanner := scanner.NewTrivyScanner()
	grypeScanner := scanner.NewGrypeScanner()

	trivyVulns, err := trivyScanner.ParseOutputForTest(trivyData)
	if err != nil {
		t.Fatalf("failed to parse Trivy output: %v", err)
	}

	grypeVulns, err := grypeScanner.ParseOutputForTest(grypeData)
	if err != nil {
		t.Fatalf("failed to parse Grype output: %v", err)
	}

	// Create scan results
	results := []models.ScanResult{
		{
			Scanner:         "trivy",
			Target:          "alpine:3.18",
			Success:         true,
			Vulnerabilities: trivyVulns,
		},
		{
			Scanner:         "grype",
			Target:          "alpine:3.18",
			Success:         true,
			Vulnerabilities: grypeVulns,
		},
	}

	// Normalize results
	norm := normalizer.NewNormalizer(
		normalizer.WithDeduplication(true),
		normalizer.WithSeverityNormalization(true),
	)
	normalized := norm.NormalizeResults(results)

	// Verify normalization
	if len(normalized) == 0 {
		t.Fatal("normalization produced no results")
	}

	// Check severity ordering (should be sorted by severity, highest first)
	for i := 1; i < len(normalized); i++ {
		if normalized[i].Severity.Weight() > normalized[i-1].Severity.Weight() {
			t.Error("vulnerabilities not sorted by severity (highest first)")
			break
		}
	}

	// Compute consensus
	analyzer := consensus.NewAnalyzer()
	consensusResult := analyzer.Analyze("alpine:3.18", results)

	// Verify consensus metrics
	if consensusResult.OverlapPercentage < 0 || consensusResult.OverlapPercentage > 100 {
		t.Errorf("invalid overlap percentage: %f", consensusResult.OverlapPercentage)
	}

	// Should have some consensus (CVE-2023-5363, CVE-2023-5678 are in both)
	if len(consensusResult.Consensus) == 0 {
		t.Error("expected some consensus vulnerabilities")
	}

	// Verify unique findings exist
	trivyUnique := consensusResult.UniqueFindings["trivy"]
	grypeUnique := consensusResult.UniqueFindings["grype"]

	// Trivy should have unique CVEs (CVE-2023-6129, CVE-2024-0727)
	if len(trivyUnique) == 0 {
		t.Error("expected Trivy to have unique vulnerabilities")
	}

	// Grype should have unique CVEs (CVE-2023-44487)
	if len(grypeUnique) == 0 {
		t.Error("expected Grype to have unique vulnerabilities")
	}

	t.Logf("Consensus: %d shared, Trivy unique: %d, Grype unique: %d, Overlap: %.1f%%",
		len(consensusResult.Consensus),
		len(trivyUnique),
		len(grypeUnique),
		consensusResult.OverlapPercentage,
	)
}

// TestReportGeneration tests all report format generators.
func TestReportGeneration(t *testing.T) {
	// Load and parse test data
	trivyData := loadTestData(t, "trivy_output.json")
	grypeData := loadTestData(t, "grype_output.json")

	trivyScanner := scanner.NewTrivyScanner()
	grypeScanner := scanner.NewGrypeScanner()

	trivyVulns, _ := trivyScanner.ParseOutputForTest(trivyData)
	grypeVulns, _ := grypeScanner.ParseOutputForTest(grypeData)

	results := []models.ScanResult{
		{Scanner: "trivy", Target: "alpine:3.18", Success: true, Vulnerabilities: trivyVulns},
		{Scanner: "grype", Target: "alpine:3.18", Success: true, Vulnerabilities: grypeVulns},
	}

	analyzer := consensus.NewAnalyzer()
	consensusResult := analyzer.Analyze("alpine:3.18", results)

	// Test Table Report
	t.Run("TableReport", func(t *testing.T) {
		gen := report.NewTableGenerator()
		var buf bytes.Buffer
		err := gen.Generate(consensusResult, &buf)
		if err != nil {
			t.Fatalf("table generation failed: %v", err)
		}

		output := buf.String()
		if len(output) == 0 {
			t.Error("table output is empty")
		}

		// Should contain key information
		if !strings.Contains(output, "CVE") {
			t.Error("table output should contain CVE information")
		}
	})

	// Test JSON Report
	t.Run("JSONReport", func(t *testing.T) {
		gen := report.NewJSONGenerator()
		var buf bytes.Buffer
		err := gen.Generate(consensusResult, &buf)
		if err != nil {
			t.Fatalf("JSON generation failed: %v", err)
		}

		// Verify valid JSON
		var parsed map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
			t.Errorf("invalid JSON output: %v", err)
		}

		// Check for expected fields
		if _, ok := parsed["consensus"]; !ok {
			t.Error("JSON should contain 'consensus' field")
		}
	})

	// Test HTML Report
	t.Run("HTMLReport", func(t *testing.T) {
		gen := report.NewHTMLGenerator()
		var buf bytes.Buffer
		err := gen.Generate(consensusResult, &buf)
		if err != nil {
			t.Fatalf("HTML generation failed: %v", err)
		}

		output := buf.String()

		// Should be valid HTML
		if !strings.Contains(output, "<!DOCTYPE html>") && !strings.Contains(output, "<html") {
			t.Error("HTML output should contain HTML document structure")
		}

		// Should contain vulnerability data
		if !strings.Contains(output, "CVE-") {
			t.Error("HTML should contain CVE information")
		}
	})
}

// TestConsensusCalculation tests detailed consensus algorithm behavior.
func TestConsensusCalculation(t *testing.T) {
	// Create controlled test data
	vulnA := models.Vulnerability{CVE: "CVE-2023-0001", Package: "pkg1", InstalledVersion: "1.0", Scanner: "scanner1", Severity: models.SeverityHigh}
	vulnB := models.Vulnerability{CVE: "CVE-2023-0001", Package: "pkg1", InstalledVersion: "1.0", Scanner: "scanner2", Severity: models.SeverityHigh}
	vulnC := models.Vulnerability{CVE: "CVE-2023-0002", Package: "pkg2", InstalledVersion: "2.0", Scanner: "scanner1", Severity: models.SeverityMedium}
	vulnD := models.Vulnerability{CVE: "CVE-2023-0003", Package: "pkg3", InstalledVersion: "3.0", Scanner: "scanner2", Severity: models.SeverityCritical}

	results := []models.ScanResult{
		{Scanner: "scanner1", Success: true, Vulnerabilities: []models.Vulnerability{vulnA, vulnC}},
		{Scanner: "scanner2", Success: true, Vulnerabilities: []models.Vulnerability{vulnB, vulnD}},
	}

	analyzer := consensus.NewAnalyzer()
	result := analyzer.Analyze("test-target", results)

	// CVE-2023-0001 should be in consensus
	if len(result.Consensus) != 1 {
		t.Errorf("expected 1 consensus vulnerability, got %d", len(result.Consensus))
	}

	// Verify the consensus CVE
	found := false
	for _, v := range result.Consensus {
		if v.CVE == "CVE-2023-0001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("CVE-2023-0001 should be in consensus")
	}

	// scanner1 should have 1 unique (CVE-2023-0002)
	if len(result.UniqueFindings["scanner1"]) != 1 {
		t.Errorf("expected 1 unique for scanner1, got %d", len(result.UniqueFindings["scanner1"]))
	}

	// scanner2 should have 1 unique (CVE-2023-0003)
	if len(result.UniqueFindings["scanner2"]) != 1 {
		t.Errorf("expected 1 unique for scanner2, got %d", len(result.UniqueFindings["scanner2"]))
	}

	// Total: 3 unique CVEs, 1 shared = ~33% overlap
	if result.OverlapPercentage < 30 || result.OverlapPercentage > 40 {
		t.Errorf("expected overlap around 33%%, got %.1f%%", result.OverlapPercentage)
	}
}

// TestNormalizerFiltering tests the normalizer's filtering capabilities.
func TestNormalizerFiltering(t *testing.T) {
	vulns := []models.Vulnerability{
		{CVE: "CVE-2023-0001", Package: "pkg1", Severity: models.SeverityCritical, Scanner: "test"},
		{CVE: "CVE-2023-0002", Package: "pkg2", Severity: models.SeverityHigh, Scanner: "test"},
		{CVE: "CVE-2023-0003", Package: "pkg3", Severity: models.SeverityMedium, Scanner: "test"},
		{CVE: "CVE-2023-0004", Package: "pkg4", Severity: models.SeverityLow, Scanner: "test"},
	}

	norm := normalizer.NewNormalizer()

	// Filter by HIGH severity
	filtered := norm.FilterBySeverity(vulns, models.SeverityHigh)
	if len(filtered) != 2 { // CRITICAL and HIGH
		t.Errorf("expected 2 vulnerabilities (CRITICAL+HIGH), got %d", len(filtered))
	}

	// Filter by CRITICAL severity
	filtered = norm.FilterBySeverity(vulns, models.SeverityCritical)
	if len(filtered) != 1 {
		t.Errorf("expected 1 vulnerability (CRITICAL only), got %d", len(filtered))
	}

	// Group by severity
	groups := norm.GroupBySeverity(vulns)
	if len(groups) != 4 {
		t.Errorf("expected 4 severity groups, got %d", len(groups))
	}
}

// TestErrorHandling tests graceful handling of invalid data.
func TestErrorHandling(t *testing.T) {
	t.Run("InvalidJSON", func(t *testing.T) {
		trivyScanner := scanner.NewTrivyScanner()
		_, err := trivyScanner.ParseOutputForTest([]byte("not valid json"))
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("EmptyInput", func(t *testing.T) {
		trivyScanner := scanner.NewTrivyScanner()
		vulns, err := trivyScanner.ParseOutputForTest([]byte(""))
		if err != nil {
			t.Errorf("empty input should not error: %v", err)
		}
		if len(vulns) != 0 {
			t.Error("empty input should produce no vulnerabilities")
		}
	})

	t.Run("FailedScanResult", func(t *testing.T) {
		results := []models.ScanResult{
			{Scanner: "failed", Success: false, Error: "scanner not available"},
			{Scanner: "working", Success: true, Vulnerabilities: []models.Vulnerability{
				{CVE: "CVE-2023-0001", Package: "pkg1", Severity: models.SeverityHigh, Scanner: "working"},
			}},
		}

		norm := normalizer.NewNormalizer()
		normalized := norm.NormalizeResults(results)

		// Should only get vulnerabilities from successful scan
		if len(normalized) != 1 {
			t.Errorf("expected 1 vulnerability from working scanner, got %d", len(normalized))
		}
	})
}

// TestSeverityOrdering verifies correct severity weight ordering.
func TestSeverityOrdering(t *testing.T) {
	severities := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityUnknown,
	}

	for i := 0; i < len(severities)-1; i++ {
		if severities[i].Weight() <= severities[i+1].Weight() {
			t.Errorf("%s should have higher weight than %s", severities[i], severities[i+1])
		}
	}
}

// TestVulnerabilityKey tests the vulnerability key generation for matching.
func TestVulnerabilityKey(t *testing.T) {
	v1 := models.Vulnerability{CVE: "CVE-2023-0001", Package: "pkg1", InstalledVersion: "1.0"}
	v2 := models.Vulnerability{CVE: "CVE-2023-0001", Package: "pkg1", InstalledVersion: "1.0", Scanner: "different"}

	// Same CVE+Package+Version should have same key regardless of scanner
	if v1.Key() != v2.Key() {
		t.Error("vulnerabilities with same CVE/Package/Version should have same key")
	}

	v3 := models.Vulnerability{CVE: "CVE-2023-0001", Package: "pkg2", InstalledVersion: "1.0"}

	// Different package should have different key
	if v1.Key() == v3.Key() {
		t.Error("vulnerabilities with different packages should have different keys")
	}
}

// TestStatisticsComputation tests the statistics calculation.
func TestStatisticsComputation(t *testing.T) {
	results := []models.ScanResult{
		{
			Scanner: "scanner1",
			Success: true,
			Vulnerabilities: []models.Vulnerability{
				{CVE: "CVE-2023-0001", Package: "pkg1", InstalledVersion: "1.0", Severity: models.SeverityCritical, Scanner: "scanner1"},
				{CVE: "CVE-2023-0002", Package: "pkg2", InstalledVersion: "1.0", Severity: models.SeverityHigh, Scanner: "scanner1"},
			},
		},
		{
			Scanner: "scanner2",
			Success: true,
			Vulnerabilities: []models.Vulnerability{
				{CVE: "CVE-2023-0001", Package: "pkg1", InstalledVersion: "1.0", Severity: models.SeverityCritical, Scanner: "scanner2"},
				{CVE: "CVE-2023-0003", Package: "pkg3", InstalledVersion: "1.0", Severity: models.SeverityMedium, Scanner: "scanner2"},
			},
		},
	}

	analyzer := consensus.NewAnalyzer()
	consensusResult := analyzer.Analyze("test", results)
	stats := analyzer.ComputeStatistics(consensusResult)

	// Check total vulnerabilities
	if stats.TotalVulnerabilities != 3 {
		t.Errorf("expected 3 total vulnerabilities, got %d", stats.TotalVulnerabilities)
	}

	// Check consensus count
	if stats.ConsensusCount != 1 {
		t.Errorf("expected 1 consensus vulnerability, got %d", stats.ConsensusCount)
	}

	// Check unique counts
	if stats.UniqueCount["scanner1"] != 1 {
		t.Errorf("expected 1 unique for scanner1, got %d", stats.UniqueCount["scanner1"])
	}
	if stats.UniqueCount["scanner2"] != 1 {
		t.Errorf("expected 1 unique for scanner2, got %d", stats.UniqueCount["scanner2"])
	}
}

// TestAgreementMatrix tests the scanner agreement matrix computation.
func TestAgreementMatrix(t *testing.T) {
	results := []models.ScanResult{
		{
			Scanner: "scanner1",
			Success: true,
			Vulnerabilities: []models.Vulnerability{
				{CVE: "CVE-2023-0001", Package: "pkg1", InstalledVersion: "1.0", Scanner: "scanner1"},
				{CVE: "CVE-2023-0002", Package: "pkg2", InstalledVersion: "1.0", Scanner: "scanner1"},
			},
		},
		{
			Scanner: "scanner2",
			Success: true,
			Vulnerabilities: []models.Vulnerability{
				{CVE: "CVE-2023-0001", Package: "pkg1", InstalledVersion: "1.0", Scanner: "scanner2"},
			},
		},
	}

	analyzer := consensus.NewAnalyzer()
	consensusResult := analyzer.Analyze("test", results)
	stats := analyzer.ComputeStatistics(consensusResult)

	// Check agreement matrix
	if stats.ScannerAgreementMatrix == nil {
		t.Fatal("agreement matrix should not be nil")
	}

	// scanner1 and scanner2 should agree on 1 vulnerability
	if stats.ScannerAgreementMatrix["scanner1"]["scanner2"] != 1 {
		t.Errorf("expected agreement of 1, got %d", stats.ScannerAgreementMatrix["scanner1"]["scanner2"])
	}
}
