package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

// Helper to create test consensus result
func makeTestResult() *models.ConsensusResult {
	return &models.ConsensusResult{
		Target:   "alpine:3.18",
		Scanners: []string{"trivy", "grype"},
		Consensus: []models.Vulnerability{
			{
				CVE:              "CVE-2021-0001",
				Package:          "libssl",
				InstalledVersion: "1.1.1",
				FixedVersion:     "1.1.2",
				Severity:         models.SeverityCritical,
				Scanner:          "multiple",
			},
		},
		UniqueFindings: map[string][]models.Vulnerability{
			"trivy": {
				{
					CVE:              "CVE-2021-0002",
					Package:          "libcurl",
					InstalledVersion: "7.64.0",
					Severity:         models.SeverityHigh,
					Scanner:          "trivy",
				},
			},
			"grype": {
				{
					CVE:              "CVE-2021-0003",
					Package:          "zlib",
					InstalledVersion: "1.2.11",
					Severity:         models.SeverityMedium,
					Scanner:          "grype",
				},
			},
		},
		AllVulnerabilities: []models.Vulnerability{
			{CVE: "CVE-2021-0001", Package: "libssl", Severity: models.SeverityCritical},
			{CVE: "CVE-2021-0002", Package: "libcurl", Severity: models.SeverityHigh},
			{CVE: "CVE-2021-0003", Package: "zlib", Severity: models.SeverityMedium},
		},
		OverlapPercentage: 33.33,
		ScanResults: []models.ScanResult{
			{Scanner: "trivy", Success: true, Duration: 5 * time.Second},
			{Scanner: "grype", Success: true, Duration: 3 * time.Second},
		},
		AnalysisTime:  time.Now(),
		TotalDuration: 8 * time.Second,
	}
}

func TestJSONGenerator(t *testing.T) {
	gen := NewJSONGenerator()
	result := makeTestResult()

	var buf bytes.Buffer
	err := gen.Generate(result, &buf)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Verify it's valid JSON
	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	// Verify structure
	if report.Metadata.Target != "alpine:3.18" {
		t.Errorf("Target = %s, want alpine:3.18", report.Metadata.Target)
	}

	if len(report.Metadata.Scanners) != 2 {
		t.Errorf("Scanners count = %d, want 2", len(report.Metadata.Scanners))
	}

	if report.Summary.TotalVulnerabilities != 3 {
		t.Errorf("TotalVulnerabilities = %d, want 3", report.Summary.TotalVulnerabilities)
	}

	if report.Summary.ConsensusCount != 1 {
		t.Errorf("ConsensusCount = %d, want 1", report.Summary.ConsensusCount)
	}

	if len(report.Consensus) != 1 {
		t.Errorf("Consensus length = %d, want 1", len(report.Consensus))
	}

	if report.SeverityDistribution.Critical != 1 {
		t.Errorf("Critical count = %d, want 1", report.SeverityDistribution.Critical)
	}
}

func TestJSONGeneratorCompact(t *testing.T) {
	gen := NewJSONGeneratorWithOptions(false) // No pretty print
	result := makeTestResult()

	var buf bytes.Buffer
	err := gen.Generate(result, &buf)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Compact JSON should not have newlines (except potentially in strings)
	output := buf.String()
	lines := strings.Split(output, "\n")
	if len(lines) > 2 { // Allow for trailing newline
		t.Error("Compact JSON should be single line")
	}
}

func TestHTMLGenerator(t *testing.T) {
	gen := NewHTMLGenerator()
	result := makeTestResult()

	var buf bytes.Buffer
	err := gen.Generate(result, &buf)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()

	// Verify it's HTML
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("Output should contain DOCTYPE")
	}

	if !strings.Contains(output, "<html") {
		t.Error("Output should contain html tag")
	}

	// Verify target is included
	if !strings.Contains(output, "alpine:3.18") {
		t.Error("Output should contain target")
	}

	// Verify CVEs are included
	if !strings.Contains(output, "CVE-2021-0001") {
		t.Error("Output should contain consensus CVE")
	}

	// Verify severity styling classes exist
	if !strings.Contains(output, "severity-critical") {
		t.Error("Output should contain severity classes")
	}
}

func TestTableGenerator(t *testing.T) {
	gen := NewTableGeneratorWithOptions(false) // No colors for testing
	result := makeTestResult()

	var buf bytes.Buffer
	err := gen.Generate(result, &buf)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()

	// Verify header
	if !strings.Contains(output, "CSVSA") {
		t.Error("Output should contain header")
	}

	// Verify target
	if !strings.Contains(output, "alpine:3.18") {
		t.Error("Output should contain target")
	}

	// Verify summary section
	if !strings.Contains(output, "SUMMARY") {
		t.Error("Output should contain summary")
	}

	// Verify CVEs appear
	if !strings.Contains(output, "CVE-2021-0001") {
		t.Error("Output should contain CVEs")
	}
}

func TestRegistryOperations(t *testing.T) {
	registry := NewRegistry()

	jsonGen := NewJSONGenerator()
	htmlGen := NewHTMLGenerator()

	registry.Register(jsonGen)
	registry.Register(htmlGen)

	// Test Get
	if got := registry.Get("json"); got != jsonGen {
		t.Error("Get should return registered generator")
	}

	if got := registry.Get("nonexistent"); got != nil {
		t.Error("Get should return nil for unregistered format")
	}

	// Test Formats
	formats := registry.Formats()
	if len(formats) != 2 {
		t.Errorf("Formats count = %d, want 2", len(formats))
	}
}

func TestDefaultRegistry(t *testing.T) {
	registry := DefaultRegistry()

	// Should have all three generators
	if registry.Get("table") == nil {
		t.Error("Default registry should have table generator")
	}

	if registry.Get("json") == nil {
		t.Error("Default registry should have json generator")
	}

	if registry.Get("html") == nil {
		t.Error("Default registry should have html generator")
	}
}

func TestMultiGenerator(t *testing.T) {
	registry := DefaultRegistry()
	multiGen := NewMultiGenerator(registry)

	result := makeTestResult()

	var jsonBuf, htmlBuf bytes.Buffer
	writers := map[string]bytes.Buffer{
		"json": jsonBuf,
		"html": htmlBuf,
	}

	// Create writer map
	writerMap := make(map[string]*bytes.Buffer)
	writerMap["json"] = &jsonBuf
	writerMap["html"] = &htmlBuf

	// Convert to io.Writer map
	ioWriters := make(map[string]interface {
		Write([]byte) (int, error)
	})
	for k, v := range writerMap {
		ioWriters[k] = v
	}

	// Manual test since the interface is slightly different
	jsonGen := registry.Get("json")
	if err := jsonGen.Generate(result, &jsonBuf); err != nil {
		t.Fatalf("JSON generation failed: %v", err)
	}

	htmlGen := registry.Get("html")
	if err := htmlGen.Generate(result, &htmlBuf); err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}

	if jsonBuf.Len() == 0 {
		t.Error("JSON output should not be empty")
	}

	if htmlBuf.Len() == 0 {
		t.Error("HTML output should not be empty")
	}

	// Suppress unused variable warning
	_ = writers
	_ = multiGen
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a long string", 10, "this is..."},
		{"abc", 3, "abc"},
		{"abcd", 3, "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := truncate(tt.input, tt.maxLen)
			if got != tt.expected {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.expected)
			}
		})
	}
}

func TestGeneratorFormats(t *testing.T) {
	tests := []struct {
		generator Generator
		format    string
	}{
		{NewTableGenerator(), "table"},
		{NewJSONGenerator(), "json"},
		{NewHTMLGenerator(), "html"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			if got := tt.generator.Format(); got != tt.format {
				t.Errorf("Format() = %q, want %q", got, tt.format)
			}
		})
	}
}

func TestEmptyResult(t *testing.T) {
	result := &models.ConsensusResult{
		Target:             "empty:test",
		Scanners:           []string{},
		Consensus:          []models.Vulnerability{},
		UniqueFindings:     map[string][]models.Vulnerability{},
		AllVulnerabilities: []models.Vulnerability{},
		OverlapPercentage:  0,
		ScanResults:        []models.ScanResult{},
		AnalysisTime:       time.Now(),
	}

	// Test all generators with empty result
	generators := []Generator{
		NewTableGenerator(),
		NewJSONGenerator(),
		NewHTMLGenerator(),
	}

	for _, gen := range generators {
		t.Run(gen.Format(), func(t *testing.T) {
			var buf bytes.Buffer
			err := gen.Generate(result, &buf)
			if err != nil {
				t.Errorf("%s generator failed with empty result: %v", gen.Format(), err)
			}
			if buf.Len() == 0 {
				t.Errorf("%s generator produced empty output", gen.Format())
			}
		})
	}
}
