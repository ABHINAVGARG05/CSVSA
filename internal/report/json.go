// Package report - JSON format generator
package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

// JSONGenerator produces machine-readable JSON output.
type JSONGenerator struct {
	// prettyPrint controls whether to format JSON with indentation.
	prettyPrint bool
}

// NewJSONGenerator creates a new JSON generator with pretty printing enabled.
func NewJSONGenerator() *JSONGenerator {
	return &JSONGenerator{
		prettyPrint: true,
	}
}

// NewJSONGeneratorWithOptions creates a JSON generator with custom options.
func NewJSONGeneratorWithOptions(prettyPrint bool) *JSONGenerator {
	return &JSONGenerator{
		prettyPrint: prettyPrint,
	}
}

// Format returns the generator format name.
func (j *JSONGenerator) Format() string {
	return "json"
}

// JSONReport is the structure of the JSON output.
type JSONReport struct {
	// Metadata about the report
	Metadata ReportMetadata `json:"metadata"`

	// Summary statistics
	Summary ReportSummary `json:"summary"`

	// Consensus vulnerabilities (found by all scanners)
	Consensus []VulnerabilityEntry `json:"consensus"`

	// Unique findings per scanner
	UniqueFindings map[string][]VulnerabilityEntry `json:"unique_findings"`

	// All vulnerabilities combined
	AllVulnerabilities []VulnerabilityEntry `json:"all_vulnerabilities"`

	// Scanner results and status
	ScannerResults []ScannerResultEntry `json:"scanner_results"`

	// Severity distribution
	SeverityDistribution SeverityStats `json:"severity_distribution"`
}

// ReportMetadata contains metadata about the analysis.
type ReportMetadata struct {
	Target        string    `json:"target"`
	Scanners      []string  `json:"scanners"`
	AnalysisTime  time.Time `json:"analysis_time"`
	TotalDuration string    `json:"total_duration"`
	Version       string    `json:"csvsa_version"`
}

// ReportSummary contains summary statistics.
type ReportSummary struct {
	TotalVulnerabilities int     `json:"total_vulnerabilities"`
	ConsensusCount       int     `json:"consensus_count"`
	UniqueCount          int     `json:"unique_count"`
	OverlapPercentage    float64 `json:"overlap_percentage"`
	SuccessfulScanners   int     `json:"successful_scanners"`
	TotalScanners        int     `json:"total_scanners"`
}

// VulnerabilityEntry represents a vulnerability in the JSON output.
type VulnerabilityEntry struct {
	CVE              string   `json:"cve"`
	Package          string   `json:"package"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version,omitempty"`
	Severity         string   `json:"severity"`
	Title            string   `json:"title,omitempty"`
	Description      string   `json:"description,omitempty"`
	References       []string `json:"references,omitempty"`
	Scanners         []string `json:"scanners,omitempty"`
}

// ScannerResultEntry represents a scanner's result status.
type ScannerResultEntry struct {
	Name               string `json:"name"`
	Success            bool   `json:"success"`
	Error              string `json:"error,omitempty"`
	VulnerabilityCount int    `json:"vulnerability_count"`
	Duration           string `json:"duration"`
}

// SeverityStats contains severity distribution data.
type SeverityStats struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

// Generate produces a JSON report.
func (j *JSONGenerator) Generate(result *models.ConsensusResult, w io.Writer) error {
	report := j.buildReport(result)

	encoder := json.NewEncoder(w)
	if j.prettyPrint {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(report)
}

// buildReport constructs the JSON report structure.
func (j *JSONGenerator) buildReport(result *models.ConsensusResult) JSONReport {
	// Calculate unique count
	uniqueCount := 0
	for _, vulns := range result.UniqueFindings {
		uniqueCount += len(vulns)
	}

	// Build severity distribution
	dist := result.SeverityDistribution()

	report := JSONReport{
		Metadata: ReportMetadata{
			Target:        result.Target,
			Scanners:      result.Scanners,
			AnalysisTime:  result.AnalysisTime,
			TotalDuration: result.TotalDuration.String(),
			Version:       "1.0.0",
		},
		Summary: ReportSummary{
			TotalVulnerabilities: len(result.AllVulnerabilities),
			ConsensusCount:       len(result.Consensus),
			UniqueCount:          uniqueCount,
			OverlapPercentage:    result.OverlapPercentage,
			SuccessfulScanners:   result.SuccessfulScanners(),
			TotalScanners:        len(result.ScanResults),
		},
		Consensus:          j.convertVulnerabilities(result.Consensus),
		UniqueFindings:     j.convertUniqueFindings(result.UniqueFindings),
		AllVulnerabilities: j.convertVulnerabilities(result.AllVulnerabilities),
		ScannerResults:     j.convertScannerResults(result.ScanResults),
		SeverityDistribution: SeverityStats{
			Critical: dist[models.SeverityCritical],
			High:     dist[models.SeverityHigh],
			Medium:   dist[models.SeverityMedium],
			Low:      dist[models.SeverityLow],
			Unknown:  dist[models.SeverityUnknown],
		},
	}

	return report
}

// convertVulnerabilities transforms model vulnerabilities to JSON entries.
func (j *JSONGenerator) convertVulnerabilities(vulns []models.Vulnerability) []VulnerabilityEntry {
	entries := make([]VulnerabilityEntry, len(vulns))
	for i, v := range vulns {
		entries[i] = VulnerabilityEntry{
			CVE:              v.CVE,
			Package:          v.Package,
			InstalledVersion: v.InstalledVersion,
			FixedVersion:     v.FixedVersion,
			Severity:         string(v.Severity),
			Title:            v.Title,
			Description:      v.Description,
			References:       v.References,
		}
	}
	return entries
}

// convertUniqueFindings transforms unique findings map.
func (j *JSONGenerator) convertUniqueFindings(findings map[string][]models.Vulnerability) map[string][]VulnerabilityEntry {
	result := make(map[string][]VulnerabilityEntry)
	for scanner, vulns := range findings {
		result[scanner] = j.convertVulnerabilities(vulns)
	}
	return result
}

// convertScannerResults transforms scanner results.
func (j *JSONGenerator) convertScannerResults(results []models.ScanResult) []ScannerResultEntry {
	entries := make([]ScannerResultEntry, len(results))
	for i, r := range results {
		entries[i] = ScannerResultEntry{
			Name:               r.Scanner,
			Success:            r.Success,
			Error:              r.Error,
			VulnerabilityCount: len(r.Vulnerabilities),
			Duration:           r.Duration.String(),
		}
	}
	return entries
}
