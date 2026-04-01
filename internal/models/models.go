// Package models defines the core data structures used throughout CSVSA.
// These models represent the normalized vulnerability data and analysis results
// that flow through the system's pipeline.
//
// Design Philosophy:
// - Immutable data structures where possible
// - Clear separation between raw scanner output and normalized data
// - Support for extensibility through composition
package models

import (
	"time"
)

// Severity represents the severity level of a vulnerability.
// We use a custom type to ensure type safety and enable validation.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
)

// SeverityWeight returns a numeric weight for severity comparison and sorting.
// Higher values indicate more severe vulnerabilities.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// IsValid checks if the severity is a recognized value.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityUnknown:
		return true
	default:
		return false
	}
}

// Vulnerability represents a normalized security vulnerability found by a scanner.
// This is the canonical representation used throughout the analysis pipeline.
//
// Fields are designed to capture the essential information needed for:
// 1. Unique identification (CVE + Package + InstalledVersion)
// 2. Severity assessment
// 3. Provenance tracking (which scanner found it)
type Vulnerability struct {
	// CVE is the Common Vulnerabilities and Exposures identifier.
	// Example: "CVE-2021-44228"
	CVE string `json:"cve"`

	CVEID string  `json:"cve_id"`

	// Package is the name of the affected software package.
	// Example: "log4j-core"
	Package string `json:"package"`

	// InstalledVersion is the version of the package that was scanned.
	// Example: "2.14.1"
	InstalledVersion string `json:"installed_version"`

	// FixedVersion is the version that resolves this vulnerability (if known).
	// May be empty if no fix is available.
	FixedVersion string `json:"fixed_version,omitempty"`

	// Severity indicates the severity level of the vulnerability.
	Severity Severity `json:"severity"`

	// Scanner identifies which scanner detected this vulnerability.
	// Example: "trivy", "grype"
	Scanner string `json:"scanner"`

	Version string 	`json:"version"`

	// Title is a brief description of the vulnerability.
	Title string `json:"title,omitempty"`

	// Description provides detailed information about the vulnerability.
	Description string `json:"description,omitempty"`

	// References contains URLs to additional information.
	References []string `json:"references,omitempty"`

	KEV *KEVInfo `json:"kev"`
}

// Key generates a unique identifier for this vulnerability.
// Used for deduplication and consensus computation.
// The key is composed of CVE + Package + InstalledVersion to ensure
// we're comparing the same vulnerability in the same package version.
func (v *Vulnerability) Key() string {
	return v.CVE + "|" + v.Package + "|" + v.InstalledVersion
}

// ScanResult represents the output from a single scanner execution.
type ScanResult struct {
	// Scanner identifies which scanner produced this result.
	Scanner string `json:"scanner"`

	Scanners [] string 	`json:"scanners"`

	AnalysisTime string `json:"analysis_time"`

	// Target is the image or filesystem that was scanned.
	Target string `json:"target"`

	Consensus       []Vulnerability `json:"consensus"`

	UniqueFindings  map[string][]Vulnerability `json:"unique_findings"`

	Statistics      Statistics      `json:"statistics"`

	// Vulnerabilities is the list of detected vulnerabilities.
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`

	// ScanTime is when the scan was performed.
	ScanTime time.Time `json:"scan_time"`

	// Duration is how long the scan took.
	Duration time.Duration `json:"duration"`

	// Error contains any error message if the scan failed.
	Error string `json:"error,omitempty"`

	// Success indicates whether the scan completed successfully.
	Success bool `json:"success"`

	// RawOutput stores the original JSON output for debugging.
	RawOutput []byte `json:"-"`
}

// VulnerabilityCount returns the total number of vulnerabilities found.
func (r *ScanResult) VulnerabilityCount() int {
	return len(r.Vulnerabilities)
}

// CountBySeverity returns a map of severity to count.
func (r *ScanResult) CountBySeverity() map[Severity]int {
	counts := make(map[Severity]int)
	for _, v := range r.Vulnerabilities {
		counts[v.Severity]++
	}
	return counts
}

// ConfidenceLevel represents the confidence in a vulnerability finding.
type ConfidenceLevel string

const (
	// ConfidenceHigh indicates the vulnerability was found by multiple scanners.
	ConfidenceHigh ConfidenceLevel = "HIGH"

	// ConfidenceMedium indicates the vulnerability was found by one scanner
	// but has strong supporting evidence.
	ConfidenceMedium ConfidenceLevel = "MEDIUM"

	// ConfidenceLow indicates the vulnerability was found by only one scanner.
	ConfidenceLow ConfidenceLevel = "LOW"
)

// ConsensusResult represents the analysis of vulnerabilities across multiple scanners.
type ConsensusResult struct {
	// Target is the image or filesystem that was analyzed.
	Target string `json:"target"`

	// Scanners lists all scanners that participated in the analysis.
	Scanners []string `json:"scanners"`

	// Consensus contains vulnerabilities found by ALL scanners.
	Consensus []Vulnerability `json:"consensus"`

	// UniqueFindings maps scanner name to vulnerabilities only that scanner found.
	UniqueFindings map[string][]Vulnerability `json:"unique_findings"`

	Statistics Statistics `json:"statistics"`

	// AllVulnerabilities contains the complete deduplicated list.
	AllVulnerabilities []Vulnerability `json:"all_vulnerabilities"`

	// OverlapPercentage is the percentage of vulnerabilities found by all scanners.
	OverlapPercentage float64 `json:"overlap_percentage"`

	// ScanResults contains the original results from each scanner.
	ScanResults []ScanResult `json:"scan_results"`

	// AnalysisTime is when the consensus analysis was performed.
	AnalysisTime time.Time `json:"analysis_time"`

	// TotalDuration is the total time for all scans and analysis.
	TotalDuration time.Duration `json:"total_duration"`
}

// SeverityDistribution returns counts for each severity level across all vulnerabilities.
func (c *ConsensusResult) SeverityDistribution() map[Severity]int {
	dist := make(map[Severity]int)
	for _, v := range c.AllVulnerabilities {
		dist[v.Severity]++
	}
	return dist
}

// ConsensusSeverityDistribution returns counts for consensus vulnerabilities only.
func (c *ConsensusResult) ConsensusSeverityDistribution() map[Severity]int {
	dist := make(map[Severity]int)
	for _, v := range c.Consensus {
		dist[v.Severity]++
	}
	return dist
}

// SuccessfulScanners returns the count of scanners that completed successfully.
func (c *ConsensusResult) SuccessfulScanners() int {
	count := 0
	for _, r := range c.ScanResults {
		if r.Success {
			count++
		}
	}
	return count
}

// ScanConfig holds configuration for a scanning operation.
type ScanConfig struct {
	// Target is the container image or filesystem path to scan.
	Target string

	// Timeout is the maximum duration for each scanner.
	Timeout time.Duration

	// Scanners lists which scanners to use. Empty means use all available.
	Scanners []string

	// OutputFormat specifies the desired output format(s).
	OutputFormat []string

	// OutputPath is where to write the output (empty for stdout).
	OutputPath string

	// Verbose enables detailed logging.
	Verbose bool

	// FailOnVulnerability causes the tool to exit with error if vulnerabilities found.
	FailOnVulnerability bool

	// MinSeverity sets the minimum severity to report.
	MinSeverity Severity
}

// DefaultConfig returns a ScanConfig with sensible defaults.
func DefaultConfig() ScanConfig {
	return ScanConfig{
		Timeout:             5 * time.Minute,
		Scanners:            []string{}, // Use all available
		OutputFormat:        []string{"table"},
		Verbose:             false,
		FailOnVulnerability: false,
		MinSeverity:         SeverityUnknown,
	}
}

// ScannerInfo contains metadata about a scanner.
type ScannerInfo struct {
	// Name is the identifier for this scanner.
	Name string `json:"name"`

	// Version is the scanner's version string.
	Version string `json:"version"`

	// Available indicates if the scanner is installed and accessible.
	Available bool `json:"available"`

	// Path is the filesystem path to the scanner executable.
	Path string `json:"path,omitempty"`
}
