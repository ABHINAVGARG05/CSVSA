// Package scanner - Grype scanner adapter implementation
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

// GrypeScanner implements the Scanner interface for Anchore's Grype.
// Grype is a vulnerability scanner for container images and filesystems.
//
// Grype Output Format:
// Grype outputs JSON with a "matches" array containing vulnerability matches
// and an "artifact" describing what was scanned.
type GrypeScanner struct {
	// executablePath allows overriding the default "grype" command.
	executablePath string
}

// NewGrypeScanner creates a new Grype scanner with default settings.
func NewGrypeScanner() *GrypeScanner {
	return &GrypeScanner{
		executablePath: "grype",
	}
}

// NewGrypeScannerWithPath creates a Grype scanner with a custom executable path.
func NewGrypeScannerWithPath(path string) *GrypeScanner {
	return &GrypeScanner{
		executablePath: path,
	}
}

// Name returns the scanner identifier.
func (g *GrypeScanner) Name() string {
	return "grype"
}

// grypeOutput represents the JSON structure returned by Grype.
type grypeOutput struct {
	Matches    []grypeMatch    `json:"matches"`
	Source     grypeSource     `json:"source"`
	Distro     grypeDistro     `json:"distro"`
	Descriptor grypeDescriptor `json:"descriptor"`
}

type grypeMatch struct {
	Vulnerability grypeVulnerability `json:"vulnerability"`
	RelatedVulns  []grypeRelatedVuln `json:"relatedVulnerabilities"`
	MatchDetails  []grypeMatchDetail `json:"matchDetails"`
	Artifact      grypeArtifact      `json:"artifact"`
}

type grypeVulnerability struct {
	ID          string        `json:"id"`
	DataSource  string        `json:"dataSource"`
	Namespace   string        `json:"namespace"`
	Severity    string        `json:"severity"`
	URLs        []string      `json:"urls"`
	Description string        `json:"description"`
	CVSS        []grypeCSVS   `json:"cvss"`
	Fix         grypeFix      `json:"fix"`
	Advisories  []interface{} `json:"advisories"`
}

type grypeCSVS struct {
	Version        string       `json:"version"`
	Vector         string       `json:"vector"`
	Metrics        grypeMetrics `json:"metrics"`
	VendorMetadata interface{}  `json:"vendorMetadata"`
}

type grypeMetrics struct {
	BaseScore           float64 `json:"baseScore"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type grypeRelatedVuln struct {
	ID          string `json:"id"`
	DataSource  string `json:"dataSource"`
	Namespace   string `json:"namespace"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type grypeMatchDetail struct {
	Type       string      `json:"type"`
	Matcher    string      `json:"matcher"`
	SearchedBy interface{} `json:"searchedBy"`
	Found      interface{} `json:"found"`
}

type grypeArtifact struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Type      string          `json:"type"`
	Locations []grypeLocation `json:"locations"`
	Language  string          `json:"language"`
	Licenses  []string        `json:"licenses"`
	CPEs      []string        `json:"cpes"`
	PURL      string          `json:"purl"`
}

type grypeLocation struct {
	Path    string `json:"path"`
	LayerID string `json:"layerID,omitempty"`
}

type grypeSource struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
}

type grypeDistro struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	IDLike  []string `json:"idLike"`
}

type grypeDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Scan executes Grype against the specified target.
func (g *GrypeScanner) Scan(ctx context.Context, target string) (*models.ScanResult, error) {
	startTime := time.Now()

	result := &models.ScanResult{
		Scanner:  g.Name(),
		Target:   target,
		ScanTime: startTime,
		Success:  false,
	}

	// Build the command with JSON output format
	// Using -o json for JSON output
	args := []string{
		target,
		"-o", "json",
		"--quiet",
	}

	cmd := exec.CommandContext(ctx, g.executablePath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Check if it was a timeout
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = "scanner execution timed out"
			return result, models.NewScanError(g.Name(), target, "scan", models.ErrScannerTimeout)
		}

		// Grype may still produce valid output even with errors
		if stdout.Len() == 0 {
			result.Error = fmt.Sprintf("scanner failed: %s", stderr.String())
			return result, models.NewScanError(g.Name(), target, "scan", fmt.Errorf("%w: %s", models.ErrScannerFailed, stderr.String()))
		}
	}

	result.RawOutput = stdout.Bytes()

	// Parse the JSON output
	vulnerabilities, parseErr := g.parseOutput(stdout.Bytes())
	if parseErr != nil {
		result.Error = fmt.Sprintf("failed to parse output: %v", parseErr)
		return result, parseErr
	}

	result.Vulnerabilities = vulnerabilities
	result.Duration = time.Since(startTime)
	result.Success = true

	return result, nil
}

// parseOutput converts Grype's JSON output to normalized vulnerabilities.
func (g *GrypeScanner) parseOutput(data []byte) ([]models.Vulnerability, error) {
	if len(data) == 0 {
		return []models.Vulnerability{}, nil
	}

	var output grypeOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, models.NewParseError(g.Name(), "", fmt.Errorf("invalid JSON: %w", err))
	}

	var vulnerabilities []models.Vulnerability

	for _, match := range output.Matches {
		// Get fixed version if available
		fixedVersion := ""
		if len(match.Vulnerability.Fix.Versions) > 0 {
			fixedVersion = match.Vulnerability.Fix.Versions[0]
		}

		// Collect references
		references := match.Vulnerability.URLs

		normalized := models.Vulnerability{
			CVE:              match.Vulnerability.ID,
			Package:          match.Artifact.Name,
			InstalledVersion: match.Artifact.Version,
			FixedVersion:     fixedVersion,
			Severity:         g.normalizeSeverity(match.Vulnerability.Severity),
			Scanner:          g.Name(),
			Title:            fmt.Sprintf("%s vulnerability in %s", match.Vulnerability.ID, match.Artifact.Name),
			Description:      match.Vulnerability.Description,
			References:       references,
		}
		vulnerabilities = append(vulnerabilities, normalized)
	}

	return vulnerabilities, nil
}

// normalizeSeverity converts Grype's severity strings to our standard format.
func (g *GrypeScanner) normalizeSeverity(severity string) models.Severity {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return models.SeverityCritical
	case "HIGH":
		return models.SeverityHigh
	case "MEDIUM":
		return models.SeverityMedium
	case "LOW":
		return models.SeverityLow
	case "NEGLIGIBLE":
		return models.SeverityLow
	default:
		return models.SeverityUnknown
	}
}

// Info returns metadata about the Grype installation.
func (g *GrypeScanner) Info(ctx context.Context) (*models.ScannerInfo, error) {
	info := &models.ScannerInfo{
		Name:      g.Name(),
		Available: false,
	}

	// Try to get version information
	cmd := exec.CommandContext(ctx, g.executablePath, "version", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		// Try without JSON format
		cmd = exec.CommandContext(ctx, g.executablePath, "version")
		output, err = cmd.Output()
		if err != nil {
			return info, nil
		}
		// Parse simple version output
		info.Version = strings.TrimSpace(string(output))
		info.Available = true
	} else {
		// Parse version JSON
		var versionInfo struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(output, &versionInfo); err == nil {
			info.Version = versionInfo.Version
		}
		info.Available = true
	}

	// Get the executable path
	if path, err := exec.LookPath(g.executablePath); err == nil {
		info.Path = path
	}

	return info, nil
}

// IsAvailable checks if Grype is installed and accessible.
func (g *GrypeScanner) IsAvailable() bool {
	_, err := exec.LookPath(g.executablePath)
	return err == nil
}

// ParseOutputForTest exposes the parseOutput method for integration testing.
// This allows tests to verify JSON parsing without needing the actual scanner binary.
func (g *GrypeScanner) ParseOutputForTest(data []byte) ([]models.Vulnerability, error) {
	return g.parseOutput(data)
}
