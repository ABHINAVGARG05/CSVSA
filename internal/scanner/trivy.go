// Package scanner - Trivy scanner adapter implementation
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

// TrivyScanner implements the Scanner interface for Aqua Security's Trivy.
// Trivy is a comprehensive vulnerability scanner for containers and other artifacts.
//
// Trivy Output Format:
// Trivy outputs JSON with a "Results" array containing vulnerability information
// for each scanned layer/component.
type TrivyScanner struct {
	// executablePath allows overriding the default "trivy" command.
	// Useful for testing or custom installations.
	executablePath string
}

// NewTrivyScanner creates a new Trivy scanner with default settings.
func NewTrivyScanner() *TrivyScanner {
	return &TrivyScanner{
		executablePath: "trivy",
	}
}

// NewTrivyScannerWithPath creates a Trivy scanner with a custom executable path.
func NewTrivyScannerWithPath(path string) *TrivyScanner {
	return &TrivyScanner{
		executablePath: path,
	}
}

// Name returns the scanner identifier.
func (t *TrivyScanner) Name() string {
	return "trivy"
}

// trivyOutput represents the JSON structure returned by Trivy.
// This is used for parsing the raw JSON output.
type trivyOutput struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Metadata      trivyMetadata `json:"Metadata"`
	Results       []trivyResult `json:"Results"`
}

type trivyMetadata struct {
	OS          *trivyOS          `json:"OS,omitempty"`
	ImageID     string            `json:"ImageID,omitempty"`
	ImageConfig *trivyImageConfig `json:"ImageConfig,omitempty"`
}

type trivyOS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

type trivyImageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"`
	Type            string               `json:"Type"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string                 `json:"VulnerabilityID"`
	PkgID            string                 `json:"PkgID"`
	PkgName          string                 `json:"PkgName"`
	InstalledVersion string                 `json:"InstalledVersion"`
	FixedVersion     string                 `json:"FixedVersion"`
	Status           string                 `json:"Status"`
	Layer            *layer                 `json:"Layer,omitempty"`
	SeveritySource   string                 `json:"SeveritySource"`
	PrimaryURL       string                 `json:"PrimaryURL"`
	Title            string                 `json:"Title"`
	Description      string                 `json:"Description"`
	Severity         string                 `json:"Severity"`
	References       []string               `json:"References"`
	CVSS             map[string]interface{} `json:"CVSS,omitempty"`
}

type layer struct {
	Digest string `json:"Digest"`
	DiffID string `json:"DiffID"`
}

// Scan executes Trivy against the specified target.
func (t *TrivyScanner) Scan(ctx context.Context, target string) (*models.ScanResult, error) {
	startTime := time.Now()

	result := &models.ScanResult{
		Scanner:  t.Name(),
		Target:   target,
		ScanTime: startTime,
		Success:  false,
	}

	// Build the command with JSON output format
	// Using --format json and --quiet to get clean JSON output
	args := []string{
		"image",
		"--format", "json",
		"--quiet",
		target,
	}

	cmd := exec.CommandContext(ctx, t.executablePath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Check if it was a timeout
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = "scanner execution timed out"
			return result, models.NewScanError(t.Name(), target, "scan", models.ErrScannerTimeout)
		}

		// Trivy may return non-zero exit code when vulnerabilities are found
		// We need to check if we still got valid JSON output
		if stdout.Len() == 0 {
			result.Error = fmt.Sprintf("scanner failed: %s", stderr.String())
			return result, models.NewScanError(t.Name(), target, "scan", fmt.Errorf("%w: %s", models.ErrScannerFailed, stderr.String()))
		}
	}

	result.RawOutput = stdout.Bytes()

	// Parse the JSON output
	vulnerabilities, parseErr := t.parseOutput(stdout.Bytes())
	if parseErr != nil {
		result.Error = fmt.Sprintf("failed to parse output: %v", parseErr)
		return result, parseErr
	}

	result.Vulnerabilities = vulnerabilities
	result.Duration = time.Since(startTime)
	result.Success = true

	return result, nil
}

// parseOutput converts Trivy's JSON output to normalized vulnerabilities.
func (t *TrivyScanner) parseOutput(data []byte) ([]models.Vulnerability, error) {
	if len(data) == 0 {
		return []models.Vulnerability{}, nil
	}

	var output trivyOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, models.NewParseError(t.Name(), "", fmt.Errorf("invalid JSON: %w", err))
	}

	var vulnerabilities []models.Vulnerability

	for _, result := range output.Results {
		for _, vuln := range result.Vulnerabilities {
			normalized := models.Vulnerability{
				CVE:              vuln.VulnerabilityID,
				Package:          vuln.PkgName,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				Severity:         t.normalizeSeverity(vuln.Severity),
				Scanner:          t.Name(),
				Title:            vuln.Title,
				Description:      vuln.Description,
				References:       vuln.References,
			}
			vulnerabilities = append(vulnerabilities, normalized)
		}
	}

	return vulnerabilities, nil
}

// normalizeSeverity converts Trivy's severity strings to our standard format.
func (t *TrivyScanner) normalizeSeverity(severity string) models.Severity {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return models.SeverityCritical
	case "HIGH":
		return models.SeverityHigh
	case "MEDIUM":
		return models.SeverityMedium
	case "LOW":
		return models.SeverityLow
	default:
		return models.SeverityUnknown
	}
}

// Info returns metadata about the Trivy installation.
func (t *TrivyScanner) Info(ctx context.Context) (*models.ScannerInfo, error) {
	info := &models.ScannerInfo{
		Name:      t.Name(),
		Available: false,
	}

	// Try to get version information
	cmd := exec.CommandContext(ctx, t.executablePath, "version", "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		return info, nil
	}

	// Parse version JSON
	var versionInfo struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(output, &versionInfo); err == nil {
		info.Version = versionInfo.Version
	}

	info.Available = true

	// Get the executable path
	if path, err := exec.LookPath(t.executablePath); err == nil {
		info.Path = path
	}

	return info, nil
}

// IsAvailable checks if Trivy is installed and accessible.
func (t *TrivyScanner) IsAvailable() bool {
	_, err := exec.LookPath(t.executablePath)
	return err == nil
}

// ParseOutputForTest exposes the parseOutput method for integration testing.
// This allows tests to verify JSON parsing without needing the actual scanner binary.
func (t *TrivyScanner) ParseOutputForTest(data []byte) ([]models.Vulnerability, error) {
	return t.parseOutput(data)
}
