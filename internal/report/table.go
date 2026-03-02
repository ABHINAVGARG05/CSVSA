// Package report - Table format generator for CLI output
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
	"github.com/fatih/color"
)

// TableGenerator produces human-readable CLI table output.
type TableGenerator struct {
	// colorEnabled controls whether to use ANSI colors.
	colorEnabled bool
}

// NewTableGenerator creates a new table generator.
func NewTableGenerator() *TableGenerator {
	return &TableGenerator{
		colorEnabled: true,
	}
}

// NewTableGeneratorWithOptions creates a table generator with custom options.
func NewTableGeneratorWithOptions(colorEnabled bool) *TableGenerator {
	return &TableGenerator{
		colorEnabled: colorEnabled,
	}
}

// Format returns the generator format name.
func (t *TableGenerator) Format() string {
	return "table"
}

// Generate produces a CLI table report.
func (t *TableGenerator) Generate(result *models.ConsensusResult, w io.Writer) error {
	// Print header
	t.printHeader(w, result)

	// Print summary statistics
	t.printSummary(w, result)

	// Print consensus vulnerabilities
	if len(result.Consensus) > 0 {
		t.printSection(w, "CONSENSUS VULNERABILITIES (Found by ALL scanners)", result.Consensus)
	}

	// Print unique findings per scanner
	for scanner, vulns := range result.UniqueFindings {
		if len(vulns) > 0 {
			title := fmt.Sprintf("UNIQUE TO %s (Not found by other scanners)", strings.ToUpper(scanner))
			t.printSection(w, title, vulns)
		}
	}

	// Print severity distribution
	t.printSeverityDistribution(w, result)

	return nil
}

// printHeader outputs the report header.
func (t *TableGenerator) printHeader(w io.Writer, result *models.ConsensusResult) {
	fmt.Fprintln(w)
	t.printColored(w, color.FgCyan, "═══════════════════════════════════════════════════════════════════════════════")
	t.printColored(w, color.FgCyan, "                    CSVSA - Container Security Vulnerability Scanner Analyzer")
	t.printColored(w, color.FgCyan, "═══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Target: %s\n", result.Target)
	fmt.Fprintf(w, "Scanners: %s\n", strings.Join(result.Scanners, ", "))
	fmt.Fprintf(w, "Analysis Time: %s\n", result.AnalysisTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintln(w)
}

// printSummary outputs summary statistics.
func (t *TableGenerator) printSummary(w io.Writer, result *models.ConsensusResult) {
	t.printColored(w, color.FgYellow, "SUMMARY")
	t.printColored(w, color.FgYellow, "───────────────────────────────────────────────────────────────────────────────")

	// Calculate metrics
	successfulScanners := result.SuccessfulScanners()
	totalUnique := 0
	for _, vulns := range result.UniqueFindings {
		totalUnique += len(vulns)
	}

	// Simple table output
	fmt.Fprintf(w, "  %-30s │ %d\n", "Total Vulnerabilities", len(result.AllVulnerabilities))
	fmt.Fprintf(w, "  %-30s │ %d\n", "Consensus (High Confidence)", len(result.Consensus))
	fmt.Fprintf(w, "  %-30s │ %d\n", "Unique Findings", totalUnique)
	fmt.Fprintf(w, "  %-30s │ %.1f%%\n", "Scanner Agreement", result.OverlapPercentage)
	fmt.Fprintf(w, "  %-30s │ %d/%d\n", "Successful Scanners", successfulScanners, len(result.ScanResults))
	fmt.Fprintln(w)
}

// printSection outputs a section of vulnerabilities.
func (t *TableGenerator) printSection(w io.Writer, title string, vulns []models.Vulnerability) {
	t.printColored(w, color.FgGreen, title)
	t.printColored(w, color.FgGreen, "───────────────────────────────────────────────────────────────────────────────")

	if len(vulns) == 0 {
		fmt.Fprintln(w, "  No vulnerabilities in this category.")
		fmt.Fprintln(w)
		return
	}

	// Print header
	fmt.Fprintf(w, "  %-18s │ %-20s │ %-12s │ %-12s │ %-10s\n",
		"CVE", "PACKAGE", "VERSION", "FIXED", "SEVERITY")
	fmt.Fprintln(w, "  "+strings.Repeat("─", 78))

	for _, v := range vulns {
		fixedVersion := v.FixedVersion
		if fixedVersion == "" {
			fixedVersion = "N/A"
		}

		severityStr := t.formatSeverity(v.Severity)
		fmt.Fprintf(w, "  %-18s │ %-20s │ %-12s │ %-12s │ %s\n",
			truncate(v.CVE, 18),
			truncate(v.Package, 20),
			truncate(v.InstalledVersion, 12),
			truncate(fixedVersion, 12),
			severityStr,
		)
	}

	fmt.Fprintln(w)
}

// printSeverityDistribution outputs severity breakdown.
func (t *TableGenerator) printSeverityDistribution(w io.Writer, result *models.ConsensusResult) {
	t.printColored(w, color.FgMagenta, "SEVERITY DISTRIBUTION")
	t.printColored(w, color.FgMagenta, "───────────────────────────────────────────────────────────────────────────────")

	dist := result.SeverityDistribution()
	consensusDist := result.ConsensusSeverityDistribution()

	severities := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityUnknown,
	}

	maxCount := 0
	for _, count := range dist {
		if count > maxCount {
			maxCount = count
		}
	}

	// Print header
	fmt.Fprintf(w, "  %-12s │ %-8s │ %-10s │ %s\n", "SEVERITY", "TOTAL", "CONSENSUS", "BAR")
	fmt.Fprintln(w, "  "+strings.Repeat("─", 60))

	for _, sev := range severities {
		total := dist[sev]
		consensus := consensusDist[sev]
		bar := t.makeBar(total, maxCount, 20)

		fmt.Fprintf(w, "  %-12s │ %-8d │ %-10d │ %s\n",
			t.formatSeverity(sev),
			total,
			consensus,
			bar,
		)
	}

	fmt.Fprintln(w)
}

// formatSeverity returns a colored severity string.
func (t *TableGenerator) formatSeverity(sev models.Severity) string {
	if !t.colorEnabled {
		return string(sev)
	}

	switch sev {
	case models.SeverityCritical:
		return color.New(color.FgRed, color.Bold).Sprint("CRITICAL")
	case models.SeverityHigh:
		return color.New(color.FgRed).Sprint("HIGH")
	case models.SeverityMedium:
		return color.New(color.FgYellow).Sprint("MEDIUM")
	case models.SeverityLow:
		return color.New(color.FgGreen).Sprint("LOW")
	default:
		return color.New(color.FgWhite).Sprint("UNKNOWN")
	}
}

// printColored outputs colored text.
func (t *TableGenerator) printColored(w io.Writer, c color.Attribute, text string) {
	if t.colorEnabled {
		color.New(c).Fprintln(w, text)
	} else {
		fmt.Fprintln(w, text)
	}
}

// makeBar creates a visual bar for the distribution chart.
func (t *TableGenerator) makeBar(value, max, width int) string {
	if max == 0 {
		return ""
	}

	filled := (value * width) / max
	if value > 0 && filled == 0 {
		filled = 1 // At least 1 char for non-zero values
	}

	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

// truncate shortens a string to maxLen with ellipsis.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
