// Package report - HTML format generator with rich visualization
package report

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

// HTMLGenerator produces rich HTML reports with styling and charts.
type HTMLGenerator struct {
	// templatePath allows custom templates (empty uses embedded default)
	templatePath string
}

// NewHTMLGenerator creates a new HTML generator.
func NewHTMLGenerator() *HTMLGenerator {
	return &HTMLGenerator{}
}

// NewHTMLGeneratorWithTemplate creates an HTML generator with a custom template.
func NewHTMLGeneratorWithTemplate(templatePath string) *HTMLGenerator {
	return &HTMLGenerator{
		templatePath: templatePath,
	}
}

// Format returns the generator format name.
func (h *HTMLGenerator) Format() string {
	return "html"
}

// HTMLReportData contains all data needed for the HTML template.
type HTMLReportData struct {
	Title                string
	Target               string
	Scanners             []string
	AnalysisTime         string
	TotalDuration        string
	TotalVulnerabilities int
	ConsensusCount       int
	UniqueCount          int
	OverlapPercentage    string
	SuccessfulScanners   int
	TotalScanners        int

	// Severity counts
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	UnknownCount  int

	// Consensus severity counts
	ConsensusCritical int
	ConsensusHigh     int
	ConsensusMedium   int
	ConsensusLow      int

	// Vulnerability lists
	ConsensusVulns []HTMLVulnerability
	UniqueFindings map[string][]HTMLVulnerability
	AllVulns       []HTMLVulnerability

	// Scanner results
	ScannerResults []HTMLScannerResult
}

// HTMLVulnerability is a vulnerability formatted for HTML display.
type HTMLVulnerability struct {
	CVE              string
	Package          string
	InstalledVersion string
	FixedVersion     string
	Severity         string
	SeverityClass    string
	Title            string
	Description      string
	References       []string
}

// HTMLScannerResult is a scanner result formatted for HTML display.
type HTMLScannerResult struct {
	Name        string
	Success     bool
	StatusClass string
	Error       string
	VulnCount   int
	Duration    string
}

// Generate produces an HTML report.
func (h *HTMLGenerator) Generate(result *models.ConsensusResult, w io.Writer) error {
	data := h.buildReportData(result)

	// Create template with helper functions
	funcMap := template.FuncMap{
		"mulf": func(a, b interface{}) float64 {
			af := toFloat64(a)
			bf := toFloat64(b)
			return af * bf
		},
		"divf": func(a, b interface{}) float64 {
			af := toFloat64(a)
			bf := toFloat64(b)
			if bf == 0 {
				return 0
			}
			return af / bf
		},
	}

    templateSource := htmlTemplate
    if h.templatePath != "" {
        contents, err := os.ReadFile(h.templatePath)
        if err != nil {
            return fmt.Errorf("failed to read custom template %s: %w", h.templatePath, err)
        }
        templateSource = string(contents)
    }

    tmpl, err := template.New("report").Funcs(funcMap).Parse(templateSource)
    if err != nil && templateSource != htmlTemplate {
        fmt.Fprintf(os.Stderr, "warning: failed to parse custom template %s: %v; falling back to embedded template\n", h.templatePath, err)
        tmpl, err = template.New("report").Funcs(funcMap).Parse(htmlTemplate)
    }
    if err != nil {
        return fmt.Errorf("failed to parse template: %w", err)
    }

	return tmpl.Execute(w, data)
}

// toFloat64 converts various numeric types to float64.
func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	case float32:
		return float64(n)
	default:
		return 0
	}
}

// buildReportData constructs the template data from the consensus result.
func (h *HTMLGenerator) buildReportData(result *models.ConsensusResult) HTMLReportData {
	dist := result.SeverityDistribution()
	consensusDist := result.ConsensusSeverityDistribution()

	uniqueCount := 0
	uniqueFindings := make(map[string][]HTMLVulnerability)
	for scanner, vulns := range result.UniqueFindings {
		uniqueCount += len(vulns)
		uniqueFindings[scanner] = h.convertVulnerabilities(vulns)
	}

	data := HTMLReportData{
		Title:                "CSVSA Vulnerability Report",
		Target:               result.Target,
		Scanners:             result.Scanners,
		AnalysisTime:         result.AnalysisTime.Format(time.RFC3339),
		TotalDuration:        result.TotalDuration.Round(time.Millisecond).String(),
		TotalVulnerabilities: len(result.AllVulnerabilities),
		ConsensusCount:       len(result.Consensus),
		UniqueCount:          uniqueCount,
		OverlapPercentage:    fmt.Sprintf("%.1f", result.OverlapPercentage),
		SuccessfulScanners:   result.SuccessfulScanners(),
		TotalScanners:        len(result.ScanResults),

		CriticalCount: dist[models.SeverityCritical],
		HighCount:     dist[models.SeverityHigh],
		MediumCount:   dist[models.SeverityMedium],
		LowCount:      dist[models.SeverityLow],
		UnknownCount:  dist[models.SeverityUnknown],

		ConsensusCritical: consensusDist[models.SeverityCritical],
		ConsensusHigh:     consensusDist[models.SeverityHigh],
		ConsensusMedium:   consensusDist[models.SeverityMedium],
		ConsensusLow:      consensusDist[models.SeverityLow],

		ConsensusVulns: h.convertVulnerabilities(result.Consensus),
		UniqueFindings: uniqueFindings,
		AllVulns:       h.convertVulnerabilities(result.AllVulnerabilities),
		ScannerResults: h.convertScannerResults(result.ScanResults),
	}

	return data
}

// convertVulnerabilities transforms model vulnerabilities to HTML format.
func (h *HTMLGenerator) convertVulnerabilities(vulns []models.Vulnerability) []HTMLVulnerability {
	result := make([]HTMLVulnerability, len(vulns))
	for i, v := range vulns {
		fixedVersion := v.FixedVersion
		if fixedVersion == "" {
			fixedVersion = "No fix available"
		}

		result[i] = HTMLVulnerability{
			CVE:              v.CVE,
			Package:          v.Package,
			InstalledVersion: v.InstalledVersion,
			FixedVersion:     fixedVersion,
			Severity:         string(v.Severity),
			SeverityClass:    h.severityClass(v.Severity),
			Title:            v.Title,
			Description:      v.Description,
			References:       v.References,
		}
	}
	return result
}

// convertScannerResults transforms scanner results to HTML format.
func (h *HTMLGenerator) convertScannerResults(results []models.ScanResult) []HTMLScannerResult {
	htmlResults := make([]HTMLScannerResult, len(results))
	for i, r := range results {
		statusClass := "success"
		if !r.Success {
			statusClass = "failure"
		}

		htmlResults[i] = HTMLScannerResult{
			Name:        r.Scanner,
			Success:     r.Success,
			StatusClass: statusClass,
			Error:       r.Error,
			VulnCount:   len(r.Vulnerabilities),
			Duration:    r.Duration.Round(time.Millisecond).String(),
		}
	}
	return htmlResults
}

// severityClass returns the CSS class for a severity level.
func (h *HTMLGenerator) severityClass(sev models.Severity) string {
	switch sev {
	case models.SeverityCritical:
		return "severity-critical"
	case models.SeverityHigh:
		return "severity-high"
	case models.SeverityMedium:
		return "severity-medium"
	case models.SeverityLow:
		return "severity-low"
	default:
		return "severity-unknown"
	}
}

// Embedded HTML template
var htmlTemplate = strings.TrimSpace(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #1e1f22;     
            --bg-surface: #2b2d30;   
            --bg-hover: #393b40;
            --border-color: #393b40;
            --text-main: #bcbec4;
            --text-muted: #868a91;
            --accent: #56a8f5;     
            
            /* Severity Colors - adjusted for dark mode contrast */
            --color-critical: #f75464;
            --color-high: #e2753a;
            --color-medium: #dfa12b;
            --color-low: #62b543;
            --color-consensus: #56a8f5;
            --color-overlap: #9d88cc;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background-color: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            padding: 2rem;
            line-height: 1.5;
            font-size: 14px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .header-titles {
            flex: 1;
        }
        
        h1 {
            font-size: 1.5rem;
            color: #ffffff;
            font-weight: 700;
            margin-bottom: 0.25rem;
            letter-spacing: -0.5px;
        }
        
        .subtitle {
            color: var(--text-muted);
            font-size: 0.9rem;
        }
        
        .meta-info {
            display: flex;
            gap: 1.5rem;
            font-size: 0.85rem;
            background: var(--bg-surface);
            padding: 0.75rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: 6px;
        }
        
        .meta-item strong {
            color: var(--text-muted);
            font-weight: normal;
            margin-right: 0.25rem;
        }

        .meta-item {
            color: var(--accent);
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        /* Update the .stat-card class to reduce side padding from 1.5rem to 1rem */
        .stat-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            /* Reduced horizontal padding to give more room for text */
            padding: 1.5rem 1rem;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .stat-value {
            /* Changed from 2.5rem to a smaller size, for example 1.8rem */
            font-size: 1.8rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
            /* This will force long unbreakable strings to break instead of cutting off */
            overflow-wrap: break-word;
        }
        
        .stat-card.critical { border-top-color: var(--color-critical); }
        .stat-card.high { border-top-color: var(--color-high); }
        .stat-card.medium { border-top-color: var(--color-medium); }
        .stat-card.low { border-top-color: var(--color-low); }
        .stat-card.consensus { border-top-color: var(--color-consensus); }
        .stat-card.overlap { border-top-color: var(--color-overlap); }
        
        
        
        .stat-label {
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .section {
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            margin-bottom: 2rem;
            overflow: hidden;
        }
        
        .section-title {
            font-size: 1rem;
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--border-color);
            color: #ffffff;
            font-weight: 500;
            background: rgba(0,0,0,0.1);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        
        th, td {
            padding: 0.75rem 1.25rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        th {
            color: var(--text-muted);
            font-weight: 500;
            white-space: nowrap;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        tr:hover td {
            background: var(--bg-hover);
        }

        strong {
            color: #ffffff;
            font-weight: 500;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            border: 1px solid transparent;
        }
        
        .severity-critical { color: var(--color-critical); border-color: rgba(247, 84, 100, 0.3); background: rgba(247, 84, 100, 0.1); }
        .severity-high { color: var(--color-high); border-color: rgba(226, 117, 58, 0.3); background: rgba(226, 117, 58, 0.1); }
        .severity-medium { color: var(--color-medium); border-color: rgba(223, 161, 43, 0.3); background: rgba(223, 161, 43, 0.1); }
        .severity-low { color: var(--color-low); border-color: rgba(98, 181, 67, 0.3); background: rgba(98, 181, 67, 0.1); }
        .severity-unknown { color: var(--text-muted); border-color: var(--border-color); background: rgba(255, 255, 255, 0.05); }
        
        .scanner-status {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        
        .status-dot.success { background: var(--color-low); }
        .status-dot.failure { background: var(--color-critical); }
        
        .severity-chart {
            display: flex;
            justify-content: space-around;
            padding: 2rem;
            gap: 1rem;
        }
        
        .chart-bar {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.5rem;
            flex: 1;
            max-width: 80px;
        }
        
        .bar-container {
            width: 100%;
            height: 120px;
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid var(--border-color);
            display: flex;
            align-items: flex-end;
        }
        
        .bar-fill {
            width: 100%;
            min-height: 2px;
        }
        
        .bar-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
        }
        
        .bar-value {
            font-weight: 700;
            font-size: 1.1rem;
        }
        
        .no-vulns {
            padding: 2rem;
            color: var(--text-muted);
            text-align: center;
            font-style: italic;
        }
        
        footer {
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border-color);
            color: var(--text-muted);
            font-size: 0.75rem;
            display: flex;
            justify-content: space-between;
        }
        
        @media (max-width: 768px) {
            body { padding: 1rem; }
            header { flex-direction: column; align-items: flex-start; }
            .meta-info { flex-direction: column; gap: 0.25rem; width: 100%; }
            .severity-chart { padding: 1rem; }
            th, td { padding: 0.5rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-titles">
                <h1>CSVSA Report</h1>
                <p class="subtitle">Container Security Vulnerability Scanner Analyzer</p>
            </div>
            <div class="meta-info">
                <span class="meta-item"><strong>TARGET:</strong>{{.Target}}</span>
                <span class="meta-item"><strong>SCANNERS:</strong>{{range $i, $s := .Scanners}}{{if $i}}, {{end}}{{$s}}{{end}}</span>
                <span class="meta-item"><strong>DURATION:</strong>{{.TotalDuration}}</span>
            </div>
        </header>
        
        <div class="dashboard">
            <div class="stat-card">
                <div class="stat-value">{{.TotalVulnerabilities}}</div>
                <div class="stat-label">Total Vulns</div>
            </div>
            <div class="stat-card consensus">
                <div class="stat-value">{{.ConsensusCount}}</div>
                <div class="stat-label">High Confidence</div>
            </div>
            <div class="stat-card overlap">
                <div class="stat-value">{{.OverlapPercentage}}%</div>
                <div class="stat-label">Scanner Agreement</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value" style="color: var(--color-critical);">{{.CriticalCount}}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value" style="color: var(--color-high);">{{.HighCount}}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value" style="color: var(--color-medium);">{{.MediumCount}}</div>
                <div class="stat-label">Medium</div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Severity Distribution</h2>
            <div class="severity-chart">
                <div class="chart-bar">
                    <div class="bar-value" style="color: var(--color-critical);">{{.CriticalCount}}</div>
                    <div class="bar-container">
                        <div class="bar-fill" style="height: {{if .TotalVulnerabilities}}{{printf "%.0f" (divf (mulf .CriticalCount 100.0) .TotalVulnerabilities)}}%{{else}}0%{{end}}; background: var(--color-critical);"></div>
                    </div>
                    <div class="bar-label">Critical</div>
                </div>
                <div class="chart-bar">
                    <div class="bar-value" style="color: var(--color-high);">{{.HighCount}}</div>
                    <div class="bar-container">
                        <div class="bar-fill" style="height: {{if .TotalVulnerabilities}}{{printf "%.0f" (divf (mulf .HighCount 100.0) .TotalVulnerabilities)}}%{{else}}0%{{end}}; background: var(--color-high);"></div>
                    </div>
                    <div class="bar-label">High</div>
                </div>
                <div class="chart-bar">
                    <div class="bar-value" style="color: var(--color-medium);">{{.MediumCount}}</div>
                    <div class="bar-container">
                        <div class="bar-fill" style="height: {{if .TotalVulnerabilities}}{{printf "%.0f" (divf (mulf .MediumCount 100.0) .TotalVulnerabilities)}}%{{else}}0%{{end}}; background: var(--color-medium);"></div>
                    </div>
                    <div class="bar-label">Medium</div>
                </div>
                <div class="chart-bar">
                    <div class="bar-value" style="color: var(--color-low);">{{.LowCount}}</div>
                    <div class="bar-container">
                        <div class="bar-fill" style="height: {{if .TotalVulnerabilities}}{{printf "%.0f" (divf (mulf .LowCount 100.0) .TotalVulnerabilities)}}%{{else}}0%{{end}}; background: var(--color-low);"></div>
                    </div>
                    <div class="bar-label">Low</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Scanner Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>SCANNER</th>
                        <th>STATUS</th>
                        <th>VULNERABILITIES</th>
                        <th>DURATION</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .ScannerResults}}
                    <tr>
                        <td><strong>{{.Name}}</strong></td>
                        <td>
                            <span class="scanner-status">
                                <span class="status-dot {{.StatusClass}}"></span>
                                {{if .Success}}Success{{else}}Failed{{end}}
                            </span>
                        </td>
                        <td>{{.VulnCount}}</td>
                        <td>{{.Duration}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2 class="section-title">Consensus Vulnerabilities (High Confidence)</h2>
            {{if .ConsensusVulns}}
            <table>
                <thead>
                    <tr>
                        <th>CVE</th>
                        <th>PACKAGE</th>
                        <th>INSTALLED</th>
                        <th>FIXED</th>
                        <th>SEVERITY</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .ConsensusVulns}}
                    <tr>
                        <td><strong>{{.CVE}}</strong></td>
                        <td>{{.Package}}</td>
                        <td>{{.InstalledVersion}}</td>
                        <td>{{.FixedVersion}}</td>
                        <td><span class="severity-badge {{.SeverityClass}}">{{.Severity}}</span></td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{else}}
            <p class="no-vulns">No consensus vulnerabilities found.</p>
            {{end}}
        </div>
        
        {{range $scanner, $vulns := .UniqueFindings}}
        {{if $vulns}}
        <div class="section">
            <h2 class="section-title">Unique to {{$scanner}}</h2>
            <table>
                <thead>
                    <tr>
                        <th>CVE</th>
                        <th>PACKAGE</th>
                        <th>INSTALLED</th>
                        <th>FIXED</th>
                        <th>SEVERITY</th>
                    </tr>
                </thead>
                <tbody>
                    {{range $vulns}}
                    <tr>
                        <td><strong>{{.CVE}}</strong></td>
                        <td>{{.Package}}</td>
                        <td>{{.InstalledVersion}}</td>
                        <td>{{.FixedVersion}}</td>
                        <td><span class="severity-badge {{.SeverityClass}}">{{.Severity}}</span></td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}
        {{end}}
        
        <footer>
            <span>CSVSA Generator</span>
            <span>Analysis performed at {{.AnalysisTime}}</span>
        </footer>
    </div>
</body>
</html>
`)
