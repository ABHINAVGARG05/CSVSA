// Package report - HTML format generator with rich visualization
package report

import (
	"fmt"
	"html/template"
	"io"
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

	// Chart data (for JavaScript)
	SeverityChartData string
	ScannerChartData  string
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

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
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

	// Build chart data
	data.SeverityChartData = fmt.Sprintf("[%d, %d, %d, %d, %d]",
		data.CriticalCount, data.HighCount, data.MediumCount, data.LowCount, data.UnknownCount)

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
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e4e4e4;
            min-height: 100vh;
            padding: 2rem;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            margin-bottom: 2rem;
            padding: 2rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        h1 {
            font-size: 2.5rem;
            background: linear-gradient(90deg, #00d9ff, #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }
        
        .subtitle {
            color: #888;
            font-size: 1rem;
        }
        
        .meta-info {
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin-top: 1rem;
            flex-wrap: wrap;
        }
        
        .meta-item {
            background: rgba(0, 217, 255, 0.1);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-size: 0.9rem;
        }
        
        .meta-item strong {
            color: #00d9ff;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 32px rgba(0, 217, 255, 0.2);
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: #888;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .stat-card.critical .stat-value { color: #ff4757; }
        .stat-card.high .stat-value { color: #ff6b6b; }
        .stat-card.medium .stat-value { color: #ffa502; }
        .stat-card.low .stat-value { color: #2ed573; }
        .stat-card.consensus .stat-value { color: #00d9ff; }
        .stat-card.overlap .stat-value { color: #00ff88; }
        
        .section {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .section-title {
            font-size: 1.3rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid rgba(0, 217, 255, 0.3);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .section-title::before {
            content: '';
            width: 4px;
            height: 24px;
            background: linear-gradient(180deg, #00d9ff, #00ff88);
            border-radius: 2px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        
        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        th {
            background: rgba(0, 217, 255, 0.1);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.05em;
        }
        
        tr:hover {
            background: rgba(255, 255, 255, 0.03);
        }
        
        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-critical {
            background: rgba(255, 71, 87, 0.2);
            color: #ff4757;
            border: 1px solid #ff4757;
        }
        
        .severity-high {
            background: rgba(255, 107, 107, 0.2);
            color: #ff6b6b;
            border: 1px solid #ff6b6b;
        }
        
        .severity-medium {
            background: rgba(255, 165, 2, 0.2);
            color: #ffa502;
            border: 1px solid #ffa502;
        }
        
        .severity-low {
            background: rgba(46, 213, 115, 0.2);
            color: #2ed573;
            border: 1px solid #2ed573;
        }
        
        .severity-unknown {
            background: rgba(128, 128, 128, 0.2);
            color: #888;
            border: 1px solid #888;
        }
        
        .scanner-status {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }
        
        .status-dot.success { background: #2ed573; }
        .status-dot.failure { background: #ff4757; }
        
        .severity-chart {
            display: flex;
            justify-content: center;
            gap: 2rem;
            padding: 1rem 0;
            flex-wrap: wrap;
        }
        
        .chart-bar {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.5rem;
        }
        
        .bar-container {
            width: 60px;
            height: 150px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            display: flex;
            align-items: flex-end;
            overflow: hidden;
        }
        
        .bar-fill {
            width: 100%;
            border-radius: 8px 8px 0 0;
            transition: height 0.5s ease;
        }
        
        .bar-label {
            font-size: 0.75rem;
            color: #888;
            text-transform: uppercase;
        }
        
        .bar-value {
            font-weight: bold;
        }
        
        .no-vulns {
            text-align: center;
            padding: 2rem;
            color: #888;
        }
        
        footer {
            text-align: center;
            margin-top: 2rem;
            padding: 1rem;
            color: #666;
            font-size: 0.85rem;
        }
        
        @media (max-width: 768px) {
            body { padding: 1rem; }
            h1 { font-size: 1.8rem; }
            .meta-info { flex-direction: column; gap: 0.5rem; }
            table { font-size: 0.8rem; }
            th, td { padding: 0.5rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>CSVSA</h1>
            <p class="subtitle">Container Security Vulnerability Scanner Analyzer</p>
            <div class="meta-info">
                <span class="meta-item"><strong>Target:</strong> {{.Target}}</span>
                <span class="meta-item"><strong>Scanners:</strong> {{range $i, $s := .Scanners}}{{if $i}}, {{end}}{{$s}}{{end}}</span>
                <span class="meta-item"><strong>Duration:</strong> {{.TotalDuration}}</span>
            </div>
        </header>
        
        <div class="dashboard">
            <div class="stat-card">
                <div class="stat-value">{{.TotalVulnerabilities}}</div>
                <div class="stat-label">Total Vulnerabilities</div>
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
                <div class="stat-value">{{.CriticalCount}}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">{{.HighCount}}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">{{.MediumCount}}</div>
                <div class="stat-label">Medium</div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Severity Distribution</h2>
            <div class="severity-chart">
                <div class="chart-bar">
                    <div class="bar-value severity-critical">{{.CriticalCount}}</div>
                    <div class="bar-container">
                        <div class="bar-fill severity-critical" style="height: {{if .TotalVulnerabilities}}{{printf "%.0f" (divf (mulf .CriticalCount 100.0) .TotalVulnerabilities)}}%{{else}}0%{{end}}; background: #ff4757;"></div>
                    </div>
                    <div class="bar-label">Critical</div>
                </div>
                <div class="chart-bar">
                    <div class="bar-value severity-high">{{.HighCount}}</div>
                    <div class="bar-container">
                        <div class="bar-fill severity-high" style="height: {{if .TotalVulnerabilities}}{{printf "%.0f" (divf (mulf .HighCount 100.0) .TotalVulnerabilities)}}%{{else}}0%{{end}}; background: #ff6b6b;"></div>
                    </div>
                    <div class="bar-label">High</div>
                </div>
                <div class="chart-bar">
                    <div class="bar-value severity-medium">{{.MediumCount}}</div>
                    <div class="bar-container">
                        <div class="bar-fill severity-medium" style="height: {{if .TotalVulnerabilities}}{{printf "%.0f" (divf (mulf .MediumCount 100.0) .TotalVulnerabilities)}}%{{else}}0%{{end}}; background: #ffa502;"></div>
                    </div>
                    <div class="bar-label">Medium</div>
                </div>
                <div class="chart-bar">
                    <div class="bar-value severity-low">{{.LowCount}}</div>
                    <div class="bar-container">
                        <div class="bar-fill severity-low" style="height: {{if .TotalVulnerabilities}}{{printf "%.0f" (divf (mulf .LowCount 100.0) .TotalVulnerabilities)}}%{{else}}0%{{end}}; background: #2ed573;"></div>
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
                        <th>Scanner</th>
                        <th>Status</th>
                        <th>Vulnerabilities</th>
                        <th>Duration</th>
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
                        <th>Package</th>
                        <th>Installed</th>
                        <th>Fixed</th>
                        <th>Severity</th>
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
                        <th>Package</th>
                        <th>Installed</th>
                        <th>Fixed</th>
                        <th>Severity</th>
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
            <p>Generated by CSVSA - Container Security Vulnerability Scanner Analyzer</p>
            <p>Analysis performed at {{.AnalysisTime}}</p>
        </footer>
    </div>
</body>
</html>
`)
