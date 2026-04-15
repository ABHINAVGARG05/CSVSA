package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/epss"
	"github.com/ABHINAVGARG05/CSVSA/internal/models"
	"github.com/stretchr/testify/require"
)

func TestGenerateReportsWritesFiles(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "report.txt")
	jsonFile := filepath.Join(dir, "report.json")
	htmlFile := filepath.Join(dir, "report.html")

	c := &CLI{config: Config{OutputFormat: "table", OutputFile: outFile, JSONFile: jsonFile, HTMLFile: htmlFile}}
	result := &models.ConsensusResult{
		Target:             "alpine:3.18",
		Scanners:           []string{"trivy"},
		Consensus:          []models.Vulnerability{{CVE: "CVE-1", Package: "pkg", Severity: models.SeverityHigh}},
		UniqueFindings:     map[string][]models.Vulnerability{},
		AllVulnerabilities: []models.Vulnerability{{CVE: "CVE-1", Package: "pkg", Severity: models.SeverityHigh}},
		AnalysisTime:       time.Now(),
	}

	require.NoError(t, c.generateReports(result))

	for _, path := range []string{outFile, jsonFile, htmlFile} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Greater(t, info.Size(), int64(0))
	}
}

func TestWriteEPSSJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "epss.json")

	result := &models.ConsensusResult{
		AllVulnerabilities: []models.Vulnerability{
			{CVE: "CVE-1", Package: "pkg1", Severity: models.SeverityHigh},
			{CVE: "CVE-2", Package: "pkg2", Severity: models.SeverityLow},
		},
	}
	c := &CLI{}

	scores := map[string]epss.Score{
		"CVE-1": {CVE: "CVE-1", EPSS: 0.5, Percentile: 0.8},
	}

	require.NoError(t, c.writeEPSSJSON(result, scores, path))

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var entries []map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &entries))
	require.Len(t, entries, 2)
}

func TestBuildScanConfig(t *testing.T) {
	c := &CLI{config: Config{Timeout: 30 * time.Second, Scanners: []string{"trivy"}, Verbose: true, MinSeverity: "high"}}
	cfg := c.buildScanConfig("alpine:3.18")

	require.Equal(t, "alpine:3.18", cfg.Target)
	require.Equal(t, 30*time.Second, cfg.Timeout)
	require.Equal(t, []string{"trivy"}, cfg.Scanners)
	require.Equal(t, models.SeverityHigh, cfg.MinSeverity)
}

func TestEPSSHelpers(t *testing.T) {
	result := &models.ConsensusResult{
		Consensus: []models.Vulnerability{{CVE: "CVE-1"}},
		AllVulnerabilities: []models.Vulnerability{{CVE: "CVE-1"}},
		UniqueFindings: map[string][]models.Vulnerability{
			"trivy": {{CVE: "CVE-1"}},
		},
	}

	scores := map[string]epss.Score{
		"CVE-1": {CVE: "CVE-1", EPSS: 0.6, Percentile: 0.9},
	}

	vals := extractEPSSScores(result.Consensus, scores)
	require.Equal(t, []float64{0.6}, vals)

	enrichVulnsWithEPSS(result, scores)
	require.NotNil(t, result.Consensus[0].EPSSScore)
	require.Equal(t, 0.6, *result.Consensus[0].EPSSScore)
	require.NotNil(t, result.Consensus[0].EPSSPercentile)
	require.Equal(t, 0.9, *result.Consensus[0].EPSSPercentile)
}
