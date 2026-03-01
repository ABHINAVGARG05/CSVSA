// Package consensus implements the core algorithm for computing agreement
// between multiple vulnerability scanners.
//
// Mathematical Foundation:
// Given sets of vulnerabilities from n scanners: V₁, V₂, ..., Vₙ
//
// Definitions:
//
//   - Consensus (Intersection): C = V₁ ∩ V₂ ∩ ... ∩ Vₙ
//     Vulnerabilities found by ALL scanners
//
//   - Union: U = V₁ ∪ V₂ ∪ ... ∪ Vₙ
//     All unique vulnerabilities found by ANY scanner
//
//   - Unique to scanner i: Uᵢ = Vᵢ - (V₁ ∪ ... ∪ Vᵢ₋₁ ∪ Vᵢ₊₁ ∪ ... ∪ Vₙ)
//     Vulnerabilities found ONLY by scanner i
//
//   - Overlap Percentage: |C| / |U| × 100
//     Measures agreement between scanners
//
// Algorithm Complexity Analysis:
// Let n = number of scanners, m = average vulnerabilities per scanner
//   - Time Complexity: O(n × m) for building sets + O(m) for intersection
//     Overall: O(n × m)
//   - Space Complexity: O(n × m) for storing all vulnerability sets
//
// Confidence Scoring:
// - HIGH: Found by all scanners (consensus)
// - MEDIUM: Found by majority of scanners (>50%)
// - LOW: Found by only one scanner
package consensus

import (
	"sort"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
	"github.com/ABHINAVGARG05/CSVSA/internal/normalizer"
)

// Analyzer computes consensus metrics from multiple scanner results.
type Analyzer struct {
	normalizer *normalizer.Normalizer
}

// NewAnalyzer creates a new consensus analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		normalizer: normalizer.NewNormalizer(),
	}
}

// Analyze computes the consensus between scan results from multiple scanners.
//
// Algorithm Steps:
// 1. Extract vulnerabilities from each successful scan
// 2. Build a map of vulnerability key -> list of scanners that found it
// 3. Compute intersection (consensus) - vulns found by ALL scanners
// 4. Compute unique findings - vulns found by ONLY one scanner
// 5. Calculate overlap percentage and confidence levels
//
// Time Complexity: O(n × m) where n = scanners, m = avg vulnerabilities
// Space Complexity: O(n × m) for the vulnerability map
func (a *Analyzer) Analyze(target string, results []models.ScanResult) *models.ConsensusResult {
	startTime := time.Now()

	// Filter to only successful scans
	successfulResults := filterSuccessful(results)
	scannerNames := extractScannerNames(successfulResults)

	if len(successfulResults) == 0 || len(scannerNames) == 0 {
		return &models.ConsensusResult{
			Target:             target,
			Scanners:           scannerNames,
			Consensus:          []models.Vulnerability{},
			UniqueFindings:     map[string][]models.Vulnerability{},
			AllVulnerabilities: []models.Vulnerability{},
			OverlapPercentage:  0,
			ScanResults:        results,
			AnalysisTime:       time.Now(),
			TotalDuration:      time.Since(startTime),
		}
	}

	// Build vulnerability occurrence map
	// Key: vulnerability key (CVE|Package|Version)
	// Value: VulnerabilityOccurrence with scanner list and merged data
	occurrenceMap := a.buildOccurrenceMap(successfulResults)

	// Compute consensus and unique findings
	consensus, uniqueFindings, allVulns := a.computeSets(occurrenceMap, scannerNames)

	// Calculate overlap percentage
	overlapPct := calculateOverlapPercentage(len(consensus), len(allVulns))

	// Sort results by severity
	sortBySeverity(consensus)
	sortBySeverity(allVulns)
	for scanner := range uniqueFindings {
		sortBySeverity(uniqueFindings[scanner])
	}

	return &models.ConsensusResult{
		Target:             target,
		Scanners:           scannerNames,
		Consensus:          consensus,
		UniqueFindings:     uniqueFindings,
		AllVulnerabilities: allVulns,
		OverlapPercentage:  overlapPct,
		ScanResults:        results,
		AnalysisTime:       time.Now(),
		TotalDuration:      time.Since(startTime),
	}
}

// VulnerabilityOccurrence tracks which scanners found a vulnerability.
type VulnerabilityOccurrence struct {
	Vulnerability models.Vulnerability
	Scanners      []string
	ScannerSet    map[string]struct{}
	Count         int
}

// buildOccurrenceMap creates a map tracking which scanners found each vulnerability.
//
// Algorithm:
// For each scanner result:
//
//	For each vulnerability:
//	  Normalize the vulnerability
//	  Add to map using vulnerability key
//	  Track which scanner found it
//
// Time Complexity: O(n × m) where n = scanners, m = vulns per scanner
func (a *Analyzer) buildOccurrenceMap(results []models.ScanResult) map[string]*VulnerabilityOccurrence {
	occurrences := make(map[string]*VulnerabilityOccurrence)

	for _, result := range results {
		for _, vuln := range result.Vulnerabilities {
			key := vuln.Key()

			if occ, exists := occurrences[key]; exists {
				// Add scanner to existing occurrence (unique per scanner)
				if _, seen := occ.ScannerSet[result.Scanner]; !seen {
					occ.ScannerSet[result.Scanner] = struct{}{}
					occ.Scanners = append(occ.Scanners, result.Scanner)
					occ.Count++
				}
				// Merge vulnerability data (keep more complete version)
				occ.Vulnerability = a.mergeVulnerability(occ.Vulnerability, vuln)
			} else {
				// Create new occurrence
				occurrences[key] = &VulnerabilityOccurrence{
					Vulnerability: vuln,
					Scanners:      []string{result.Scanner},
					ScannerSet:    map[string]struct{}{result.Scanner: {}},
					Count:         1,
				}
			}
		}
	}

	return occurrences
}

// mergeVulnerability combines data from multiple scanner findings.
// Prefers non-empty fields and longer descriptions.
func (a *Analyzer) mergeVulnerability(a1, a2 models.Vulnerability) models.Vulnerability {
	merged := a1

	// Prefer non-empty fixed version
	if merged.FixedVersion == "" && a2.FixedVersion != "" {
		merged.FixedVersion = a2.FixedVersion
	}

	// Prefer longer description
	if len(a2.Description) > len(merged.Description) {
		merged.Description = a2.Description
	}

	// Prefer longer title
	if len(a2.Title) > len(merged.Title) {
		merged.Title = a2.Title
	}

	// Merge references
	merged.References = mergeReferences(merged.References, a2.References)

	// For scanner field, indicate multiple sources
	merged.Scanner = "multiple"

	return merged
}

// computeSets calculates consensus, unique findings, and all vulnerabilities.
//
// Mathematical Operations:
// - Consensus: vulnerabilities where count == total scanners
// - Unique[i]: vulnerabilities where scanners == [i] only
// - All: union of all vulnerabilities
func (a *Analyzer) computeSets(
	occurrences map[string]*VulnerabilityOccurrence,
	scanners []string,
) ([]models.Vulnerability, map[string][]models.Vulnerability, []models.Vulnerability) {

	totalScanners := len(scanners)
	var consensus []models.Vulnerability
	uniqueFindings := make(map[string][]models.Vulnerability)
	var allVulns []models.Vulnerability

	// Initialize unique findings map
	for _, scanner := range scanners {
		uniqueFindings[scanner] = []models.Vulnerability{}
	}

	for _, occ := range occurrences {
		vuln := occ.Vulnerability
		allVulns = append(allVulns, vuln)

		if occ.Count == totalScanners {
			// Found by ALL scanners - consensus
			consensus = append(consensus, vuln)
		} else if occ.Count == 1 {
			// Found by only ONE scanner - unique
			scanner := occ.Scanners[0]
			// Restore original scanner name for unique findings
			vulnCopy := vuln
			vulnCopy.Scanner = scanner
			uniqueFindings[scanner] = append(uniqueFindings[scanner], vulnCopy)
		}
		// Note: vulns found by some but not all scanners are in allVulns but
		// not in consensus or unique
	}

	return consensus, uniqueFindings, allVulns
}

// ConfidenceScore calculates confidence for a vulnerability based on scanner agreement.
type ConfidenceScore struct {
	Level      models.ConfidenceLevel
	Scanners   []string
	Percentage float64
}

// CalculateConfidence determines confidence level for a vulnerability.
func (a *Analyzer) CalculateConfidence(occ *VulnerabilityOccurrence, totalScanners int) ConfidenceScore {
	if totalScanners == 0 {
		return ConfidenceScore{
			Level:      models.ConfidenceLow,
			Scanners:   occ.Scanners,
			Percentage: 0,
		}
	}
	percentage := float64(occ.Count) / float64(totalScanners) * 100

	var level models.ConfidenceLevel
	switch {
	case occ.Count == totalScanners:
		level = models.ConfidenceHigh
	case percentage > 50:
		level = models.ConfidenceMedium
	default:
		level = models.ConfidenceLow
	}

	return ConfidenceScore{
		Level:      level,
		Scanners:   occ.Scanners,
		Percentage: percentage,
	}
}

// GetVulnerabilityConfidences returns confidence scores for all vulnerabilities.
func (a *Analyzer) GetVulnerabilityConfidences(results []models.ScanResult) map[string]ConfidenceScore {
	successfulResults := filterSuccessful(results)
	totalScanners := len(successfulResults)
	occurrences := a.buildOccurrenceMap(successfulResults)

	confidences := make(map[string]ConfidenceScore)
	for key, occ := range occurrences {
		confidences[key] = a.CalculateConfidence(occ, totalScanners)
	}

	return confidences
}

// Statistics holds computed statistics about the consensus analysis.
type Statistics struct {
	TotalVulnerabilities   int
	ConsensusCount         int
	UniqueCount            map[string]int
	OverlapPercentage      float64
	SeverityDistribution   map[models.Severity]int
	ConsensusBySeverity    map[models.Severity]int
	HighConfidenceCount    int
	MediumConfidenceCount  int
	LowConfidenceCount     int
	ScannerAgreementMatrix map[string]map[string]int
}

// ComputeStatistics calculates detailed statistics from the analysis.
func (a *Analyzer) ComputeStatistics(result *models.ConsensusResult) Statistics {
	stats := Statistics{
		TotalVulnerabilities: len(result.AllVulnerabilities),
		ConsensusCount:       len(result.Consensus),
		UniqueCount:          make(map[string]int),
		OverlapPercentage:    result.OverlapPercentage,
		SeverityDistribution: make(map[models.Severity]int),
		ConsensusBySeverity:  make(map[models.Severity]int),
	}

	// Count unique per scanner
	for scanner, vulns := range result.UniqueFindings {
		stats.UniqueCount[scanner] = len(vulns)
	}

	// Severity distribution for all
	for _, v := range result.AllVulnerabilities {
		stats.SeverityDistribution[v.Severity]++
	}

	// Severity distribution for consensus
	for _, v := range result.Consensus {
		stats.ConsensusBySeverity[v.Severity]++
	}

	// Compute scanner agreement matrix
	stats.ScannerAgreementMatrix = a.computeAgreementMatrix(result.ScanResults)

	return stats
}

// computeAgreementMatrix calculates pairwise agreement between scanners.
// Entry [i][j] = number of vulnerabilities found by both scanner i and scanner j.
func (a *Analyzer) computeAgreementMatrix(results []models.ScanResult) map[string]map[string]int {
	successfulResults := filterSuccessful(results)
	occurrences := a.buildOccurrenceMap(successfulResults)

	// Initialize matrix
	matrix := make(map[string]map[string]int)
	for _, r := range successfulResults {
		matrix[r.Scanner] = make(map[string]int)
	}

	// Count pairwise agreements
	for _, occ := range occurrences {
		// For each pair of scanners that found this vuln
		for i := 0; i < len(occ.Scanners); i++ {
			for j := i; j < len(occ.Scanners); j++ {
				s1, s2 := occ.Scanners[i], occ.Scanners[j]
				matrix[s1][s2]++
				if s1 != s2 {
					matrix[s2][s1]++
				}
			}
		}
	}

	return matrix
}

// Helper functions

func filterSuccessful(results []models.ScanResult) []models.ScanResult {
	var successful []models.ScanResult
	for _, r := range results {
		if r.Success {
			successful = append(successful, r)
		}
	}
	return successful
}

func extractScannerNames(results []models.ScanResult) []string {
	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.Scanner
	}
	sort.Strings(names)
	return names
}

func calculateOverlapPercentage(consensusCount, totalCount int) float64 {
	if totalCount == 0 {
		return 0
	}
	return float64(consensusCount) / float64(totalCount) * 100
}

func sortBySeverity(vulns []models.Vulnerability) {
	sort.Slice(vulns, func(i, j int) bool {
		if vulns[i].Severity.Weight() != vulns[j].Severity.Weight() {
			return vulns[i].Severity.Weight() > vulns[j].Severity.Weight()
		}
		return vulns[i].CVE < vulns[j].CVE
	})
}

func mergeReferences(refs1, refs2 []string) []string {
	seen := make(map[string]bool)
	var merged []string

	for _, ref := range refs1 {
		if !seen[ref] {
			seen[ref] = true
			merged = append(merged, ref)
		}
	}

	for _, ref := range refs2 {
		if !seen[ref] {
			seen[ref] = true
			merged = append(merged, ref)
		}
	}

	return merged
}
