// Package normalizer provides functionality for normalizing vulnerability data
// from different scanner outputs into a unified format.
//
// Design Philosophy:
// Each scanner has its own JSON schema and data representation. The normalizer
// serves as an anti-corruption layer that:
// 1. Isolates the core domain from external schema changes
// 2. Provides consistent data regardless of source
// 3. Handles missing/malformed fields gracefully
// 4. Enables new scanner integration without affecting existing code
//
// Error Handling Strategy:
// - Missing fields: Use sensible defaults
// - Malformed data: Log warning, skip individual record, continue processing
// - Empty responses: Return empty slice (not error)
// - Invalid JSON: Return error (unrecoverable)
package normalizer

import (
	"sort"
	"strings"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

// Normalizer handles the normalization of vulnerability data from multiple sources.
type Normalizer struct {
	// deduplicationEnabled controls whether to remove duplicate vulnerabilities.
	deduplicationEnabled bool

	// severityNormalization controls whether to normalize severity strings.
	severityNormalization bool
}

// Option is a functional option for configuring the Normalizer.
type Option func(*Normalizer)

// WithDeduplication enables or disables deduplication.
func WithDeduplication(enabled bool) Option {
	return func(n *Normalizer) {
		n.deduplicationEnabled = enabled
	}
}

// WithSeverityNormalization enables or disables severity normalization.
func WithSeverityNormalization(enabled bool) Option {
	return func(n *Normalizer) {
		n.severityNormalization = enabled
	}
}

// NewNormalizer creates a new Normalizer with the given options.
func NewNormalizer(opts ...Option) *Normalizer {
	n := &Normalizer{
		deduplicationEnabled:  true,
		severityNormalization: true,
	}
	for _, opt := range opts {
		opt(n)
	}
	return n
}

// NormalizeResults takes scan results from multiple scanners and produces
// a unified, normalized list of vulnerabilities.
//
// Processing Steps:
// 1. Extract vulnerabilities from all results
// 2. Normalize severity values
// 3. Clean and validate fields
// 4. Optionally deduplicate
// 5. Sort by severity (highest first)
//
// Time Complexity: O(n log n) where n is total vulnerabilities
// Space Complexity: O(n) for storing all vulnerabilities
func (n *Normalizer) NormalizeResults(results []models.ScanResult) []models.Vulnerability {
	var allVulns []models.Vulnerability

	for _, result := range results {
		if !result.Success {
			continue
		}

		for _, vuln := range result.Vulnerabilities {
			normalized := n.normalizeVulnerability(vuln)
			if n.isValidVulnerability(normalized) {
				allVulns = append(allVulns, normalized)
			}
		}
	}

	if n.deduplicationEnabled {
		allVulns = n.deduplicate(allVulns)
	}

	// Sort by severity (highest first), then by CVE
	sort.Slice(allVulns, func(i, j int) bool {
		if allVulns[i].Severity.Weight() != allVulns[j].Severity.Weight() {
			return allVulns[i].Severity.Weight() > allVulns[j].Severity.Weight()
		}
		return allVulns[i].CVE < allVulns[j].CVE
	})

	return allVulns
}

// normalizeVulnerability applies normalization rules to a single vulnerability.
func (n *Normalizer) normalizeVulnerability(v models.Vulnerability) models.Vulnerability {
	normalized := models.Vulnerability{
		CVE:              n.normalizeCVE(v.CVE),
		Package:          n.normalizePackageName(v.Package),
		InstalledVersion: n.normalizeVersion(v.InstalledVersion),
		FixedVersion:     n.normalizeVersion(v.FixedVersion),
		Severity:         v.Severity,
		Scanner:          v.Scanner,
		Title:            strings.TrimSpace(v.Title),
		Description:      strings.TrimSpace(v.Description),
		References:       n.normalizeReferences(v.References),
	}

	if n.severityNormalization {
		normalized.Severity = n.normalizeSeverity(string(v.Severity))
	}

	return normalized
}

// normalizeCVE cleans and validates CVE identifiers.
func (n *Normalizer) normalizeCVE(cve string) string {
	cve = strings.TrimSpace(cve)
	cve = strings.ToUpper(cve)

	// Handle common prefixes
	if strings.HasPrefix(cve, "CVE-") {
		return cve
	}

	// Some scanners use different ID formats (GHSA, etc.)
	return cve
}

// normalizePackageName cleans package names.
func (n *Normalizer) normalizePackageName(pkg string) string {
	return strings.TrimSpace(pkg)
}

// normalizeVersion cleans version strings.
func (n *Normalizer) normalizeVersion(version string) string {
	return strings.TrimSpace(version)
}

// normalizeSeverity converts various severity representations to standard format.
func (n *Normalizer) normalizeSeverity(severity string) models.Severity {
	severity = strings.ToUpper(strings.TrimSpace(severity))

	switch severity {
	case "CRITICAL", "CRIT":
		return models.SeverityCritical
	case "HIGH", "H":
		return models.SeverityHigh
	case "MEDIUM", "MODERATE", "MED", "M":
		return models.SeverityMedium
	case "LOW", "L":
		return models.SeverityLow
	case "NEGLIGIBLE", "MINIMAL", "INFO", "INFORMATIONAL", "NONE":
		return models.SeverityLow
	default:
		return models.SeverityUnknown
	}
}

// normalizeReferences cleans and deduplicates reference URLs.
func (n *Normalizer) normalizeReferences(refs []string) []string {
	if len(refs) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var cleaned []string

	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref != "" && !seen[ref] {
			seen[ref] = true
			cleaned = append(cleaned, ref)
		}
	}

	return cleaned
}

// isValidVulnerability checks if a vulnerability has required fields.
func (n *Normalizer) isValidVulnerability(v models.Vulnerability) bool {
	// Must have a CVE or similar identifier
	if v.CVE == "" {
		return false
	}

	// Must have a package name
	if v.Package == "" {
		return false
	}

	return true
}

// deduplicate removes duplicate vulnerabilities based on their key.
// When duplicates exist, it prefers the one with more information.
//
// Algorithm:
// 1. Group vulnerabilities by key (CVE + Package + Version)
// 2. For each group, select the "best" entry
// 3. Return deduplicated list
//
// Time Complexity: O(n) for grouping + O(k) for selection where k is unique keys
// Space Complexity: O(n) for the map
func (n *Normalizer) deduplicate(vulns []models.Vulnerability) []models.Vulnerability {
	if len(vulns) == 0 {
		return vulns
	}

	groups := make(map[string][]models.Vulnerability)

	for _, v := range vulns {
		key := v.Key()
		groups[key] = append(groups[key], v)
	}

	result := make([]models.Vulnerability, 0, len(groups))
	for _, group := range groups {
		best := n.selectBest(group)
		result = append(result, best)
	}

	return result
}

// selectBest chooses the best vulnerability record from a group of duplicates.
// Prefers entries with more complete information.
func (n *Normalizer) selectBest(group []models.Vulnerability) models.Vulnerability {
	if len(group) == 1 {
		return group[0]
	}

	best := group[0]
	bestScore := n.completenessScore(best)

	for _, v := range group[1:] {
		score := n.completenessScore(v)
		if score > bestScore {
			best = v
			bestScore = score
		}
	}

	return best
}

// completenessScore calculates how complete a vulnerability record is.
func (n *Normalizer) completenessScore(v models.Vulnerability) int {
	score := 0

	if v.CVE != "" {
		score += 10
	}
	if v.Package != "" {
		score += 10
	}
	if v.InstalledVersion != "" {
		score += 5
	}
	if v.FixedVersion != "" {
		score += 5
	}
	if v.Severity != models.SeverityUnknown {
		score += 5
	}
	if v.Title != "" {
		score += 3
	}
	if v.Description != "" {
		score += 3
	}
	if len(v.References) > 0 {
		score += 2
	}

	return score
}

// MergeVulnerabilities combines vulnerabilities from multiple sources,
// tracking which scanners found each vulnerability.
//
// This is useful for consensus analysis where we need to know
// which scanners agree on a vulnerability.
func (n *Normalizer) MergeVulnerabilities(results []models.ScanResult) map[string][]models.Vulnerability {
	merged := make(map[string][]models.Vulnerability)

	for _, result := range results {
		if !result.Success {
			continue
		}

		for _, vuln := range result.Vulnerabilities {
			normalized := n.normalizeVulnerability(vuln)
			if n.isValidVulnerability(normalized) {
				key := normalized.Key()
				merged[key] = append(merged[key], normalized)
			}
		}
	}

	return merged
}

// FilterBySeverity returns only vulnerabilities at or above the given severity.
func (n *Normalizer) FilterBySeverity(vulns []models.Vulnerability, minSeverity models.Severity) []models.Vulnerability {
	minWeight := minSeverity.Weight()
	var filtered []models.Vulnerability

	for _, v := range vulns {
		if v.Severity.Weight() >= minWeight {
			filtered = append(filtered, v)
		}
	}

	return filtered
}

// GroupBySeverity organizes vulnerabilities by their severity level.
func (n *Normalizer) GroupBySeverity(vulns []models.Vulnerability) map[models.Severity][]models.Vulnerability {
	groups := make(map[models.Severity][]models.Vulnerability)

	for _, v := range vulns {
		groups[v.Severity] = append(groups[v.Severity], v)
	}

	return groups
}

// GroupByPackage organizes vulnerabilities by package name.
func (n *Normalizer) GroupByPackage(vulns []models.Vulnerability) map[string][]models.Vulnerability {
	groups := make(map[string][]models.Vulnerability)

	for _, v := range vulns {
		groups[v.Package] = append(groups[v.Package], v)
	}

	return groups
}

// GroupByScanner organizes vulnerabilities by scanner.
func (n *Normalizer) GroupByScanner(vulns []models.Vulnerability) map[string][]models.Vulnerability {
	groups := make(map[string][]models.Vulnerability)

	for _, v := range vulns {
		groups[v.Scanner] = append(groups[v.Scanner], v)
	}

	return groups
}
