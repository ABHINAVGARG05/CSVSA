package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

// PersistScanResults saves a complete scan result to the database.
// This is called automatically after each scan to persist results.
func (s *SQLiteStore) PersistScanResults(ctx context.Context, imageName, category string, result *models.ConsensusResult) (*Image, error) {
	s.logger.Info("persisting scan results",
		"image", imageName,
		"category", category,
		"total_vulns", len(result.AllVulnerabilities),
	)

	// Create image record
	image, err := s.CreateImage(ctx, imageName, category)
	if err != nil {
		return nil, fmt.Errorf("failed to create image: %w", err)
	}

	// Build scanner occurrence map for consensus type calculation
	scannerMap := s.buildScannerMap(result)

	// Persist each vulnerability and its findings
	now := time.Now().UTC()
	for _, vuln := range result.AllVulnerabilities {
		vulnRecord, err := s.UpsertVulnerability(ctx, &VulnerabilityRecord{
			CVEID:        vuln.CVE,
			Package:      vuln.Package,
			Version:      vuln.InstalledVersion,
			Severity:     vuln.Severity,
			FixedVersion: vuln.FixedVersion,
			Title:        vuln.Title,
			Description:  vuln.Description,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to upsert vulnerability %s: %w", vuln.CVE, err)
		}

		// Get scanners that found this vulnerability and consensus type
		key := vuln.Key()
		scanners, consensusType := s.getScannersAndType(key, scannerMap, len(result.Scanners))

		// Create finding for each scanner
		for _, scanner := range scanners {
			finding := &ScannerFinding{
				ImageID:         image.ID,
				VulnerabilityID: vulnRecord.ID,
				ScannerName:     scanner,
				ConsensusType:   consensusType,
				FoundAt:         now,
			}
			if err := s.CreateScannerFinding(ctx, finding); err != nil {
				return nil, fmt.Errorf("failed to create finding: %w", err)
			}
		}
	}

	s.logger.Info("scan results persisted",
		"image_id", image.ID,
		"vulns_saved", len(result.AllVulnerabilities),
	)

	return image, nil
}

// buildScannerMap creates a map of vulnerability key -> list of scanners.
func (s *SQLiteStore) buildScannerMap(result *models.ConsensusResult) map[string][]string {
	scannerMap := make(map[string][]string)

	for _, scanResult := range result.ScanResults {
		if !scanResult.Success {
			continue
		}
		for _, vuln := range scanResult.Vulnerabilities {
			key := vuln.Key()
			scannerMap[key] = append(scannerMap[key], scanResult.Scanner)
		}
	}

	return scannerMap
}

// getScannersAndType returns scanners and consensus type for a vulnerability.
func (s *SQLiteStore) getScannersAndType(key string, scannerMap map[string][]string, totalScanners int) ([]string, ConsensusType) {
	scanners := scannerMap[key]
	if len(scanners) == 0 {
		return []string{"unknown"}, ConsensusTypeUnique
	}

	// Deduplicate scanners
	seen := make(map[string]bool)
	unique := make([]string, 0, len(scanners))
	for _, sc := range scanners {
		if !seen[sc] {
			seen[sc] = true
			unique = append(unique, sc)
		}
	}

	var consensusType ConsensusType
	switch {
	case len(unique) == totalScanners:
		consensusType = ConsensusTypeConsensus
	case len(unique) == 1:
		consensusType = ConsensusTypeUnique
	default:
		consensusType = ConsensusTypePartial
	}

	return unique, consensusType
}

// GetAllFindingsWithEPSS retrieves all findings with vulnerability and EPSS data.
func (s *SQLiteStore) GetAllFindingsWithEPSS(ctx context.Context) ([]FindingWithDetails, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			sf.id, sf.image_id, sf.vulnerability_id, sf.scanner_name, sf.consensus_type, sf.found_at,
			v.id, v.cve_id, v.package, v.version, v.severity, v.fixed_version, v.title, v.description,
			i.id, i.name, i.category, i.scan_date,
			e.cve_id, e.epss_score, e.percentile, e.fetched_date
		FROM scanner_findings sf
		JOIN vulnerabilities v ON sf.vulnerability_id = v.id
		JOIN images i ON sf.image_id = i.id
		LEFT JOIN epss_scores e ON v.cve_id = e.cve_id
		ORDER BY i.scan_date DESC, v.severity DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	return s.scanFindingsWithDetails(rows)
}

// GetFindingsByCategory retrieves findings for images in a specific category.
func (s *SQLiteStore) GetFindingsByCategory(ctx context.Context, category string) ([]FindingWithDetails, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			sf.id, sf.image_id, sf.vulnerability_id, sf.scanner_name, sf.consensus_type, sf.found_at,
			v.id, v.cve_id, v.package, v.version, v.severity, v.fixed_version, v.title, v.description,
			i.id, i.name, i.category, i.scan_date,
			e.cve_id, e.epss_score, e.percentile, e.fetched_date
		FROM scanner_findings sf
		JOIN vulnerabilities v ON sf.vulnerability_id = v.id
		JOIN images i ON sf.image_id = i.id
		LEFT JOIN epss_scores e ON v.cve_id = e.cve_id
		WHERE i.category = ?
		ORDER BY i.scan_date DESC, v.severity DESC
	`, category)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	return s.scanFindingsWithDetails(rows)
}

// GetFindingsByConsensusType retrieves findings with a specific consensus type.
func (s *SQLiteStore) GetFindingsByConsensusType(ctx context.Context, consensusType ConsensusType) ([]FindingWithDetails, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			sf.id, sf.image_id, sf.vulnerability_id, sf.scanner_name, sf.consensus_type, sf.found_at,
			v.id, v.cve_id, v.package, v.version, v.severity, v.fixed_version, v.title, v.description,
			i.id, i.name, i.category, i.scan_date,
			e.cve_id, e.epss_score, e.percentile, e.fetched_date
		FROM scanner_findings sf
		JOIN vulnerabilities v ON sf.vulnerability_id = v.id
		JOIN images i ON sf.image_id = i.id
		LEFT JOIN epss_scores e ON v.cve_id = e.cve_id
		WHERE sf.consensus_type = ?
		ORDER BY e.epss_score DESC NULLS LAST
	`, string(consensusType))
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	return s.scanFindingsWithDetails(rows)
}

// GetUniqueCVEsForImage returns distinct CVE IDs for an image.
func (s *SQLiteStore) GetUniqueCVEsForImage(ctx context.Context, imageID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT v.cve_id
		FROM scanner_findings sf
		JOIN vulnerabilities v ON sf.vulnerability_id = v.id
		WHERE sf.image_id = ?
	`, imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to query CVEs: %w", err)
	}
	defer rows.Close()

	var cves []string
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return nil, fmt.Errorf("failed to scan CVE: %w", err)
		}
		cves = append(cves, cve)
	}
	return cves, rows.Err()
}

// GetAllUniqueCVEs returns all distinct CVE IDs in the database.
func (s *SQLiteStore) GetAllUniqueCVEs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT DISTINCT cve_id FROM vulnerabilities")
	if err != nil {
		return nil, fmt.Errorf("failed to query CVEs: %w", err)
	}
	defer rows.Close()

	var cves []string
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return nil, fmt.Errorf("failed to scan CVE: %w", err)
		}
		cves = append(cves, cve)
	}
	return cves, rows.Err()
}

// GetEPSSScoresBatch retrieves EPSS scores for multiple CVEs efficiently.
func (s *SQLiteStore) GetEPSSScoresBatch(ctx context.Context, cveIDs []string) (map[string]*EPSSScore, error) {
	if len(cveIDs) == 0 {
		return make(map[string]*EPSSScore), nil
	}

	placeholders := make([]string, len(cveIDs))
	args := make([]interface{}, len(cveIDs))
	for i, id := range cveIDs {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf(`
		SELECT cve_id, epss_score, percentile, fetched_date 
		FROM epss_scores 
		WHERE cve_id IN (%s)
	`, strings.Join(placeholders, ", "))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query EPSS scores: %w", err)
	}
	defer rows.Close()

	scores := make(map[string]*EPSSScore)
	for rows.Next() {
		score := &EPSSScore{}
		if err := rows.Scan(&score.CVEID, &score.EPSSScore, &score.Percentile, &score.FetchedDate); err != nil {
			return nil, fmt.Errorf("failed to scan EPSS score: %w", err)
		}
		scores[score.CVEID] = score
	}
	return scores, rows.Err()
}
