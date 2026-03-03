// Package database provides SQLite persistence for CSVSA scan results.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"

	// Pure Go SQLite driver - no CGO required
	_ "modernc.org/sqlite"
)

// SQLiteStore implements the Store interface using SQLite.
type SQLiteStore struct {
	db     *sql.DB
	logger *slog.Logger
}

// SQLiteConfig holds configuration for SQLite connection.
type SQLiteConfig struct {
	// Path is the filesystem path to the SQLite database file.
	// Use ":memory:" for an in-memory database.
	Path string

	// Logger is the structured logger instance.
	Logger *slog.Logger
}

// DefaultConfig returns a SQLiteConfig with sensible defaults.
func DefaultConfig() SQLiteConfig {
	return SQLiteConfig{
		Path:   "csvsa.db",
		Logger: slog.Default(),
	}
}

// NewSQLiteStore creates a new SQLite store and applies migrations.
func NewSQLiteStore(ctx context.Context, cfg SQLiteConfig) (*SQLiteStore, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Build connection string with pragmas for better performance
	dsn := cfg.Path
	if !strings.Contains(dsn, "?") {
		dsn += "?"
	} else {
		dsn += "&"
	}
	dsn += "_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Verify connection
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(1) // SQLite doesn't handle concurrent writes well
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	store := &SQLiteStore{
		db:     db,
		logger: cfg.Logger,
	}

	// Run migrations
	migrator := NewMigrator(db, cfg.Logger)
	if err := migrator.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	cfg.Logger.Info("database initialized", slog.String("path", cfg.Path))

	return store, nil
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// Ping verifies the database connection is still alive.
func (s *SQLiteStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// CreateImage creates a new image record.
func (s *SQLiteStore) CreateImage(ctx context.Context, name, category string) (*Image, error) {
	if category == "" {
		category = "uncategorized"
	}

	result, err := s.db.ExecContext(ctx,
		"INSERT INTO images (name, category, scan_date) VALUES (?, ?, ?)",
		name, category, time.Now().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create image: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return s.GetImage(ctx, id)
}

// GetImage retrieves an image by ID.
func (s *SQLiteStore) GetImage(ctx context.Context, id int64) (*Image, error) {
	img := &Image{}
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, category, scan_date FROM images WHERE id = ?",
		id,
	).Scan(&img.ID, &img.Name, &img.Category, &img.ScanDate)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get image: %w", err)
	}

	return img, nil
}

// GetImageByName retrieves the most recent image with the given name.
func (s *SQLiteStore) GetImageByName(ctx context.Context, name string) (*Image, error) {
	img := &Image{}
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, category, scan_date FROM images WHERE name = ? ORDER BY scan_date DESC LIMIT 1",
		name,
	).Scan(&img.ID, &img.Name, &img.Category, &img.ScanDate)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get image by name: %w", err)
	}

	return img, nil
}

// GetImagesByCategory retrieves all images in a category.
func (s *SQLiteStore) GetImagesByCategory(ctx context.Context, category string) ([]Image, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, category, scan_date FROM images WHERE category = ? ORDER BY scan_date DESC",
		category,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query images: %w", err)
	}
	defer rows.Close()

	var images []Image
	for rows.Next() {
		var img Image
		if err := rows.Scan(&img.ID, &img.Name, &img.Category, &img.ScanDate); err != nil {
			return nil, fmt.Errorf("failed to scan image row: %w", err)
		}
		images = append(images, img)
	}

	return images, rows.Err()
}

// ListImages retrieves all images.
func (s *SQLiteStore) ListImages(ctx context.Context) ([]Image, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, category, scan_date FROM images ORDER BY scan_date DESC",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query images: %w", err)
	}
	defer rows.Close()

	var images []Image
	for rows.Next() {
		var img Image
		if err := rows.Scan(&img.ID, &img.Name, &img.Category, &img.ScanDate); err != nil {
			return nil, fmt.Errorf("failed to scan image row: %w", err)
		}
		images = append(images, img)
	}

	return images, rows.Err()
}

// DeleteImage deletes an image and all related records (cascade).
func (s *SQLiteStore) DeleteImage(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM images WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete image: %w", err)
	}
	return nil
}

// UpsertVulnerability creates or updates a vulnerability record.
func (s *SQLiteStore) UpsertVulnerability(ctx context.Context, vuln *VulnerabilityRecord) (*VulnerabilityRecord, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (cve_id, package, version, severity, fixed_version, title, description)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cve_id, package, version) DO UPDATE SET
			severity = excluded.severity,
			fixed_version = COALESCE(excluded.fixed_version, vulnerabilities.fixed_version),
			title = COALESCE(excluded.title, vulnerabilities.title),
			description = COALESCE(excluded.description, vulnerabilities.description)
	`, vuln.CVEID, vuln.Package, vuln.Version, string(vuln.Severity),
		vuln.FixedVersion, vuln.Title, vuln.Description,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert vulnerability: %w", err)
	}

	return s.GetVulnerability(ctx, vuln.CVEID, vuln.Package, vuln.Version)
}

// GetVulnerability retrieves a vulnerability by its natural key.
func (s *SQLiteStore) GetVulnerability(ctx context.Context, cveID, pkg, version string) (*VulnerabilityRecord, error) {
	vuln := &VulnerabilityRecord{}
	var severity string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, cve_id, package, version, severity, fixed_version, title, description
		FROM vulnerabilities WHERE cve_id = ? AND package = ? AND version = ?
	`, cveID, pkg, version).Scan(
		&vuln.ID, &vuln.CVEID, &vuln.Package, &vuln.Version, &severity,
		&vuln.FixedVersion, &vuln.Title, &vuln.Description,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability: %w", err)
	}

	vuln.Severity = models.Severity(severity)
	return vuln, nil
}

// GetVulnerabilityByID retrieves a vulnerability by ID.
func (s *SQLiteStore) GetVulnerabilityByID(ctx context.Context, id int64) (*VulnerabilityRecord, error) {
	vuln := &VulnerabilityRecord{}
	var severity string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, cve_id, package, version, severity, fixed_version, title, description
		FROM vulnerabilities WHERE id = ?
	`, id).Scan(
		&vuln.ID, &vuln.CVEID, &vuln.Package, &vuln.Version, &severity,
		&vuln.FixedVersion, &vuln.Title, &vuln.Description,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability: %w", err)
	}

	vuln.Severity = models.Severity(severity)
	return vuln, nil
}

// ListVulnerabilities retrieves all vulnerabilities.
func (s *SQLiteStore) ListVulnerabilities(ctx context.Context) ([]VulnerabilityRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, cve_id, package, version, severity, fixed_version, title, description
		FROM vulnerabilities ORDER BY cve_id
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulns []VulnerabilityRecord
	for rows.Next() {
		var vuln VulnerabilityRecord
		var severity string
		if err := rows.Scan(
			&vuln.ID, &vuln.CVEID, &vuln.Package, &vuln.Version, &severity,
			&vuln.FixedVersion, &vuln.Title, &vuln.Description,
		); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability row: %w", err)
		}
		vuln.Severity = models.Severity(severity)
		vulns = append(vulns, vuln)
	}

	return vulns, rows.Err()
}

// GetVulnerabilitiesBySeverity retrieves vulnerabilities with a specific severity.
func (s *SQLiteStore) GetVulnerabilitiesBySeverity(ctx context.Context, severity models.Severity) ([]VulnerabilityRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, cve_id, package, version, severity, fixed_version, title, description
		FROM vulnerabilities WHERE severity = ? ORDER BY cve_id
	`, string(severity))
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulns []VulnerabilityRecord
	for rows.Next() {
		var vuln VulnerabilityRecord
		var sev string
		if err := rows.Scan(
			&vuln.ID, &vuln.CVEID, &vuln.Package, &vuln.Version, &sev,
			&vuln.FixedVersion, &vuln.Title, &vuln.Description,
		); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability row: %w", err)
		}
		vuln.Severity = models.Severity(sev)
		vulns = append(vulns, vuln)
	}

	return vulns, rows.Err()
}

// CreateScannerFinding creates a new scanner finding record.
func (s *SQLiteStore) CreateScannerFinding(ctx context.Context, finding *ScannerFinding) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO scanner_findings (image_id, vulnerability_id, scanner_name, consensus_type, found_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(image_id, vulnerability_id, scanner_name) DO UPDATE SET
			consensus_type = excluded.consensus_type,
			found_at = excluded.found_at
	`, finding.ImageID, finding.VulnerabilityID, finding.ScannerName, string(finding.ConsensusType), finding.FoundAt)

	if err != nil {
		return fmt.Errorf("failed to create scanner finding: %w", err)
	}
	return nil
}

// GetFindingsForImage retrieves all findings for an image.
func (s *SQLiteStore) GetFindingsForImage(ctx context.Context, imageID int64) ([]ScannerFinding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, image_id, vulnerability_id, scanner_name, consensus_type, found_at
		FROM scanner_findings WHERE image_id = ?
	`, imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to query scanner findings: %w", err)
	}
	defer rows.Close()

	var findings []ScannerFinding
	for rows.Next() {
		var f ScannerFinding
		var consensusType string
		if err := rows.Scan(&f.ID, &f.ImageID, &f.VulnerabilityID, &f.ScannerName, &consensusType, &f.FoundAt); err != nil {
			return nil, fmt.Errorf("failed to scan finding row: %w", err)
		}
		f.ConsensusType = ConsensusType(consensusType)
		findings = append(findings, f)
	}

	return findings, rows.Err()
}

// GetFindingsForVulnerability retrieves all findings for a vulnerability.
func (s *SQLiteStore) GetFindingsForVulnerability(ctx context.Context, vulnID int64) ([]ScannerFinding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, image_id, vulnerability_id, scanner_name, consensus_type, found_at
		FROM scanner_findings WHERE vulnerability_id = ?
	`, vulnID)
	if err != nil {
		return nil, fmt.Errorf("failed to query scanner findings: %w", err)
	}
	defer rows.Close()

	var findings []ScannerFinding
	for rows.Next() {
		var f ScannerFinding
		var consensusType string
		if err := rows.Scan(&f.ID, &f.ImageID, &f.VulnerabilityID, &f.ScannerName, &consensusType, &f.FoundAt); err != nil {
			return nil, fmt.Errorf("failed to scan finding row: %w", err)
		}
		f.ConsensusType = ConsensusType(consensusType)
		findings = append(findings, f)
	}

	return findings, rows.Err()
}

// GetFindingsByConsensusType retrieves all findings with a specific consensus type.
func (s *SQLiteStore) GetFindingsByConsensusType(ctx context.Context, consensusType ConsensusType) ([]ScannerFinding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, image_id, vulnerability_id, scanner_name, consensus_type, found_at
		FROM scanner_findings WHERE consensus_type = ?
	`, string(consensusType))
	if err != nil {
		return nil, fmt.Errorf("failed to query scanner findings: %w", err)
	}
	defer rows.Close()

	var findings []ScannerFinding
	for rows.Next() {
		var f ScannerFinding
		var ct string
		if err := rows.Scan(&f.ID, &f.ImageID, &f.VulnerabilityID, &f.ScannerName, &ct, &f.FoundAt); err != nil {
			return nil, fmt.Errorf("failed to scan finding row: %w", err)
		}
		f.ConsensusType = ConsensusType(ct)
		findings = append(findings, f)
	}

	return findings, rows.Err()
}

// GetFindingsWithDetails retrieves findings with full vulnerability and image details.
func (s *SQLiteStore) GetFindingsWithDetails(ctx context.Context, imageID int64) ([]FindingWithDetails, error) {
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
		WHERE sf.image_id = ?
	`, imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings with details: %w", err)
	}
	defer rows.Close()

	var findings []FindingWithDetails
	for rows.Next() {
		var f FindingWithDetails
		var consensusType, severity string
		var epssCVE sql.NullString
		var epssScore, epssPercentile sql.NullFloat64
		var epssFetched sql.NullTime

		if err := rows.Scan(
			&f.ID, &f.ImageID, &f.VulnerabilityID, &f.ScannerName, &consensusType, &f.FoundAt,
			&f.Vulnerability.ID, &f.Vulnerability.CVEID, &f.Vulnerability.Package,
			&f.Vulnerability.Version, &severity, &f.Vulnerability.FixedVersion,
			&f.Vulnerability.Title, &f.Vulnerability.Description,
			&f.Image.ID, &f.Image.Name, &f.Image.Category, &f.Image.ScanDate,
			&epssCVE, &epssScore, &epssPercentile, &epssFetched,
		); err != nil {
			return nil, fmt.Errorf("failed to scan finding row: %w", err)
		}

		f.ConsensusType = ConsensusType(consensusType)
		f.Vulnerability.Severity = models.Severity(severity)

		if epssCVE.Valid {
			f.EPSSScore = &EPSSScore{
				CVEID:       epssCVE.String,
				EPSSScore:   epssScore.Float64,
				Percentile:  epssPercentile.Float64,
				FetchedDate: epssFetched.Time,
			}
		}

		findings = append(findings, f)
	}

	return findings, rows.Err()
}

// UpsertEPSSScore creates or updates an EPSS score record.
func (s *SQLiteStore) UpsertEPSSScore(ctx context.Context, score *EPSSScore) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO epss_scores (cve_id, epss_score, percentile, fetched_date)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			epss_score = excluded.epss_score,
			percentile = excluded.percentile,
			fetched_date = excluded.fetched_date
	`, score.CVEID, score.EPSSScore, score.Percentile, score.FetchedDate)

	if err != nil {
		return fmt.Errorf("failed to upsert EPSS score: %w", err)
	}
	return nil
}

// GetEPSSScore retrieves an EPSS score for a CVE.
func (s *SQLiteStore) GetEPSSScore(ctx context.Context, cveID string) (*EPSSScore, error) {
	score := &EPSSScore{}
	err := s.db.QueryRowContext(ctx,
		"SELECT cve_id, epss_score, percentile, fetched_date FROM epss_scores WHERE cve_id = ?",
		cveID,
	).Scan(&score.CVEID, &score.EPSSScore, &score.Percentile, &score.FetchedDate)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get EPSS score: %w", err)
	}

	return score, nil
}

// GetEPSSScores retrieves EPSS scores for multiple CVEs.
func (s *SQLiteStore) GetEPSSScores(ctx context.Context, cveIDs []string) (map[string]*EPSSScore, error) {
	if len(cveIDs) == 0 {
		return make(map[string]*EPSSScore), nil
	}

	placeholders := make([]string, len(cveIDs))
	args := make([]interface{}, len(cveIDs))
	for i, id := range cveIDs {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf(
		"SELECT cve_id, epss_score, percentile, fetched_date FROM epss_scores WHERE cve_id IN (%s)",
		strings.Join(placeholders, ", "),
	)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query EPSS scores: %w", err)
	}
	defer rows.Close()

	scores := make(map[string]*EPSSScore)
	for rows.Next() {
		score := &EPSSScore{}
		if err := rows.Scan(&score.CVEID, &score.EPSSScore, &score.Percentile, &score.FetchedDate); err != nil {
			return nil, fmt.Errorf("failed to scan EPSS score row: %w", err)
		}
		scores[score.CVEID] = score
	}

	return scores, rows.Err()
}

// GetCachedCVEs returns which CVEs from the input list already have cached EPSS scores.
func (s *SQLiteStore) GetCachedCVEs(ctx context.Context, cveIDs []string) ([]string, error) {
	if len(cveIDs) == 0 {
		return nil, nil
	}

	placeholders := make([]string, len(cveIDs))
	args := make([]interface{}, len(cveIDs))
	for i, id := range cveIDs {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf(
		"SELECT cve_id FROM epss_scores WHERE cve_id IN (%s)",
		strings.Join(placeholders, ", "),
	)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query cached CVEs: %w", err)
	}
	defer rows.Close()

	var cached []string
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			return nil, fmt.Errorf("failed to scan CVE ID: %w", err)
		}
		cached = append(cached, cveID)
	}

	return cached, rows.Err()
}

// BulkUpsertEPSSScores inserts or updates multiple EPSS scores in a single transaction.
func (s *SQLiteStore) BulkUpsertEPSSScores(ctx context.Context, scores []EPSSScore) error {
	if len(scores) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO epss_scores (cve_id, epss_score, percentile, fetched_date)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			epss_score = excluded.epss_score,
			percentile = excluded.percentile,
			fetched_date = excluded.fetched_date
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, score := range scores {
		if _, err = stmt.ExecContext(ctx, score.CVEID, score.EPSSScore, score.Percentile, score.FetchedDate); err != nil {
			return fmt.Errorf("failed to upsert EPSS score for %s: %w", score.CVEID, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// UpsertScanMetadata creates or updates scan metadata.
func (s *SQLiteStore) UpsertScanMetadata(ctx context.Context, meta *ScanMetadata) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO scan_metadata (
			image_id, total_vulnerabilities, consensus_count, partial_count, 
			unique_count, overlap_percentage, scanners_used, scan_duration_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(image_id) DO UPDATE SET
			total_vulnerabilities = excluded.total_vulnerabilities,
			consensus_count = excluded.consensus_count,
			partial_count = excluded.partial_count,
			unique_count = excluded.unique_count,
			overlap_percentage = excluded.overlap_percentage,
			scanners_used = excluded.scanners_used,
			scan_duration_ms = excluded.scan_duration_ms
	`, meta.ImageID, meta.TotalVulnerabilities, meta.ConsensusCount, meta.PartialCount,
		meta.UniqueCount, meta.OverlapPercentage, meta.ScannersUsed, meta.ScanDurationMs)

	if err != nil {
		return fmt.Errorf("failed to upsert scan metadata: %w", err)
	}
	return nil
}

// GetScanMetadata retrieves scan metadata for an image.
func (s *SQLiteStore) GetScanMetadata(ctx context.Context, imageID int64) (*ScanMetadata, error) {
	meta := &ScanMetadata{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, image_id, total_vulnerabilities, consensus_count, partial_count,
			   unique_count, overlap_percentage, scanners_used, scan_duration_ms
		FROM scan_metadata WHERE image_id = ?
	`, imageID).Scan(
		&meta.ID, &meta.ImageID, &meta.TotalVulnerabilities, &meta.ConsensusCount,
		&meta.PartialCount, &meta.UniqueCount, &meta.OverlapPercentage,
		&meta.ScannersUsed, &meta.ScanDurationMs,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get scan metadata: %w", err)
	}

	return meta, nil
}
