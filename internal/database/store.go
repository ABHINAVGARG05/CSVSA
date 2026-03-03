// Package database provides SQLite persistence for CSVSA scan results.
package database

import (
	"context"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

// ConsensusType represents the level of scanner agreement for a finding.
type ConsensusType string

const (
	// ConsensusTypeConsensus indicates all scanners found this vulnerability.
	ConsensusTypeConsensus ConsensusType = "consensus"

	// ConsensusTypePartial indicates some but not all scanners found this vulnerability.
	ConsensusTypePartial ConsensusType = "partial"

	// ConsensusTypeUnique indicates only one scanner found this vulnerability.
	ConsensusTypeUnique ConsensusType = "unique"
)

// Image represents a scanned container image record.
type Image struct {
	ID       int64     `json:"id"`
	Name     string    `json:"name"`
	Category string    `json:"category"`
	ScanDate time.Time `json:"scan_date"`
}

// VulnerabilityRecord represents a vulnerability stored in the database.
type VulnerabilityRecord struct {
	ID           int64           `json:"id"`
	CVEID        string          `json:"cve_id"`
	Package      string          `json:"package"`
	Version      string          `json:"version"`
	Severity     models.Severity `json:"severity"`
	FixedVersion string          `json:"fixed_version,omitempty"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
}

// ScannerFinding represents a relationship between an image, vulnerability, and scanner.
type ScannerFinding struct {
	ID              int64         `json:"id"`
	ImageID         int64         `json:"image_id"`
	VulnerabilityID int64         `json:"vulnerability_id"`
	ScannerName     string        `json:"scanner_name"`
	ConsensusType   ConsensusType `json:"consensus_type"`
	FoundAt         time.Time     `json:"found_at"`
}

// EPSSScore represents an EPSS (Exploit Prediction Scoring System) score.
type EPSSScore struct {
	CVEID       string    `json:"cve_id"`
	EPSSScore   float64   `json:"epss_score"`
	Percentile  float64   `json:"percentile"`
	FetchedDate time.Time `json:"fetched_date"`
}

// ScanMetadata represents statistical metadata about a scan.
type ScanMetadata struct {
	ID                   int64   `json:"id"`
	ImageID              int64   `json:"image_id"`
	TotalVulnerabilities int     `json:"total_vulnerabilities"`
	ConsensusCount       int     `json:"consensus_count"`
	PartialCount         int     `json:"partial_count"`
	UniqueCount          int     `json:"unique_count"`
	OverlapPercentage    float64 `json:"overlap_percentage"`
	ScannersUsed         string  `json:"scanners_used"`
	ScanDurationMs       int64   `json:"scan_duration_ms"`
}

// FindingWithDetails combines a scanner finding with vulnerability details.
type FindingWithDetails struct {
	ScannerFinding
	Vulnerability VulnerabilityRecord `json:"vulnerability"`
	Image         Image               `json:"image"`
	EPSSScore     *EPSSScore          `json:"epss_score,omitempty"`
}

// Store defines the interface for database operations.
// This interface enables dependency injection and testing with mocks.
type Store interface {
	// Image operations
	CreateImage(ctx context.Context, name, category string) (*Image, error)
	GetImage(ctx context.Context, id int64) (*Image, error)
	GetImageByName(ctx context.Context, name string) (*Image, error)
	GetImagesByCategory(ctx context.Context, category string) ([]Image, error)
	ListImages(ctx context.Context) ([]Image, error)
	DeleteImage(ctx context.Context, id int64) error

	// Vulnerability operations
	UpsertVulnerability(ctx context.Context, vuln *VulnerabilityRecord) (*VulnerabilityRecord, error)
	GetVulnerability(ctx context.Context, cveID, pkg, version string) (*VulnerabilityRecord, error)
	GetVulnerabilityByID(ctx context.Context, id int64) (*VulnerabilityRecord, error)
	ListVulnerabilities(ctx context.Context) ([]VulnerabilityRecord, error)
	GetVulnerabilitiesBySeverity(ctx context.Context, severity models.Severity) ([]VulnerabilityRecord, error)

	// Scanner finding operations
	CreateScannerFinding(ctx context.Context, finding *ScannerFinding) error
	GetFindingsForImage(ctx context.Context, imageID int64) ([]ScannerFinding, error)
	GetFindingsForVulnerability(ctx context.Context, vulnID int64) ([]ScannerFinding, error)
	GetFindingsByConsensusType(ctx context.Context, consensusType ConsensusType) ([]ScannerFinding, error)
	GetFindingsWithDetails(ctx context.Context, imageID int64) ([]FindingWithDetails, error)

	// EPSS score operations
	UpsertEPSSScore(ctx context.Context, score *EPSSScore) error
	GetEPSSScore(ctx context.Context, cveID string) (*EPSSScore, error)
	GetEPSSScores(ctx context.Context, cveIDs []string) (map[string]*EPSSScore, error)
	GetCachedCVEs(ctx context.Context, cveIDs []string) ([]string, error)
	BulkUpsertEPSSScores(ctx context.Context, scores []EPSSScore) error

	// Scan metadata operations
	UpsertScanMetadata(ctx context.Context, meta *ScanMetadata) error
	GetScanMetadata(ctx context.Context, imageID int64) (*ScanMetadata, error)

	// Bulk operations for scan persistence
	PersistScanResults(ctx context.Context, imageName, category string, result *models.ConsensusResult) (*Image, error)

	// Query operations for analysis
	GetAllFindingsWithEPSS(ctx context.Context) ([]FindingWithDetails, error)
	GetFindingsByCategory(ctx context.Context, category string) ([]FindingWithDetails, error)
	GetAgreementStats(ctx context.Context) (map[string]map[models.Severity]float64, error)

	// Database management
	Close() error
	Ping(ctx context.Context) error
}
