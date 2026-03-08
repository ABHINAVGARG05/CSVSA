package database

import (
	"context"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

// ConsensusType represents the level of scanner agreement.
type ConsensusType string

const (
	ConsensusTypeConsensus ConsensusType = "consensus"
	ConsensusTypePartial   ConsensusType = "partial"
	ConsensusTypeUnique    ConsensusType = "unique"
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

// ScannerFinding links an image, vulnerability, and scanner.
type ScannerFinding struct {
	ID              int64         `json:"id"`
	ImageID         int64         `json:"image_id"`
	VulnerabilityID int64         `json:"vulnerability_id"`
	ScannerName     string        `json:"scanner_name"`
	ConsensusType   ConsensusType `json:"consensus_type"`
	FoundAt         time.Time     `json:"found_at"`
}

// EPSSScore represents an EPSS score for a CVE.
type EPSSScore struct {
	CVEID       string    `json:"cve_id"`
	EPSSScore   float64   `json:"epss_score"`
	Percentile  float64   `json:"percentile"`
	FetchedDate time.Time `json:"fetched_date"`
}

// FindingWithDetails combines finding with vulnerability and EPSS data.
type FindingWithDetails struct {
	ScannerFinding
	Vulnerability VulnerabilityRecord `json:"vulnerability"`
	Image         Image               `json:"image"`
	EPSSScore     *EPSSScore          `json:"epss_score,omitempty"`
}

// Store defines the interface for database operations.
type Store interface {
	// Image operations
	CreateImage(ctx context.Context, name, category string) (*Image, error)
	GetImage(ctx context.Context, id int64) (*Image, error)
	GetImageByName(ctx context.Context, name string) (*Image, error)
	ListImages(ctx context.Context) ([]Image, error)

	// Vulnerability operations
	UpsertVulnerability(ctx context.Context, vuln *VulnerabilityRecord) (*VulnerabilityRecord, error)
	GetVulnerability(ctx context.Context, cveID, pkg, version string) (*VulnerabilityRecord, error)

	// Scanner finding operations
	CreateScannerFinding(ctx context.Context, finding *ScannerFinding) error
	GetFindingsForImage(ctx context.Context, imageID int64) ([]ScannerFinding, error)
	GetFindingsWithDetails(ctx context.Context, imageID int64) ([]FindingWithDetails, error)

	// EPSS operations
	UpsertEPSSScore(ctx context.Context, score *EPSSScore) error
	GetEPSSScore(ctx context.Context, cveID string) (*EPSSScore, error)
	GetCachedCVEs(ctx context.Context, cveIDs []string) ([]string, error)
	BulkUpsertEPSSScores(ctx context.Context, scores []EPSSScore) error

	// Bulk persist after scan
	PersistScanResults(ctx context.Context, imageName, category string, result *models.ConsensusResult) (*Image, error)

	// Analysis queries
	GetAllFindingsWithEPSS(ctx context.Context) ([]FindingWithDetails, error)

	// Management
	Close() error
	Ping(ctx context.Context) error
}
