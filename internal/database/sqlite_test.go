package database

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

func TestSQLiteStorePersistAndQuery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	store, err := NewSQLiteStore(ctx, SQLiteConfig{
		Path:   path,
		Logger: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	result := makeConsensusResult()
	image, err := store.PersistScanResults(ctx, "alpine:3.18", "prod", result)
	if err != nil {
		t.Fatalf("PersistScanResults failed: %v", err)
	}
	if image == nil || image.ID == 0 {
		t.Fatal("expected image to be persisted")
	}

	images, err := store.ListImages(ctx)
	if err != nil {
		t.Fatalf("ListImages failed: %v", err)
	}
	if len(images) != 1 {
		t.Fatalf("expected 1 image, got %d", len(images))
	}

	findings, err := store.GetFindingsForImage(ctx, image.ID)
	if err != nil {
		t.Fatalf("GetFindingsForImage failed: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(findings))
	}

	consensusCount := 0
	uniqueCount := 0
	for _, f := range findings {
		switch f.ConsensusType {
		case ConsensusTypeConsensus:
			consensusCount++
		case ConsensusTypeUnique:
			uniqueCount++
		}
	}
	if consensusCount != 2 {
		t.Errorf("expected 2 consensus findings, got %d", consensusCount)
	}
	if uniqueCount != 2 {
		t.Errorf("expected 2 unique findings, got %d", uniqueCount)
	}

	score := &EPSSScore{
		CVEID:       "CVE-2024-0001",
		EPSSScore:   0.90,
		Percentile:  99,
		FetchedDate: time.Now().UTC(),
	}
	if err := store.UpsertEPSSScore(ctx, score); err != nil {
		t.Fatalf("UpsertEPSSScore failed: %v", err)
	}

	findingsWithDetails, err := store.GetFindingsWithDetails(ctx, image.ID)
	if err != nil {
		t.Fatalf("GetFindingsWithDetails failed: %v", err)
	}
	if len(findingsWithDetails) == 0 {
		t.Fatal("expected findings with details")
	}

	var epssFound bool
	for _, f := range findingsWithDetails {
		if f.EPSSScore != nil && f.EPSSScore.CVEID == "CVE-2024-0001" {
			epssFound = true
			break
		}
	}
	if !epssFound {
		t.Error("expected EPSS score to be joined in findings")
	}
}

func TestSQLiteStoreEPSSCache(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	store, err := NewSQLiteStore(ctx, SQLiteConfig{Path: path})
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	scores := []EPSSScore{
		{CVEID: "CVE-2024-0001", EPSSScore: 0.10, Percentile: 10, FetchedDate: time.Now().UTC()},
		{CVEID: "CVE-2024-0002", EPSSScore: 0.20, Percentile: 20, FetchedDate: time.Now().UTC()},
	}
	if err := store.BulkUpsertEPSSScores(ctx, scores); err != nil {
		t.Fatalf("BulkUpsertEPSSScores failed: %v", err)
	}

	cached, err := store.GetCachedCVEs(ctx, []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-9999"})
	if err != nil {
		t.Fatalf("GetCachedCVEs failed: %v", err)
	}
	if len(cached) != 2 {
		t.Errorf("expected 2 cached CVEs, got %d", len(cached))
	}

	score := &EPSSScore{CVEID: "CVE-2024-0003", EPSSScore: 0.30, Percentile: 30, FetchedDate: time.Now().UTC()}
	if err := store.UpsertEPSSScore(ctx, score); err != nil {
		t.Fatalf("UpsertEPSSScore failed: %v", err)
	}

	loaded, err := store.GetEPSSScore(ctx, "CVE-2024-0003")
	if err != nil {
		t.Fatalf("GetEPSSScore failed: %v", err)
	}
	if loaded == nil || loaded.EPSSScore != 0.30 {
		t.Fatalf("unexpected EPSS score: %+v", loaded)
	}
}

func TestSQLiteStoreQueries(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	store, err := NewSQLiteStore(ctx, SQLiteConfig{Path: path})
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	result := makeConsensusResult()
	image, err := store.PersistScanResults(ctx, "alpine:3.18", "prod", result)
	if err != nil {
		t.Fatalf("PersistScanResults failed: %v", err)
	}

	if img, err := store.GetImageByName(ctx, "alpine:3.18"); err != nil || img == nil {
		t.Fatalf("GetImageByName failed: %v", err)
	}

	unique, err := store.GetAllUniqueCVEs(ctx)
	if err != nil {
		t.Fatalf("GetAllUniqueCVEs failed: %v", err)
	}
	if len(unique) != 3 {
		t.Fatalf("expected 3 unique CVEs, got %d", len(unique))
	}

	imageCVEs, err := store.GetUniqueCVEsForImage(ctx, image.ID)
	if err != nil {
		t.Fatalf("GetUniqueCVEsForImage failed: %v", err)
	}
	if len(imageCVEs) != 3 {
		t.Fatalf("expected 3 CVEs for image, got %d", len(imageCVEs))
	}

	byCategory, err := store.GetFindingsByCategory(ctx, "prod")
	if err != nil {
		t.Fatalf("GetFindingsByCategory failed: %v", err)
	}
	if len(byCategory) == 0 {
		t.Fatal("expected findings for category")
	}

	consensusFindings, err := store.GetFindingsByConsensusType(ctx, ConsensusTypeConsensus)
	if err != nil {
		t.Fatalf("GetFindingsByConsensusType failed: %v", err)
	}
	if len(consensusFindings) == 0 {
		t.Fatal("expected consensus findings")
	}

	uniqueFindings, err := store.GetFindingsByConsensusType(ctx, ConsensusTypeUnique)
	if err != nil {
		t.Fatalf("GetFindingsByConsensusType unique failed: %v", err)
	}
	if len(uniqueFindings) == 0 {
		t.Fatal("expected unique findings")
	}

	scores := []EPSSScore{
		{CVEID: "CVE-2024-0001", EPSSScore: 0.10, Percentile: 10, FetchedDate: time.Now().UTC()},
		{CVEID: "CVE-2024-0002", EPSSScore: 0.20, Percentile: 20, FetchedDate: time.Now().UTC()},
	}
	if err := store.BulkUpsertEPSSScores(ctx, scores); err != nil {
		t.Fatalf("BulkUpsertEPSSScores failed: %v", err)
	}

	allFindings, err := store.GetAllFindingsWithEPSS(ctx)
	if err != nil {
		t.Fatalf("GetAllFindingsWithEPSS failed: %v", err)
	}
	if len(allFindings) == 0 {
		t.Fatal("expected findings with EPSS data")
	}

	batchScores, err := store.GetEPSSScoresBatch(ctx, []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-9999"})
	if err != nil {
		t.Fatalf("GetEPSSScoresBatch failed: %v", err)
	}
	if len(batchScores) != 2 {
		t.Fatalf("expected 2 EPSS scores, got %d", len(batchScores))
	}
}

func makeConsensusResult() *models.ConsensusResult {
	vulnConsensus := models.Vulnerability{
		CVE:              "CVE-2024-0001",
		Package:          "pkg1",
		InstalledVersion: "1.0.0",
		FixedVersion:     "1.1.0",
		Severity:         models.SeverityCritical,
		Title:            "Test vuln",
		Description:      "Test description",
	}
	vulnTrivy := models.Vulnerability{
		CVE:              "CVE-2024-0002",
		Package:          "pkg2",
		InstalledVersion: "2.0.0",
		Severity:         models.SeverityHigh,
	}
	vulnGrype := models.Vulnerability{
		CVE:              "CVE-2024-0003",
		Package:          "pkg3",
		InstalledVersion: "3.0.0",
		Severity:         models.SeverityMedium,
	}

	results := []models.ScanResult{
		{
			Scanner: "trivy",
			Success: true,
			Vulnerabilities: []models.Vulnerability{
				vulnConsensus,
				vulnTrivy,
			},
		},
		{
			Scanner: "grype",
			Success: true,
			Vulnerabilities: []models.Vulnerability{
				vulnConsensus,
				vulnGrype,
			},
		},
	}

	return &models.ConsensusResult{
		Target:             "alpine:3.18",
		Scanners:           []string{"trivy", "grype"},
		Consensus:          []models.Vulnerability{vulnConsensus},
		UniqueFindings:     map[string][]models.Vulnerability{"trivy": {vulnTrivy}, "grype": {vulnGrype}},
		AllVulnerabilities: []models.Vulnerability{vulnConsensus, vulnTrivy, vulnGrype},
		OverlapPercentage:  33.3,
		ScanResults:        results,
		AnalysisTime:       time.Now().UTC(),
		TotalDuration:      2 * time.Second,
	}
}
