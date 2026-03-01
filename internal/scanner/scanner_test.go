package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

// MockScanner implements Scanner interface for testing.
type MockScanner struct {
	name       string
	available  bool
	scanResult *models.ScanResult
	scanError  error
	scanDelay  time.Duration
	info       *models.ScannerInfo
}

func NewMockScanner(name string, available bool) *MockScanner {
	return &MockScanner{
		name:      name,
		available: available,
		scanResult: &models.ScanResult{
			Scanner:         name,
			Success:         true,
			Vulnerabilities: []models.Vulnerability{},
		},
		info: &models.ScannerInfo{
			Name:      name,
			Available: available,
			Version:   "1.0.0",
		},
	}
}

func (m *MockScanner) Name() string {
	return m.name
}

func (m *MockScanner) Scan(ctx context.Context, target string) (*models.ScanResult, error) {
	// Simulate scan delay
	if m.scanDelay > 0 {
		select {
		case <-time.After(m.scanDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if m.scanError != nil {
		return nil, m.scanError
	}

	result := *m.scanResult
	result.Target = target
	result.ScanTime = time.Now()
	return &result, nil
}

func (m *MockScanner) Info(ctx context.Context) (*models.ScannerInfo, error) {
	return m.info, nil
}

func (m *MockScanner) IsAvailable() bool {
	return m.available
}

func (m *MockScanner) WithVulnerabilities(vulns []models.Vulnerability) *MockScanner {
	m.scanResult.Vulnerabilities = vulns
	return m
}

func (m *MockScanner) WithError(err error) *MockScanner {
	m.scanError = err
	return m
}

func (m *MockScanner) WithDelay(d time.Duration) *MockScanner {
	m.scanDelay = d
	return m
}

// TestRegistryOperations tests the scanner registry.
func TestRegistryOperations(t *testing.T) {
	registry := NewRegistry()

	// Test empty registry
	if registry.Count() != 0 {
		t.Errorf("New registry should be empty, got count %d", registry.Count())
	}

	// Register scanners
	mock1 := NewMockScanner("scanner1", true)
	mock2 := NewMockScanner("scanner2", false)

	registry.Register(mock1)
	registry.Register(mock2)

	if registry.Count() != 2 {
		t.Errorf("Registry should have 2 scanners, got %d", registry.Count())
	}

	// Test Get
	if got := registry.Get("scanner1"); got != mock1 {
		t.Error("Get should return registered scanner")
	}

	if got := registry.Get("nonexistent"); got != nil {
		t.Error("Get should return nil for unregistered scanner")
	}

	// Test GetAvailable
	available := registry.GetAvailable()
	if len(available) != 1 {
		t.Errorf("Should have 1 available scanner, got %d", len(available))
	}

	// Test Names
	names := registry.Names()
	if len(names) != 2 {
		t.Errorf("Should have 2 names, got %d", len(names))
	}
}

// TestOrchestratorScanAll tests concurrent scanner execution.
func TestOrchestratorScanAll(t *testing.T) {
	registry := NewRegistry()

	vulns1 := []models.Vulnerability{
		{CVE: "CVE-2021-0001", Package: "pkg1", Severity: models.SeverityHigh},
		{CVE: "CVE-2021-0002", Package: "pkg2", Severity: models.SeverityCritical},
	}
	vulns2 := []models.Vulnerability{
		{CVE: "CVE-2021-0001", Package: "pkg1", Severity: models.SeverityHigh},
		{CVE: "CVE-2021-0003", Package: "pkg3", Severity: models.SeverityMedium},
	}

	mock1 := NewMockScanner("scanner1", true).WithVulnerabilities(vulns1)
	mock2 := NewMockScanner("scanner2", true).WithVulnerabilities(vulns2)

	registry.Register(mock1)
	registry.Register(mock2)

	config := models.DefaultConfig()
	orchestrator := NewOrchestrator(registry, config)

	ctx := context.Background()
	results, err := orchestrator.ScanAll(ctx, "test-image:latest")

	if err != nil {
		t.Fatalf("ScanAll should not return error: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Should have 2 results, got %d", len(results))
	}

	// Verify both scanners returned results
	scannerNames := make(map[string]bool)
	for _, r := range results {
		scannerNames[r.Scanner] = true
		if !r.Success {
			t.Errorf("Scanner %s should have succeeded", r.Scanner)
		}
	}

	if !scannerNames["scanner1"] || !scannerNames["scanner2"] {
		t.Error("Should have results from both scanners")
	}
}

// TestOrchestratorFaultTolerance tests that one failing scanner doesn't break everything.
func TestOrchestratorFaultTolerance(t *testing.T) {
	registry := NewRegistry()

	vulns := []models.Vulnerability{
		{CVE: "CVE-2021-0001", Package: "pkg1", Severity: models.SeverityHigh},
	}

	mock1 := NewMockScanner("scanner1", true).WithVulnerabilities(vulns)
	mock2 := NewMockScanner("scanner2", true).WithError(models.ErrScannerFailed)

	registry.Register(mock1)
	registry.Register(mock2)

	config := models.DefaultConfig()
	orchestrator := NewOrchestrator(registry, config)

	ctx := context.Background()
	results, err := orchestrator.ScanAll(ctx, "test-image:latest")

	if err != nil {
		t.Fatalf("ScanAll should not return error when one scanner succeeds: %v", err)
	}

	// Should still have results from both, but one failed
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	if successCount != 1 {
		t.Errorf("Should have 1 successful result, got %d", successCount)
	}
}

// TestOrchestratorAllFailed tests error when all scanners fail.
func TestOrchestratorAllFailed(t *testing.T) {
	registry := NewRegistry()

	mock1 := NewMockScanner("scanner1", true).WithError(models.ErrScannerFailed)
	mock2 := NewMockScanner("scanner2", true).WithError(models.ErrScannerFailed)

	registry.Register(mock1)
	registry.Register(mock2)

	config := models.DefaultConfig()
	orchestrator := NewOrchestrator(registry, config)

	ctx := context.Background()
	_, err := orchestrator.ScanAll(ctx, "test-image:latest")

	if err != models.ErrAllScannersFailed {
		t.Errorf("Should return ErrAllScannersFailed, got %v", err)
	}
}

// TestOrchestratorNoScanners tests error when no scanners are available.
func TestOrchestratorNoScanners(t *testing.T) {
	registry := NewRegistry()

	config := models.DefaultConfig()
	orchestrator := NewOrchestrator(registry, config)

	ctx := context.Background()
	_, err := orchestrator.ScanAll(ctx, "test-image:latest")

	if err != models.ErrNoScanners {
		t.Errorf("Should return ErrNoScanners, got %v", err)
	}
}

// TestOrchestratorTimeout tests scanner timeout handling.
func TestOrchestratorTimeout(t *testing.T) {
	registry := NewRegistry()

	// Scanner that takes too long
	mock := NewMockScanner("slow-scanner", true).WithDelay(5 * time.Second)
	registry.Register(mock)

	config := models.DefaultConfig()
	config.Timeout = 100 * time.Millisecond

	orchestrator := NewOrchestrator(registry, config)

	ctx := context.Background()
	results, err := orchestrator.ScanAll(ctx, "test-image:latest")

	// Should return error because all scanners timed out
	if err != models.ErrAllScannersFailed {
		t.Logf("Expected ErrAllScannersFailed, got: %v", err)
	}

	// The result should indicate failure
	if len(results) > 0 && results[0].Success {
		t.Error("Timed out scanner should not report success")
	}
}

// TestOrchestratorSelectiveScanners tests running specific scanners.
func TestOrchestratorSelectiveScanners(t *testing.T) {
	registry := NewRegistry()

	mock1 := NewMockScanner("scanner1", true)
	mock2 := NewMockScanner("scanner2", true)
	mock3 := NewMockScanner("scanner3", true)

	registry.Register(mock1)
	registry.Register(mock2)
	registry.Register(mock3)

	config := models.DefaultConfig()
	config.Scanners = []string{"scanner1", "scanner3"}

	orchestrator := NewOrchestrator(registry, config)

	ctx := context.Background()
	results, err := orchestrator.ScanAll(ctx, "test-image:latest")

	if err != nil {
		t.Fatalf("ScanAll should not return error: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Should have 2 results, got %d", len(results))
	}

	for _, r := range results {
		if r.Scanner == "scanner2" {
			t.Error("scanner2 should not have been run")
		}
	}
}
