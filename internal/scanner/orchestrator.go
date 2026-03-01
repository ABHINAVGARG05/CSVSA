// Package scanner - Orchestrator for running multiple scanners concurrently
package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

// Orchestrator manages the execution of multiple scanners.
// It handles:
// - Concurrent scanner execution
// - Timeout management per scanner
// - Error aggregation and fault tolerance
// - Result collection
//
// Design Decision: Fault Tolerance
// The orchestrator continues even if individual scanners fail.
// This ensures partial results are still available and useful.
type Orchestrator struct {
	registry *Registry
	config   models.ScanConfig
}

// NewOrchestrator creates a new scanner orchestrator.
func NewOrchestrator(registry *Registry, config models.ScanConfig) *Orchestrator {
	return &Orchestrator{
		registry: registry,
		config:   config,
	}
}

// ScanAll executes all available scanners against the target.
// Returns results from all scanners, including failed ones.
//
// Concurrency Model:
// - Each scanner runs in its own goroutine
// - Each scanner has an independent timeout
// - Results are collected via channel
// - Main goroutine waits for all scanners to complete
//
// Time Complexity: O(max(T1, T2, ..., Tn)) where Ti is the time for scanner i
// This is because scanners run concurrently.
func (o *Orchestrator) ScanAll(ctx context.Context, target string) ([]models.ScanResult, error) {
	scanners := o.getScannersToRun()

	if len(scanners) == 0 {
		return nil, models.ErrNoScanners
	}

	// Channel to collect results
	resultChan := make(chan models.ScanResult, len(scanners))

	// WaitGroup to track completion
	var wg sync.WaitGroup

	// Launch each scanner in its own goroutine
	for _, scanner := range scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()
			result := o.runScanner(ctx, s, target)
			resultChan <- result
		}(scanner)
	}

	// Close the channel when all scanners complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var results []models.ScanResult
	for result := range resultChan {
		results = append(results, result)
	}

	// Check if all scanners failed
	allFailed := true
	for _, r := range results {
		if r.Success {
			allFailed = false
			break
		}
	}

	if allFailed {
		return results, models.ErrAllScannersFailed
	}

	return results, nil
}

// runScanner executes a single scanner with timeout.
func (o *Orchestrator) runScanner(ctx context.Context, scanner Scanner, target string) models.ScanResult {
	// Create a timeout context for this specific scanner
	scanCtx, cancel := context.WithTimeout(ctx, o.config.Timeout)
	defer cancel()

	result, err := scanner.Scan(scanCtx, target)
	if err != nil {
		// Return a result with error information
		return models.ScanResult{
			Scanner:  scanner.Name(),
			Target:   target,
			ScanTime: time.Now(),
			Success:  false,
			Error:    err.Error(),
		}
	}

	return *result
}

// getScannersToRun determines which scanners should be executed.
func (o *Orchestrator) getScannersToRun() []Scanner {
	// If specific scanners are requested, use only those
	if len(o.config.Scanners) > 0 {
		var scanners []Scanner
		for _, name := range o.config.Scanners {
			if scanner := o.registry.Get(name); scanner != nil {
				if scanner.IsAvailable() {
					scanners = append(scanners, scanner)
				}
			}
		}
		return scanners
	}

	// Otherwise, use all available scanners
	return o.registry.GetAvailable()
}

// ScanWithScanner executes a specific scanner by name.
func (o *Orchestrator) ScanWithScanner(ctx context.Context, scannerName, target string) (*models.ScanResult, error) {
	scanner := o.registry.Get(scannerName)
	if scanner == nil {
		return nil, models.NewScanError(scannerName, target, "lookup", models.ErrScannerNotFound)
	}

	if !scanner.IsAvailable() {
		return nil, models.NewScanError(scannerName, target, "availability check", models.ErrScannerNotFound)
	}

	scanCtx, cancel := context.WithTimeout(ctx, o.config.Timeout)
	defer cancel()

	return scanner.Scan(scanCtx, target)
}

// GetAvailableScanners returns information about all available scanners.
func (o *Orchestrator) GetAvailableScanners(ctx context.Context) []models.ScannerInfo {
	var infos []models.ScannerInfo

	for _, scanner := range o.registry.GetAll() {
		info, err := scanner.Info(ctx)
		if err != nil {
			infos = append(infos, models.ScannerInfo{
				Name:      scanner.Name(),
				Available: false,
			})
		} else {
			infos = append(infos, *info)
		}
	}

	return infos
}
