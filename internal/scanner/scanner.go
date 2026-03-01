// Package scanner provides the abstraction layer for container vulnerability scanners.
//
// Design Pattern: Strategy Pattern
// The Scanner interface defines a contract that all scanner implementations must follow.
// This enables:
// 1. Easy addition of new scanners without modifying existing code (Open/Closed Principle)
// 2. Runtime selection of scanners
// 3. Mock implementations for testing
// 4. Consistent error handling across all scanners
//
// Architecture Decision: Why Interface-Based Design?
// - Decouples the orchestration logic from specific scanner implementations
// - Enables unit testing with mock scanners
// - Allows users to add custom scanners by implementing the interface
// - Follows SOLID principles, specifically Interface Segregation
package scanner

import (
	"context"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

// Scanner defines the contract for all vulnerability scanner implementations.
// Each scanner adapter must implement this interface to be usable by the orchestrator.
//
// Design Considerations:
// - Scan() accepts a context for timeout/cancellation support
// - Returns structured ScanResult rather than raw output
// - Info() provides metadata for scanner discovery and validation
type Scanner interface {
	// Name returns the unique identifier for this scanner.
	// Used for logging, reporting, and scanner selection.
	Name() string

	// Scan executes the vulnerability scan on the specified target.
	// The target can be:
	// - A container image reference (e.g., "alpine:3.18", "nginx:latest")
	// - A local image (e.g., "my-app:dev")
	// - A filesystem path (e.g., "/path/to/project")
	//
	// The context should have a timeout set to prevent runaway scans.
	// Returns a ScanResult containing normalized vulnerabilities or an error.
	Scan(ctx context.Context, target string) (*models.ScanResult, error)

	// Info returns metadata about this scanner.
	// Used to check availability and version information.
	Info(ctx context.Context) (*models.ScannerInfo, error)

	// IsAvailable checks if the scanner is installed and accessible.
	// This is a quick check that doesn't perform a full scan.
	IsAvailable() bool
}

// Registry maintains a collection of available scanners.
// It provides scanner discovery and selection capabilities.
type Registry struct {
	scanners map[string]Scanner
}

// NewRegistry creates an empty scanner registry.
func NewRegistry() *Registry {
	return &Registry{
		scanners: make(map[string]Scanner),
	}
}

// Register adds a scanner to the registry.
// If a scanner with the same name already exists, it will be replaced.
func (r *Registry) Register(scanner Scanner) {
	r.scanners[scanner.Name()] = scanner
}

// Get retrieves a scanner by name.
// Returns nil if the scanner is not registered.
func (r *Registry) Get(name string) Scanner {
	return r.scanners[name]
}

// GetAll returns all registered scanners.
func (r *Registry) GetAll() []Scanner {
	scanners := make([]Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		scanners = append(scanners, s)
	}
	return scanners
}

// GetAvailable returns only scanners that are currently available.
func (r *Registry) GetAvailable() []Scanner {
	available := make([]Scanner, 0)
	for _, s := range r.scanners {
		if s.IsAvailable() {
			available = append(available, s)
		}
	}
	return available
}

// Names returns the names of all registered scanners.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.scanners))
	for name := range r.scanners {
		names = append(names, name)
	}
	return names
}

// Count returns the number of registered scanners.
func (r *Registry) Count() int {
	return len(r.scanners)
}

// DefaultRegistry creates a registry with all built-in scanners.
func DefaultRegistry() *Registry {
	registry := NewRegistry()
	registry.Register(NewTrivyScanner())
	registry.Register(NewGrypeScanner())
	return registry
}
