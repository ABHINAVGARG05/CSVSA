// Package report provides multiple output formats for vulnerability analysis results.
//
// Design Pattern: Strategy Pattern
// Each report format is implemented as a separate Generator, allowing:
// 1. Easy addition of new formats without modifying existing code
// 2. Runtime selection of output format
// 3. Consistent interface across all formats
//
// Supported Formats:
// - Table: Human-readable CLI output with colors
// - JSON: Machine-readable structured output
// - HTML: Rich visual report with charts and styling
package report

import (
	"io"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

// Generator defines the interface for report generators.
type Generator interface {
	// Generate produces a report from the consensus result.
	Generate(result *models.ConsensusResult, w io.Writer) error

	// Format returns the format name (e.g., "table", "json", "html").
	Format() string
}

// Registry holds available report generators.
type Registry struct {
	generators map[string]Generator
}

// NewRegistry creates an empty generator registry.
func NewRegistry() *Registry {
	return &Registry{
		generators: make(map[string]Generator),
	}
}

// Register adds a generator to the registry.
func (r *Registry) Register(g Generator) {
	r.generators[g.Format()] = g
}

// Get retrieves a generator by format name.
func (r *Registry) Get(format string) Generator {
	return r.generators[format]
}

// Formats returns all available format names.
func (r *Registry) Formats() []string {
	formats := make([]string, 0, len(r.generators))
	for f := range r.generators {
		formats = append(formats, f)
	}
	return formats
}

// DefaultRegistry creates a registry with all built-in generators.
func DefaultRegistry() *Registry {
	registry := NewRegistry()
	registry.Register(NewTableGenerator())
	registry.Register(NewJSONGenerator())
	registry.Register(NewHTMLGenerator())
	return registry
}

// MultiGenerator generates reports in multiple formats.
type MultiGenerator struct {
	registry *Registry
}

// NewMultiGenerator creates a generator that can output multiple formats.
func NewMultiGenerator(registry *Registry) *MultiGenerator {
	return &MultiGenerator{registry: registry}
}

// Generate produces reports in the specified formats.
func (m *MultiGenerator) Generate(result *models.ConsensusResult, formats []string, writers map[string]io.Writer) error {
	for _, format := range formats {
		gen := m.registry.Get(format)
		if gen == nil {
			continue
		}

		w, ok := writers[format]
		if !ok {
			continue
		}

		if err := gen.Generate(result, w); err != nil {
			return err
		}
	}
	return nil
}
