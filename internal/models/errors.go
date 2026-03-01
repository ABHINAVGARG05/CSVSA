// Package models - Error definitions for CSVSA
package models

import (
	"errors"
	"fmt"
)

// Standard errors used throughout CSVSA.
// Using sentinel errors enables callers to use errors.Is() for comparison.
var (
	// ErrScannerNotFound indicates a requested scanner is not installed.
	ErrScannerNotFound = errors.New("scanner not found")

	// ErrScannerTimeout indicates a scanner exceeded its time limit.
	ErrScannerTimeout = errors.New("scanner execution timed out")

	// ErrScannerFailed indicates a scanner returned a non-zero exit code.
	ErrScannerFailed = errors.New("scanner execution failed")

	// ErrInvalidTarget indicates the scan target is invalid or inaccessible.
	ErrInvalidTarget = errors.New("invalid scan target")

	// ErrParseFailure indicates JSON parsing failed.
	ErrParseFailure = errors.New("failed to parse scanner output")

	// ErrNoScanners indicates no scanners are available.
	ErrNoScanners = errors.New("no scanners available")

	// ErrAllScannersFailed indicates all scanner executions failed.
	ErrAllScannersFailed = errors.New("all scanners failed")

	// ErrInvalidConfig indicates configuration validation failed.
	ErrInvalidConfig = errors.New("invalid configuration")
)

// ScanError wraps an error with additional context about the scan operation.
type ScanError struct {
	Scanner string // Which scanner produced this error
	Target  string // What was being scanned
	Op      string // What operation failed
	Err     error  // The underlying error
}

// Error implements the error interface.
func (e *ScanError) Error() string {
	if e.Scanner != "" {
		return fmt.Sprintf("%s: %s on target %q: %v", e.Scanner, e.Op, e.Target, e.Err)
	}
	return fmt.Sprintf("%s on target %q: %v", e.Op, e.Target, e.Err)
}

// Unwrap returns the underlying error for errors.Is() and errors.As().
func (e *ScanError) Unwrap() error {
	return e.Err
}

// NewScanError creates a new ScanError with the given context.
func NewScanError(scanner, target, op string, err error) *ScanError {
	return &ScanError{
		Scanner: scanner,
		Target:  target,
		Op:      op,
		Err:     err,
	}
}

// ParseError represents an error that occurred while parsing scanner output.
type ParseError struct {
	Scanner  string // Which scanner's output we were parsing
	Field    string // Which field caused the issue (if known)
	RawValue string // The problematic raw value (if applicable)
	Err      error  // The underlying error
}

// Error implements the error interface.
func (e *ParseError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("parsing %s output: field %q: %v", e.Scanner, e.Field, e.Err)
	}
	return fmt.Sprintf("parsing %s output: %v", e.Scanner, e.Err)
}

// Unwrap returns the underlying error.
func (e *ParseError) Unwrap() error {
	return e.Err
}

// NewParseError creates a new ParseError with the given context.
func NewParseError(scanner, field string, err error) *ParseError {
	return &ParseError{
		Scanner: scanner,
		Field:   field,
		Err:     err,
	}
}
