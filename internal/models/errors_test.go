package models

import (
	"errors"
	"testing"
)

func TestScanErrorError(t *testing.T) {
	tests := []struct {
		name     string
		err      *ScanError
		expected string
	}{
		{
			name: "with scanner",
			err: &ScanError{
				Scanner: "trivy",
				Target:  "alpine:latest",
				Op:      "scan",
				Err:     errors.New("connection refused"),
			},
			expected: `trivy: scan on target "alpine:latest": connection refused`,
		},
		{
			name: "without scanner",
			err: &ScanError{
				Target: "alpine:latest",
				Op:     "validate",
				Err:    errors.New("invalid image"),
			},
			expected: `validate on target "alpine:latest": invalid image`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ScanError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestScanErrorUnwrap(t *testing.T) {
	underlying := errors.New("underlying error")
	err := NewScanError("trivy", "alpine:latest", "scan", underlying)

	if !errors.Is(err, underlying) {
		t.Error("errors.Is() should return true for underlying error")
	}
}

func TestParseErrorError(t *testing.T) {
	tests := []struct {
		name     string
		err      *ParseError
		expected string
	}{
		{
			name: "with field",
			err: &ParseError{
				Scanner: "trivy",
				Field:   "Severity",
				Err:     errors.New("unknown value"),
			},
			expected: `parsing trivy output: field "Severity": unknown value`,
		},
		{
			name: "without field",
			err: &ParseError{
				Scanner: "grype",
				Err:     errors.New("invalid JSON"),
			},
			expected: `parsing grype output: invalid JSON`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ParseError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	// Ensure sentinel errors are properly defined
	sentinels := []error{
		ErrScannerNotFound,
		ErrScannerTimeout,
		ErrScannerFailed,
		ErrInvalidTarget,
		ErrParseFailure,
		ErrNoScanners,
		ErrAllScannersFailed,
		ErrInvalidConfig,
	}

	for _, err := range sentinels {
		if err == nil {
			t.Error("Sentinel error should not be nil")
		}
		if err.Error() == "" {
			t.Error("Sentinel error message should not be empty")
		}
	}
}
