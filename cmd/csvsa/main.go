// CSVSA - Container Security Vulnerability Scanner Analyzer
//
// A tool that aggregates vulnerability scan results from multiple container
// security scanners and provides consensus analysis.
//
// Usage:
//
//	csvsa [target] [flags]
//
// Examples:
//
//	csvsa alpine:3.18
//	csvsa nginx:latest --format json
//	csvsa myimage:dev --html report.html --json results.json
//
// For more information, run: csvsa --help
package main

import (
	"os"

	"github.com/ABHINAVGARG05/CSVSA/internal/cli"
)

// Build-time variables (set via ldflags)
var (
	version   = "1.0.0"
	buildDate = "unknown"
	gitCommit = "unknown"
)

func main() {
	// Set version info
	cli.Version = version
	cli.BuildDate = buildDate
	cli.GitCommit = gitCommit

	// Create and execute CLI
	app := cli.New()
	exitCode := app.Execute()
	os.Exit(exitCode)
}
