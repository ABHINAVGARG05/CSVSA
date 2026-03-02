// Package cli provides the command-line interface for CSVSA.
//
// Design Decisions:
// - Uses cobra for professional CLI structure
// - Supports multiple output formats via flags
// - Provides sensible defaults with full customization
// - Implements graceful error handling with exit codes
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/consensus"
	"github.com/ABHINAVGARG05/CSVSA/internal/models"
	"github.com/ABHINAVGARG05/CSVSA/internal/report"
	"github.com/ABHINAVGARG05/CSVSA/internal/scanner"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// Version information (set at build time)
var (
	Version   = "1.0.0"
	BuildDate = "unknown"
	GitCommit = "unknown"
)

// Exit codes
const (
	ExitSuccess              = 0
	ExitError                = 1
	ExitVulnerabilitiesFound = 2
)

// CLI holds the command-line application state.
type CLI struct {
	rootCmd *cobra.Command
	config  Config
}

// Config holds CLI configuration options.
type Config struct {
	Target              string
	Timeout             time.Duration
	Scanners            []string
	OutputFormat        string
	OutputFile          string
	HTMLFile            string
	JSONFile            string
	Verbose             bool
	NoColor             bool
	FailOnVulnerability bool
	MinSeverity         string
}

// New creates a new CLI instance.
func New() *CLI {
	cli := &CLI{}
	cli.rootCmd = cli.buildRootCommand()
	return cli
}

// Execute runs the CLI application.
func (c *CLI) Execute() int {
	if err := c.rootCmd.Execute(); err != nil {
		return ExitError
	}
	return ExitSuccess
}

// buildRootCommand creates the main command structure.
func (c *CLI) buildRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "csvsa [target]",
		Short: "Container Security Vulnerability Scanner Analyzer",
		Long: `CSVSA - Container Security Vulnerability Scanner Analyzer

A tool that aggregates vulnerability scan results from multiple container 
security scanners (Trivy, Grype) and provides consensus analysis.

Features:
  - Runs multiple scanners in parallel
  - Normalizes and deduplicates findings
  - Computes consensus (vulnerabilities found by all scanners)
  - Identifies unique findings per scanner
  - Generates reports in multiple formats (table, JSON, HTML)

Examples:
  # Scan an image with default settings
  csvsa alpine:3.18

  # Scan with specific scanners
  csvsa alpine:3.18 --scanners trivy,grype

  # Generate HTML report
  csvsa alpine:3.18 --html report.html

  # Generate JSON output
  csvsa alpine:3.18 --format json

  # Fail if vulnerabilities found (for CI/CD)
  csvsa alpine:3.18 --fail-on-vuln`,
		Args:    cobra.MaximumNArgs(1),
		Version: fmt.Sprintf("%s (built %s, commit %s)", Version, BuildDate, GitCommit),
		RunE:    c.runScan,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if c.config.NoColor {
				color.NoColor = true
			}
		},
	}

	// Add flags
	c.addFlags(rootCmd)

	// Add subcommands
	rootCmd.AddCommand(c.buildScannersCommand())
	rootCmd.AddCommand(c.buildVersionCommand())

	return rootCmd
}

// addFlags adds command-line flags to the root command.
func (c *CLI) addFlags(cmd *cobra.Command) {
	flags := cmd.Flags()

	flags.DurationVarP(&c.config.Timeout, "timeout", "t", 5*time.Minute,
		"Timeout for each scanner")

	flags.StringSliceVarP(&c.config.Scanners, "scanners", "s", []string{},
		"Scanners to use (comma-separated, default: all available)")

	flags.StringVarP(&c.config.OutputFormat, "format", "f", "table",
		"Output format: table, json, html")

	flags.StringVarP(&c.config.OutputFile, "output", "o", "",
		"Output file (default: stdout)")

	flags.StringVar(&c.config.HTMLFile, "html", "",
		"Generate HTML report to file")

	flags.StringVar(&c.config.JSONFile, "json", "",
		"Generate JSON report to file")

	flags.BoolVarP(&c.config.Verbose, "verbose", "v", false,
		"Enable verbose output")

	flags.BoolVar(&c.config.NoColor, "no-color", false,
		"Disable colored output")

	flags.BoolVar(&c.config.FailOnVulnerability, "fail-on-vuln", false,
		"Exit with code 2 if vulnerabilities found")

	flags.StringVar(&c.config.MinSeverity, "min-severity", "",
		"Minimum severity to report: critical, high, medium, low")
}

// buildScannersCommand creates the 'scanners' subcommand.
func (c *CLI) buildScannersCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "scanners",
		Short: "List available scanners",
		Long:  "Display information about available vulnerability scanners.",
		RunE:  c.runScanners,
	}
}

// buildVersionCommand creates the 'version' subcommand.
func (c *CLI) buildVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("CSVSA %s\n", Version)
			fmt.Printf("Build Date: %s\n", BuildDate)
			fmt.Printf("Git Commit: %s\n", GitCommit)
		},
	}
}

// runScan executes the main scan command.
func (c *CLI) runScan(cmd *cobra.Command, args []string) error {
	// Check for target
	if len(args) == 0 {
		return fmt.Errorf("target is required (e.g., csvsa alpine:3.18)")
	}
	target := args[0]

	// Setup context with signal handling
	ctx, cancel := c.setupContext()
	defer cancel()

	// Initialize components
	registry := scanner.DefaultRegistry()
	config := c.buildScanConfig(target)
	orchestrator := scanner.NewOrchestrator(registry, config)

	// Check for available scanners
	available := registry.GetAvailable()
	if len(available) == 0 {
		return fmt.Errorf("no scanners available. Please install trivy or grype")
	}

	// Print scan start info
	if c.config.Verbose {
		c.printScanStart(target, available)
	}

	// Execute scans
	results, err := orchestrator.ScanAll(ctx, target)
	if err != nil && err != models.ErrAllScannersFailed {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Check if we got any successful results
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	if successCount == 0 {
		c.printScanErrors(results)
		return fmt.Errorf("all scanners failed")
	}

	// Analyze results
	analyzer := consensus.NewAnalyzer()
	consensusResult := analyzer.Analyze(target, results)

	// Generate reports
	if err := c.generateReports(consensusResult); err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}

	// Check exit code
	if c.config.FailOnVulnerability && len(consensusResult.AllVulnerabilities) > 0 {
		os.Exit(ExitVulnerabilitiesFound)
	}

	return nil
}

// runScanners executes the 'scanners' subcommand.
func (c *CLI) runScanners(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	registry := scanner.DefaultRegistry()

	fmt.Println("\nAvailable Scanners:")
	fmt.Println("───────────────────────────────────────────")

	for _, s := range registry.GetAll() {
		info, _ := s.Info(ctx)

		status := color.RedString("✗ Not installed")
		if info.Available {
			status = color.GreenString("✓ Available")
		}

		fmt.Printf("  %-10s %s\n", s.Name(), status)
		if info.Available {
			fmt.Printf("             Version: %s\n", info.Version)
			if info.Path != "" {
				fmt.Printf("             Path: %s\n", info.Path)
			}
		}
		fmt.Println()
	}

	return nil
}

// setupContext creates a context with signal handling.
func (c *CLI) setupContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\nInterrupted, canceling scans...")
		cancel()
	}()

	return ctx, cancel
}

// buildScanConfig creates a ScanConfig from CLI options.
func (c *CLI) buildScanConfig(target string) models.ScanConfig {
	config := models.DefaultConfig()
	config.Target = target
	config.Timeout = c.config.Timeout
	config.Scanners = c.config.Scanners
	config.Verbose = c.config.Verbose

	if c.config.MinSeverity != "" {
		config.MinSeverity = parseSeverity(c.config.MinSeverity)
	}

	return config
}

// generateReports creates output in requested formats.
func (c *CLI) generateReports(result *models.ConsensusResult) error {
	registry := report.DefaultRegistry()

	// Always generate primary output
	primaryGen := registry.Get(c.config.OutputFormat)
	if primaryGen == nil {
		primaryGen = registry.Get("table")
	}

	// Determine output writer
	var primaryWriter *os.File
	if c.config.OutputFile != "" {
		f, err := os.Create(c.config.OutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		primaryWriter = f
	} else {
		primaryWriter = os.Stdout
	}

	if err := primaryGen.Generate(result, primaryWriter); err != nil {
		return fmt.Errorf("failed to generate %s report: %w", c.config.OutputFormat, err)
	}

	// Generate additional HTML report if requested
	if c.config.HTMLFile != "" {
		if err := c.generateToFile(registry.Get("html"), result, c.config.HTMLFile); err != nil {
			return err
		}
		if c.config.Verbose {
			fmt.Printf("HTML report written to: %s\n", c.config.HTMLFile)
		}
	}

	// Generate additional JSON report if requested
	if c.config.JSONFile != "" {
		if err := c.generateToFile(registry.Get("json"), result, c.config.JSONFile); err != nil {
			return err
		}
		if c.config.Verbose {
			fmt.Printf("JSON report written to: %s\n", c.config.JSONFile)
		}
	}

	return nil
}

// generateToFile writes a report to a file.
func (c *CLI) generateToFile(gen report.Generator, result *models.ConsensusResult, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", filename, err)
	}
	defer f.Close()

	if err := gen.Generate(result, f); err != nil {
		return fmt.Errorf("failed to generate %s report: %w", gen.Format(), err)
	}

	return nil
}

// printScanStart prints scan initialization info.
func (c *CLI) printScanStart(target string, scanners []scanner.Scanner) {
	fmt.Println()
	color.Cyan("CSVSA - Container Security Vulnerability Scanner Analyzer")
	fmt.Println()
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Scanners: ")
	names := make([]string, len(scanners))
	for i, s := range scanners {
		names[i] = s.Name()
	}
	fmt.Printf("%s\n", strings.Join(names, ", "))
	fmt.Printf("Timeout: %s per scanner\n", c.config.Timeout)
	fmt.Println()
	fmt.Println("Scanning...")
}

// printScanErrors prints scanner error information.
func (c *CLI) printScanErrors(results []models.ScanResult) {
	color.Red("\nScanner Errors:")
	for _, r := range results {
		if !r.Success && r.Error != "" {
			fmt.Printf("  %s: %s\n", r.Scanner, r.Error)
		}
	}
}

// parseSeverity converts a string to Severity.
func parseSeverity(s string) models.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return models.SeverityCritical
	case "HIGH":
		return models.SeverityHigh
	case "MEDIUM":
		return models.SeverityMedium
	case "LOW":
		return models.SeverityLow
	default:
		return models.SeverityUnknown
	}
}
