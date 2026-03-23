package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/analysis"
	"github.com/ABHINAVGARG05/CSVSA/internal/consensus"
	"github.com/ABHINAVGARG05/CSVSA/internal/database"
	"github.com/ABHINAVGARG05/CSVSA/internal/epss"
	"github.com/ABHINAVGARG05/CSVSA/internal/models"
	"github.com/ABHINAVGARG05/CSVSA/internal/report"
	"github.com/ABHINAVGARG05/CSVSA/internal/scanner"
	"github.com/ABHINAVGARG05/CSVSA/internal/viz"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
    Version   = "dev"
    BuildDate = "unknown"
    GitCommit = "unknown"
)

func init() {
    if info, ok := debug.ReadBuildInfo(); ok {
        if info.Main.Version != "" && info.Main.Version != "(devel)" {
            Version = info.Main.Version
        }
        for _, s := range info.Settings {
            switch s.Key {
            case "vcs.revision":
                if len(s.Value) > 7 {
                    GitCommit = s.Value[:7]
                } else {
                    GitCommit = s.Value
                }
            case "vcs.time":
                BuildDate = s.Value
            }
        }
    }
}

const (
	ExitSuccess              = 0
	ExitError                = 1
	ExitVulnerabilitiesFound = 2
)

type CLI struct {
	rootCmd *cobra.Command
	config  Config
}

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
	DBEnabled 			bool
	DBPath    			string
	Category  			string
	EPSSEnabled 		bool
	EPSSOutput  		string
	ChartFile 			string
	AnalysisEnabled 	bool
}

func New() *CLI {
	c := &CLI{}
	c.rootCmd = c.buildRootCommand()
	return c
}

func (c *CLI) Execute() int {
	if err := c.rootCmd.Execute(); err != nil {
		return ExitError
	}
	return ExitSuccess
}

func (c *CLI) buildRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "csvsa [target]",
		Short: "Container Security Vulnerability Scanner Analyzer",
		Long: `CSVSA - Container Security Vulnerability Scanner Analyzer

Aggregates results from Trivy and Grype, computes consensus, and optionally:
  • Persists results to SQLite  (--db)
  • Enriches CVEs with EPSS scores  (--epss)
  • Runs statistical analysis  (--analyze)
  • Generates severity bar charts  (--chart)

Examples:
  csvsa alpine:3.18
  csvsa alpine:3.18 --db --epss --analyze
  csvsa alpine:3.18 --db --category production --chart severity.png --html report.html`,
		Args:    cobra.MaximumNArgs(1),
        Version: fmt.Sprintf("%s (built %s, commit %s)", Version, BuildDate, GitCommit),
		RunE:    c.runScan,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if c.config.NoColor {
				color.NoColor = true
			}
		},
	}

	c.addFlags(rootCmd)
	rootCmd.AddCommand(c.buildScannersCommand())
	rootCmd.AddCommand(c.buildVersionCommand())
	rootCmd.AddCommand(c.buildHistoryCommand())
	rootCmd.AddCommand(c.buildAnalyzeCommand())
	return rootCmd
}

func (c *CLI) addFlags(cmd *cobra.Command) {
	f := cmd.Flags()

	f.DurationVarP(&c.config.Timeout, "timeout", "t", 5*time.Minute, "Timeout for each scanner")
	f.StringSliceVarP(&c.config.Scanners, "scanners", "s", []string{}, "Scanners to use (comma-separated)")
	f.StringVarP(&c.config.OutputFormat, "format", "f", "table", "Output format: table, json, html")
	f.StringVarP(&c.config.OutputFile, "output", "o", "", "Output file (default: stdout)")
	f.StringVar(&c.config.HTMLFile, "html", "", "Generate HTML report to file")
	f.StringVar(&c.config.JSONFile, "json", "", "Generate JSON report to file")
	f.BoolVarP(&c.config.Verbose, "verbose", "v", false, "Enable verbose output")
	f.BoolVar(&c.config.NoColor, "no-color", false, "Disable colored output")
	f.BoolVar(&c.config.FailOnVulnerability, "fail-on-vuln", false, "Exit with code 2 if vulnerabilities found")
	f.StringVar(&c.config.MinSeverity, "min-severity", "", "Minimum severity: critical, high, medium, low")

	f.BoolVar(&c.config.DBEnabled, "db", false, "Persist scan results to SQLite database")
	f.StringVar(&c.config.DBPath, "db-path", "csvsa.db", "Path to SQLite database file")
	f.StringVar(&c.config.Category, "category", "", "Category tag for this image (e.g. production, staging)")

	f.BoolVar(&c.config.EPSSEnabled, "epss", false, "Enrich vulnerabilities with EPSS exploit-probability scores")
	f.StringVar(&c.config.EPSSOutput, "epss-output", "", "Write EPSS-enriched results to this JSON file")

	f.StringVar(&c.config.ChartFile, "chart", "", "Generate severity bar chart PNG to this file")

	f.BoolVar(&c.config.AnalysisEnabled, "analyze", false, "Run statistical analysis on EPSS score distributions")
}

func (c *CLI) buildScannersCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "scanners",
		Short: "List available scanners",
		RunE:  c.runScanners,
	}
}

func (c *CLI) buildVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("CSVSA %s\nBuild Date: %s\nGit Commit: %s\n", Version, BuildDate, GitCommit)
		},
	}
}

func (c *CLI) buildHistoryCommand() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show historical scan results from the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runHistory(cmd.Context(), dbPath)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db-path", "csvsa.db", "Path to SQLite database file")
	return cmd
}

func (c *CLI) buildAnalyzeCommand() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Run statistical analysis on persisted EPSS scores",
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runAnalyze(cmd.Context(), dbPath)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db-path", "csvsa.db", "Path to SQLite database file")
	return cmd
}


func (c *CLI) runScan(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("target is required (e.g., csvsa alpine:3.18)")
	}
	target := args[0]

	ctx, cancel := c.setupContext()
	defer cancel()

	registry := scanner.DefaultRegistry()
	scanConfig := c.buildScanConfig(target)
	orchestrator := scanner.NewOrchestrator(registry, scanConfig)

	available := registry.GetAvailable()
	if len(available) == 0 {
		return fmt.Errorf("no scanners available. Please install trivy or grype")
	}
	if c.config.Verbose {
		c.printScanStart(target, available)
	}

	results, err := orchestrator.ScanAll(ctx, target)
	if err != nil && err != models.ErrAllScannersFailed {
		return fmt.Errorf("scan failed: %w", err)
	}

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

	analyzer := consensus.NewAnalyzer()
	consensusResult := analyzer.Analyze(target, results)

	var store database.Store
	if c.config.DBEnabled {
		store, err = c.initDB(ctx)
		if err != nil {
			return fmt.Errorf("database init failed: %w", err)
		}
		defer store.Close()

		if _, err := store.PersistScanResults(ctx, target, c.config.Category, consensusResult); err != nil {
			return fmt.Errorf("failed to persist scan results: %w", err)
		}
		if c.config.Verbose {
			color.Green("Results persisted to %s\n", c.config.DBPath)
		}
	}

	var epssScores map[string]epss.Score
	if c.config.EPSSEnabled {
		epssScores, err = c.fetchEPSSScores(ctx, consensusResult, store)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: EPSS enrichment failed: %v\n", err)
		} else if c.config.Verbose {
			color.Green("EPSS scores fetched for %d CVEs\n", len(epssScores))
		}

		if c.config.EPSSOutput != "" {
			if werr := c.writeEPSSJSON(consensusResult, epssScores, c.config.EPSSOutput); werr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to write EPSS output: %v\n", werr)
			} else if c.config.Verbose {
				fmt.Printf("EPSS JSON written to: %s\n", c.config.EPSSOutput)
			}
		}
	}

	if c.config.AnalysisEnabled && len(epssScores) > 0 {
		c.runEPSSAnalysis(consensusResult, epssScores)
	}

	// 5. Chart generation
	if c.config.ChartFile != "" {
		if cerr := c.generateSeverityChart(consensusResult); cerr != nil {
			fmt.Fprintf(os.Stderr, "Warning: chart generation failed: %v\n", cerr)
		} else if c.config.Verbose {
			fmt.Printf("Chart written to: %s\n", c.config.ChartFile)
		}
	}

	// 6. Reports
	if err := c.generateReports(consensusResult); err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}

	if c.config.FailOnVulnerability && len(consensusResult.AllVulnerabilities) > 0 {
		os.Exit(ExitVulnerabilitiesFound)
	}
	return nil
}

// ── Component helpers ─────────────────────────────────────────────────────────

func (c *CLI) initDB(ctx context.Context) (database.Store, error) {
	level := slog.LevelInfo
	if !c.config.Verbose {
		level = slog.LevelError
	}
	cfg := database.SQLiteConfig{
		Path:   c.config.DBPath,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})),
	}
	return database.NewSQLiteStore(ctx, cfg)
}

func (c *CLI) fetchEPSSScores(ctx context.Context, result *models.ConsensusResult, store database.Store) (map[string]epss.Score, error) {
	cveSet := make(map[string]struct{})
	for _, v := range result.AllVulnerabilities {
		if v.CVE != "" {
			cveSet[v.CVE] = struct{}{}
		}
	}
	if len(cveSet) == 0 {
		return make(map[string]epss.Score), nil
	}

	cveIDs := make([]string, 0, len(cveSet))
	for id := range cveSet {
		cveIDs = append(cveIDs, id)
	}

	client := epss.NewClient()
	scores, err := client.GetScores(ctx, cveIDs)
	if err != nil {
		return nil, err
	}

	if store != nil && len(scores) > 0 {
		var dbScores []database.EPSSScore
		for _, s := range scores {
			dbScores = append(dbScores, database.EPSSScore{
				CVEID:       s.CVE,
				EPSSScore:   s.EPSS,
				Percentile:  s.Percentile,
				FetchedDate: s.FetchedAt,
			})
		}
		if berr := store.BulkUpsertEPSSScores(ctx, dbScores); berr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to cache EPSS scores: %v\n", berr)
		}
	}
	return scores, nil
}

func (c *CLI) writeEPSSJSON(result *models.ConsensusResult, scores map[string]epss.Score, filename string) error {
	type entry struct {
		CVE        string  `json:"cve"`
		Package    string  `json:"package"`
		Severity   string  `json:"severity"`
		EPSS       float64 `json:"epss_score"`
		Percentile float64 `json:"epss_percentile"`
	}
	var entries []entry
	for _, v := range result.AllVulnerabilities {
		e := entry{CVE: v.CVE, Package: v.Package, Severity: string(v.Severity)}
		if s, ok := scores[v.CVE]; ok {
			e.EPSS = s.EPSS
			e.Percentile = s.Percentile
		}
		entries = append(entries, e)
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func (c *CLI) runEPSSAnalysis(result *models.ConsensusResult, scores map[string]epss.Score) {
	consensusScores := extractEPSSScores(result.Consensus, scores)
	var uniqueScores []float64
	for _, vulns := range result.UniqueFindings {
		uniqueScores = append(uniqueScores, extractEPSSScores(vulns, scores)...)
	}

	fmt.Println()
	color.Cyan("── EPSS Statistical Analysis ─────────────────────────────────────────────")

	if len(consensusScores) >= 2 && len(uniqueScores) >= 2 {
		cmp, err := analysis.CompareCategoryDistributions("consensus", consensusScores, "unique", uniqueScores)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Analysis error: %v\n", err)
		} else {
			fmt.Println(cmp.String())
			if cmp.TestResult.IsSignificant(0.05) {
				color.Yellow("→ Significant difference in EPSS distributions (p < 0.05)\n")
			} else {
				fmt.Println("→ No significant difference in EPSS distributions")
			}
		}
	} else {
		fmt.Println("Not enough data for statistical comparison (need ≥2 scores per group)")
	}

	var allScores []float64
	for _, s := range scores {
		allScores = append(allScores, s.EPSS)
	}
	stats := viz.CalculateSummaryStats(allScores,
		len(result.Consensus),
		len(result.AllVulnerabilities)-len(result.Consensus),
		countUnique(result.UniqueFindings),
	)
	fmt.Printf("\nEPSS Summary: mean=%.4f  median=%.4f  high-risk(>0.5)=%d  critical-risk(>0.75)=%d\n",
		stats.MeanEPSS, stats.MedianEPSS, stats.HighRiskCount, stats.CriticalRiskCount)
}

func (c *CLI) generateSeverityChart(result *models.ConsensusResult) error {
	dist := viz.SeverityDistribution{}
	for _, v := range result.AllVulnerabilities {
		switch v.Severity {
		case models.SeverityCritical:
			dist.Critical++
		case models.SeverityHigh:
			dist.High++
		case models.SeverityMedium:
			dist.Medium++
		case models.SeverityLow:
			dist.Low++
		default:
			dist.Unknown++
		}
	}
	barData := viz.CreateSeverityPieData(dist)
	cfg := viz.DefaultBarChartConfig()
	cfg.Title = fmt.Sprintf("Vulnerability Severity — %s", result.Target)
	p, err := viz.CreateBarChart(barData, cfg)
	if err != nil {
		return err
	}
	return viz.SavePlot(p, c.config.ChartFile, cfg.Width, cfg.Height)
}

func (c *CLI) runHistory(ctx context.Context, dbPath string) error {
	cfg := database.SQLiteConfig{
		Path:   dbPath,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	store, err := database.NewSQLiteStore(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer store.Close()

	images, err := store.ListImages(ctx)
	if err != nil {
		return fmt.Errorf("failed to list images: %w", err)
	}
	if len(images) == 0 {
		fmt.Println("No scan history found. Run a scan with --db to start recording.")
		return nil
	}

	color.Cyan("\n── Scan History ──────────────────────────────────────────────────────────")
	fmt.Printf("%-5s  %-40s  %-15s  %s\n", "ID", "Image", "Category", "Scanned At")
	fmt.Println(strings.Repeat("─", 80))
	for _, img := range images {
		fmt.Printf("%-5d  %-40s  %-15s  %s\n",
			img.ID, img.Name, img.Category, img.ScanDate.Format("2006-01-02 15:04:05"))
	}
	return nil
}

func (c *CLI) runAnalyze(ctx context.Context, dbPath string) error {
	cfg := database.SQLiteConfig{
		Path:   dbPath,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	store, err := database.NewSQLiteStore(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer store.Close()

	findings, err := store.GetAllFindingsWithEPSS(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch findings: %w", err)
	}
	if len(findings) == 0 {
		fmt.Println("No findings with EPSS data. Run a scan with --db --epss first.")
		return nil
	}

	buckets := map[string][]float64{"consensus": {}, "partial": {}, "unique": {}}
	for _, f := range findings {
		if f.EPSSScore == nil {
			continue
		}
		key := string(f.ConsensusType)
		buckets[key] = append(buckets[key], f.EPSSScore.EPSSScore)
	}

	color.Cyan("\n── Database EPSS Analysis ────────────────────────────────────────────────")
	for ct, s := range buckets {
		if len(s) == 0 {
			continue
		}
		stats, err := analysis.Compute(s)
		if err != nil {
			continue
		}
		fmt.Printf("[%s]  n=%d  min=%.4f  max=%.4f  mean=%.4f  median=%.4f  stddev=%.4f\n",
			strings.ToUpper(ct), stats.N, stats.Min, stats.Max, stats.Mean, stats.Median, stats.StdDev)
	}

	if len(buckets["consensus"]) >= 2 && len(buckets["unique"]) >= 2 {
		cmp, err := analysis.CompareCategoryDistributions("consensus", buckets["consensus"], "unique", buckets["unique"])
		if err == nil {
			fmt.Printf("\nConsensus vs Unique: %s\n", cmp.String())
		}
	}
	return nil
}

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

func (c *CLI) buildScanConfig(target string) models.ScanConfig {
	cfg := models.DefaultConfig()
	cfg.Target = target
	cfg.Timeout = c.config.Timeout
	cfg.Scanners = c.config.Scanners
	cfg.Verbose = c.config.Verbose
	if c.config.MinSeverity != "" {
		cfg.MinSeverity = parseSeverity(c.config.MinSeverity)
	}
	return cfg
}

func (c *CLI) generateReports(result *models.ConsensusResult) error {
	registry := report.DefaultRegistry()
	primaryGen := registry.Get(c.config.OutputFormat)
	if primaryGen == nil {
		primaryGen = registry.Get("table")
	}

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

	if c.config.HTMLFile != "" {
		if err := c.generateToFile(registry.Get("html"), result, c.config.HTMLFile); err != nil {
			return err
		}
		if c.config.Verbose {
			fmt.Printf("HTML report written to: %s\n", c.config.HTMLFile)
		}
	}

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

func (c *CLI) printScanStart(target string, scanners []scanner.Scanner) {
	fmt.Println()
	color.Cyan("CSVSA - Container Security Vulnerability Scanner Analyzer")
	fmt.Println()
	fmt.Printf("Target:   %s\n", target)
	names := make([]string, len(scanners))
	for i, s := range scanners {
		names[i] = s.Name()
	}
	fmt.Printf("Scanners: %s\n", strings.Join(names, ", "))
	fmt.Printf("Timeout:  %s per scanner\n", c.config.Timeout)
	if c.config.DBEnabled {
		fmt.Printf("Database: %s  category=%q\n", c.config.DBPath, c.config.Category)
	}
	if c.config.EPSSEnabled {
		fmt.Println("EPSS:     enabled")
	}
	if c.config.ChartFile != "" {
		fmt.Printf("Chart:    %s\n", c.config.ChartFile)
	}
	fmt.Println()
	fmt.Println("Scanning...")
}

func (c *CLI) printScanErrors(results []models.ScanResult) {
	color.Red("\nScanner Errors:")
	for _, r := range results {
		if !r.Success && r.Error != "" {
			fmt.Printf("  %s: %s\n", r.Scanner, r.Error)
		}
	}
}

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


func extractEPSSScores(vulns []models.Vulnerability, scores map[string]epss.Score) []float64 {
	var out []float64
	for _, v := range vulns {
		if s, ok := scores[v.CVE]; ok {
			out = append(out, s.EPSS)
		}
	}
	return out
}

func countUnique(m map[string][]models.Vulnerability) int {
	total := 0
	for _, v := range m {
		total += len(v)
	}
	return total
}