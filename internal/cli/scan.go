package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ABHINAVGARG05/CSVSA/internal/consensus"
	"github.com/ABHINAVGARG05/CSVSA/internal/kev"
	"github.com/ABHINAVGARG05/CSVSA/internal/models"
	"github.com/ABHINAVGARG05/CSVSA/internal/normalizer"
	"github.com/ABHINAVGARG05/CSVSA/internal/report"
	"github.com/ABHINAVGARG05/CSVSA/internal/scanner"
)

func newScanCmd() *cobra.Command {
	var (
		format     string
		output     string
		scanners   []string
		timeout    time.Duration
		minSev     string
		failOnVuln bool
		verbose    bool
		skipKEV    bool
	)

	cmd := &cobra.Command{
		Use:   "scan [IMAGE]",
		Short: "Scan a container image for vulnerabilities",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			registry := scanner.DefaultRegistry()

			scanConfig := models.DefaultConfig()
			scanConfig.Target = target
			scanConfig.Timeout = timeout
			scanConfig.Scanners = scanners
			scanConfig.Verbose = verbose

			orch := scanner.NewOrchestrator(registry, scanConfig)

			results, err := orch.ScanAll(ctx, target)
			if err != nil {
				return err
			}

			analyzer := consensus.NewAnalyzer()
			result := analyzer.Analyze(target, results)

			if minSev != "" {
				severity := parseSeverity(minSev)
				filterConsensusResult(result, severity)
			}

			if !skipKEV {
				if verbose {
					fmt.Println("🔍 Fetching CISA KEV catalog...")
				}

				kevClient := kev.NewClient()
				enricher := kev.NewEnricher(kevClient)

				if err := enricher.EnrichConsensusResult(ctx, result); err != nil {
					// Non-fatal: warn but continue
					fmt.Fprintf(os.Stderr, "KEV enrichment failed: %v\n", err)
				} else if verbose {
					fmt.Printf("KEV catalog loaded (%d known exploited vulns checked)\n",
						kevClient.Count())
					if result.Statistics.KEVCount > 0 {
						fmt.Printf("%d vulnerabilities are actively exploited (CISA KEV)\n",
							result.Statistics.KEVCount)
					}
				}
			}

			if err := generateScanReport(result, format, output); err != nil {
				return err
			}

			if failOnVuln && len(result.AllVulnerabilities) > 0 {
				os.Exit(ExitVulnerabilitiesFound)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json, html")
	cmd.Flags().StringVar(&output, "output", "", "Output file path")
	cmd.Flags().StringSliceVar(&scanners, "scanners", nil, "Scanners to use")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Scan timeout")
	cmd.Flags().StringVar(&minSev, "min-severity", "low", "Minimum severity")
	cmd.Flags().BoolVar(&failOnVuln, "fail-on-vuln", false, "Exit 2 if vulnerabilities found")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Verbose output")

	cmd.Flags().BoolVar(&skipKEV, "skip-kev", false, "Skip CISA KEV lookup (offline mode)")

	return cmd
}

func generateScanReport(result *models.ConsensusResult, format, output string) error {
	registry := report.DefaultRegistry()
	gen := registry.Get(format)
	if gen == nil {
		gen = registry.Get("table")
	}

	var writer *os.File
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		writer = f
	} else {
		writer = os.Stdout
	}

	if err := gen.Generate(result, writer); err != nil {
		return fmt.Errorf("failed to generate %s report: %w", gen.Format(), err)
	}
	return nil
}

func filterConsensusResult(result *models.ConsensusResult, minSeverity models.Severity) {
	n := normalizer.NewNormalizer()

	result.Consensus = n.FilterBySeverity(result.Consensus, minSeverity)
	result.AllVulnerabilities = n.FilterBySeverity(result.AllVulnerabilities, minSeverity)

	for scannerName, vulns := range result.UniqueFindings {
		result.UniqueFindings[scannerName] = n.FilterBySeverity(vulns, minSeverity)
	}

	if len(result.AllVulnerabilities) == 0 {
		result.OverlapPercentage = 0
	} else {
		result.OverlapPercentage = float64(len(result.Consensus)) / float64(len(result.AllVulnerabilities)) * 100
	}

	result.Statistics.KEVConsensusCount = countKEV(result.Consensus)
	result.Statistics.KEVCount = result.Statistics.KEVConsensusCount
	for _, vulns := range result.UniqueFindings {
		result.Statistics.KEVCount += countKEV(vulns)
	}
}

func countKEV(vulns []models.Vulnerability) int {
	count := 0
	for _, v := range vulns {
		if v.KEV != nil && v.KEV.IsKEV {
			count++
		}
	}
	return count
}