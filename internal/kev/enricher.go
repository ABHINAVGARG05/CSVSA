package kev

import (
	"context"
	"fmt"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

type Enricher struct {
	client *Client
}

func NewEnricher(client *Client) *Enricher {
	return &Enricher{client: client}
}

// Enrich updates vulnerabilities in-place using pointer access
func (e *Enricher) Enrich(ctx context.Context, vulns []models.Vulnerability) (int, error) {
	kevCount := 0

	for i := range vulns {
		v := &vulns[i] // 🔥 FIX: use pointer to modify original struct

		cveID := v.CVEID
		if cveID == "" {
			cveID = v.CVE
		}
		if cveID == "" {
			continue
		}

		isKEV, entry, err := e.client.IsKEV(ctx, cveID)
		if err != nil {
			fmt.Printf("Warning: KEV lookup failed for %s: %v\n", cveID, err)
			continue
		}

		if isKEV {
			kevCount++
			v.KEV = &models.KEVInfo{
				IsKEV:             true,
				VulnerabilityName: entry.VulnerabilityName,
				DateAdded:         entry.DateAdded,
				RequiredAction:    entry.RequiredAction,
				DueDate:           entry.DueDate,
				ShortDescription:  entry.ShortDescription,
			}
		} else {
			v.KEV = &models.KEVInfo{IsKEV: false}
		}
	}

	return kevCount, nil
}

func (e *Enricher) EnrichConsensusResult(ctx context.Context, result *models.ConsensusResult) error {
	consensusKEV, err := e.Enrich(ctx, result.Consensus)
	if err != nil {
		return fmt.Errorf("enriching consensus findings: %w", err)
	}
	result.Statistics.KEVConsensusCount = consensusKEV

	totalKEV := consensusKEV

	// Enrich unique findings per scanner
	for scanner, vulns := range result.UniqueFindings {
		count, err := e.Enrich(ctx, vulns)
		if err != nil {
			return fmt.Errorf("enriching findings for %s: %w", scanner, err)
		}

		// Re-assign (safe even though slice is modified in-place)
		result.UniqueFindings[scanner] = vulns
		totalKEV += count
	}

	result.Statistics.KEVCount = totalKEV
	return nil
}