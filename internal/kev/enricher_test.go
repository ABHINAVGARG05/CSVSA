package kev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

func TestEnricherEnrich(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := catalog{
			Title:          "KEV",
			CatalogVersion: "1.0",
			DateReleased:   "2024-01-01",
			Count:          1,
			Vulnerabilities: []Entry{
				{
					CVEID:             "CVE-2024-0001",
					VulnerabilityName: "Test Vuln",
					DateAdded:         "2024-01-01",
					RequiredAction:    "Update",
					DueDate:           "2024-02-01",
					ShortDescription:  "Test entry",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL), WithHTTPClient(server.Client()))
	enricher := NewEnricher(client)

	vulns := []models.Vulnerability{
		{CVE: "CVE-2024-0001"},
		{CVEID: "CVE-2024-0002"},
	}

	count, err := enricher.Enrich(context.Background(), vulns)
	if err != nil {
		t.Fatalf("Enrich returned error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 KEV match, got %d", count)
	}

	if vulns[0].KEV == nil || !vulns[0].KEV.IsKEV {
		t.Fatal("expected first vulnerability to be KEV")
	}
	if vulns[1].KEV == nil || vulns[1].KEV.IsKEV {
		t.Fatal("expected second vulnerability to be non-KEV")
	}
}
