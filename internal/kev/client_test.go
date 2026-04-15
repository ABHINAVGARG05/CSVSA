package kev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientIsKEV(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
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
	ctx := context.Background()

	isKEV, entry, err := client.IsKEV(ctx, "CVE-2024-0001")
	require.NoError(t, err)
	require.True(t, isKEV)
	require.Equal(t, "Test Vuln", entry.VulnerabilityName)

	// Unknown CVE should return false.
	isKEV, _, err = client.IsKEV(ctx, "CVE-2024-9999")
	require.NoError(t, err)
	require.False(t, isKEV)

	// Second call should hit cache.
	_, _, err = client.IsKEV(ctx, "CVE-2024-0001")
	require.NoError(t, err)
	require.Equal(t, 1, requestCount)
}
