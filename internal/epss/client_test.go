package epss

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		c := NewClient()
		if c.baseURL != DefaultBaseURL {
			t.Errorf("expected baseURL %s, got %s", DefaultBaseURL, c.baseURL)
		}
		if c.maxRetries != DefaultMaxRetries {
			t.Errorf("expected maxRetries %d, got %d", DefaultMaxRetries, c.maxRetries)
		}
		if c.initialBackoff != DefaultInitialBackoff {
			t.Errorf("expected initialBackoff %v, got %v", DefaultInitialBackoff, c.initialBackoff)
		}
	})

	t.Run("with options", func(t *testing.T) {
		customURL := "https://custom.example.com/epss"
		c := NewClient(
			WithBaseURL(customURL),
			WithMaxRetries(5),
			WithBackoff(2*time.Second, 1*time.Minute),
			WithCacheTTL(1*time.Hour),
		)
		if c.baseURL != customURL {
			t.Errorf("expected baseURL %s, got %s", customURL, c.baseURL)
		}
		if c.maxRetries != 5 {
			t.Errorf("expected maxRetries 5, got %d", c.maxRetries)
		}
		if c.initialBackoff != 2*time.Second {
			t.Errorf("expected initialBackoff 2s, got %v", c.initialBackoff)
		}
		if c.maxBackoff != 1*time.Minute {
			t.Errorf("expected maxBackoff 1m, got %v", c.maxBackoff)
		}
		if c.cacheTTL != 1*time.Hour {
			t.Errorf("expected cacheTTL 1h, got %v", c.cacheTTL)
		}
	})
}

func TestGetScores(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		c := NewClient()
		scores, err := c.GetScores(context.Background(), []string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(scores) != 0 {
			t.Errorf("expected empty map, got %d entries", len(scores))
		}
	})

	t.Run("successful fetch", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cves := r.URL.Query().Get("cve")
			cveList := strings.Split(cves, ",")

			data := make([]Score, 0, len(cveList))
			for _, cve := range cveList {
				data = append(data, Score{
					CVE:        cve,
					EPSS:       0.5,
					Percentile: 0.75,
					Date:       "2024-01-15",
				})
			}

			resp := apiResponse{
				Status:     "OK",
				StatusCode: 200,
				Total:      len(data),
				Data:       data,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		c := NewClient(
			WithBaseURL(server.URL),
			WithCacheTTL(0), // Disable caching
		)

		cves := []string{"CVE-2023-1234", "CVE-2023-5678"}
		scores, err := c.GetScores(context.Background(), cves)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(scores) != 2 {
			t.Errorf("expected 2 scores, got %d", len(scores))
		}
		for _, cve := range cves {
			if _, ok := scores[cve]; !ok {
				t.Errorf("missing score for %s", cve)
			}
		}
	})

	t.Run("deduplication", func(t *testing.T) {
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			cves := r.URL.Query().Get("cve")
			cveList := strings.Split(cves, ",")

			// Should only have 2 unique CVEs
			if len(cveList) != 2 {
				t.Errorf("expected 2 CVEs in request, got %d", len(cveList))
			}

			data := make([]Score, 0, len(cveList))
			for _, cve := range cveList {
				data = append(data, Score{
					CVE:        cve,
					EPSS:       0.5,
					Percentile: 0.75,
					Date:       "2024-01-15",
				})
			}

			resp := apiResponse{
				Status:     "OK",
				StatusCode: 200,
				Total:      len(data),
				Data:       data,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		c := NewClient(
			WithBaseURL(server.URL),
			WithCacheTTL(0),
		)

		// Duplicate CVEs with different cases
		cves := []string{"CVE-2023-1234", "cve-2023-1234", "CVE-2023-5678", "CVE-2023-5678"}
		scores, err := c.GetScores(context.Background(), cves)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(scores) != 2 {
			t.Errorf("expected 2 unique scores, got %d", len(scores))
		}
		if requestCount != 1 {
			t.Errorf("expected 1 request, got %d", requestCount)
		}
	})

	t.Run("batching large requests", func(t *testing.T) {
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			cves := r.URL.Query().Get("cve")
			cveList := strings.Split(cves, ",")

			// Each batch should have at most MaxBatchSize CVEs
			if len(cveList) > MaxBatchSize {
				t.Errorf("batch size %d exceeds maximum %d", len(cveList), MaxBatchSize)
			}

			data := make([]Score, 0, len(cveList))
			for _, cve := range cveList {
				data = append(data, Score{
					CVE:        cve,
					EPSS:       0.5,
					Percentile: 0.75,
					Date:       "2024-01-15",
				})
			}

			resp := apiResponse{
				Status:     "OK",
				StatusCode: 200,
				Total:      len(data),
				Data:       data,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		c := NewClient(
			WithBaseURL(server.URL),
			WithCacheTTL(0),
		)

		// Generate 250 unique CVEs (should require 3 batches)
		cves := make([]string, 250)
		for i := 0; i < 250; i++ {
			cves[i] = "CVE-2023-" + strings.Repeat("0", 4-len(string(rune('0'+i%10)))) + string(rune('0'+i%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i/100%10)) + string(rune('0'+i/1000%10))
		}
		// Simplify: just use incrementing numbers
		for i := 0; i < 250; i++ {
			cves[i] = "CVE-2023-" + padInt(i, 4)
		}

		scores, err := c.GetScores(context.Background(), cves)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(scores) != 250 {
			t.Errorf("expected 250 scores, got %d", len(scores))
		}
		// 250 CVEs / 100 per batch = 3 batches
		if requestCount != 3 {
			t.Errorf("expected 3 requests, got %d", requestCount)
		}
	})
}

func padInt(n, width int) string {
	s := ""
	for i := 0; i < width; i++ {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestGetScore(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := apiResponse{
				Status:     "OK",
				StatusCode: 200,
				Total:      1,
				Data: []Score{
					{CVE: "CVE-2023-1234", EPSS: 0.85, Percentile: 0.95, Date: "2024-01-15"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		c := NewClient(WithBaseURL(server.URL), WithCacheTTL(0))
		score, err := c.GetScore(context.Background(), "CVE-2023-1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if score.EPSS != 0.85 {
			t.Errorf("expected EPSS 0.85, got %f", score.EPSS)
		}
		if score.Percentile != 0.95 {
			t.Errorf("expected Percentile 0.95, got %f", score.Percentile)
		}
	})

	t.Run("not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := apiResponse{
				Status:     "OK",
				StatusCode: 200,
				Total:      0,
				Data:       []Score{},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		c := NewClient(WithBaseURL(server.URL), WithCacheTTL(0))
		_, err := c.GetScore(context.Background(), "CVE-2023-9999")
		if err == nil {
			t.Fatal("expected error for missing CVE")
		}
		if !strings.Contains(err.Error(), "no EPSS score found") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

func TestCaching(t *testing.T) {
	t.Run("cache hit", func(t *testing.T) {
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			resp := apiResponse{
				Status:     "OK",
				StatusCode: 200,
				Total:      1,
				Data: []Score{
					{CVE: "CVE-2023-1234", EPSS: 0.5, Percentile: 0.75, Date: "2024-01-15"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		c := NewClient(
			WithBaseURL(server.URL),
			WithCacheTTL(1*time.Hour),
		)

		// First request - should hit API
		_, err := c.GetScore(context.Background(), "CVE-2023-1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if requestCount != 1 {
			t.Errorf("expected 1 request after first call, got %d", requestCount)
		}

		// Second request - should use cache
		_, err = c.GetScore(context.Background(), "CVE-2023-1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if requestCount != 1 {
			t.Errorf("expected 1 request after second call (cached), got %d", requestCount)
		}

		if c.CacheSize() != 1 {
			t.Errorf("expected cache size 1, got %d", c.CacheSize())
		}
	})

	t.Run("cache disabled", func(t *testing.T) {
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			resp := apiResponse{
				Status:     "OK",
				StatusCode: 200,
				Total:      1,
				Data: []Score{
					{CVE: "CVE-2023-1234", EPSS: 0.5, Percentile: 0.75, Date: "2024-01-15"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		c := NewClient(
			WithBaseURL(server.URL),
			WithCacheTTL(0), // Disable cache
		)

		// First request
		_, err := c.GetScore(context.Background(), "CVE-2023-1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Second request - should hit API again
		_, err = c.GetScore(context.Background(), "CVE-2023-1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if requestCount != 2 {
			t.Errorf("expected 2 requests with cache disabled, got %d", requestCount)
		}
	})

	t.Run("clear cache", func(t *testing.T) {
		c := NewClient(WithCacheTTL(1 * time.Hour))
		c.PreloadCache([]Score{
			{CVE: "CVE-2023-1234", EPSS: 0.5, Percentile: 0.75},
			{CVE: "CVE-2023-5678", EPSS: 0.3, Percentile: 0.50},
		})

		if c.CacheSize() != 2 {
			t.Errorf("expected cache size 2 after preload, got %d", c.CacheSize())
		}

		c.ClearCache()

		if c.CacheSize() != 0 {
			t.Errorf("expected cache size 0 after clear, got %d", c.CacheSize())
		}
	})
}

func TestPreloadCache(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		resp := apiResponse{
			Status:     "OK",
			StatusCode: 200,
			Total:      0,
			Data:       []Score{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewClient(
		WithBaseURL(server.URL),
		WithCacheTTL(1*time.Hour),
	)

	// Preload cache
	c.PreloadCache([]Score{
		{CVE: "CVE-2023-1234", EPSS: 0.5, Percentile: 0.75, Date: "2024-01-15"},
	})

	// Request should use preloaded cache
	score, err := c.GetScore(context.Background(), "CVE-2023-1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if score.EPSS != 0.5 {
		t.Errorf("expected EPSS 0.5, got %f", score.EPSS)
	}
	if requestCount != 0 {
		t.Errorf("expected no API requests with preloaded cache, got %d", requestCount)
	}
}

func TestRetry(t *testing.T) {
	t.Run("retry on server error", func(t *testing.T) {
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			if requestCount < 3 {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("server error"))
				return
			}
			resp := apiResponse{
				Status:     "OK",
				StatusCode: 200,
				Total:      1,
				Data: []Score{
					{CVE: "CVE-2023-1234", EPSS: 0.5, Percentile: 0.75, Date: "2024-01-15"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		c := NewClient(
			WithBaseURL(server.URL),
			WithMaxRetries(3),
			WithBackoff(1*time.Millisecond, 10*time.Millisecond), // Fast backoff for tests
			WithCacheTTL(0),
		)

		score, err := c.GetScore(context.Background(), "CVE-2023-1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if score.EPSS != 0.5 {
			t.Errorf("expected EPSS 0.5, got %f", score.EPSS)
		}
		if requestCount != 3 {
			t.Errorf("expected 3 requests (2 retries), got %d", requestCount)
		}
	})

	t.Run("max retries exceeded", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
		}))
		defer server.Close()

		c := NewClient(
			WithBaseURL(server.URL),
			WithMaxRetries(2),
			WithBackoff(1*time.Millisecond, 10*time.Millisecond),
			WithCacheTTL(0),
		)

		_, err := c.GetScore(context.Background(), "CVE-2023-1234")
		if err == nil {
			t.Fatal("expected error after max retries")
		}
		if !strings.Contains(err.Error(), "all 3 attempts failed") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		resp := apiResponse{
			Status:     "OK",
			StatusCode: 200,
			Total:      1,
			Data: []Score{
				{CVE: "CVE-2023-1234", EPSS: 0.5, Percentile: 0.75, Date: "2024-01-15"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewClient(
		WithBaseURL(server.URL),
		WithCacheTTL(0),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := c.GetScore(ctx, "CVE-2023-1234")
	if err == nil {
		t.Fatal("expected error on context cancellation")
	}
	if ctx.Err() == nil {
		t.Error("expected context to be cancelled")
	}
}
