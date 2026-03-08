// Package epss provides a client for the FIRST EPSS API.
// It supports batch requests, exponential backoff, and caching.
package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultBaseURL is the EPSS API base URL.
	DefaultBaseURL = "https://api.first.org/data/v1/epss"

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 30 * time.Second

	// MaxBatchSize is the maximum number of CVEs per API request.
	MaxBatchSize = 100

	// DefaultMaxRetries is the default number of retry attempts.
	DefaultMaxRetries = 3

	// DefaultInitialBackoff is the initial backoff duration for retries.
	DefaultInitialBackoff = 1 * time.Second

	// DefaultMaxBackoff is the maximum backoff duration.
	DefaultMaxBackoff = 30 * time.Second
)

// Score represents an EPSS score for a CVE.
type Score struct {
	CVE        string    `json:"cve"`
	EPSS       float64   `json:"epss,string"`
	Percentile float64   `json:"percentile,string"`
	Date       string    `json:"date"`
	FetchedAt  time.Time `json:"-"`
}

// apiResponse represents the EPSS API response structure.
type apiResponse struct {
	Status     string  `json:"status"`
	StatusCode int     `json:"status-code"`
	Version    string  `json:"version"`
	Total      int     `json:"total"`
	Offset     int     `json:"offset"`
	Limit      int     `json:"limit"`
	Data       []Score `json:"data"`
}

// Client is an EPSS API client with batching and caching support.
type Client struct {
	baseURL        string
	httpClient     *http.Client
	logger         *slog.Logger
	maxRetries     int
	initialBackoff time.Duration
	maxBackoff     time.Duration

	// Cache for EPSS scores
	cache    map[string]Score
	cacheMu  sync.RWMutex
	cacheTTL time.Duration
}

// Option is a functional option for configuring the Client.
type Option func(*Client)

// WithBaseURL sets a custom base URL for the API.
func WithBaseURL(url string) Option {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) {
		c.logger = logger
	}
}

// WithMaxRetries sets the maximum number of retry attempts.
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		c.maxRetries = n
	}
}

// WithBackoff sets the initial and maximum backoff durations.
func WithBackoff(initial, max time.Duration) Option {
	return func(c *Client) {
		c.initialBackoff = initial
		c.maxBackoff = max
	}
}

// WithCacheTTL sets the cache time-to-live duration.
// Set to 0 to disable caching.
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *Client) {
		c.cacheTTL = ttl
	}
}

// NewClient creates a new EPSS API client.
func NewClient(opts ...Option) *Client {
	c := &Client{
		baseURL: DefaultBaseURL,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		logger:         slog.Default(),
		maxRetries:     DefaultMaxRetries,
		initialBackoff: DefaultInitialBackoff,
		maxBackoff:     DefaultMaxBackoff,
		cache:          make(map[string]Score),
		cacheTTL:       24 * time.Hour, // Default: cache for 24 hours
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GetScores fetches EPSS scores for the given CVE IDs.
// It automatically batches requests if more than MaxBatchSize CVEs are provided.
// Results are cached according to the configured TTL.
func (c *Client) GetScores(ctx context.Context, cveIDs []string) (map[string]Score, error) {
	if len(cveIDs) == 0 {
		return make(map[string]Score), nil
	}

	// Deduplicate CVE IDs
	cveSet := make(map[string]struct{}, len(cveIDs))
	for _, id := range cveIDs {
		cveSet[strings.ToUpper(id)] = struct{}{}
	}

	uniqueCVEs := make([]string, 0, len(cveSet))
	for id := range cveSet {
		uniqueCVEs = append(uniqueCVEs, id)
	}

	results := make(map[string]Score, len(uniqueCVEs))
	var toFetch []string

	// Check cache first
	if c.cacheTTL > 0 {
		c.cacheMu.RLock()
		now := time.Now()
		for _, id := range uniqueCVEs {
			if score, ok := c.cache[id]; ok {
				if now.Sub(score.FetchedAt) < c.cacheTTL {
					results[id] = score
					continue
				}
			}
			toFetch = append(toFetch, id)
		}
		c.cacheMu.RUnlock()
	} else {
		toFetch = uniqueCVEs
	}

	if len(toFetch) == 0 {
		c.logger.Debug("all CVEs found in cache", "count", len(results))
		return results, nil
	}

	c.logger.Info("fetching EPSS scores",
		"total", len(uniqueCVEs),
		"cached", len(results),
		"to_fetch", len(toFetch))

	// Batch requests
	for i := 0; i < len(toFetch); i += MaxBatchSize {
		end := i + MaxBatchSize
		if end > len(toFetch) {
			end = len(toFetch)
		}
		batch := toFetch[i:end]

		scores, err := c.fetchBatch(ctx, batch)
		if err != nil {
			return nil, fmt.Errorf("fetching batch %d-%d: %w", i, end, err)
		}

		// Update results and cache
		c.cacheMu.Lock()
		for _, score := range scores {
			score.FetchedAt = time.Now()
			results[score.CVE] = score
			if c.cacheTTL > 0 {
				c.cache[score.CVE] = score
			}
		}
		c.cacheMu.Unlock()

		c.logger.Debug("batch completed",
			"batch_start", i,
			"batch_end", end,
			"scores_received", len(scores))
	}

	return results, nil
}

// GetScore fetches the EPSS score for a single CVE ID.
func (c *Client) GetScore(ctx context.Context, cveID string) (Score, error) {
	scores, err := c.GetScores(ctx, []string{cveID})
	if err != nil {
		return Score{}, err
	}

	cveID = strings.ToUpper(cveID)
	if score, ok := scores[cveID]; ok {
		return score, nil
	}

	return Score{}, fmt.Errorf("no EPSS score found for %s", cveID)
}

// fetchBatch fetches EPSS scores for a batch of CVEs with retry logic.
func (c *Client) fetchBatch(ctx context.Context, cveIDs []string) ([]Score, error) {
	if len(cveIDs) > MaxBatchSize {
		return nil, fmt.Errorf("batch size %d exceeds maximum %d", len(cveIDs), MaxBatchSize)
	}

	// Build URL with CVE parameter
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing base URL: %w", err)
	}

	q := u.Query()
	q.Set("cve", strings.Join(cveIDs, ","))
	u.RawQuery = q.Encode()

	var lastErr error
	backoff := c.initialBackoff

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			c.logger.Debug("retrying request",
				"attempt", attempt,
				"backoff", backoff,
				"url", u.String())

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}

			// Exponential backoff with cap
			backoff *= 2
			if backoff > c.maxBackoff {
				backoff = c.maxBackoff
			}
		}

		scores, err := c.doRequest(ctx, u.String())
		if err == nil {
			return scores, nil
		}

		lastErr = err
		c.logger.Warn("request failed",
			"attempt", attempt,
			"error", err)

		// Don't retry on context cancellation
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("all %d attempts failed: %w", c.maxRetries+1, lastErr)
}

// doRequest performs a single HTTP request to the EPSS API.
func (c *Client) doRequest(ctx context.Context, url string) ([]Score, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "CSVSA/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if apiResp.Status != "OK" {
		return nil, fmt.Errorf("API error: status=%s, code=%d", apiResp.Status, apiResp.StatusCode)
	}

	return apiResp.Data, nil
}

// ClearCache clears all cached EPSS scores.
func (c *Client) ClearCache() {
	c.cacheMu.Lock()
	c.cache = make(map[string]Score)
	c.cacheMu.Unlock()
	c.logger.Debug("cache cleared")
}

// CacheSize returns the number of cached EPSS scores.
func (c *Client) CacheSize() int {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	return len(c.cache)
}

// PreloadCache loads scores into the cache from an external source.
// This is useful for initializing the cache from a database.
func (c *Client) PreloadCache(scores []Score) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	now := time.Now()
	for _, score := range scores {
		score.FetchedAt = now
		c.cache[score.CVE] = score
	}

	c.logger.Debug("cache preloaded", "count", len(scores))
}
