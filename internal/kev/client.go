package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	KEVURL         = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultTimeout = 15 * time.Second
	CacheTTL       = 24 * time.Hour
)

type Entry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	Notes             string `json:"notes"`
}

type catalog struct {
	Title           string  `json:"title"`
	CatalogVersion  string  `json:"catalogVersion"`
	DateReleased    string  `json:"dateReleased"`
	Count           int     `json:"count"`
	Vulnerabilities []Entry `json:"vulnerabilities"`
}

type Client struct {
	baseURL    string
	mu         sync.RWMutex
	index      map[string]Entry
	fetchedAt  time.Time
	httpClient *http.Client
}

// Option configures the KEV client.
type Option func(*Client)

// WithBaseURL overrides the KEV catalog URL (useful for tests).
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

func NewClient(opts ...Option) *Client {
	client := &Client{
		baseURL:    KEVURL,
		httpClient: &http.Client{Timeout: DefaultTimeout},
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

func (c *Client) IsKEV(ctx context.Context, cveID string) (bool, Entry, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return false, Entry{}, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, found := c.index[cveID]
	return found, entry, nil
}

func (c *Client) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.index)
}

func (c *Client) ensureLoaded(ctx context.Context) error {
	c.mu.RLock()
	fresh := c.index != nil && time.Since(c.fetchedAt) < CacheTTL
	c.mu.RUnlock()

	if fresh {
		return nil
	}

	return c.fetch(ctx)
}

func (c *Client) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL, nil)
	if err != nil {
		return fmt.Errorf("kev: creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("kev: fetching catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kev: unexpected status %d", resp.StatusCode)
	}

	var cat catalog
	if err := json.NewDecoder(resp.Body).Decode(&cat); err != nil {
		return fmt.Errorf("kev: decoding catalog: %w", err)
	}

	index := make(map[string]Entry, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		index[v.CVEID] = v
	}

	c.mu.Lock()
	c.index = index
	c.fetchedAt = time.Now()
	c.mu.Unlock()

	return nil
}