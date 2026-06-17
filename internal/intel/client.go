package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kennedy-aikohi/jigphish/internal/config"
	"github.com/kennedy-aikohi/jigphish/internal/model"
)

type Options struct {
	Timeout   time.Duration
	UserAgent string
}

type Client struct {
	keys       config.APIKeys
	httpClient *http.Client
	userAgent  string
}

func NewClient(keys config.APIKeys, opts Options) *Client {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 12 * time.Second
	}
	return &Client{
		keys:       keys,
		httpClient: &http.Client{Timeout: timeout},
		userAgent:  opts.UserAgent,
	}
}

// Enrich runs all configured OSINT lookups concurrently for:
//   - Attachment SHA-256 hashes (VT, Hybrid Analysis)
//   - URL domains and full URLs (VT domain, VT URL, AbuseIPDB if IP, urlscan.io)
//   - Routing hop IPs from the Received chain (VT IP, AbuseIPDB, urlscan.io page.ip)
func (c *Client) Enrich(ctx context.Context, result *model.AnalysisResult) {
	var wg sync.WaitGroup
	var mu sync.Mutex

	add := func(entries []model.ReputationEntry) {
		mu.Lock()
		result.ThreatIntel.Lookups = append(result.ThreatIntel.Lookups, entries...)
		mu.Unlock()
	}
	skip := func(reason string) {
		mu.Lock()
		result.ThreatIntel.SkippedReason = append(result.ThreatIntel.SkippedReason, reason)
		mu.Unlock()
	}

	// ── Attachment hashes ────────────────────────────────────────────────────
	for i := range result.Attachments {
		idx := i
		sha256 := result.Attachments[idx].SHA256
		if sha256 == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			entries := c.lookupHash(ctx, sha256)
			mu.Lock()
			result.Attachments[idx].Intel = append(result.Attachments[idx].Intel, entries...)
			result.ThreatIntel.Lookups = append(result.ThreatIntel.Lookups, entries...)
			mu.Unlock()
		}()
	}

	// ── URL domains + full URLs ──────────────────────────────────────────────
	// Deduplicate by domain so the same domain is only queried once.
	// The first URL encountered for a domain is also checked at the URL level
	// (VT URL endpoint), which gives per-path reputation beyond the domain report.
	seenDomains := map[string]struct{}{}
	for i := range result.URLs {
		idx := i
		domain := result.URLs[idx].Domain
		fullURL := result.URLs[idx].Normalized
		if domain == "" {
			continue
		}
		if _, ok := seenDomains[domain]; ok {
			continue
		}
		seenDomains[domain] = struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			entries := c.lookupURLIndicator(ctx, domain, fullURL)
			mu.Lock()
			result.URLs[idx].Intel = append(result.URLs[idx].Intel, entries...)
			result.ThreatIntel.Lookups = append(result.ThreatIntel.Lookups, entries...)
			mu.Unlock()
		}()
	}

	// ── Routing hop IPs ──────────────────────────────────────────────────────
	// Every public IP seen in the Received chain is checked against VT IP,
	// AbuseIPDB, and urlscan.io (page.ip query). Results are attached to the
	// hop for display in the Routing tab and also added to the global lookups.
	seenIPs := map[string]struct{}{}
	for i := range result.ReceivedChain {
		idx := i
		ip := result.ReceivedChain[idx].IP
		if ip == "" {
			continue
		}
		if _, ok := seenIPs[ip]; ok {
			continue
		}
		seenIPs[ip] = struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			entries := c.lookupIP(ctx, ip)
			mu.Lock()
			result.ReceivedChain[idx].Intel = append(result.ReceivedChain[idx].Intel, entries...)
			result.ThreatIntel.Lookups = append(result.ThreatIntel.Lookups, entries...)
			mu.Unlock()
		}()
	}

	// Record which providers are unconfigured.
	if c.keys.VirusTotal == "" {
		skip("VirusTotal disabled: no API key configured")
	}
	if c.keys.HybridAnalysis == "" {
		skip("Hybrid Analysis disabled: no API key configured")
	}
	if c.keys.AbuseIPDB == "" {
		skip("AbuseIPDB disabled: no API key configured")
	}
	if c.keys.Urlscan == "" {
		skip("urlscan.io disabled: no API key configured")
	}

	wg.Wait()

	// Fold intel hits back into the MCI risk score.
	for _, entry := range result.ThreatIntel.Lookups {
		if entry.Found && entry.Score > 0 {
			result.Risk.Score += entry.Score / 5
			result.Risk.Reasons = append(result.Risk.Reasons,
				fmt.Sprintf("%s flagged %s (%s)", entry.Provider, entry.Indicator, entry.Type))
		}
	}
	if result.Risk.Score > 100 {
		result.Risk.Score = 100
	}
	if result.Risk.Score >= 75 {
		result.Risk.Level = "Critical"
	} else if result.Risk.Score >= 50 {
		result.Risk.Level = "High"
	} else if result.Risk.Score >= 25 {
		result.Risk.Level = "Medium"
	}
	_ = add // suppress unused if no callers remain
}

// lookupHash checks a file SHA-256 against VT and Hybrid Analysis.
func (c *Client) lookupHash(ctx context.Context, sha256 string) []model.ReputationEntry {
	var entries []model.ReputationEntry
	if c.keys.VirusTotal != "" {
		entries = append(entries, c.virusTotalFileHash(ctx, sha256))
	}
	if c.keys.HybridAnalysis != "" {
		entries = append(entries, c.hybridAnalysisHash(ctx, sha256))
	}
	return entries
}

// lookupURLIndicator checks a URL's domain and the full URL path separately.
// When the domain is a bare IP, the VT IP endpoint is used instead of the
// domain endpoint (they are different resources in the VT API).
func (c *Client) lookupURLIndicator(ctx context.Context, domain, fullURL string) []model.ReputationEntry {
	var entries []model.ReputationEntry
	isIP := net.ParseIP(domain) != nil
	if c.keys.VirusTotal != "" {
		if isIP {
			entries = append(entries, c.virusTotalIP(ctx, domain))
		} else {
			entries = append(entries, c.virusTotalDomain(ctx, domain))
		}
		if fullURL != "" {
			entries = append(entries, c.virusTotalURL(ctx, fullURL))
		}
	}
	if c.keys.AbuseIPDB != "" && isIP {
		entries = append(entries, c.abuseIPDB(ctx, domain))
	}
	if c.keys.Urlscan != "" {
		entries = append(entries, c.urlscanSearch(ctx, domain))
	}
	return entries
}

// lookupIP checks a routing hop IP against VT IP, AbuseIPDB, and urlscan.io.
func (c *Client) lookupIP(ctx context.Context, ip string) []model.ReputationEntry {
	var entries []model.ReputationEntry
	if c.keys.VirusTotal != "" {
		entries = append(entries, c.virusTotalIP(ctx, ip))
	}
	if c.keys.AbuseIPDB != "" {
		entries = append(entries, c.abuseIPDB(ctx, ip))
	}
	if c.keys.Urlscan != "" {
		entries = append(entries, c.urlscanIPSearch(ctx, ip))
	}
	return entries
}

func (c *Client) requestJSON(ctx context.Context, method, endpoint string, headers map[string]string, into any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return err
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("rate limited by provider (HTTP 429)")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("provider returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

var errNotFound = fmt.Errorf("indicator not found")

func severityFromScore(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 40:
		return "high"
	case score >= 15:
		return "medium"
	default:
		return "informational"
	}
}

func nowEntry(provider, indicator, typ string) model.ReputationEntry {
	return model.ReputationEntry{
		Provider:  provider,
		Indicator: indicator,
		Type:      typ,
		CheckedAt: time.Now().UTC(),
	}
}

func escapePathPart(v string) string {
	return url.PathEscape(strings.TrimSpace(v))
}
