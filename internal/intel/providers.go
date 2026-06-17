package intel

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennedy-aikohi/jigphish/internal/model"
)

// vtResponse is shared by the VT files, domains, ip_addresses and urls endpoints
// — they all return last_analysis_stats and a self link under the same shape.
type vtResponse struct {
	Data struct {
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

// ── VirusTotal ─────────────────────────────────────────────────────────────────

func (c *Client) virusTotalFileHash(ctx context.Context, sha256 string) model.ReputationEntry {
	entry := nowEntry("VirusTotal", sha256, "sha256")
	var out vtResponse
	err := c.requestJSON(ctx, http.MethodGet, "https://www.virustotal.com/api/v3/files/"+escapePathPart(sha256),
		map[string]string{"x-apikey": c.keys.VirusTotal}, &out)
	if err != nil {
		entry.Message = err.Error()
		entry.Found = !errors.Is(err, errNotFound)
		return entry
	}
	mal := out.Data.Attributes.LastAnalysisStats.Malicious
	sus := out.Data.Attributes.LastAnalysisStats.Suspicious
	entry.Found = true
	entry.Score = mal*20 + sus*10
	entry.Severity = severityFromScore(entry.Score)
	entry.Reference = out.Data.Links.Self
	entry.Message = fmt.Sprintf("%d malicious, %d suspicious detections", mal, sus)
	return entry
}

func (c *Client) virusTotalDomain(ctx context.Context, domain string) model.ReputationEntry {
	entry := nowEntry("VirusTotal", domain, "domain")
	var out vtResponse
	err := c.requestJSON(ctx, http.MethodGet, "https://www.virustotal.com/api/v3/domains/"+escapePathPart(domain),
		map[string]string{"x-apikey": c.keys.VirusTotal}, &out)
	if err != nil {
		entry.Message = err.Error()
		entry.Found = !errors.Is(err, errNotFound)
		return entry
	}
	mal := out.Data.Attributes.LastAnalysisStats.Malicious
	sus := out.Data.Attributes.LastAnalysisStats.Suspicious
	entry.Found = true
	entry.Score = mal*18 + sus*8
	entry.Severity = severityFromScore(entry.Score)
	entry.Reference = out.Data.Links.Self
	entry.Message = fmt.Sprintf("%d malicious, %d suspicious domain detections", mal, sus)
	return entry
}

// virusTotalIP calls the /api/v3/ip_addresses/{ip} endpoint — distinct from the
// domain endpoint. Calling the domain endpoint with an IP returns a 404 or wrong data.
func (c *Client) virusTotalIP(ctx context.Context, ip string) model.ReputationEntry {
	entry := nowEntry("VirusTotal", ip, "ip")
	var out vtResponse
	err := c.requestJSON(ctx, http.MethodGet, "https://www.virustotal.com/api/v3/ip_addresses/"+escapePathPart(ip),
		map[string]string{"x-apikey": c.keys.VirusTotal}, &out)
	if err != nil {
		entry.Message = err.Error()
		entry.Found = !errors.Is(err, errNotFound)
		return entry
	}
	mal := out.Data.Attributes.LastAnalysisStats.Malicious
	sus := out.Data.Attributes.LastAnalysisStats.Suspicious
	entry.Found = true
	entry.Score = mal*20 + sus*10
	entry.Severity = severityFromScore(entry.Score)
	entry.Reference = out.Data.Links.Self
	entry.Message = fmt.Sprintf("%d malicious, %d suspicious IP detections", mal, sus)
	return entry
}

// virusTotalURL calls the /api/v3/urls/{id} endpoint where id is the
// base64url-encoded URL (no padding). This gives per-path reputation distinct
// from the domain-level check — critical for phishing URLs that share a domain.
func (c *Client) virusTotalURL(ctx context.Context, rawURL string) model.ReputationEntry {
	entry := nowEntry("VirusTotal", rawURL, "url")
	id := base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(rawURL)))
	var out vtResponse
	err := c.requestJSON(ctx, http.MethodGet, "https://www.virustotal.com/api/v3/urls/"+id,
		map[string]string{"x-apikey": c.keys.VirusTotal}, &out)
	if err != nil {
		entry.Message = err.Error()
		entry.Found = !errors.Is(err, errNotFound)
		return entry
	}
	mal := out.Data.Attributes.LastAnalysisStats.Malicious
	sus := out.Data.Attributes.LastAnalysisStats.Suspicious
	entry.Found = true
	entry.Score = mal*20 + sus*10
	entry.Severity = severityFromScore(entry.Score)
	entry.Reference = out.Data.Links.Self
	entry.Message = fmt.Sprintf("%d malicious, %d suspicious URL detections", mal, sus)
	return entry
}

// ── Hybrid Analysis ───────────────────────────────────────────────────────────

type hybridResponse struct {
	SHA256      string `json:"sha256"`
	Verdict     string `json:"verdict"`
	ThreatScore int    `json:"threat_score"`
	AnalysisURL string `json:"analysis_url"`
}

func (c *Client) hybridAnalysisHash(ctx context.Context, sha256 string) model.ReputationEntry {
	entry := nowEntry("Hybrid Analysis", sha256, "sha256")
	var out hybridResponse
	err := c.requestJSON(ctx, http.MethodGet, "https://www.hybrid-analysis.com/api/v2/overview/"+escapePathPart(sha256),
		map[string]string{"api-key": c.keys.HybridAnalysis, "accept": "application/json"}, &out)
	if err != nil {
		entry.Message = err.Error()
		entry.Found = !errors.Is(err, errNotFound)
		return entry
	}
	entry.Found = true
	entry.Score = out.ThreatScore
	entry.Severity = severityFromScore(entry.Score)
	entry.Reference = out.AnalysisURL
	entry.Message = out.Verdict
	return entry
}

// ── AbuseIPDB ─────────────────────────────────────────────────────────────────

type abuseResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		TotalReports         int    `json:"totalReports"`
		CountryCode          string `json:"countryCode"`
		ISP                  string `json:"isp"`
	} `json:"data"`
}

func (c *Client) abuseIPDB(ctx context.Context, ip string) model.ReputationEntry {
	entry := nowEntry("AbuseIPDB", ip, "ip")
	var out abuseResponse
	endpoint := "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=" + url.QueryEscape(ip)
	err := c.requestJSON(ctx, http.MethodGet, endpoint,
		map[string]string{"Key": c.keys.AbuseIPDB, "Accept": "application/json"}, &out)
	if err != nil {
		entry.Message = err.Error()
		entry.Found = !errors.Is(err, errNotFound)
		return entry
	}
	entry.Found = true
	entry.Score = out.Data.AbuseConfidenceScore
	entry.Severity = severityFromScore(entry.Score)
	isp := out.Data.ISP
	if isp == "" {
		isp = out.Data.CountryCode
	}
	entry.Message = fmt.Sprintf("%d reports (confidence %d%%) — %s", out.Data.TotalReports, out.Data.AbuseConfidenceScore, isp)
	return entry
}

// ── urlscan.io ────────────────────────────────────────────────────────────────

type urlscanResponse struct {
	Total   int `json:"total"`
	Results []struct {
		Result string `json:"result"`
		Stats  struct {
			Malicious int `json:"malicious"`
		} `json:"stats"`
	} `json:"results"`
}

func (c *Client) urlscanSearch(ctx context.Context, domain string) model.ReputationEntry {
	entry := nowEntry("urlscan.io", domain, "domain")
	var out urlscanResponse
	endpoint := "https://urlscan.io/api/v1/search/?q=domain:" + url.QueryEscape(domain) + "&size=5"
	err := c.requestJSON(ctx, http.MethodGet, endpoint,
		map[string]string{"API-Key": c.keys.Urlscan}, &out)
	if err != nil {
		entry.Message = err.Error()
		entry.Found = !errors.Is(err, errNotFound)
		return entry
	}
	entry.Found = out.Total > 0
	malCount := 0
	for _, r := range out.Results {
		malCount += r.Stats.Malicious
	}
	if malCount > 0 && len(out.Results) > 0 {
		entry.Score = min(malCount*25, 100)
		entry.Reference = out.Results[0].Result
	}
	entry.Severity = severityFromScore(entry.Score)
	entry.Message = fmt.Sprintf("%d historical scans (%d malicious pages)", out.Total, malCount)
	return entry
}

// urlscanIPSearch queries urlscan.io for pages served from a specific IP.
func (c *Client) urlscanIPSearch(ctx context.Context, ip string) model.ReputationEntry {
	entry := nowEntry("urlscan.io", ip, "ip")
	var out urlscanResponse
	endpoint := "https://urlscan.io/api/v1/search/?q=page.ip:" + url.QueryEscape(ip) + "&size=5"
	err := c.requestJSON(ctx, http.MethodGet, endpoint,
		map[string]string{"API-Key": c.keys.Urlscan}, &out)
	if err != nil {
		entry.Message = err.Error()
		entry.Found = !errors.Is(err, errNotFound)
		return entry
	}
	entry.Found = out.Total > 0
	malCount := 0
	for _, r := range out.Results {
		malCount += r.Stats.Malicious
	}
	if malCount > 0 && len(out.Results) > 0 {
		entry.Score = min(malCount*25, 100)
		entry.Reference = out.Results[0].Result
	}
	entry.Severity = severityFromScore(entry.Score)
	entry.Message = fmt.Sprintf("%d pages hosted on IP (%d malicious)", out.Total, malCount)
	return entry
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
