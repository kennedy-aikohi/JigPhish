package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// knownHighRiskASNs maps AS numbers to descriptive reasons.
// These networks are associated with bulletproof hosting, spam infrastructure,
// or persistent high-abuse activity documented by threat intelligence feeds.
var knownHighRiskASNs = map[string]string{
	"AS49981":  "WorldStream B.V. — documented bulletproof hosting",
	"AS9009":   "M247 Europe SRL — frequently used by spam/malware operators",
	"AS62744":  "ASTEN TECHNOLOGIES — bulletproof hosting",
	"AS398355": "Frantech Solutions (BuyVM) — bulletproof hosting",
	"AS53667":  "Frantech Solutions — bulletproof hosting",
	"AS48721":  "FLP VOLIA — Eastern European high-abuse ISP",
	"AS206728": "Media Land LLC — documented bulletproof hosting",
	"AS59796":  "Starry Network Ltd — high-abuse ASN",
	"AS202425": "IP Volume Inc — spam/phishing hosting",
	"AS36352":  "ColoCrossing — high-abuse VPS provider",
	"AS51396":  "Pfcloud UG — bulletproof hosting",
	"AS35913":  "dhosting die Rackspace GmbH — abused for spam",
	"AS30083":  "LiquidWeb LLC — high-volume abuse",
	"AS394711": "Limenet — frequently used by phishing operators",
}

type ipAPIResponse struct {
	Country string  `json:"country"`
	City    string  `json:"city"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	AS      string  `json:"as"`
	Org     string  `json:"org"`
	Status  string  `json:"status"`
}

type asnLookupClient struct {
	http *http.Client
}

func newASNClient() *asnLookupClient {
	return &asnLookupClient{
		http: &http.Client{Timeout: 5 * time.Second},
	}
}

// Lookup queries ip-api.com for geolocation and ASN metadata for a single IP.
// Returns zero values on any failure; analysis always continues regardless.
func (c *asnLookupClient) Lookup(ctx context.Context, ip string) (country, city, asn, org string, bulletproof bool, asnReason string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://ip-api.com/json/%s?fields=country,city,lat,lon,as,org,status", ip), nil)
	if err != nil {
		return
	}
	resp, err := c.http.Do(req)
	if err != nil || resp == nil {
		return
	}
	defer resp.Body.Close()

	var out ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Status != "success" {
		return
	}

	country = out.Country
	city = out.City
	org = out.Org
	asn = extractASNumber(out.AS)

	if reason, ok := knownHighRiskASNs[asn]; ok {
		bulletproof = true
		asnReason = reason
	}
	return
}

// extractASNumber extracts the ASN token from ip-api.com's "as" field,
// e.g. "AS13335 Cloudflare, Inc." → "AS13335".
func extractASNumber(as string) string {
	if idx := strings.Index(as, " "); idx > 0 {
		return as[:idx]
	}
	return as
}
