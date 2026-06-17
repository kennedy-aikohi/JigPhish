package parser

import (
	"fmt"
	"net"
	netmail "net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/emersion/go-message"
	"github.com/kennedy-aikohi/jigphish/internal/model"
	"golang.org/x/net/publicsuffix"
)

var (
	receivedIPPattern   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	receivedFromPattern = regexp.MustCompile(`(?i)\bfrom\s+([^\s;\(\)]+)`)
	receivedByPattern   = regexp.MustCompile(`(?i)\bby\s+([^\s;\(\)]+)`)
)

// parseReceivedChain extracts and annotates every Received: hop in document
// order (topmost = most recent).
func (p *Parser) parseReceivedChain(h message.Header) []model.ReceivedHop {
	values := headerValues(h, "Received")
	hops := make([]model.ReceivedHop, 0, len(values))
	var prior time.Time
	for i, raw := range values {
		hop := model.ReceivedHop{Index: i + 1, Raw: decodeHeader(raw)}
		if m := receivedFromPattern.FindStringSubmatch(raw); len(m) == 2 {
			hop.FromHost = strings.Trim(m[1], "[]")
		}
		if m := receivedByPattern.FindStringSubmatch(raw); len(m) == 2 {
			hop.ByHost = strings.Trim(m[1], "[]")
		}
		if ip := firstPublicIP(raw); ip != "" {
			hop.IP = ip
			hop.Geo = p.geoIP.Lookup(ip)
		}
		if idx := strings.LastIndex(raw, ";"); idx >= 0 {
			if ts, err := netmail.ParseDate(strings.TrimSpace(raw[idx+1:])); err == nil {
				hop.Timestamp = ts.UTC()
				if !prior.IsZero() {
					hop.DeltaFromPrior = prior.Sub(hop.Timestamp)
					if hop.DeltaFromPrior < 0 {
						hop.Anomalies = append(hop.Anomalies, "timestamp inversion in Received chain — possible header manipulation")
					}
				}
				prior = hop.Timestamp
			}
		}
		if hop.IP == "" {
			hop.Anomalies = append(hop.Anomalies, "no public IPv4 observable in this hop")
		}
		hops = append(hops, hop)
	}
	return hops
}

// firstPublicIP returns the first globally-routable IPv4 address found in raw.
func firstPublicIP(raw string) string {
	for _, candidate := range receivedIPPattern.FindAllString(raw, -1) {
		ip := net.ParseIP(candidate)
		if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		return candidate
	}
	return ""
}

// assessAuth evaluates SPF, DKIM, and DMARC authentication for the message
// using a structured, RFC 7601-compliant parser with a strict trust model.
func assessAuth(h message.Header) model.AuthAssessment {
	auth := model.AuthAssessment{
		FromDomain:       domainFromAddress(h.Get("From")),
		ReturnPathDomain: domainFromAddress(h.Get("Return-Path")),
	}

	// ── Parse Authentication-Results ─────────────────────────────────────────
	// TRUST MODEL: Only the FIRST (topmost/innermost) Authentication-Results
	// header is trusted — it was stamped by the receiving MTA that we control.
	// All subsequent headers were added by earlier relays or the originating
	// server (potentially the attacker) and are explicitly ignored per RFC 7601 §7.2.
	arValues := headerValues(h, "Authentication-Results")
	if len(arValues) > 0 {
		_, blocks := parseAuthResultsHeader(arValues[0])
		for _, b := range blocks {
			switch b.Method {
			case "spf":
				auth.SPFResult = b.Result
				// smtp.mailfrom is the authoritative envelope sender used by SPF
				// evaluation — prefer it over the Return-Path header.
				if mf := b.prop("smtp.mailfrom"); mf != "" {
					if d := domainFromAddress(mf); d != "" {
						auth.ReturnPathDomain = d
					}
				}

			case "dkim":
				auth.DKIMResult = b.Result
				// header.d is the DKIM signing domain (primary alignment target).
				if d := b.prop("header.d"); d != "" {
					auth.SigningDomains = appendUnique(auth.SigningDomains, strings.ToLower(d))
				}
				// header.i is the agent identifier "@domain" or "user@domain" form.
				if id := b.prop("header.i"); id != "" {
					if d := domainFromAddress(id); d != "" {
						auth.SigningDomains = appendUnique(auth.SigningDomains, d)
					}
				}

			case "dmarc":
				auth.DMARCResult = b.Result
			}
		}
	}

	// ── DKIM-Signature fallback ───────────────────────────────────────────────
	// When the trusted Authentication-Results header did not include header.d
	// (e.g. older MTAs), extract the signing domain directly from the
	// structured DKIM-Signature header using the RFC 6376 §3.5 tag parser.
	if len(auth.SigningDomains) == 0 {
		for _, raw := range headerValues(h, "DKIM-Signature") {
			if d, _, _ := parseDKIMSignatureHeader(raw); d != "" {
				auth.SigningDomains = appendUnique(auth.SigningDomains, d)
			}
		}
	}

	// ── Alignment ─────────────────────────────────────────────────────────────
	// SPF alignment (relaxed): envelope sender domain aligns with From domain
	// at the organizational domain level per RFC 7489 §3.1.1.
	auth.SPFAligned = auth.FromDomain != "" &&
		auth.ReturnPathDomain != "" &&
		sameOrganizationalDomain(auth.FromDomain, auth.ReturnPathDomain)

	// DKIM alignment (relaxed): at least one signing domain aligns with From.
	for _, d := range auth.SigningDomains {
		if sameOrganizationalDomain(auth.FromDomain, d) {
			auth.DKIMAligned = true
			break
		}
	}

	// DMARC alignment: defer to what the receiving MTA evaluated.
	// A "pass" result already implies identifier alignment was satisfied.
	auth.DMARCAligned = auth.DMARCResult == "pass"

	// ── Anomaly detection ─────────────────────────────────────────────────────

	// Return-Path / From misalignment (cross-domain spoofing indicator)
	if auth.FromDomain != "" && auth.ReturnPathDomain != "" && !auth.SPFAligned {
		auth.Anomalies = append(auth.Anomalies,
			fmt.Sprintf("Return-Path / envelope sender (%s) not aligned with visible From domain (%s) — potential cross-domain spoofing",
				auth.ReturnPathDomain, auth.FromDomain))
	}

	// DKIM passes but on a domain not aligned with From
	if auth.DKIMResult == "pass" && !auth.DKIMAligned {
		auth.Anomalies = append(auth.Anomalies,
			"DKIM passes but signing domain is not aligned with visible From domain — message may be a third-party relay or the From header is forged")
	}

	// Granular SPF anomalies
	switch auth.SPFResult {
	case "fail":
		auth.Anomalies = append(auth.Anomalies,
			"SPF hard fail — sending IP is explicitly unauthorized by the domain's SPF policy")
	case "softfail":
		auth.Anomalies = append(auth.Anomalies,
			"SPF softfail — sending IP is weakly unauthorized (~all); domain policy recommends rejection")
	case "permerror":
		auth.Anomalies = append(auth.Anomalies,
			"SPF permerror — the domain's SPF record has a permanent syntax or configuration error")
	case "temperror":
		auth.Anomalies = append(auth.Anomalies,
			"SPF temperror — a transient DNS lookup failure occurred during SPF evaluation")
	}

	// Granular DKIM anomalies
	switch auth.DKIMResult {
	case "fail":
		auth.Anomalies = append(auth.Anomalies,
			"DKIM fail — signature is present but cryptographically invalid (body modified or key mismatch)")
	case "permerror":
		auth.Anomalies = append(auth.Anomalies,
			"DKIM permerror — permanent error in DKIM signature or public key (likely malformed record)")
	case "temperror":
		auth.Anomalies = append(auth.Anomalies,
			"DKIM temperror — transient failure during DKIM public key DNS lookup")
	}

	// Granular DMARC anomalies
	switch auth.DMARCResult {
	case "fail":
		auth.Anomalies = append(auth.Anomalies,
			"DMARC fail — message did not satisfy the domain's DMARC policy (neither SPF nor DKIM alignment passed)")
	case "temperror":
		auth.Anomalies = append(auth.Anomalies,
			"DMARC temperror — transient error prevented DMARC evaluation")
	case "permerror":
		auth.Anomalies = append(auth.Anomalies,
			"DMARC permerror — domain DMARC record has a permanent configuration error")
	}

	// No Authentication-Results header at all
	if len(arValues) == 0 {
		auth.Anomalies = append(auth.Anomalies,
			"No Authentication-Results header found — receiving MTA did not record SPF/DKIM/DMARC evaluation")
	}

	// Multiple Authentication-Results headers (possible injection attempt)
	if len(arValues) > 1 {
		auth.Anomalies = append(auth.Anomalies,
			fmt.Sprintf("%d Authentication-Results headers present — only the innermost (topmost) is trusted; others may be injected", len(arValues)))
	}

	return auth
}

// sameOrganizationalDomain uses the ICANN Public Suffix List to compare the
// registrable domain (eTLD+1) of two hostnames. This correctly handles
// multi-label TLDs (.co.uk, .com.au) and prevents bare-TLD false matches.
func sameOrganizationalDomain(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	a = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a), "."))
	b = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(b), "."))
	aReg, err1 := publicsuffix.EffectiveTLDPlusOne(a)
	bReg, err2 := publicsuffix.EffectiveTLDPlusOne(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	return aReg == bReg
}

func domainFromAddress(raw string) string {
	raw = strings.Trim(raw, "<> ")
	addr, err := netmail.ParseAddress(raw)
	if err == nil {
		raw = addr.Address
	}
	parts := strings.Split(raw, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(strings.Trim(parts[1], "<> "))
}

func appendUnique(values []string, v string) []string {
	for _, e := range values {
		if e == v {
			return values
		}
	}
	return append(values, v)
}

func headerValues(h message.Header, key string) []string {
	var values []string
	fields := h.FieldsByKey(key)
	for fields.Next() {
		values = append(values, fields.Value())
	}
	return values
}
