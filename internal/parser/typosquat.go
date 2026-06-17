package parser

import (
	"strings"
	"unicode"
)

// homoglyphTable maps visually deceptive runes to their canonical ASCII equivalents.
// Covers Cyrillic, Greek, Latin-extended, and common digit substitutions used in
// domain-name spoofing attacks.
var homoglyphTable = map[rune]rune{
	// Cyrillic lookalikes (lowercase)
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
	// Cyrillic lookalikes (uppercase)
	'А': 'a', 'В': 'b', 'Е': 'e', 'К': 'k', 'М': 'm', 'Н': 'h',
	'О': 'o', 'Р': 'p', 'С': 'c', 'Т': 't', 'Х': 'x',
	// Greek lookalikes
	'ο': 'o', 'ρ': 'p', 'ν': 'v', 'κ': 'k', 'α': 'a',
	// Latin extended
	'á': 'a', 'à': 'a', 'ä': 'a', 'â': 'a', 'ã': 'a', 'å': 'a',
	'é': 'e', 'è': 'e', 'ë': 'e', 'ê': 'e',
	'í': 'i', 'ì': 'i', 'ï': 'i', 'î': 'i',
	'ó': 'o', 'ò': 'o', 'ö': 'o', 'ô': 'o', 'õ': 'o',
	'ú': 'u', 'ù': 'u', 'ü': 'u', 'û': 'u',
	'ý': 'y', 'ÿ': 'y', 'ñ': 'n', 'ç': 'c',
	// Common digit substitutions (leet-speak domain attacks)
	'0': 'o', '1': 'i', '3': 'e', '5': 's', '6': 'g',
}

// multiLabelTLDs lists common two-label TLDs so registrableDomain can correctly
// extract eTLD+1 without requiring a full Public Suffix List dependency.
var multiLabelTLDs = map[string]bool{
	"co.uk": true, "co.nz": true, "co.jp": true, "co.za": true, "co.in": true,
	"co.il": true, "co.kr": true, "co.id": true, "co.th": true, "co.ke": true,
	"com.au": true, "com.br": true, "com.mx": true, "com.ar": true, "com.co": true,
	"com.sg": true, "com.my": true, "com.ph": true, "com.tr": true, "com.ng": true,
	"org.uk": true, "org.au": true, "org.nz": true,
	"net.uk": true, "net.au": true,
	"gov.uk": true, "gov.au": true, "gov.in": true,
	"ac.uk": true, "ac.nz": true, "ac.jp": true,
	"edu.au": true, "edu.sg": true,
}

// registrableDomain returns the registrable domain (eTLD+1) of a hostname.
// e.g. "mail.paypal.com" → "paypal.com", "signin.paypal.co.uk" → "paypal.co.uk".
func registrableDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}
	if len(parts) >= 3 {
		twoLabel := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if multiLabelTLDs[twoLabel] {
			return parts[len(parts)-3] + "." + twoLabel
		}
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// normalizeForTyposquat converts a domain name to a canonical ASCII form for
// fuzzy comparison, replacing homoglyphs and stripping hyphens.
func normalizeForTyposquat(s string) string {
	s = strings.ToLower(strings.ReplaceAll(s, "-", ""))
	var b strings.Builder
	for _, r := range s {
		if mapped, ok := homoglyphTable[r]; ok {
			b.WriteRune(mapped)
		} else if r <= unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// levenshtein computes the edit distance between two strings using dynamic programming.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			if ra[i-1] == rb[j-1] {
				curr[j] = prev[j-1]
			} else {
				curr[j] = 1 + min3(prev[j], curr[j-1], prev[j-1])
			}
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}

// stripLabel removes the TLD suffix from a normalized registrable domain,
// leaving just the second-level label (e.g. "paypal.com" → "paypal").
func stripLabel(reg string) string {
	if idx := strings.LastIndex(reg, "."); idx >= 0 {
		return reg[:idx]
	}
	return reg
}

// isTyposquat returns true when urlDomain appears to be a lookalike of fromDomain
// via character-level substitution, insertion, deletion, or subdomain embedding.
func isTyposquat(fromDomain, urlDomain string) bool {
	if fromDomain == "" || urlDomain == "" {
		return false
	}
	fromReg := registrableDomain(fromDomain)
	urlReg := registrableDomain(urlDomain)

	// Same registrable domain is legitimate — not a typosquat.
	if fromReg == urlReg {
		return false
	}

	fromNorm := normalizeForTyposquat(fromReg)
	urlNorm := normalizeForTyposquat(urlReg)

	// Identical after homoglyph normalization = IDN homograph attack.
	if fromNorm == urlNorm {
		return true
	}

	fromBase := stripLabel(fromNorm)
	urlBase := stripLabel(urlNorm)

	// Short sender names are too generic to match reliably.
	if len(fromBase) < 4 {
		return false
	}

	// Levenshtein distance ≤ 2 signals character-swap / insertion / deletion attacks.
	if dist := levenshtein(fromBase, urlBase); dist > 0 && dist <= 2 {
		return true
	}

	// Subdomain-embedding attack: attacker puts brand name as a subdomain of evil TLD.
	// e.g. fromDomain=paypal.com, urlDomain=paypal.com.phish.ru
	fullUrlNorm := normalizeForTyposquat(urlDomain)
	if strings.Contains(fullUrlNorm, fromBase+".") {
		return true
	}

	return false
}

// findTyposquatMatches returns the subset of urlDomains that appear to be
// lookalike/typosquat domains of fromDomain.
func findTyposquatMatches(fromDomain string, urlDomains []string) []string {
	var matches []string
	seen := map[string]bool{}
	for _, d := range urlDomains {
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		if isTyposquat(fromDomain, d) {
			matches = append(matches, d)
		}
	}
	return matches
}
