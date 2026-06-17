package parser

// RFC 7601 Authentication-Results header parser.
//
// Design principles (inspired by the structured tokenization approach in
// Nager.EmailAuthentication for DNS record parsing):
//
//  1. Unfold RFC 5322 header folding before processing.
//  2. Strip RFC 5321 parenthesized comments (nested parens supported).
//  3. Split on semicolons — each segment is one method=result statement.
//  4. Validate method and result against a strict whitelist (no regex
//     substring matching — prevents false positives from crafted headers).
//  5. Extract ptype.property=value properties structurally, not by regex.
//  6. Trust model: callers MUST pass only the FIRST (innermost/topmost)
//     Authentication-Results header value — the one stamped by the receiving
//     MTA. All subsequent headers are stamped by earlier relays or the
//     originating server and are untrusted per RFC 7601 §7.2.

import "strings"

// validARResults maps each known authentication method to its set of valid
// result tokens per RFC 7601 §2.7.1. Any result not in this set is rejected,
// preventing attacker-crafted "spf=trusted" style injection.
var validARResults = map[string]map[string]bool{
	"spf": {
		"pass":      true,
		"fail":      true,
		"softfail":  true,
		"neutral":   true,
		"none":      true,
		"temperror": true,
		"permerror": true,
	},
	"dkim": {
		"pass":      true,
		"fail":      true,
		"neutral":   true,
		"none":      true,
		"temperror": true,
		"permerror": true,
	},
	"dmarc": {
		"pass":      true,
		"fail":      true,
		"none":      true,
		"temperror": true,
		"permerror": true,
	},
	"arc": {
		"pass": true,
		"fail": true,
		"none": true,
	},
	"iprev": {
		"pass":      true,
		"fail":      true,
		"none":      true,
		"temperror": true,
		"permerror": true,
	},
	"bimi": {
		"pass":      true,
		"fail":      true,
		"none":      true,
		"temperror": true,
	},
}

// arBlock is one parsed method=result statement from an Authentication-Results header.
type arBlock struct {
	Method     string            // "spf", "dkim", "dmarc", …
	Result     string            // "pass", "fail", "softfail", …
	Reason     string            // optional reason= value
	Properties map[string]string // "smtp.mailfrom", "header.d", "header.from", …
}

// prop returns the property value for the given ptype.property key, or "".
func (b arBlock) prop(key string) string { return b.Properties[key] }

// parseAuthResultsHeader parses one Authentication-Results header value and
// returns the authserv-id and all parsed method blocks.
//
// The caller MUST pass only headerValues(h, "Authentication-Results")[0] —
// the topmost header added by the receiving MTA. See trust-model note above.
func parseAuthResultsHeader(raw string) (authservID string, blocks []arBlock) {
	// Step 1 — unfold RFC 5322 header folding (CRLF + horizontal whitespace).
	raw = arUnfold(raw)
	// Step 2 — strip RFC 5321 parenthesized comments.
	raw = arStripComments(raw)

	// Step 3 — split on semicolons; first segment is the authserv-id.
	segs := strings.Split(raw, ";")
	if len(segs) == 0 {
		return
	}
	authservID = strings.TrimSpace(segs[0])

	// Step 4 — parse each subsequent segment as a method block.
	for _, seg := range segs[1:] {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if b := arParseMethodSegment(seg); b != nil {
			blocks = append(blocks, *b)
		}
	}
	return
}

// arParseMethodSegment parses one "method=result [ptype.prop=val …]" segment.
// Returns nil when the segment does not conform to RFC 7601 (unknown method,
// invalid result, malformed first token) so callers can skip it silently.
func arParseMethodSegment(seg string) *arBlock {
	tokens := strings.Fields(seg)
	if len(tokens) == 0 {
		return nil
	}

	// First token must be exactly method=result — no prefix/suffix.
	kv := strings.SplitN(tokens[0], "=", 2)
	if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
		return nil
	}

	method := strings.ToLower(strings.TrimSpace(kv[0]))
	result := strings.ToLower(strings.TrimSpace(kv[1]))

	// Reject unknown methods (e.g. "x-spf", "custom-dkim").
	allowed, known := validARResults[method]
	if !known {
		return nil
	}
	// Reject invalid result values for this method.
	if !allowed[result] {
		return nil
	}

	b := &arBlock{
		Method:     method,
		Result:     result,
		Properties: make(map[string]string, 6),
	}

	// Parse remaining tokens as ptype.property=value pairs.
	for _, tok := range tokens[1:] {
		lower := strings.ToLower(tok)

		// Special: reason=<value> (not a ptype.property key).
		if strings.HasPrefix(lower, "reason=") {
			b.Reason = strings.Trim(tok[7:], `"'`)
			continue
		}

		kv2 := strings.SplitN(tok, "=", 2)
		if len(kv2) != 2 || kv2[1] == "" {
			continue
		}

		key := strings.ToLower(kv2[0])
		val := strings.Trim(kv2[1], `"'`)

		// ptype.property keys must have exactly one dot, not leading or trailing.
		dot := strings.Index(key, ".")
		if dot <= 0 || dot >= len(key)-1 {
			continue
		}

		b.Properties[key] = val
	}

	return b
}

// parseDKIMSignatureHeader extracts d=, s=, a= tags from a raw DKIM-Signature
// header value following RFC 6376 §3.5 (semicolon-separated tag=value pairs).
// Used as a fallback when Authentication-Results does not provide header.d.
func parseDKIMSignatureHeader(raw string) (domain, selector, algorithm string) {
	raw = arUnfold(raw)
	for _, tag := range strings.Split(raw, ";") {
		tag = strings.TrimSpace(tag)
		kv := strings.SplitN(tag, "=", 2)
		if len(kv) != 2 || kv[1] == "" {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "d":
			domain = strings.ToLower(val)
		case "s":
			selector = strings.ToLower(val)
		case "a":
			algorithm = strings.ToLower(val)
		}
	}
	return
}

// arUnfold collapses RFC 5322 folded header whitespace (CRLF + WSP) into
// a single space character, as required before tokenizing a header value.
func arUnfold(s string) string {
	s = strings.ReplaceAll(s, "\r\n\t", " ")
	s = strings.ReplaceAll(s, "\r\n ", " ")
	s = strings.ReplaceAll(s, "\n\t", " ")
	s = strings.ReplaceAll(s, "\n ", " ")
	return s
}

// arStripComments removes RFC 5321 §4.1.3 parenthesized comments from s.
// Handles arbitrary nesting depth and backslash-quoted characters inside
// comments. Characters outside comments are passed through unchanged.
func arStripComments(s string) string {
	var buf strings.Builder
	buf.Grow(len(s))
	depth := 0
	escaped := false
	for _, r := range s {
		if escaped {
			escaped = false
			if depth == 0 {
				buf.WriteRune(r)
			}
			continue
		}
		if r == '\\' {
			escaped = true
			if depth == 0 {
				buf.WriteRune(r)
			}
			continue
		}
		switch r {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				buf.WriteRune(r)
			}
		}
	}
	return buf.String()
}
