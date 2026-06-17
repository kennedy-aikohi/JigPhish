package parser

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"mime"
	"net/http"
	netmail "net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // registers iso-8859-1, windows-125x, gb2312, etc.
	"github.com/kennedy-aikohi/jigphish/internal/model"
	"github.com/kennedy-aikohi/jigphish/pkg/defang"
)

type Options struct {
	RedirectLimit int
	UserAgent     string
	Timeout       time.Duration
	GeoIPPath     string
	// StealthMode suppresses all live network contact with threat-actor infrastructure:
	// redirect-following HTTP requests are skipped and ASN lookups are disabled.
	// Attachment hash and domain reputation checks (VirusTotal et al.) are unaffected
	// because they never contact attacker-controlled servers.
	StealthMode bool
}

type Parser struct {
	redirectLimit int
	userAgent     string
	stealthMode   bool
	httpClient    *http.Client
	geoIP         GeoResolver
	asnClient     *asnLookupClient
}

type GeoResolver interface {
	Lookup(ip string) model.GeoIP
}

func New(opts Options) *Parser {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 12 * time.Second
	}
	p := &Parser{
		redirectLimit: opts.RedirectLimit,
		userAgent:     opts.UserAgent,
		stealthMode:   opts.StealthMode,
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= opts.RedirectLimit {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		geoIP: NoopGeoResolver{},
	}
	if !opts.StealthMode {
		p.asnClient = newASNClient()
	}
	return p
}

func (p *Parser) ParseFile(ctx context.Context, path string) (model.AnalysisResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return model.AnalysisResult{}, fmt.Errorf("open email: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return model.AnalysisResult{}, fmt.Errorf("stat email: %w", err)
	}

	result, err := p.Parse(ctx, f)
	if err != nil {
		return result, err
	}
	result.FileName = path
	result.SizeBytes = info.Size()
	result.ID = stableID(path, info.Size(), result.MessageID)
	return result, nil
}

func (p *Parser) Parse(ctx context.Context, r io.Reader) (model.AnalysisResult, error) {
	result := model.AnalysisResult{
		ParsedAt:          time.Now().UTC(),
		Watermark:         model.Watermark,
		StealthModeActive: p.stealthMode,
	}

	entity, err := message.Read(r)
	if err != nil {
		return result, fmt.Errorf("read MIME message: %w", err)
	}

	result.Headers = flattenHeaders(entity.Header)
	result.Subject = decodeHeader(entity.Header.Get("Subject"))
	result.From = decodeHeader(entity.Header.Get("From"))
	result.To = parseAddressList(entity.Header.Get("To"))
	result.MessageID = strings.TrimSpace(entity.Header.Get("Message-ID"))
	if d, err := netmail.ParseDate(entity.Header.Get("Date")); err == nil {
		result.Date = d
	}

	result.ReceivedChain = p.parseReceivedChain(entity.Header)

	// Enrich Received hops with ASN geolocation when not in stealth mode.
	// This identifies bulletproof hosting networks without contacting attacker infrastructure.
	if !p.stealthMode && p.asnClient != nil {
		p.enrichHopsWithASN(ctx, result.ReceivedChain)
	}

	result.Auth = assessAuth(entity.Header)

	var body bytes.Buffer
	if err := p.walkEntity(entity, &result, &body); err != nil {
		result.Errors = append(result.Errors, err.Error())
	}
	bodyText := body.String()
	result.BodyHeuristics = analyzeBody(bodyText)
	result.URLs = p.extractURLs(ctx, bodyText)

	// Scan inline base64 images in the HTML body for QR/barcodes.
	if inlineBarcodes := extractInlineImageBarcodes(bodyText); len(inlineBarcodes) > 0 {
		for i := range inlineBarcodes {
			inlineBarcodes[i].Source = "inline-image"
		}
		result.Barcodes = append(result.Barcodes, inlineBarcodes...)
	}

	// For every barcode that encodes a URL: mark the QR flag and inject the URL
	// into the URL artifact list so it gets full OSINT enrichment.
	seenURLs := map[string]struct{}{}
	for _, u := range result.URLs {
		seenURLs[u.Normalized] = struct{}{}
	}
	for _, bc := range result.Barcodes {
		if !bc.IsURL {
			continue
		}
		result.BodyHeuristics.QRCodeDetected = true
		if _, seen := seenURLs[bc.Data]; seen {
			continue
		}
		seenURLs[bc.Data] = struct{}{}
		art := model.URLArtifact{
			Original:       bc.Data,
			Normalized:     bc.Data,
			Defanged:       bc.Defanged,
			Domain:         bc.Domain,
			ExtractionHint: "barcode:" + bc.Format,
		}
		if !p.stealthMode {
			final, chain := p.followRedirects(ctx, bc.Data)
			art.FinalURL = final
			if final != "" {
				art.FinalDefanged = defang.URL(final)
			}
			art.RedirectChain = chain
		}
		result.URLs = append(result.URLs, art)
	}

	// Typosquatting detection requires both From domain and extracted URL domains.
	p.detectTyposquatting(&result)

	result.Risk = assessRisk(result)
	return result, nil
}

// enrichHopsWithASN queries ip-api.com for each hop IP and flags bulletproof ASNs.
func (p *Parser) enrichHopsWithASN(ctx context.Context, hops []model.ReceivedHop) {
	for i := range hops {
		if hops[i].IP == "" {
			continue
		}
		country, city, asn, org, bulletproof, reason := p.asnClient.Lookup(ctx, hops[i].IP)
		hops[i].Geo.Country = country
		hops[i].Geo.City = city
		hops[i].Geo.ASN = asn
		hops[i].Geo.Org = org
		if bulletproof {
			hops[i].Geo.BulletproofRisk = true
			hops[i].Anomalies = append(hops[i].Anomalies,
				fmt.Sprintf("high-risk ASN detected: %s — %s", asn, reason))
		}
	}
}

// detectTyposquatting compares URL domains against the sender's domain and sets
// TyposquatSuspicion on BodyHeuristics when a lookalike is found.
func (p *Parser) detectTyposquatting(result *model.AnalysisResult) {
	fromDomain := result.Auth.FromDomain
	if fromDomain == "" {
		return
	}
	urlDomains := make([]string, 0, len(result.URLs))
	for _, u := range result.URLs {
		if u.Domain != "" {
			urlDomains = append(urlDomains, u.Domain)
		}
	}
	matches := findTyposquatMatches(fromDomain, urlDomains)
	if len(matches) > 0 {
		result.BodyHeuristics.TyposquatSuspicion = true
		result.BodyHeuristics.TyposquatMatches = matches
		result.BodyHeuristics.Matches = append(result.BodyHeuristics.Matches,
			"spoofing:typosquat:"+strings.Join(matches, ","))
	}
}

func (p *Parser) walkEntity(entity *message.Entity, result *model.AnalysisResult, body *bytes.Buffer) error {
	mr := entity.MultipartReader()
	if mr != nil {
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return fmt.Errorf("read MIME part: %w", err)
			}
			if err := p.walkEntity(part, result, body); err != nil {
				result.Errors = append(result.Errors, err.Error())
			}
		}
	}

	contentType, _, _ := mime.ParseMediaType(entity.Header.Get("Content-Type"))
	disposition, dispParams, _ := mime.ParseMediaType(entity.Header.Get("Content-Disposition"))
	fileName := dispParams["filename"]
	if fileName == "" {
		_, params, _ := mime.ParseMediaType(entity.Header.Get("Content-Type"))
		fileName = params["name"]
	}

	if strings.EqualFold(disposition, "attachment") || fileName != "" {
		isImage := strings.HasPrefix(strings.ToLower(contentType), "image/")
		var attachment model.Attachment
		var err error
		if isImage {
			// Buffer the full image so we can hash it AND scan it for barcodes.
			// Cap at 10 MB — phishing QR images are always far smaller.
			imgData, _ := io.ReadAll(io.LimitReader(entity.Body, 10<<20))
			attachment, err = hashAttachment(bytes.NewReader(imgData), fileName, contentType)
			if err != nil {
				return err
			}
			attachment.Barcodes = detectBarcodesFromBytes(imgData)
			for _, bc := range attachment.Barcodes {
				bc.Source = "attachment:" + fileName
				result.Barcodes = append(result.Barcodes, bc)
			}
		} else {
			attachment, err = hashAttachment(entity.Body, fileName, contentType)
			if err != nil {
				return err
			}
		}
		result.Attachments = append(result.Attachments, attachment)
		return nil
	}

	if strings.HasPrefix(strings.ToLower(contentType), "text/") || contentType == "" {
		_, _ = io.Copy(body, io.LimitReader(entity.Body, 8<<20))
	}
	return nil
}

func hashAttachment(r io.Reader, name, contentType string) (model.Attachment, error) {
	md5h, sha1h, sha256h := md5.New(), sha1.New(), sha256.New()
	w := io.MultiWriter(md5h, sha1h, sha256h)
	n, err := io.Copy(w, r)
	if err != nil {
		return model.Attachment{}, fmt.Errorf("hash attachment %q: %w", name, err)
	}
	if name == "" {
		name = "unnamed-attachment"
	}
	return model.Attachment{
		FileName:    filepath.Base(name),
		ContentType: contentType,
		SizeBytes:   n,
		MD5:         sumHex(md5h),
		SHA1:        sumHex(sha1h),
		SHA256:      sumHex(sha256h),
	}, nil
}

func sumHex(h hash.Hash) string {
	return hex.EncodeToString(h.Sum(nil))
}

var urlPattern = regexp.MustCompile(`(?i)\b(?:https?://|hxxps?://)[^\s<>"')]+`)

func (p *Parser) extractURLs(ctx context.Context, text string) []model.URLArtifact {
	seen := map[string]struct{}{}
	matches := urlPattern.FindAllString(text, -1)
	out := make([]model.URLArtifact, 0, len(matches))
	for _, raw := range matches {
		trimmed := strings.TrimRight(raw, ".,;:]}")
		normalized := defang.Refang(trimmed)
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}

		u, err := url.Parse(normalized)
		if err != nil {
			continue
		}

		artifact := model.URLArtifact{
			Original:   trimmed,
			Normalized: normalized,
			Defanged:   defang.URL(normalized),
			Domain:     strings.ToLower(u.Hostname()),
		}

		if p.stealthMode {
			// Stealth mode: no live HTTP requests to potentially attacker-controlled URLs.
			artifact.FinalURL = normalized
			artifact.FinalDefanged = defang.URL(normalized)
			artifact.ExtractionHint = "stealth-mode:redirect-following-disabled"
		} else {
			finalURL, chain := p.followRedirects(ctx, normalized)
			artifact.FinalURL = finalURL
			if finalURL != "" {
				artifact.FinalDefanged = defang.URL(finalURL)
			}
			artifact.RedirectChain = chain
		}
		out = append(out, artifact)
	}
	return out
}

func (p *Parser) followRedirects(ctx context.Context, raw string) (string, []string) {
	if p.redirectLimit == 0 {
		return raw, nil
	}
	chain := make([]string, 0, p.redirectLimit)
	current := raw
	for i := 0; i < p.redirectLimit; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, current, nil)
		if err != nil {
			return current, chain
		}
		req.Header.Set("User-Agent", p.userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		resp, err := p.httpClient.Do(req)
		if err != nil || resp == nil {
			return current, chain
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 300 || resp.StatusCode > 399 {
			return resp.Request.URL.String(), chain
		}
		location := resp.Header.Get("Location")
		if location == "" {
			return current, chain
		}
		next, err := resp.Request.URL.Parse(location)
		if err != nil {
			return current, chain
		}
		current = next.String()
		chain = append(chain, defang.URL(current))
	}
	return current, chain
}

func flattenHeaders(h message.Header) []model.HeaderField {
	var fields []model.HeaderField
	fieldsIter := h.Fields()
	for fieldsIter.Next() {
		fields = append(fields, model.HeaderField{
			Key:   fieldsIter.Key(),
			Value: decodeHeader(fieldsIter.Value()),
		})
	}
	return fields
}

func decodeHeader(v string) string {
	decoded, err := (&mime.WordDecoder{}).DecodeHeader(v)
	if err != nil {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(decoded)
}

func parseAddressList(raw string) []string {
	addrs, err := netmail.ParseAddressList(raw)
	if err != nil {
		if strings.TrimSpace(raw) == "" {
			return nil
		}
		return []string{decodeHeader(raw)}
	}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

func stableID(path string, size int64, messageID string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s:%d:%s", filepath.Clean(path), size, messageID)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

type NoopGeoResolver struct{}

func (NoopGeoResolver) Lookup(string) model.GeoIP { return model.GeoIP{} }

func containsMixedScripts(s string) bool {
	hasLatin := false
	hasCyrillic := false
	for _, r := range s {
		if unicode.In(r, unicode.Latin) {
			hasLatin = true
		}
		if unicode.In(r, unicode.Cyrillic) {
			hasCyrillic = true
		}
	}
	return hasLatin && hasCyrillic
}
