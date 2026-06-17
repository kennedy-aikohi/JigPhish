package parser

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kennedy-aikohi/jigphish/internal/model"
)

var (
	urgencyTerms = regexp.MustCompile(
		`(?i)\b(urgent|immediate|expires?|verify now|final notice|action required|` +
			`suspended|limited time|within 24 hours|your account|confirm your|` +
			`click here immediately|sign in now|download now|act now|last chance|` +
			`security alert|unusual activity|unauthorized access)\b`)

	financialTerms = regexp.MustCompile(
		`(?i)\b(invoice|payment|wire transfer|payroll|bank account|crypto|wallet|` +
			`refund|purchase order|remittance|direct deposit|tax return|irs|` +
			`beneficiary|routing number|swift code|ach transfer|outstanding balance)\b`)

	zeroFontCSS = regexp.MustCompile(
		`(?i)(font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)`)

	// ── ClickFix / Paste-and-Run social engineering patterns ─────────────────
	// ClickFix is a technique where victims are instructed to paste a pre-copied
	// malicious command into Win+R or a terminal. Signals ranked by specificity.

	cfClipboardJS = regexp.MustCompile(
		`(?i)(navigator\.clipboard\.write|document\.execCommand\s*\(\s*['"]copy['"]|` +
			`clipboardData\.setData|window\.clipboardData\.setData)`)

	cfWinR = regexp.MustCompile(
		`(?i)(press|hold|hit|use).{0,40}(win\s*\+\s*r|windows\s*key.{0,20}\br\b|` +
			`windows\s*\+\s*r|winkey|start\s*→?\s*run)`)

	cfPowerShellLaunch = regexp.MustCompile(
		`(?i)(open|launch|press|start|run|type).{0,50}(powershell|cmd\.exe|` +
			`command\s*prompt|windows\s*terminal|run\s*dialog|terminal)`)

	cfPasteRun = regexp.MustCompile(
		`(?i)(paste|ctrl\s*\+\s*v|ctrl-v|press\s+v).{0,50}(run|execute|enter|` +
			`confirm|press\s*enter|hit\s*enter)`)

	cfFakeCaptcha = regexp.MustCompile(
		`(?i)(captcha|i\s+am\s+not\s+a\s+robot|human\s+verification|` +
			`prove\s+you.{0,5}re\s+human|complete\s+verification|` +
			`verify\s+you.{0,5}re\s+human|robot\s+check|security\s+check)`)

	cfEncodedPS = regexp.MustCompile(
		`(?i)(-enc\s+|-encodedcommand\s+)[A-Za-z0-9+/]{20,}`)

	cfLolBinsRemote = regexp.MustCompile(
		`(?i)\b(mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|` +
			`msiexec|odbcconf)\b.{0,120}(https?://|\\\\[a-z0-9])`)

	cfStepInstructions = regexp.MustCompile(
		`(?i)(step\s+[1-4].{0,60}(paste|run|execute|open)|` +
			`to\s+continue.{0,50}(paste|run|click\s+allow)|` +
			`copy\s+.{0,30}clipboard.{0,30}(run|paste|execute))`)

	cfPSDownloadCradle = regexp.MustCompile(
		`(?i)(iex\s*\(|invoke-expression|invoke-webrequest|` +
			`downloadstring|webclient|start-process).{0,100}http`)
)

func analyzeBody(body string) model.BodyHeuristics {
	normalized := strings.Join(strings.Fields(body), " ")
	h := model.BodyHeuristics{}

	for _, match := range urgencyTerms.FindAllString(normalized, -1) {
		h.UrgencyScore += 10
		h.Matches = append(h.Matches, "urgency:"+strings.ToLower(strings.TrimSpace(match)))
	}
	for _, match := range financialTerms.FindAllString(normalized, -1) {
		h.FinancialScore += 8
		h.Matches = append(h.Matches, "financial:"+strings.ToLower(strings.TrimSpace(match)))
	}
	if zeroFontCSS.MatchString(body) {
		h.ZeroFontDetected = true
		h.ObfuscationScore += 25
		h.Matches = append(h.Matches, "obfuscation:zero-font-or-hidden-css")
	}
	if containsMixedScripts(body) {
		h.HomoglyphSuspicion = true
		h.ObfuscationScore += 20
		h.Matches = append(h.Matches, "obfuscation:mixed-latin-cyrillic")
	}
	if strings.Count(body, "&#") > 20 || strings.Count(body, "%") > 30 {
		h.EncodedContentDensity = true
		h.ObfuscationScore += 10
		h.Matches = append(h.Matches, "obfuscation:encoded-content-density")
	}

	// ClickFix / Paste-and-Run detection
	h.ClickFixDetected, h.ClickFixSignals = detectClickFix(body)
	if h.ClickFixDetected {
		h.Matches = append(h.Matches, "social_engineering:clickfix")
	}

	return h
}

// detectClickFix checks for ClickFix (Paste-and-Run / Fake-CAPTCHA) social
// engineering patterns. Each matched pattern is recorded individually so
// analysts can see exactly which signals fired.
func detectClickFix(body string) (detected bool, signals []string) {
	check := func(re *regexp.Regexp, label string) {
		if re.MatchString(body) {
			signals = append(signals, label)
		}
	}
	check(cfClipboardJS,
		"JavaScript clipboard hijack — navigator.clipboard.write / execCommand(copy) copies payload without user action")
	check(cfWinR,
		"Win+R run-dialog instruction — victim told to press Windows+R to open the Execute dialog")
	check(cfPowerShellLaunch,
		"PowerShell / CMD launch instruction — email directs victim to open a shell")
	check(cfPasteRun,
		"Paste-and-run instruction — Ctrl+V followed by Enter to execute a pre-loaded payload")
	check(cfFakeCaptcha,
		"Fake CAPTCHA / human-verification lure — classic ClickFix entry point disguised as bot check")
	check(cfEncodedPS,
		"Base64-encoded PowerShell (-EncodedCommand) — obfuscated execution payload detected")
	check(cfLolBinsRemote,
		"Living-off-the-land binary with remote URL (mshta/wscript/certutil/bitsadmin) — fileless execution technique")
	check(cfStepInstructions,
		"Step-by-step paste-and-run template — numbered instruction matching known ClickFix script pattern")
	check(cfPSDownloadCradle,
		"PowerShell download cradle (IEX / Invoke-WebRequest / DownloadString) — one-liner dropper detected")
	detected = len(signals) > 0
	return
}

// assessRisk computes the Malicious Confidence Index (MCI) using a weighted signal
// matrix. Each contributing signal is recorded individually in MCIBreakdown for
// full auditability — analysts can trace every point back to a concrete indicator.
func assessRisk(r model.AnalysisResult) model.RiskAssessment {
	score := 0
	var breakdown []model.MCIComponent

	add := func(category, signal string, points int) {
		score += points
		breakdown = append(breakdown, model.MCIComponent{
			Category: category,
			Signal:   signal,
			Points:   points,
		})
	}

	// ── AUTHENTICATION FAILURES ──────────────────────────────────────────────
	// DMARC is the authoritative end-to-end policy; weight it highest.
	switch r.Auth.DMARCResult {
	case "fail", "permerror":
		add("auth", "DMARC hard fail — domain policy explicitly rejects this message", 30)
	case "softfail", "temperror":
		add("auth", "DMARC soft/temp failure — message partially violates domain policy", 15)
	case "none":
		add("auth", "DMARC result: none — domain has no policy or was not evaluated", 8)
	case "":
		add("auth", "DMARC absent — no Authentication-Results header present", 5)
	}

	switch r.Auth.SPFResult {
	case "fail":
		add("auth", "SPF hard fail — sending IP is explicitly unauthorized", 20)
	case "softfail":
		add("auth", "SPF softfail — sending IP weakly unauthorized (~all)", 12)
	case "permerror":
		add("auth", "SPF permerror — domain SPF record configuration error", 10)
	case "temperror":
		add("auth", "SPF temperror — transient DNS failure during SPF evaluation", 6)
	case "none":
		add("auth", "SPF: none — domain publishes no SPF record", 5)
	}

	switch r.Auth.DKIMResult {
	case "fail", "permerror":
		add("auth", "DKIM invalid — signature does not match or key is revoked", 15)
	case "temperror":
		add("auth", "DKIM temperror — transient DKIM key lookup failure", 8)
	case "none":
		add("auth", "DKIM: none — message carries no DKIM signature", 5)
	}

	// Cross-domain spoofing: Return-Path and From belong to different organizations.
	if r.Auth.FromDomain != "" && r.Auth.ReturnPathDomain != "" && !r.Auth.SPFAligned {
		add("auth",
			fmt.Sprintf("Return-Path (%s) misaligned with From (%s) — cross-domain spoofing", r.Auth.ReturnPathDomain, r.Auth.FromDomain),
			25)
	}

	// Relay-domain DKIM: passes but the signing org is different from From.
	if r.Auth.DKIMResult == "pass" && !r.Auth.DKIMAligned {
		add("auth", "DKIM passes but signing domain differs from From — relay or forged header", 20)
	}

	// ── RECEIVED CHAIN ANOMALIES ─────────────────────────────────────────────
	bulletproofHops := map[int]bool{}
	for _, hop := range r.ReceivedChain {
		for _, anomaly := range hop.Anomalies {
			lower := strings.ToLower(anomaly)
			switch {
			case strings.Contains(lower, "timestamp inversion"):
				add("routing", fmt.Sprintf("Hop %d: received-chain timestamp inversion", hop.Index), 20)
			case strings.Contains(lower, "no public ipv4"):
				add("routing", fmt.Sprintf("Hop %d: no observable public IP in Received header", hop.Index), 15)
			case strings.Contains(lower, "high-risk asn") && !bulletproofHops[hop.Index]:
				add("routing", fmt.Sprintf("Hop %d: %s", hop.Index, anomaly), 40)
				bulletproofHops[hop.Index] = true
			}
		}
		// BulletproofRisk is set by enrichHopsWithASN; guard against double-counting.
		if hop.Geo.BulletproofRisk && !bulletproofHops[hop.Index] {
			add("routing",
				fmt.Sprintf("Hop %d: traverses high-risk/bulletproof ASN %s", hop.Index, hop.Geo.ASN),
				40)
			bulletproofHops[hop.Index] = true
		}
	}

	// ── URL ARTIFACTS ────────────────────────────────────────────────────────
	if n := len(r.URLs); n > 0 {
		pts := capPoints(n*5, 25)
		add("content", fmt.Sprintf("%d external URL artifact(s) extracted from body", n), pts)
	}

	// ── ATTACHMENTS ──────────────────────────────────────────────────────────
	for _, att := range r.Attachments {
		if isExecutableType(att.ContentType, att.FileName) {
			add("content", fmt.Sprintf("executable/script attachment: %s", att.FileName), 35)
		} else {
			add("content", fmt.Sprintf("non-executable attachment: %s", att.FileName), 5)
		}
	}

	// ── BODY OBFUSCATION ────────────────────────────────────────────────────
	if r.BodyHeuristics.ZeroFontDetected {
		add("obfuscation", "zero-font or CSS-hidden text detected (content invisible to reader)", 30)
	}
	if r.BodyHeuristics.HomoglyphSuspicion {
		add("obfuscation", "mixed Latin+Cyrillic scripts — homoglyph substitution indicator", 25)
	}
	if r.BodyHeuristics.EncodedContentDensity {
		add("obfuscation", "high-density HTML entity / percent-encoded content", 10)
	}

	// ── SOCIAL ENGINEERING SIGNALS ───────────────────────────────────────────
	if pts := capPoints(r.BodyHeuristics.UrgencyScore/2, 20); pts > 0 {
		add("social_engineering", "urgency language signals (pressure tactics)", pts)
	}
	if pts := capPoints(r.BodyHeuristics.FinancialScore/2, 15); pts > 0 {
		add("social_engineering", "financial language signals (monetary lure)", pts)
	}

	// ── TYPOSQUATTING / LOOKALIKE DOMAIN ────────────────────────────────────
	if r.BodyHeuristics.TyposquatSuspicion {
		matches := strings.Join(r.BodyHeuristics.TyposquatMatches, ", ")
		add("spoofing",
			fmt.Sprintf("URL domain(s) are lookalikes of sender domain (%s) — typosquat/IDN attack: %s",
				r.Auth.FromDomain, matches),
			40)
	}

	// ── CLICKFIX SOCIAL ENGINEERING ──────────────────────────────────────────
	// ClickFix (Paste-and-Run / Fake-CAPTCHA) is a high-confidence malicious
	// indicator — weight scales with the number of corroborating signals.
	if r.BodyHeuristics.ClickFixDetected {
		pts := capPoints(len(r.BodyHeuristics.ClickFixSignals)*15, 60)
		add("social_engineering",
			fmt.Sprintf("ClickFix / Paste-and-Run attack detected (%d corroborating signals)",
				len(r.BodyHeuristics.ClickFixSignals)),
			pts)
	}

	// ── QR CODE / QUISHING ───────────────────────────────────────────────────
	// QR codes in email that encode URLs are the hallmark of "quishing" attacks
	// designed to bypass URL scanners that don't decode image content.
	if r.BodyHeuristics.QRCodeDetected {
		add("obfuscation", "QR code with embedded URL detected — possible quishing (QR-phishing) attack", 30)
	}
	for _, bc := range r.Barcodes {
		if !bc.IsURL {
			// Non-URL barcode payload in email is unusual and suspicious.
			add("obfuscation",
				fmt.Sprintf("barcode (%s) with non-URL payload found in %s", bc.Format, bc.Source),
				10)
		}
	}

	score = capPoints(score, 100)

	reasons := make([]string, 0, len(breakdown))
	for _, c := range breakdown {
		reasons = append(reasons, fmt.Sprintf("[%s] %s (+%d)", c.Category, c.Signal, c.Points))
	}

	level := "Low"
	switch {
	case score >= 75:
		level = "Critical"
	case score >= 50:
		level = "High"
	case score >= 25:
		level = "Medium"
	}
	return model.RiskAssessment{
		Score:        score,
		Level:        level,
		Reasons:      reasons,
		MCIBreakdown: breakdown,
	}
}

// capPoints clamps v to [0, max].
func capPoints(v, max int) int {
	if v > max {
		return max
	}
	if v < 0 {
		return 0
	}
	return v
}

// isExecutableType returns true when a file's content type or extension indicates
// it is executable, scriptable, or capable of running arbitrary code on open.
func isExecutableType(contentType, fileName string) bool {
	execContentTypes := []string{
		"application/x-msdownload",
		"application/x-executable",
		"application/x-dosexec",
		"application/x-sh",
		"application/x-bat",
		"application/x-powershell",
		"application/x-msdos-program",
		"application/x-javascript",
		"application/java-archive",
		"application/x-python-code",
		"application/vnd.ms-htmlhelp",
	}
	ct := strings.ToLower(contentType)
	for _, t := range execContentTypes {
		if strings.HasPrefix(ct, t) {
			return true
		}
	}
	execExts := []string{
		".exe", ".dll", ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
		".vbs", ".vbe", ".js", ".jse", ".jar", ".py", ".pyc",
		".sh", ".bash", ".hta", ".scr", ".msi", ".msp", ".com",
		".cpl", ".reg", ".wsf", ".wsh", ".lnk", ".iso", ".img",
	}
	fn := strings.ToLower(fileName)
	for _, ext := range execExts {
		if strings.HasSuffix(fn, ext) {
			return true
		}
	}
	return false
}
