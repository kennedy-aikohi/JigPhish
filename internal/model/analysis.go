package model

import "time"

const Version = "1.0.0"
const Watermark = "JigPhish v1.0.0 · Kennedy Aikohi · Open-Source Phishing Intelligence"

type AnalysisRequest struct {
	Path string `json:"path"`
}

type AnalysisResult struct {
	ID                string             `json:"id"`
	FileName          string             `json:"fileName"`
	SizeBytes         int64              `json:"sizeBytes"`
	ParsedAt          time.Time          `json:"parsedAt"`
	Subject           string             `json:"subject"`
	From              string             `json:"from"`
	To                []string           `json:"to"`
	Date              time.Time          `json:"date"`
	MessageID         string             `json:"messageId"`
	Headers           []HeaderField      `json:"headers"`
	ReceivedChain     []ReceivedHop      `json:"receivedChain"`
	Auth              AuthAssessment     `json:"auth"`
	URLs              []URLArtifact      `json:"urls"`
	Attachments       []Attachment       `json:"attachments"`
	Barcodes          []BarcodeArtifact  `json:"barcodes,omitempty"`
	BodyHeuristics    BodyHeuristics     `json:"bodyHeuristics"`
	ThreatIntel       ThreatIntelSummary `json:"threatIntel"`
	Risk              RiskAssessment     `json:"risk"`
	StealthModeActive bool               `json:"stealthModeActive"`
	Watermark         string             `json:"watermark"`
	Errors            []string           `json:"errors,omitempty"`
}

type HeaderField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type ReceivedHop struct {
	Index          int               `json:"index"`
	Raw            string            `json:"raw"`
	FromHost       string            `json:"fromHost"`
	ByHost         string            `json:"byHost"`
	IP             string            `json:"ip"`
	Timestamp      time.Time         `json:"timestamp"`
	DeltaFromPrior time.Duration     `json:"deltaFromPrior"`
	Geo            GeoIP             `json:"geo"`
	Anomalies      []string          `json:"anomalies,omitempty"`
	Intel          []ReputationEntry `json:"intel,omitempty"`
}

type GeoIP struct {
	Country         string  `json:"country,omitempty"`
	City            string  `json:"city,omitempty"`
	Latitude        float64 `json:"latitude,omitempty"`
	Longitude       float64 `json:"longitude,omitempty"`
	ASN             string  `json:"asn,omitempty"`
	Org             string  `json:"org,omitempty"`
	BulletproofRisk bool    `json:"bulletproofRisk,omitempty"`
}

type AuthAssessment struct {
	SPFResult        string   `json:"spfResult"`
	DKIMResult       string   `json:"dkimResult"`
	DMARCResult      string   `json:"dmarcResult"`
	SPFAligned       bool     `json:"spfAligned"`
	DKIMAligned      bool     `json:"dkimAligned"`
	DMARCAligned     bool     `json:"dmarcAligned"`
	FromDomain       string   `json:"fromDomain"`
	ReturnPathDomain string   `json:"returnPathDomain"`
	SigningDomains   []string `json:"signingDomains"`
	Anomalies        []string `json:"anomalies,omitempty"`
}

type URLArtifact struct {
	Original       string            `json:"original"`
	Normalized     string            `json:"normalized"`
	Defanged       string            `json:"defanged"`
	FinalURL       string            `json:"finalUrl"`
	FinalDefanged  string            `json:"finalDefanged"`
	Domain         string            `json:"domain"`
	IP             string            `json:"ip,omitempty"`
	RedirectChain  []string          `json:"redirectChain"`
	Intel          []ReputationEntry `json:"intel,omitempty"`
	ExtractionHint string            `json:"extractionHint,omitempty"`
}

// BarcodeArtifact holds a decoded barcode or QR code found in an image
// attachment or an inline image embedded in the email body.
type BarcodeArtifact struct {
	Format   string `json:"format"`            // "QR_CODE", "DATA_MATRIX", "CODE_128", …
	Data     string `json:"data"`              // raw decoded payload
	IsURL    bool   `json:"isUrl"`             // true when payload is a valid http/https URL
	Defanged string `json:"defanged,omitempty"` // defanged form of URL when IsURL=true
	Domain   string `json:"domain,omitempty"`   // hostname when IsURL=true
	Source   string `json:"source"`             // "inline-image" or "attachment:<filename>"
}

type Attachment struct {
	FileName    string            `json:"fileName"`
	ContentType string            `json:"contentType"`
	SizeBytes   int64             `json:"sizeBytes"`
	MD5         string            `json:"md5"`
	SHA1        string            `json:"sha1"`
	SHA256      string            `json:"sha256"`
	Intel       []ReputationEntry `json:"intel,omitempty"`
	Barcodes    []BarcodeArtifact `json:"barcodes,omitempty"`
}

type BodyHeuristics struct {
	UrgencyScore          int      `json:"urgencyScore"`
	FinancialScore        int      `json:"financialScore"`
	ObfuscationScore      int      `json:"obfuscationScore"`
	HomoglyphSuspicion    bool     `json:"homoglyphSuspicion"`
	ZeroFontDetected      bool     `json:"zeroFontDetected"`
	EncodedContentDensity bool     `json:"encodedContentDensity"`
	TyposquatSuspicion    bool     `json:"typosquatSuspicion"`
	QRCodeDetected        bool     `json:"qrCodeDetected"`
	ClickFixDetected      bool     `json:"clickFixDetected"`
	TyposquatMatches      []string `json:"typosquatMatches,omitempty"`
	ClickFixSignals       []string `json:"clickFixSignals,omitempty"`
	Matches               []string `json:"matches,omitempty"`
}

type ThreatIntelSummary struct {
	Lookups       []ReputationEntry `json:"lookups"`
	SkippedReason []string          `json:"skippedReason,omitempty"`
}

type ReputationEntry struct {
	Provider  string    `json:"provider"`
	Indicator string    `json:"indicator"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Score     int       `json:"score"`
	Found     bool      `json:"found"`
	Reference string    `json:"reference,omitempty"`
	Message   string    `json:"message,omitempty"`
	CheckedAt time.Time `json:"checkedAt"`
}

// MCIComponent represents a single weighted signal in the Malicious Confidence Index.
type MCIComponent struct {
	Category string `json:"category"`
	Signal   string `json:"signal"`
	Points   int    `json:"points"`
}

type RiskAssessment struct {
	Score        int            `json:"score"`
	Level        string         `json:"level"`
	Reasons      []string       `json:"reasons"`
	MCIBreakdown []MCIComponent `json:"mciBreakdown,omitempty"`
}
