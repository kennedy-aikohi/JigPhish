# JigPhish

**Local-first phishing email intelligence workbench for SOC analysts and DFIR practitioners.**

> Built by [KENNEDY AIKOHI](https://github.com/kennedy-aikohi) · MIT License

---

## What it does

JigPhish parses `.eml` files on your desktop and produces a structured forensic analysis — no cloud upload, no external processing. Every byte of email content stays on your machine.

Drop an `.eml` file, get back:

- Full SPF / DKIM / DMARC verdict with RFC 7601-compliant parsing (no false positives from attacker-injected headers)
- Received-chain routing forensics with hop-by-hop GeoIP and bulletproof ASN detection
- Sender IP cross-referenced live against VirusTotal, AbuseIPDB, and urlscan.io
- URL artifact extraction with redirect-chain following and full OSINT enrichment
- **QR code / quishing detection** — decodes barcodes from image attachments and inline HTML images, injects extracted URLs into the OSINT pipeline
- **ClickFix / Paste-and-Run detection** — 9 independent signals covering clipboard hijack JS, Win+R instructions, fake CAPTCHAs, PowerShell download cradles, and more
- Attachment SHA-256 cross-referenced against VirusTotal and Hybrid Analysis
- Weighted Malicious Confidence Index (MCI) with per-signal audit trail and full breakdown
- Typosquatting detection via Levenshtein distance + homoglyph normalisation (PSL-correct)
- Full JSON export for SIEM ingestion or ticket documentation
- **Stealth Mode** — zero live contact with attacker infrastructure (redirect following and ASN lookups suppressed)

---

## Detection capabilities at a glance

| Category | Signals |
|---|---|
| **Email Authentication** | SPF · DKIM · DMARC · alignment (relaxed, PSL-correct) · trust-model (RFC 7601 §7.2) |
| **Routing Forensics** | Received-chain reconstruction · timestamp inversion · missing public IP · GeoIP · bulletproof ASN |
| **IP OSINT** | Sender routing-hop IPs → VirusTotal IP · AbuseIPDB · urlscan.io (page.ip) |
| **URL OSINT** | Domain → VT domain + VT URL (per-path) · AbuseIPDB (bare-IP URLs) · urlscan.io |
| **File OSINT** | Attachment SHA-256 → VirusTotal files · Hybrid Analysis |
| **QR / Quishing** | ZXing multi-reader on image attachments + inline `data:image` base64 blobs |
| **ClickFix** | Clipboard JS hijack · Win+R · PowerShell launch · Paste-and-run · Fake CAPTCHA · Encoded PS · LoLBins · Download cradle |
| **Obfuscation** | Zero-font / hidden CSS · Homoglyph / mixed Latin-Cyrillic · High-density HTML entity encoding |
| **Social Engineering** | Urgency language · Financial language · Typosquat / lookalike domains |

---

## Screenshots

> Drop a screenshot here — launch `build/bin/JigPhish.exe` and drag in a `.eml` to generate one.

---

## Requirements

| Tool | Version |
|---|---|
| Go | 1.22 or newer |
| Node.js | 20 or newer |
| Wails CLI | v2.12 or newer |

Install Wails:
```powershell
go install github.com/wailsapp/wails/v2/cmd/wails@latest
```

---

## Build

```powershell
git clone https://github.com/kennedy-aikohi/JigPhish.git
cd JigPhish
wails build
```

The compiled binary is written to `build/bin/JigPhish.exe`.

### Development mode (hot-reload)

```powershell
wails dev
```

### Headless batch mode (no GUI)

```powershell
go run .\cmd\jigphish -headless -config .\configs\jigphish.example.json .\testdata\phishing-test.eml
```

---

## Configuration

Copy the example config to your local config path:

```powershell
# Windows — recommended location
copy configs\jigphish.example.json "$env:APPDATA\JigPhish\jigphish.local.json"
```

Or set the `JIGPHISH_CONFIG` environment variable to any path, or pass `-config <path>` at the command line.

**`jigphish.example.json`**
```json
{
  "analyst_name": "SOC Analyst",
  "max_workers": 6,
  "request_timeout_seconds": 12,
  "redirect_limit": 7,
  "stealth_mode": false,
  "api_keys": {
    "virustotal": "",
    "hybrid_analysis": "",
    "abuseipdb": "",
    "urlscan": ""
  }
}
```

API keys can also be configured from the Settings panel inside the GUI (`Ctrl+,`). Keys are stored locally and are never transmitted with email content.

### API key sources

| Provider | Free tier |
|---|---|
| [VirusTotal](https://www.virustotal.com/gui/my-apikey) | 4 req/min · 500/day |
| [Hybrid Analysis](https://www.hybrid-analysis.com/apikeys/info) | 200 req/min |
| [AbuseIPDB](https://www.abuseipdb.com/account/api) | 1,000 req/day |
| [urlscan.io](https://urlscan.io/user/profile/) | 60 req/min |

All are optional. JigPhish runs fully offline without any keys.

---

## Privacy model

JigPhish does **not** upload email bodies or attachment contents to any external service.

- Attachments are streamed through local MD5 / SHA-1 / SHA-256 hashers only
- OSINT lookups transmit hashes, domain names, and IP addresses — never raw email data
- URL redirect resolution uses a local HTTP client with a configurable user agent
- In **Stealth Mode**, all live network contact is suppressed — only local heuristic analysis runs

---

## Project layout

```
JigPhish/
├── cmd/jigphish/         # CLI entrypoint (headless batch mode)
├── internal/
│   ├── app/              # Wails bindings (IPC layer)
│   ├── config/           # Config loading (file → env → flags)
│   ├── engine/           # Concurrent worker pool for multi-file analysis
│   ├── intel/            # OSINT clients (VT, Hybrid Analysis, AbuseIPDB, urlscan.io)
│   ├── model/            # Shared data types (AnalysisResult, BarcodeArtifact, …)
│   ├── parser/           # MIME parser, auth assessment, barcode scanner, ClickFix detector
│   └── report/           # HTML report renderer
├── pkg/defang/           # URL defanging utility
├── frontend/
│   ├── src/              # React + Tailwind UI (App.tsx, style.css)
│   └── wailsjs/          # Auto-generated Go→TypeScript bindings
├── build/
│   ├── appicon.png       # Application icon
│   └── windows/          # Windows manifest and icon resources
├── configs/
│   └── jigphish.example.json
└── testdata/
    └── phishing-test.eml # Multi-signal test email for validating detection
```

---

## MCI scoring

The **Malicious Confidence Index** is a weighted scoring system capped at 100. Every point is traceable to a named signal in the "Full MCI Breakdown" tab:

| Category | Example signals | Weight |
|---|---|---|
| Auth | DMARC hard fail | 30 |
| Auth | SPF hard fail | 20 |
| Auth | Return-Path / From misalignment | 25 |
| Routing | Bulletproof / high-risk ASN | 40 |
| Routing | Received-chain timestamp inversion | 20 |
| Social engineering | ClickFix (per corroborating signal) | up to 60 |
| Obfuscation | QR code with embedded URL | 30 |
| Obfuscation | Zero-font / hidden CSS | 30 |
| Spoofing | Typosquatting lookalike domain | 40 |

OSINT hits from live providers add `score / 5` to the MCI after the base analysis.

---

## Author

**KENNEDY AIKOHI**
[github.com/kennedy-aikohi](https://github.com/kennedy-aikohi)

Built for the blue team. Released freely under MIT.

---

## License

MIT — see [LICENSE](LICENSE).
