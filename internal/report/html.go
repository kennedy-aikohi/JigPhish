package report

import (
	"bytes"
	"html/template"
	"time"

	"github.com/kennedy-aikohi/jigphish/internal/model"
)

func RenderHTML(result model.AnalysisResult) ([]byte, error) {
	tpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = tpl.Execute(&buf, struct {
		Result    model.AnalysisResult
		Generated time.Time
	}{
		Result:    result,
		Generated: time.Now().UTC(),
	})
	return buf.Bytes(), err
}

const reportTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>JigPhish Investigation Report</title>
  <style>
    body { margin: 0; font-family: Inter, Segoe UI, Arial, sans-serif; background: #0B0F19; color: #E5E7EB; }
    main { padding: 32px; }
    h1, h2 { color: #F8FAFC; }
    table { width: 100%; border-collapse: collapse; margin: 16px 0; }
    th, td { border: 1px solid #1F2937; padding: 8px; text-align: left; vertical-align: top; }
    th { color: #67E8F9; background: #111827; }
    .watermark { margin-top: 32px; padding-top: 16px; border-top: 1px solid #06B6D4; color: #93C5FD; font-size: 12px; letter-spacing: .04em; }
  </style>
</head>
<body>
<main>
  <h1>JigPhish Investigation Report</h1>
  <p><strong>Subject:</strong> {{.Result.Subject}}</p>
  <p><strong>From:</strong> {{.Result.From}}</p>
  <p><strong>Risk:</strong> {{.Result.Risk.Level}} / {{.Result.Risk.Score}}</p>
  <h2>Defanged URLs</h2>
  <table><tr><th>Domain</th><th>Defanged</th><th>Final</th></tr>{{range .Result.URLs}}<tr><td>{{.Domain}}</td><td>{{.Defanged}}</td><td>{{.FinalDefanged}}</td></tr>{{end}}</table>
  <h2>Attachments</h2>
  <table><tr><th>Name</th><th>SHA-256</th><th>Size</th></tr>{{range .Result.Attachments}}<tr><td>{{.FileName}}</td><td>{{.SHA256}}</td><td>{{.SizeBytes}}</td></tr>{{end}}</table>
  <h2>Received Chain</h2>
  <table><tr><th>#</th><th>From</th><th>By</th><th>IP</th><th>Timestamp</th></tr>{{range .Result.ReceivedChain}}<tr><td>{{.Index}}</td><td>{{.FromHost}}</td><td>{{.ByHost}}</td><td>{{.IP}}</td><td>{{.Timestamp}}</td></tr>{{end}}</table>
  <div class="watermark">{{.Result.Watermark}} | Generated {{.Generated}}</div>
</main>
</body>
</html>`
