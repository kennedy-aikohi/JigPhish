package app

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/kennedy-aikohi/jigphish/internal/config"
	"github.com/kennedy-aikohi/jigphish/internal/engine"
	"github.com/kennedy-aikohi/jigphish/internal/model"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:assets
var embeddedAssets embed.FS

type App struct {
	ctx     context.Context
	engine  *engine.Engine
	cfg     config.Config
	cfgPath string
}

// AppConfigView is the read-only settings payload sent to the frontend.
// API keys are never exposed — only boolean presence flags are returned.
type AppConfigView struct {
	AnalystName       string `json:"analystName"`
	StealthMode       bool   `json:"stealthMode"`
	MaxWorkers        int    `json:"maxWorkers"`
	RedirectLimit     int    `json:"redirectLimit"`
	VTConfigured      bool   `json:"vtConfigured"`
	HAConfigured      bool   `json:"haConfigured"`
	AIPDBConfigured   bool   `json:"aipdbConfigured"`
	URLScanConfigured bool   `json:"urlscanConfigured"`
}

// APIKeyInput carries new API keys and settings from the frontend.
// Empty key strings are treated as "keep existing value".
type APIKeyInput struct {
	VirusTotal     string `json:"virustotal"`
	HybridAnalysis string `json:"hybridAnalysis"`
	AbuseIPDB      string `json:"abuseipdb"`
	Urlscan        string `json:"urlscan"`
	AnalystName    string `json:"analystName"`
	StealthMode    bool   `json:"stealthMode"`
}

func New(eng *engine.Engine, cfg config.Config, cfgPath string) *App {
	return &App{engine: eng, cfg: cfg, cfgPath: cfgPath}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// GetConfig returns the current non-sensitive configuration state.
func (a *App) GetConfig() AppConfigView {
	return AppConfigView{
		AnalystName:       a.cfg.AnalystName,
		StealthMode:       a.cfg.StealthMode,
		MaxWorkers:        a.cfg.MaxWorkers,
		RedirectLimit:     a.cfg.RedirectLimit,
		VTConfigured:      a.cfg.APIKeys.VirusTotal != "",
		HAConfigured:      a.cfg.APIKeys.HybridAnalysis != "",
		AIPDBConfigured:   a.cfg.APIKeys.AbuseIPDB != "",
		URLScanConfigured: a.cfg.APIKeys.Urlscan != "",
	}
}

// SaveAPIKeys persists the provided keys to the local config file.
// Blank key strings preserve the existing stored value.
// API key changes take effect on the next application launch.
func (a *App) SaveAPIKeys(input APIKeyInput) error {
	if input.VirusTotal != "" {
		a.cfg.APIKeys.VirusTotal = input.VirusTotal
	}
	if input.HybridAnalysis != "" {
		a.cfg.APIKeys.HybridAnalysis = input.HybridAnalysis
	}
	if input.AbuseIPDB != "" {
		a.cfg.APIKeys.AbuseIPDB = input.AbuseIPDB
	}
	if input.Urlscan != "" {
		a.cfg.APIKeys.Urlscan = input.Urlscan
	}
	if input.AnalystName != "" {
		a.cfg.AnalystName = input.AnalystName
	}
	a.cfg.StealthMode = input.StealthMode
	return config.Save(a.cfgPath, a.cfg)
}

func (a *App) AnalyzePaths(paths []string) ([]model.AnalysisResult, error) {
	if a.engine == nil {
		return nil, fmt.Errorf("analysis engine is not initialized")
	}
	paths, err := cleanEvidencePaths(paths)
	if err != nil {
		return nil, err
	}
	return a.engine.AnalyzeFiles(a.ctx, paths)
}

func (a *App) SelectEmailFiles() ([]model.AnalysisResult, error) {
	if a.ctx == nil {
		return nil, fmt.Errorf("application context is not ready")
	}
	paths, err := runtime.OpenMultipleFilesDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select email evidence",
		Filters: []runtime.FileFilter{
			{
				DisplayName: "Email evidence (*.eml)",
				Pattern:     "*.eml",
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("open evidence dialog: %w", err)
	}
	if len(paths) == 0 {
		return nil, nil
	}
	return a.AnalyzePaths(paths)
}

func (a *App) Watermark() string {
	return model.Watermark
}

func (a *App) Version() string {
	return model.Version
}

func Run(ctx context.Context, analysisEngine *engine.Engine, cfg config.Config, cfgPath string) error {
	application := New(analysisEngine, cfg, cfgPath)
	assets, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		return fmt.Errorf("load embedded frontend assets: %w", err)
	}
	return wails.Run(&options.App{
		Title:            "JigPhish",
		Width:            1560,
		Height:           960,
		MinWidth:         1200,
		MinHeight:        780,
		BackgroundColour: &options.RGBA{R: 11, G: 15, B: 25, A: 1},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		DragAndDrop: &options.DragAndDrop{
			EnableFileDrop:     true,
			DisableWebViewDrop: true,
		},
		OnStartup: application.startup,
		Bind: []interface{}{
			application,
		},
	})
}

func cleanEvidencePaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("drop or select at least one .eml file")
	}
	cleaned := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".eml" {
			return nil, fmt.Errorf("unsupported evidence type %q for %s; JigPhish currently accepts .eml files", ext, filepath.Base(path))
		}
		cleaned = append(cleaned, path)
	}
	if len(cleaned) == 0 {
		return nil, fmt.Errorf("drop or select at least one .eml file")
	}
	return cleaned, nil
}
