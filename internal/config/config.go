package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type APIKeys struct {
	VirusTotal     string `json:"virustotal"`
	HybridAnalysis string `json:"hybrid_analysis"`
	AbuseIPDB      string `json:"abuseipdb"`
	Urlscan        string `json:"urlscan"`
}

type Config struct {
	AnalystName           string        `json:"analyst_name"`
	MaxWorkers            int           `json:"max_workers"`
	RequestTimeoutSeconds int           `json:"request_timeout_seconds"`
	RedirectLimit         int           `json:"redirect_limit"`
	UserAgent             string        `json:"user_agent"`
	GeoIPDatabasePath     string        `json:"geoip_database_path"`
	// StealthMode disables live network contact with threat-actor infrastructure:
	// redirect-following and ASN lookups are suppressed. Attachment hash and domain
	// reputation checks (VirusTotal et al.) are unaffected as they never contact
	// the attacker directly.
	StealthMode    bool          `json:"stealth_mode"`
	APIKeys        APIKeys       `json:"api_keys"`
	RequestTimeout time.Duration `json:"-"`
}

func Load(path string) (Config, error) {
	cfg := defaults()
	if path == "" {
		path = defaultConfigPath()
	}

	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg.RequestTimeout = time.Duration(cfg.RequestTimeoutSeconds) * time.Second
			return cfg, nil
		}
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.normalize()
	return cfg, nil
}

func defaults() Config {
	cfg := Config{
		AnalystName:           "SOC Analyst",
		MaxWorkers:            6,
		RequestTimeoutSeconds: 12,
		RedirectLimit:         7,
		UserAgent:             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 JigPhish/1.0",
	}
	cfg.normalize()
	return cfg
}

func (c *Config) normalize() {
	if c.MaxWorkers < 1 {
		c.MaxWorkers = 1
	}
	if c.MaxWorkers > 32 {
		c.MaxWorkers = 32
	}
	if c.RequestTimeoutSeconds < 3 {
		c.RequestTimeoutSeconds = 3
	}
	if c.RedirectLimit < 0 {
		c.RedirectLimit = 0
	}
	if c.RedirectLimit > 15 {
		c.RedirectLimit = 15
	}
	if c.UserAgent == "" {
		c.UserAgent = defaults().UserAgent
	}
	c.RequestTimeout = time.Duration(c.RequestTimeoutSeconds) * time.Second
}

func defaultConfigPath() string {
	if v := os.Getenv("JIGPHISH_CONFIG"); v != "" {
		return v
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "jigphish.local.json"
	}
	return filepath.Join(dir, "JigPhish", "jigphish.local.json")
}

// Resolve returns the effective config path: the provided path if non-empty,
// otherwise the platform default (%APPDATA%\JigPhish\jigphish.local.json on Windows).
func Resolve(path string) string {
	if path != "" {
		return path
	}
	return defaultConfigPath()
}

// Save writes cfg to path as indented JSON, creating the parent directory if needed.
// File permissions are set to 0600 so only the owning user can read API keys.
func Save(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}
