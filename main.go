package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kennedy-aikohi/jigphish/internal/app"
	"github.com/kennedy-aikohi/jigphish/internal/config"
	"github.com/kennedy-aikohi/jigphish/internal/engine"
	"github.com/kennedy-aikohi/jigphish/internal/intel"
	"github.com/kennedy-aikohi/jigphish/internal/parser"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfgPath := config.Resolve("")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	emailParser := parser.New(parser.Options{
		RedirectLimit: cfg.RedirectLimit,
		UserAgent:     cfg.UserAgent,
		Timeout:       cfg.RequestTimeout,
		GeoIPPath:     cfg.GeoIPDatabasePath,
		StealthMode:   cfg.StealthMode,
	})
	intelClient := intel.NewClient(cfg.APIKeys, intel.Options{
		Timeout:   cfg.RequestTimeout,
		UserAgent: cfg.UserAgent,
	})
	analysisEngine := engine.New(emailParser, intelClient, engine.Options{
		MaxWorkers: cfg.MaxWorkers,
	})

	if err := app.Run(ctx, analysisEngine, cfg, cfgPath); err != nil {
		log.Fatalf("launch app: %v", err)
	}
}
