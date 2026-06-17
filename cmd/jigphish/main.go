package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/kennedy-aikohi/jigphish/internal/app"
	"github.com/kennedy-aikohi/jigphish/internal/config"
	"github.com/kennedy-aikohi/jigphish/internal/engine"
	"github.com/kennedy-aikohi/jigphish/internal/intel"
	"github.com/kennedy-aikohi/jigphish/internal/parser"
)

func main() {
	configFlag := flag.String("config", "", "path to JigPhish local JSON config")
	headless := flag.Bool("headless", false, "run CLI analysis without launching Wails")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfgPath := config.Resolve(*configFlag)
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

	if *headless {
		if flag.NArg() == 0 {
			log.Fatal("headless mode requires at least one .eml path")
		}
		results, err := analysisEngine.AnalyzeFiles(ctx, flag.Args())
		if err != nil {
			log.Fatalf("analysis failed: %v", err)
		}
		for _, result := range results {
			fmt.Printf("%s\t%s\t%s\t%d\t%s\n",
				filepath.Base(result.FileName), result.From, result.Subject,
				result.Risk.Score, result.Risk.Level)
		}
		return
	}

	if err := app.Run(ctx, analysisEngine, cfg, cfgPath); err != nil {
		log.Fatalf("launch app: %v", err)
	}
}
