package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/kennedy-aikohi/jigphish/internal/model"
)

type Parser interface {
	ParseFile(context.Context, string) (model.AnalysisResult, error)
}

type IntelClient interface {
	Enrich(context.Context, *model.AnalysisResult)
}

type Options struct {
	MaxWorkers int
}

type Engine struct {
	parser     Parser
	intel      IntelClient
	maxWorkers int
}

func New(parser Parser, intel IntelClient, opts Options) *Engine {
	workers := opts.MaxWorkers
	if workers < 1 {
		workers = 1
	}
	if workers > 32 {
		workers = 32
	}
	return &Engine{parser: parser, intel: intel, maxWorkers: workers}
}

func (e *Engine) AnalyzeFiles(ctx context.Context, paths []string) ([]model.AnalysisResult, error) {
	if len(paths) == 0 {
		return nil, errors.New("no email files supplied")
	}

	type job struct {
		index int
		path  string
	}
	type outcome struct {
		index  int
		result model.AnalysisResult
		err    error
	}

	jobs := make(chan job)
	outcomes := make(chan outcome, len(paths))
	var wg sync.WaitGroup

	workerCount := e.maxWorkers
	if len(paths) < workerCount {
		workerCount = len(paths)
	}
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				result, err := e.parser.ParseFile(ctx, j.path)
				if err == nil && e.intel != nil {
					e.intel.Enrich(ctx, &result)
				}
				outcomes <- outcome{index: j.index, result: result, err: err}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for i, p := range paths {
			select {
			case <-ctx.Done():
				return
			case jobs <- job{index: i, path: p}:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(outcomes)
	}()

	results := make([]outcome, 0, len(paths))
	for out := range outcomes {
		results = append(results, out)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].index < results[j].index })

	final := make([]model.AnalysisResult, 0, len(results))
	var joined error
	for _, out := range results {
		if out.err != nil {
			joined = errors.Join(joined, fmt.Errorf("%s: %w", paths[out.index], out.err))
			continue
		}
		final = append(final, out.result)
	}
	if ctx.Err() != nil {
		joined = errors.Join(joined, ctx.Err())
	}
	return final, joined
}
