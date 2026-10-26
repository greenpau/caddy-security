//go:build ignore

// Copyright 2026 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This report-only command consumes the projection verified by ci_tests.py.
// It reuses tested's renderer without fabricating single-process run metadata.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/greenpau/tested/pkg/artifact"
	"github.com/greenpau/tested/pkg/coverage"
	"github.com/greenpau/tested/pkg/protocol"
	"github.com/greenpau/tested/pkg/report"
	"github.com/greenpau/tested/pkg/result"
)

func render(directory string) error {
	workdir, err := os.Getwd()
	if err != nil {
		return err
	}
	layout, err := artifact.Resolve(workdir, directory)
	if err != nil {
		return err
	}
	if err := layout.PrepareReport(); err != nil {
		return err
	}
	analyzer, err := result.NewAnalyzer(result.AnalyzerOptions{
		MaxOutputBytes:      64 << 10,
		MaxTotalOutputBytes: 64 << 20,
	})
	if err != nil {
		return err
	}
	events, err := os.Open(layout.TestOutputJSONL)
	if err != nil {
		return err
	}
	var analysisErr error
	stream, readErr := protocol.Read(events, protocol.StreamOptions{
		Handler: func(record protocol.Record) {
			if err := analyzer.AddRecord(record); err != nil && analysisErr == nil {
				analysisErr = err
			}
		},
	})
	if err := errors.Join(readErr, analysisErr, events.Close()); err != nil {
		return err
	}
	snapshot := analyzer.Finalize(result.RunMetadata{
		WorkDir: workdir,
		Command: []string{"CI aggregate of verified test shards"},
	})
	if stream.DiagnosticCount != 0 || snapshot.Incomplete || snapshot.Signals.Any() ||
		snapshot.Summary.Tests.Failed != 0 || snapshot.Summary.Packages.Failed != 0 ||
		snapshot.Summary.IntegrityDiagnostics != 0 {
		return errors.New("aggregate test projection is unsuccessful or incomplete")
	}
	profile, err := coverage.ParseFile(layout.CoverageProfile)
	if err != nil {
		return err
	}
	renderer, err := report.New(report.Options{Title: "Caddy Security CI test and coverage report"})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := coverage.GenerateHTML(ctx, coverage.HTMLOptions{
		ProjectDir:  workdir,
		ProfilePath: layout.CoverageProfile,
		OutputPath:  layout.CoverageHTML,
		Decorate:    renderer.DecorateCoverageHTML,
	}); err != nil {
		return err
	}
	return renderer.Publish(layout, report.Input{Result: snapshot, Coverage: profile})
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run assets/scripts/ci_coverage_report.go REPORT_DIRECTORY")
		os.Exit(2)
	}
	if err := render(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
