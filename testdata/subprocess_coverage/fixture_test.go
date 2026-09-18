// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package security

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

func runCoverageProcess(t *testing.T, mode string, wantStatus int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCoverageProcess$", "-test.timeout=10s")
	cmd.Env = append(os.Environ(), "CADDY_COVERAGE_FIXTURE_PROCESS="+mode)
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != wantStatus {
		t.Fatalf("%s process: %v\n%s", mode, err, output)
	}
	if mode == "exit" || mode == "exit-failure" {
		if string(output) != "CLI output\n" {
			t.Fatalf("coverage polluted CLI output: %q", output)
		}
	}
}

func TestCoverageE2E(t *testing.T) {
	if parentOnly() != 1 {
		t.Fatal("parent")
	}
	for _, mode := range []string{"child-1", "child-2", "exit", "exit-failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			status := 0
			if mode == "exit-failure" {
				status = 3
			}
			runCoverageProcess(t, mode, status)
		})
	}
}

func TestCoverageFailureE2E(t *testing.T) {
	runCoverageProcess(t, "failure", 0)
}

func TestCoverageParentOnly(t *testing.T) {
	if parentOnly() != 1 {
		t.Fatal("parent")
	}
}

func TestCoverageProcess(t *testing.T) {
	switch os.Getenv("CADDY_COVERAGE_FIXTURE_PROCESS") {
	case "":
		t.Skip("subprocess helper")
	case "child-1", "child-2":
		if childOnly() != 2 {
			t.Fatal("child")
		}
		runCoverageProcess(t, "grandchild", 0)
	case "grandchild":
		if grandchildOnly() != 3 {
			t.Fatal("grandchild")
		}
	case "exit":
		exitOnly()
		fmt.Println("CLI output")
		os.Exit(0)
	case "exit-failure":
		exitFailureOnly()
		fmt.Println("CLI output")
		os.Exit(3)
	case "failure":
		failedChildOnly()
		t.Fatal("intentional child failure")
	default:
		t.Fatal("unknown subprocess mode")
	}
}
