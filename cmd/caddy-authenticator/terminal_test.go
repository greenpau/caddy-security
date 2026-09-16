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

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestTerminalKeepsBufferedSetupInput(t *testing.T) {
	for _, input := range []string{"https://example.test\nlocal\nalice\n", "\x1b[200~https://example.test\nlocal\nalice\x1b[201~\n"} {
		var output bytes.Buffer
		terminal := newTerminalInput(strings.NewReader(input), &output)
		for _, want := range []string{"https://example.test", "local", "alice"} {
			got, err := terminal.readLine(false)
			if err != nil || got != want {
				t.Fatal("setup input was lost between prompts")
			}
		}
	}
}

func TestTerminalSecretsStayOutOfEchoAndHistory(t *testing.T) {
	var output bytes.Buffer
	terminal := newTerminalInput(strings.NewReader("synthetic-password\n123456\n\x1b[A\n"), &output)
	for _, want := range []string{"synthetic-password", "123456", ""} {
		got, err := terminal.readLine(true)
		if err != nil || got != want {
			t.Fatal("secret input changed or entered terminal history")
		}
	}
	if strings.Contains(output.String(), "synthetic-password") || strings.Contains(output.String(), "123456") {
		t.Fatal("terminal echoed secret input")
	}
}

func TestTerminalRejectsMalformedSecret(t *testing.T) {
	for _, value := range []string{"secret-\xff\n", "secret-\ufffd\n", "secret-\xc3"} {
		var output bytes.Buffer
		terminal := newTerminalInput(strings.NewReader(value), &output)
		if _, err := terminal.readLine(true); !errors.Is(err, errTerminalEncoding) {
			t.Fatal("malformed terminal input was accepted or changed")
		}
		if strings.Contains(output.String(), "secret") {
			t.Fatal("malformed secret was echoed")
		}
	}
}
