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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
	"golang.org/x/text/transform"
)

var errTerminalEncoding = errors.New("terminal input contains invalid UTF-8 or a replacement character; use a private credentials or secret file")

// x/term's editor can discard RuneError. Reject it before editing instead of
// silently changing a password; file input still supports a literal U+FFFD.
type terminalUTF8 struct{ transform.NopResetter }

func (terminalUTF8) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	for nSrc < len(src) {
		if !atEOF && !utf8.FullRune(src[nSrc:]) {
			return nDst, nSrc, transform.ErrShortSrc
		}
		value, size := utf8.DecodeRune(src[nSrc:])
		if value == utf8.RuneError {
			return nDst, nSrc, errTerminalEncoding
		}
		if len(dst)-nDst < size {
			return nDst, nSrc, transform.ErrShortDst
		}
		copy(dst[nDst:], src[nSrc:nSrc+size])
		nDst += size
		nSrc += size
	}
	return nDst, nSrc, nil
}

// Keep one editor per command so input already read after a newline remains
// available to the next prompt. Secret reads bypass the editor's echo/history.
type terminalInput struct {
	input  io.Reader
	output io.Writer
	editor *term.Terminal
}

func newTerminalInput(input io.Reader, output io.Writer) *terminalInput {
	editor := term.NewTerminal(struct {
		io.Reader
		io.Writer
	}{transform.NewReader(input, terminalUTF8{}), output}, "")
	return &terminalInput{input: input, output: output, editor: editor}
}

func (t *terminalInput) readLine(secret bool) (string, error) {
	if secret {
		return t.editor.ReadPassword("")
	}
	value, err := t.editor.ReadLine()
	// A pasted setup line is complete input, with subsequent lines retained
	// for the next prompt. Secret input still rejects embedded pasted newlines.
	if errors.Is(err, term.ErrPasteIndicator) {
		err = nil
	}
	return value, err
}

func (t *terminalInput) read(ctx context.Context, label string, secret bool) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f, ok := t.input.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return "", errors.New("terminal input required; use configuration flags or a private secret file for automation")
	}
	fd := int(f.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return "", errors.New("cannot read terminal input")
	}
	// The calling goroutine owns restoration, including cancellation. A blocked
	// editor has no deferred terminal reset that could race a later restore.
	defer term.Restore(fd, state)
	if _, err := fmt.Fprint(t.output, label); err != nil {
		return "", err
	}
	type answer struct {
		value string
		err   error
	}
	answers := make(chan answer, 1)
	go func() {
		value, err := t.readLine(secret)
		answers <- answer{value, err}
	}()
	select {
	case result := <-answers:
		if result.err != nil {
			if errors.Is(result.err, errTerminalEncoding) {
				return "", errTerminalEncoding
			}
			return "", errors.New("terminal input interrupted")
		}
		if !validValue(result.value) {
			return "", errors.New("invalid terminal input")
		}
		return result.value, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func readSecretFile(ctx context.Context, input io.Reader, path string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var data []byte
	var err error
	if path == "-" {
		// Stdin may be an idle pipe. Bound the caller by its command deadline.
		type result struct {
			data []byte
			err  error
		}
		ready := make(chan result, 1)
		go func() { data, err := io.ReadAll(io.LimitReader(input, maxFileSize+1)); ready <- result{data, err} }()
		select {
		case r := <-ready:
			data, err = r.data, r.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	} else {
		data, err = readFile(path, true)
	}
	if err != nil || len(data) > maxFileSize {
		return "", errors.New("cannot read private secret file or size limit exceeded")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	value := strings.TrimSuffix(string(data), "\n")
	if len(value) < len(data) {
		value = strings.TrimSuffix(value, "\r")
	}
	if !validValue(value) || value == "" {
		return "", errors.New("secret must contain a nonempty UTF-8 value without line breaks or NUL")
	}
	return value, nil
}
