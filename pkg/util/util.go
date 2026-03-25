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

package util

import (
	"errors"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
	"github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// FindReplaceAll uses caddy.Replacer to replace strings in a given slice.
func FindReplaceAll(repl *caddy.Replacer, arr []string) ([]string, bool, error) {
	var outputs []string
	var anyReplaced bool
	for _, item := range arr {
		output, replaced, err := FindReplace(repl, item)
		if err != nil {
			return outputs, replaced, err
		}
		if replaced {
			anyReplaced = true
		}
		outputs = append(outputs, output)
	}
	return outputs, anyReplaced, nil
}

// FindReplace uses caddy.Replacer to replace strings in a given string.
func FindReplace(repl *caddy.Replacer, s string) (string, bool, error) {
	var replaced bool
	output := repl.ReplaceAll(s, cfg.ReplErrStr)
	if strings.Contains(output, cfg.ReplErrStr) {
		return "", true, errors.New("failed to perform replacement")
	}
	if output != s {
		replaced = true
	}
	return output, replaced, nil
}

// GetRequestID returns HTTP request id.
func GetRequestID(r *http.Request) string {
	rawRequestID := caddyhttp.GetVar(r.Context(), "request_id")
	if rawRequestID == nil {
		requestID := r.Header.Get("X-Request-Id")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		caddyhttp.SetVar(r.Context(), "request_id", requestID)
		return requestID
	}
	return rawRequestID.(string)
}
