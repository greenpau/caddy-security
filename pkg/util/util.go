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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
	"github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"net/http"
)

// FindReplaceAll uses caddy.Replacer to replace strings in a given slice.
func FindReplaceAll(repl *caddy.Replacer, arr []string) (output []string) {
	for _, item := range arr {
		output = append(output, repl.ReplaceAll(item, cfg.ReplErrStr))
	}
	return output
}

// FindReplace uses caddy.Replacer to replace strings in a given string.
func FindReplace(repl *caddy.Replacer, s string) string {
	return repl.ReplaceAll(s, cfg.ReplErrStr)
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
