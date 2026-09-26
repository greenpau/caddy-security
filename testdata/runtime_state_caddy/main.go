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

// This executable runs Caddy's real command and production modules. Its only
// fixture addition installs an isolated TLS root pool before any networking.
package main

import (
	"crypto/x509"
	"os"
	_ "unsafe" // Go issue 67401: fixture trust, never an OS trust-store change.

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/greenpau/caddy-security"
	_ "github.com/greenpau/caddy-trace"
)

//go:linkname systemRoots crypto/x509.systemRoots
var systemRoots *x509.CertPool

func main() {
	if path := os.Getenv("CADDY_SECURITY_TEST_CA"); path != "" {
		if _, err := x509.SystemCertPool(); err != nil {
			panic("initialize fixture roots")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			panic("read fixture root")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			panic("decode fixture root")
		}
		systemRoots = roots
	}
	caddycmd.Main()
}
