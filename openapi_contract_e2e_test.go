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

package security

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

// The real Caddy process-global runtime is isolated from other suites. The
// contract reader consumes the selected module's authored schema, not a portal
// documentation endpoint or a separately generated sibling artifact.
func TestCaddyOpenAPIContractE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyOpenAPIContractProcess$", "-test.v", "-test.timeout=135s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_OPENAPI_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("TLS Caddy OpenAPI contracts: %v\n%s", err, output)
	}
}

func TestCaddyOpenAPIContractProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_OPENAPI_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	contracts := newOpenAPIContracts(t)
	cert, key, roots := cookieTLSCertificate(t)
	for _, tc := range []struct{ name, mount string }{{"root", ""}, {"nested", "/company/auth"}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCaddyAdminFixture(t, tc.mount, "enable admin api\ntransform user {\nmatch any\nadd contract_probe preserved as string\n}", true, cert, key, roots)
			browserToken := f.login(t, "keyadmin")
			memberToken := f.login(t, "keymember")
			const invalidToken = "malformed-openapi-credential"
			f.secrets = append(f.secrets, invalidToken)
			t.Run("negotiation", func(t *testing.T) {
				openAPIContractNegotiation(t, contracts, f, browserToken, invalidToken)
			})
			t.Run("metadata", func(t *testing.T) {
				for _, tc := range []struct {
					name, token string
					status      int
				}{{"admin", browserToken, 200}, {"member", memberToken, 403}, {"missing", "", 403}, {"invalid", invalidToken, 401}} {
					t.Run(tc.name, func(t *testing.T) {
						before := time.Now()
						r := openAPIContractRequest(t, f, "GET", f.mount+"/api/server/metadata", openAPIContractHeaders(tc.token, "application/json"), nil)
						openAPIContractStatus(t, r, tc.status)
						contracts.AssertResponse(t, "GET", "/api/server/metadata", r.status, r.header, r.body)
						openAPIContractPrivate(t, r)
						if tc.status == 200 {
							openAPIContractMedia(t, r, "text/plain")
							var metadata map[string]json.RawMessage
							if json.Unmarshal(r.body, &metadata) != nil {
								t.Fatal("metadata did not contain JSON bytes")
							}
							var timestamp string
							if json.Unmarshal(metadata["timestamp"], &timestamp) != nil {
								t.Fatal("metadata timestamp was not a string")
							}
							parsed, err := time.Parse(time.RFC3339Nano, timestamp)
							if err != nil || parsed.Before(before.Add(-time.Second)) || parsed.After(time.Now().Add(time.Second)) || !strings.HasSuffix(timestamp, "Z") {
								t.Fatal("metadata timestamp was not a current UTC RFC3339 time")
							}
							// The identity library owns optional name/version/build fields;
							// they must not be compared with the Caddy module's VERSION.
						}
					})
				}
			})
			t.Run("profile_session_boundary", func(t *testing.T) {
				openAPIContractProfile(t, contracts, f, browserToken)
			})
			t.Run("public_jwks_and_mount", func(t *testing.T) {
				openAPIContractJWKS(t, contracts, f, invalidToken)
			})
		})
	}
}

func openAPIContractHeaders(token, accept string) http.Header {
	headers := make(http.Header)
	if token != "" {
		headers.Set("Authorization", "Bearer "+token)
	}
	if accept != "" {
		headers.Set("Accept", accept)
	}
	return headers
}

// Preserve negotiated responses and redirects; the ordinary admin helper
// deliberately permits only JSON API responses without redirects.
func openAPIContractRequest(t *testing.T, f *caddyAdminFixture, method, target string, headers http.Header, body []byte) oidcRPResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, f.base+target, bytes.NewReader(body))
	if err != nil {
		t.Fatal("could not construct contract request")
	}
	req.Header = headers.Clone()
	if len(body) > 0 {
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := f.client.Do(req)
	if err != nil {
		t.Fatal("contract request failed over TLS")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		t.Fatal("invalid or oversized contract response")
	}
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("contract request did not use verified TLS")
	}
	encoded, err := json.Marshal(response.Header)
	if err != nil {
		t.Fatal("could not inspect contract response headers")
	}
	assertAdminRedacted(t, encoded, f.secrets)
	assertAdminRedacted(t, data, f.secrets)
	return oidcRPResponse{response.StatusCode, response.Header.Clone(), data}
}

func openAPIContractStatus(t *testing.T, response oidcRPResponse, want int) {
	t.Helper()
	if response.status != want {
		t.Fatalf("contract HTTP status: got %d, want %d", response.status, want)
	}
}

func openAPIContractMedia(t *testing.T, response oidcRPResponse, want string) {
	t.Helper()
	media, _, err := mime.ParseMediaType(response.header.Get("Content-Type"))
	if err != nil || media != want {
		t.Fatal("contract response used an unexpected media type")
	}
}

func openAPIContractPrivate(t *testing.T, response oidcRPResponse) {
	t.Helper()
	if response.header.Get("Cache-Control") != "no-store" || response.header.Get("Pragma") != "no-cache" {
		t.Fatal("portal contract response permitted caching")
	}
}

func openAPIContractNegotiation(t *testing.T, contracts *openAPIContracts, f *caddyAdminFixture, token, invalid string) {
	t.Helper()
	for _, endpoint := range []string{"/beacon", "/whoami"} {
		for _, format := range []struct {
			name, accept, query string
			json                bool
		}{
			{"exact", "application/json", "", true},
			{"absent", "", "", false},
			{"parameter", "application/json; charset=utf-8", "", false},
			{"list", "application/json, text/html;q=0.9", "", false},
			{"query", "text/html", "?format=json", true},
		} {
			for _, identity := range []struct{ name, token string }{{"valid", token}, {"missing", ""}, {"invalid", invalid}} {
				t.Run(strings.TrimPrefix(endpoint, "/")+"/"+format.name+"/"+identity.name, func(t *testing.T) {
					r := openAPIContractRequest(t, f, "GET", f.mount+endpoint+format.query, openAPIContractHeaders(identity.token, format.accept), nil)
					status := 200
					switch {
					case !format.json && endpoint == "/beacon":
						status = 404
					case identity.name != "valid" && format.json:
						status = 401
					case identity.name != "valid":
						status = 302
					}
					openAPIContractStatus(t, r, status)
					contracts.AssertResponse(t, "GET", endpoint, r.status, r.header, r.body)
					openAPIContractPrivate(t, r)
					if format.json {
						openAPIContractMedia(t, r, "application/json")
						if r.header.Get("Location") != "" {
							t.Fatal("JSON probe redirected")
						}
						if status == 200 && endpoint == "/beacon" && string(r.body) != "OK" {
							t.Fatal("successful beacon changed its raw two-byte body")
						}
						if status == 200 && endpoint == "/whoami" {
							openAPIContractClaims(t, r.body, false, time.Now(), time.Now())
						}
					} else if status == 302 {
						location, err := url.Parse(r.header.Get("Location"))
						if err != nil || location.Scheme+"://"+location.Host != f.base || location.Path != f.mount+"/login" || len(r.body) != 0 {
							t.Fatal("HTML identity rejection lost its portal login redirect")
						}
					} else {
						openAPIContractMedia(t, r, "text/html")
						if endpoint == "/whoami" && (!bytes.Contains(r.body, []byte("keyadmin@example.test")) || !bytes.Contains(r.body, []byte("expires_at_utc"))) {
							t.Fatal("HTML identity page omitted its account or display times")
						}
					}
				})
			}
		}
	}
	before := time.Now()
	r := openAPIContractRequest(t, f, "GET", f.mount+"/whoami?probe=true&id_token=true", openAPIContractHeaders(token, "application/json"), nil)
	after := time.Now()
	openAPIContractStatus(t, r, 200)
	contracts.AssertResponse(t, "GET", "/whoami", r.status, r.header, r.body)
	openAPIContractPrivate(t, r)
	openAPIContractClaims(t, r.body, true, before, after)
}

func openAPIContractClaims(t *testing.T, body []byte, probe bool, before, after time.Time) {
	t.Helper()
	var claims map[string]json.RawMessage
	if json.Unmarshal(body, &claims) != nil {
		t.Fatal("identity response was not a JSON object")
	}
	for name, want := range map[string]string{"sub": "keyadmin", "email": "keyadmin@example.test", "origin": "local", "contract_probe": "preserved"} {
		var value string
		if json.Unmarshal(claims[name], &value) != nil || value != want {
			t.Fatalf("identity claim %s changed", name)
		}
	}
	var roles []string
	if json.Unmarshal(claims["roles"], &roles) != nil || !slices.Contains(roles, "authp/admin") {
		t.Fatal("identity response lost the authenticated role")
	}
	var issued, expires, notBefore int64
	if json.Unmarshal(claims["iat"], &issued) != nil || json.Unmarshal(claims["exp"], &expires) != nil || json.Unmarshal(claims["nbf"], &notBefore) != nil || issued < before.Add(-5*time.Minute).Unix() || issued > after.Add(time.Second).Unix() || expires <= issued || expires-issued > 24*60*60 || notBefore > issued || issued-notBefore > 300 {
		t.Fatal("identity times were not plausible integer Unix seconds")
	}
	for _, name := range []string{"expires_at_utc", "issued_at_utc", "not_before_utc", "id_token"} {
		if _, exists := claims[name]; exists {
			t.Fatal("JSON claims leaked HTML display fields or an unconfigured identity token")
		}
	}
	if probe {
		var authenticated bool
		var remaining int64
		if json.Unmarshal(claims["authenticated"], &authenticated) != nil || !authenticated || json.Unmarshal(claims["expires_in"], &remaining) != nil || remaining < expires-after.Unix() || remaining > expires-before.Unix() {
			t.Fatal("probe lifetime was not the remaining duration in seconds")
		}
	} else if claims["expires_in"] != nil || claims["authenticated"] != nil {
		t.Fatal("ordinary identity response gained probe-only annotations")
	}
}

func openAPIContractProfile(t *testing.T, contracts *openAPIContracts, f *caddyAdminFixture, browserToken string) {
	t.Helper()
	request := []byte(`{"kind":"fetch_user_info"}`)
	headers := openAPIContractHeaders(browserToken, "application/json")
	headers.Set("Content-Type", "application/json")
	contracts.AssertRequest(t, "POST", "/api/profile", headers, request)
	r := openAPIContractRequest(t, f, "POST", f.mount+"/api/profile", headers, request)
	openAPIContractStatus(t, r, 200)
	contracts.AssertResponse(t, "POST", "/api/profile", r.status, r.header, r.body)
	openAPIContractPrivate(t, r)
	var profile struct {
		Entry json.RawMessage `json:"entry"`
	}
	if json.Unmarshal(r.body, &profile) != nil {
		t.Fatal("profile result was not JSON")
	}
	contracts.AssertComponent(t, "ProfileUserInfo", profile.Entry)
	var entry struct {
		Metadata struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		} `json:"metadata"`
		Token string `json:"token"`
	}
	if json.Unmarshal(profile.Entry, &entry) != nil || entry.Metadata.Username != "keyadmin" || entry.Metadata.Email != "keyadmin@example.test" || !json.Valid([]byte(entry.Token)) {
		t.Fatal("profile entry lost its canonical account or JSON-encoded claims")
	}
	var sessionClaims map[string]json.RawMessage
	if json.Unmarshal([]byte(entry.Token), &sessionClaims) != nil || sessionClaims["expires_at_utc"] == nil {
		t.Fatal("profile claims omitted the documented display-time projection")
	}
	// Obtain a real access-only credential, without manufacturing a JWT or a
	// browser session. The optional wire observer checks this selected journey.
	wire := &authenticationClientWire{t: t, next: f.client.Transport, path: f.mount + "/login", password: lifecyclePassword, contracts: contracts}
	client := *f.client
	client.Transport = wire
	login, err := authclient.NewClient(&authclient.Config{BaseURL: f.base + f.mount, Username: "keyadmin", Realm: "local", Password: lifecyclePassword}, authclient.Options{HTTPClient: &client})
	if err != nil {
		t.Fatal("could not construct the actual access-only client")
	}
	credentials, err := login.Authenticate(t.Context())
	if err != nil || credentials == nil || credentials.AccessToken == "" || credentials.RefreshToken != "" || credentials.AccessToken == browserToken || wire.requests < 2 {
		t.Fatal("actual access-only password login failed")
	}
	f.secrets = append(f.secrets, credentials.AccessToken)
	for _, checkpoint := range wire.responses {
		f.secrets = append(f.secrets, checkpoint.SandboxSecret)
	}
	r = openAPIContractRequest(t, f, "POST", f.mount+"/api/profile", openAPIContractHeaders(credentials.AccessToken, "application/json"), request)
	openAPIContractStatus(t, r, 401)
	contracts.AssertResponse(t, "POST", "/api/profile", r.status, r.header, r.body)
	openAPIContractPrivate(t, r)
	// Administration authorizes the genuine admin token without requiring the
	// stored browser evidence that the immediately preceding profile read lacked.
	r = openAPIContractRequest(t, f, "GET", f.mount+"/api/server/metadata", openAPIContractHeaders(credentials.AccessToken, "application/json"), nil)
	openAPIContractStatus(t, r, 200)
	contracts.AssertResponse(t, "GET", "/api/server/metadata", r.status, r.header, r.body)
	openAPIContractMedia(t, r, "text/plain")
	openAPIContractPrivate(t, r)
	for _, tc := range []struct {
		name, token string
		status      int
	}{{"stored browser session", browserToken, 200}, {"access-only login", credentials.AccessToken, 403}} {
		r = openAPIContractRequest(t, f, "GET", f.mount+"/whoami?probe=login", openAPIContractHeaders(tc.token, "application/json"), nil)
		openAPIContractStatus(t, r, tc.status)
		contracts.AssertResponse(t, "GET", "/whoami", r.status, r.header, r.body)
		openAPIContractPrivate(t, r)
	}
	// The denied profile does not make a genuine access token invalid.
	r = openAPIContractRequest(t, f, "GET", f.mount+"/whoami?probe=true", openAPIContractHeaders(credentials.AccessToken, "application/json"), nil)
	openAPIContractStatus(t, r, 200)
	contracts.AssertResponse(t, "GET", "/whoami", r.status, r.header, r.body)
	openAPIContractPrivate(t, r)
}

func openAPIContractJWKS(t *testing.T, contracts *openAPIContracts, f *caddyAdminFixture, invalid string) {
	t.Helper()
	get := openAPIContractRequest(t, f, "GET", f.mount+adminJWKSPath, openAPIContractHeaders(invalid, "text/html"), nil)
	openAPIContractStatus(t, get, 200)
	contracts.AssertResponse(t, "GET", adminJWKSPath, get.status, get.header, get.body)
	f.publicKey(t, get.body)
	openAPIContractMedia(t, get, "application/jwk-set+json")
	if get.header.Get("Content-Length") != strconv.Itoa(len(get.body)) || get.header.Get("Cache-Control") != "no-store" || get.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("JWKS lost exact length or public response protections")
	}
	head := openAPIContractRequest(t, f, "HEAD", f.mount+adminJWKSPath, nil, nil)
	openAPIContractStatus(t, head, 200)
	contracts.AssertResponse(t, "HEAD", adminJWKSPath, head.status, head.header, head.body)
	if len(head.body) != 0 {
		t.Fatal("HEAD JWKS returned a response body")
	}
	for _, header := range []string{"Content-Type", "Content-Length", "Cache-Control", "X-Content-Type-Options"} {
		if head.header.Get(header) != get.header.Get(header) {
			t.Fatalf("HEAD JWKS changed its %s contract", header)
		}
	}
	if f.mount != "" {
		for _, target := range []string{adminJWKSPath, f.mount + "entication" + adminJWKSPath, "/other" + f.mount + adminJWKSPath} {
			r := openAPIContractRequest(t, f, "GET", target, nil, nil)
			openAPIContractStatus(t, r, 404)
			if string(r.body) != "unmatched" || len(r.header.Values("Set-Cookie")) != 0 {
				t.Fatal("unmounted discovery path entered the portal")
			}
		}
	}
	for _, target := range []struct {
		path   string
		status int
	}{{adminJWKSPath + ".extra", 404}, {"/openapi.json", 404}, {"/openapi.yaml", 404}, {"/api/docs", 400}} {
		r := openAPIContractRequest(t, f, "GET", f.mount+target.path, nil, nil)
		openAPIContractStatus(t, r, target.status)
		if bytes.Contains(r.body, []byte(`"keys"`)) || bytes.Contains(r.body, []byte(`"openapi"`)) {
			t.Fatal("undocumented path exposed discovery or an invented documentation endpoint")
		}
	}
}
