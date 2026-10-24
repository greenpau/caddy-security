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
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

func TestCaddyPortalMountE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyPortalMountProcess$", "-test.v", "-test.timeout=170s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_PORTAL_MOUNT_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy explicit portal mounts: %v\n%s", err, output)
	}
}

func TestCaddyPortalMountProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_PORTAL_MOUNT_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	for _, scenario := range []struct{ name, mount string }{
		{"root", ""}, {"nested", "/company/auth"}, {"permitted_lookalike", "/saml-service"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			declared := scenario.mount
			if declared == "" {
				declared = "/"
			}
			f := newLocalIdentityFixture(t, localIdentityOptions{mount: scenario.mount, refreshRealm: "local", oidcRealm: "local", configure: func(input string) string {
				input = strings.Replace(input, "enable identity stores localdb excludeddb", "enable identity store localdb", 1)
				input = strings.Replace(input, "authenticate with myportal", "authenticate with myportal at "+declared, 1)
				// The explicit handler, rather than a restrictive Caddy matcher,
				// must reject neighboring and encoded-alias requests. The real
				// protected resource remains ahead of this broad portal route.
				routes := "route /rewrite-probe {\nrewrite * " + scenario.mount + "/login\nauthenticate with myportal at " + declared + "\n}\n  route {"
				return strings.Replace(input, "route "+scenario.mount+"/* {", routes, 1)
			}}, cert, key, roots)
			portalMountDiscovery(t, f)
			portalMountLanding(t, f)
			portalMountAPIRejections(t, f)
			portalMountBoundary(t, f)
			before := portalMountLogin(t, f)
			portalMountAPIRejections(t, f)
			portalMountBoundary(t, f)
			if after := portalMountWhoami(t, f); after != before {
				t.Fatal("mount or API rejection changed authenticated identity or refresh session")
			}
			if scenario.name == "nested" {
				portalMountRejectedReload(t, f, before)
				portalMountNativeRefreshOverride(t, f)
			}
		})
	}
	t.Run("legacy_omission", func(t *testing.T) {
		f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/legacy/auth", refreshRealm: "local", oidcRealm: "local"}, cert, key, roots)
		portalMountDiscovery(t, f)
		portalMountLogin(t, f)
	})
	t.Run("cold_persistent_native_rejection", func(t *testing.T) {
		portalMountColdRejection(t, cert, key)
	})
}

// The helper captures issued synthetic credentials before any assertion can
// fail, and uses the shared bounded, TLS-verifying request transport without
// printing URI, response bodies, Location or Cookie headers.
func portalMountRequest(t *testing.T, f *localIdentityFixture, method, target string, form url.Values, headers http.Header) oidcRPResponse {
	t.Helper()
	response := providerDestinationRequest(t, f.oidcRPFixture, method, target, form, headers)
	for _, cookie := range (&http.Response{Header: response.header}).Cookies() {
		if cookie.Value == "" || cookie.MaxAge < 0 {
			continue
		}
		if cookie.Name == "AUTHP_SANDBOX_ID" || strings.HasPrefix(cookie.Name, "AUTHP_SANDBOX_ID_") ||
			cookie.Name == "AUTHP_ACCESS_TOKEN" || cookie.Name == "AUTHP_REFRESH_TOKEN" ||
			cookie.Name == "AUTHP_OIDC_SESSION_ID" || cookie.Name == "AUTHP_OIDC_REQUEST_ID" {
			f.secrets = append(f.secrets, cookie.Value)
		}
	}
	return response
}

func portalMountStatus(t *testing.T, response oidcRPResponse, status int) {
	t.Helper()
	if response.status != status {
		t.Fatalf("portal mount response status: got %d, want %d", response.status, status)
	}
}

func portalMountDiscovery(t *testing.T, f *localIdentityFixture) {
	t.Helper()
	get := portalMountRequest(t, f, "GET", "/.well-known/jwks.json", nil, http.Header{"Accept": {"text/html"}})
	portalMountStatus(t, get, 200)
	get.noStore(t)
	var keyset struct{ Keys []map[string]string }
	if json.Unmarshal(get.body, &keyset) != nil || len(keyset.Keys) != 1 || keyset.Keys[0]["kid"] != "access" ||
		get.header.Get("Content-Type") != "application/jwk-set+json" || len(get.header.Values("Set-Cookie")) != 0 {
		t.Fatal("explicit discovery did not publish exactly its public signing keyset")
	}
	head := portalMountRequest(t, f, "HEAD", "/.well-known/jwks.json", nil, nil)
	portalMountStatus(t, head, 200)
	if len(head.body) != 0 || head.header.Get("Content-Type") != get.header.Get("Content-Type") || head.header.Get("Content-Length") != strconv.Itoa(len(get.body)) {
		t.Fatal("mounted JWKS HEAD changed the public bodyless contract")
	}
	discovery := portalMountRequest(t, f, "GET", "/.well-known/openid-configuration", nil, nil)
	portalMountStatus(t, discovery, 200)
	var provider map[string]any
	if json.Unmarshal(discovery.body, &provider) != nil || provider["issuer"] != f.issuer || provider["token_endpoint"] != f.issuer+"/oidc/token" {
		t.Fatal("explicit OP discovery lost its configured mount")
	}
	if len(discovery.header.Values("Set-Cookie")) != 0 {
		t.Fatal("public OP discovery created browser credentials")
	}
}

func portalMountLanding(t *testing.T, f *localIdentityFixture) {
	t.Helper()
	bare := f.base + f.mount
	if f.mount == "" {
		bare += "/"
	}
	targets := []string{bare}
	if f.mount != "" {
		targets = append(targets, bare+"/")
	}
	for _, target := range targets {
		r := portalMountRequest(t, f, "GET", target, nil, nil)
		portalMountStatus(t, r, 302)
		u, err := url.Parse(r.header.Get("Location"))
		if err != nil || u.Scheme+"://"+u.Host != f.base || u.Path != f.mount+"/login" {
			t.Fatal("explicit bare or trailing-slash mount lost its login destination")
		}
	}
	page := portalMountRequest(t, f, "GET", "/login?probe=/api/logout&next=/oidc/token", nil, nil)
	portalMountStatus(t, page, 200)
	if !bytes.Contains(page.body, []byte(`id="username"`)) || !bytes.Contains(page.body, []byte(f.mount+"/assets/js/login.js")) {
		t.Fatal("mounted login page or misleading query changed route ownership")
	}
	asset := portalMountRequest(t, f, "GET", "/assets/js/login.js", nil, nil)
	portalMountStatus(t, asset, 200)
	if !strings.Contains(asset.header.Get("Content-Type"), "javascript") || asset.header.Get("Location") != "" {
		t.Fatal("mounted asset was handled as an authentication page")
	}
}

func portalMountAPIRejections(t *testing.T, f *localIdentityFixture) {
	t.Helper()
	for _, endpoint := range []string{"/api/logout", "/api/refresh_token", "/api/refresh_session"} {
		r := portalMountRequest(t, f, "GET", endpoint, nil, http.Header{"Accept": {"text/html"}})
		portalMountStatus(t, r, 405)
		media, _, err := mime.ParseMediaType(r.header.Get("Content-Type"))
		if err != nil || media != "application/json" || r.header.Get("Allow") != "POST" || r.header.Get("Location") != "" || len(r.header.Values("Set-Cookie")) != 0 {
			t.Fatal("API method rejection crossed into browser redirect or cookie handling")
		}
		r.noStore(t)
	}
}

func portalMountBoundary(t *testing.T, f *localIdentityFixture) {
	t.Helper()
	denied := []string{f.base + "/rewrite-probe"}
	if f.mount != "" {
		// Encode a real mount byte without changing the decoded request path.
		encodedMount := "/" + fmt.Sprintf("%%%02x", f.mount[1]) + f.mount[2:]
		denied = append(denied,
			f.base+f.mount+"entic/login", f.base+"/outside/.well-known/jwks.json", f.base+"/outside/oidc/token",
			f.base+f.mount+"%2flogin", f.base+encodedMount+"/login",
			f.base+strings.ToUpper(f.mount)+"/login")
	}
	for index, target := range denied {
		t.Run(fmt.Sprintf("boundary_%d", index), func(t *testing.T) {
			r := portalMountRequest(t, f, "GET", target, nil, nil)
			portalMountStatus(t, r, 404)
			if r.header.Get("Cache-Control") != "no-store" || r.header.Get("Location") != "" || len(r.header.Values("Set-Cookie")) != 0 {
				t.Fatal("outside or rewritten path reached portal response state")
			}
		})
	}
	for _, child := range []string{"/api/.well-known/jwks.json", "/other/.well-known/jwks.json", "/.well-known/%6awks.json"} {
		r := portalMountRequest(t, f, "GET", f.base+f.mount+child, nil, http.Header{"Accept": {"text/html"}})
		if r.status < 400 || r.status >= 500 || r.header.Get("Content-Type") == "application/jwk-set+json" || bytes.Contains(r.body, []byte(`"keys"`)) {
			t.Fatal("a discovery suffix or encoded leaf published signing keys")
		}
		providerDestinationNoIssuance(t, r)
	}
}

type portalMountIdentity struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Realm   string `json:"origin"`
	Session string `json:"sid"`
}

func portalMountWhoami(t *testing.T, f *localIdentityFixture) portalMountIdentity {
	t.Helper()
	r := portalMountRequest(t, f, "GET", "/whoami", nil, http.Header{"Accept": {"application/json"}})
	portalMountStatus(t, r, 200)
	var identity portalMountIdentity
	if json.Unmarshal(r.body, &identity) != nil || identity.Subject != "alice" || identity.Email != "alice@example.test" || identity.Realm != "local" || identity.Session == "" {
		t.Fatal("mounted identity probe lost its authenticated account or refresh session")
	}
	return identity
}

func portalMountLogin(t *testing.T, f *localIdentityFixture) portalMountIdentity {
	t.Helper()
	f.newBrowser(t)
	headers := http.Header{"Origin": {f.base}}
	start := portalMountRequest(t, f, "POST", "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, headers)
	portalMountStatus(t, start, 303)
	checkpoint, err := url.Parse(start.header.Get("Location"))
	if err != nil || checkpoint.Scheme+"://"+checkpoint.Host != f.base || !strings.HasPrefix(checkpoint.Path, f.mount+"/sandbox/") {
		t.Fatal("explicit login checkpoint left its declared mount")
	}
	portalMountStatus(t, portalMountRequest(t, f, "GET", checkpoint.String(), nil, nil), 200)
	portalMountStatus(t, portalMountRequest(t, f, "POST", checkpoint.String(), url.Values{"secret": {lifecyclePassword}}, headers), 303)
	completion := portalMountRequest(t, f, "GET", checkpoint.String(), nil, nil)
	portalMountStatus(t, completion, 303)
	mountedRefresh := false
	for _, cookie := range (&http.Response{Header: completion.header}).Cookies() {
		if cookie.Name == "AUTHP_REFRESH_TOKEN" && cookie.MaxAge > 0 {
			mount := f.mount
			if mount == "" {
				mount = "/"
			}
			mountedRefresh = cookie.Path == mount && cookie.Secure && cookie.HttpOnly && cookie.Domain == ""
		}
	}
	if !mountedRefresh {
		t.Fatal("explicit login did not issue private refresh credentials at its mount")
	}
	access := f.cookie("AUTHP_ACCESS_TOKEN")
	claims := challengeClaims(t, f, access, "pwd")
	if claims["sub"] != "alice" || claims["origin"] != "local" {
		t.Fatal("explicit login signed the wrong account")
	}
	resource := portalMountRequest(t, f, "GET", f.base+"/resource", nil, nil)
	portalMountStatus(t, resource, 200)
	if string(resource.body) != "identity resource" {
		t.Fatal("mounted login did not authorize the actual protected resource")
	}
	return portalMountWhoami(t, f)
}

func portalMountNativeCandidate(t *testing.T, input, mount string) []byte {
	t.Helper()
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal("cannot adapt valid mount candidate before native JSON mutation")
	}
	var config any
	if json.Unmarshal(data, &config) != nil {
		t.Fatal("cannot decode native mount candidate")
	}
	count := 0
	var visit func(any)
	visit = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			if value["handler"] == "authenticator" {
				value["base_path"] = mount
				count++
			}
			for _, child := range value {
				visit(child)
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
		}
	}
	visit(config)
	if count == 0 {
		t.Fatal("native candidate did not contain an authenticator")
	}
	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal("cannot encode native mount candidate")
	}
	return data
}

func portalMountNativeRefreshOverride(t *testing.T, f *localIdentityFixture) {
	t.Helper()
	data := portalMountNativeCandidate(t, f.input, f.mount)
	var config, apps map[string]json.RawMessage
	var app App
	if json.Unmarshal(data, &config) != nil || json.Unmarshal(config["apps"], &apps) != nil ||
		json.Unmarshal(apps["security"], &app) != nil || app.Config == nil || len(app.Config.AuthenticationPortals) != 1 {
		t.Fatal("cannot decode native refresh override fixture")
	}
	portal := app.Config.AuthenticationPortals[0]
	if portal.CookieConfig == nil || portal.RefreshTokens == nil || !portal.RefreshTokens.Enabled || len(app.PortalCookieDirectives) != 0 {
		t.Fatal("native refresh override fixture lacks independent typed configuration")
	}
	// Preserve the shared helper's effective cookie name while making the native
	// stored name invalid on its own. Only the enabled refresh override repairs
	// this collision, before mount preflight and runtime cookie validation.
	portal.CookieConfig.RefreshTokenCookieName = portal.CookieConfig.AccessTokenCookieName
	portal.RefreshTokens.CookieName = "AUTHP_REFRESH_TOKEN"
	var err error
	apps["security"], err = json.Marshal(&app)
	if err != nil {
		t.Fatal("cannot encode native security override")
	}
	config["apps"], err = json.Marshal(apps)
	if err != nil {
		t.Fatal("cannot encode native apps override")
	}
	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal("cannot encode native refresh override candidate")
	}
	// The local JSON identity database cannot overlap across live candidates.
	// Stop/drain first, then load the native candidate at the same trusted origin.
	if err := caddy.Stop(); err != nil {
		t.Fatal("cannot drain Caddy before native override restart")
	}
	f.client.CloseIdleConnections()
	if err := caddy.Load(data, true); err != nil {
		t.Fatal("valid native refresh override was rejected before serving")
	}
	portalMountDiscovery(t, f)
	// This performs real username/password checkpoints, verifies the independent
	// access signature, and checks the effective refresh cookie name/path/flags.
	portalMountLogin(t, f)
}

func portalMountRejectedReload(t *testing.T, f *localIdentityFixture, before portalMountIdentity) {
	t.Helper()
	input := f.input
	for _, path := range []string{f.database, filepath.Join(filepath.Dir(f.database), "excluded.json")} {
		input = strings.Replace(input, fmt.Sprintf("path %q", path), "path :memory:", 1)
	}
	for _, candidate := range []struct{ mount, failure string }{
		{"/tenant/login-service", "invalid portal mount"},
		{"/different/auth", "portal mount conflicts with"},
	} {
		data := portalMountNativeCandidate(t, input, candidate.mount)
		if err := caddy.Load(data, true); err == nil || !strings.Contains(err.Error(), candidate.failure) {
			t.Fatal("native candidate did not fail at the intended mount boundary")
		}
		if after := portalMountWhoami(t, f); after != before {
			t.Fatal("rejected native candidate changed the serving session")
		}
		resource := portalMountRequest(t, f, "GET", f.base+"/resource", nil, nil)
		portalMountStatus(t, resource, 200)
	}
	portalMountLogin(t, f)
}

func portalMountColdRejection(t *testing.T, cert, key string) {
	t.Helper()
	address := lifecycleAddress(t)
	directory := filepath.Join(t.TempDir(), "uncreated-runtime")
	input := fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 log {
  level ERROR
 }
 security {
  state {
   directory %q
  }
  local identity store localdb {
   realm local
   path :memory:
  }
  authentication portal myportal {
   enable identity store localdb
   crypto key sign-verify synthetic-portal-mount-signing-key-longer-than-32-bytes
  }
 }
}
https://%s {
 tls %q %q
 authenticate with myportal at /auth
}`, directory, address, cert, key)
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error("cannot stop cold mount candidate")
		}
	})
	data := portalMountNativeCandidate(t, input, "/tenant/api/auth")
	if err := caddy.Load(data, true); err == nil || !strings.Contains(err.Error(), "invalid portal mount") {
		t.Fatal("cold persistent native candidate did not reject its mount before startup")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("mount rejection initialized persistent runtime storage")
	}
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal("rejected candidate retained its TCP listener")
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal("rejected candidate retained its UDP listener")
	}
	defer udp.Close()
}
