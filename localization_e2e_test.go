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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"golang.org/x/net/html"
)

const localizationWrongPassword = "WrongLocalizationPassword42!"
const localizationBrand = `Marque <img id="localization-injected" src=x> & texte`
const localizationClientName = `Workspace <img id="localization-client-injected" src=x> & Team`
const localizationSigningKey = "synthetic-localization-access-signing-key-with-sufficient-entropy"

type localizationPortal struct {
	Language     string `json:"language"`
	Mount        string `json:"mount"`
	Resource     string `json:"resource"`
	CookiePrefix string `json:"cookiePrefix"`
	MetaTitle    string `json:"metaTitle,omitempty"`
	title        string
	description  string
	label        string
}

type localizationCallback struct {
	outcome string
	err     error
}

type localizationFixture struct {
	base, input, issuer string
	database            string
	client              *http.Client
	portals             []localizationPortal
	rp                  *httptest.Server
	keys                oidcRPKeys
	callbacks           chan localizationCallback
	mu                  sync.Mutex
	expected            map[string]url.Values
	used                map[string]bool
	secrets             []string
}

func TestCaddyLocalizationE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyLocalizationProcess$", "-test.v", "-test.timeout=220s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_LOCALIZATION_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	assertAdminRedacted(t, output, []string{lifecyclePassword, localizationWrongPassword, applicationTestSecret, localizationSigningKey, "BEGIN PRIVATE KEY"})
	if err != nil {
		t.Fatalf("Caddy localization: %v\n%s", err, output)
	}
}

func TestCaddyLocalizationProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_LOCALIZATION_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	f := newLocalizationFixture(t, cert, key, roots)
	t.Run("portal_snapshots", func(t *testing.T) { f.testSnapshots(t) })
	t.Run("unsupported_reload", func(t *testing.T) { f.testRejectedReload(t) })
	t.Run("localized_op_errors", func(t *testing.T) { f.testOPErrors(t) })
	t.Run("trusted_chrome", func(t *testing.T) { f.runBrowser(t, cert) })
}

func newLocalizationFixture(t *testing.T, cert, key string, roots *x509.CertPool) *localizationFixture {
	t.Helper()
	f := &localizationFixture{
		base: "https://" + lifecycleAddress(t), expected: make(map[string]url.Values), used: make(map[string]bool),
		callbacks: make(chan localizationCallback, 4),
		secrets:   []string{lifecyclePassword, localizationWrongPassword, applicationTestSecret, localizationSigningKey},
	}
	f.issuer = f.base + "/tenant/auth"
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	f.client = &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal("cannot load localization TLS fixture")
	}
	f.rp = httptest.NewUnstartedServer(http.HandlerFunc(f.callback))
	f.rp.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	f.rp.StartTLS()
	t.Cleanup(f.rp.Close)
	database := filepath.Join(t.TempDir(), "accounts.json")
	f.database = database
	db, err := identity.NewDatabase(database)
	if err != nil {
		t.Fatal("cannot initialize localization identity store")
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: lifecyclePassword, Roles: []string{"authp/user"}}}); err != nil {
		t.Fatal("cannot seed localization identity")
	}
	opKey := newOIDCRPKey(t, "localization-op")
	f.portals = []localizationPortal{
		{Language: "en", Mount: "/en", CookiePrefix: "EN", title: "Authentication Portal", description: "Performs user authentication.", label: "Please provide username or email address"},
		{Language: "fr", Mount: "/tenant/auth", CookiePrefix: "FR", MetaTitle: localizationBrand, title: localizationBrand, description: "Authentifie les utilisateurs.", label: "Veuillez fournir un nom d'utilisateur ou une adresse e-mail"},
		{Language: "ar", Mount: "/rtl", CookiePrefix: "AR", title: "بوابة المصادقة", description: "يُجري مصادقة المستخدمين.", label: "يرجى تقديم اسم المستخدم أو عنوان البريد الإلكتروني"},
	}
	var declarations, routes strings.Builder
	for i := range f.portals {
		p := &f.portals[i]
		p.Resource = f.base + "/resource/" + p.Language
		language, branding, provider := "", "", ""
		switch p.Language {
		case "fr":
			language = `language " FRENCH "`
			branding = fmt.Sprintf("meta title %q", p.MetaTitle)
			provider = fmt.Sprintf("oidc provider {\nissuer %s\nrealms local\nsigning key files %q\napplications localized\n}\n", f.issuer, opKey.private)
		case "ar":
			language = "language ar"
		}
		fmt.Fprintf(&declarations, `authentication portal %s {
 enable identity store localdb
 enable cross-device login
 crypto key sign-verify %s
 cookie prefix %s
 trust login redirect uri domain exact %s path exact /resource/%s
 ui {
  %s
  %s
 }
 %s
}
authorization policy %s {
 crypto key verify %s
 set token sources cookie
 set access_token cookie name %s_ACCESS_TOKEN
 set session_id cookie name %s_SESSION_ID
 set auth url %s%s/login
 allow roles authp/user
}
`, p.Language, localizationSigningKey, p.CookiePrefix, strings.TrimPrefix(f.base, "https://"), p.Language, language, branding, provider,
			p.Language, localizationSigningKey, p.CookiePrefix, p.CookiePrefix, f.base, p.Mount)
		fmt.Fprintf(&routes, "route %s/* {\nauthenticate with %s\n}\nroute /resource/%s {\nauthorize with %s\nrespond \"localized resource\"\n}\n", p.Mount, p.Language, p.Language, p.Language)
	}
	f.input = fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 log {
  level ERROR
 }
 security {
  local identity store localdb {
   realm local
   path %q
  }
  oauth application localized {
   client_id localized
   client_name %q
   client_secret %s
   redirect_uri %s/callback
   scopes openid profile email
   skip_consent off
  }
  %s
 }
}
%s {
 tls %q %q
 route {
  %s
  respond unmatched 404
 }
}
`, database, localizationClientName, applicationTestSecret, f.rp.URL, declarations.String(), f.base, cert, key, routes.String())
	config, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(f.input), nil)
	if err != nil {
		t.Fatalf("adapt localization fixture: %v", err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error("cannot stop localization Caddy fixture")
		}
	})
	if err := caddy.Load(config, true); err != nil {
		t.Fatalf("load localization fixture: %v", err)
	}
	response := f.request(t, f.client, "GET", f.issuer+"/oidc/jwks", nil, nil)
	response.requireStatus(t, 200)
	if json.Unmarshal(response.body, &f.keys) != nil || len(f.keys.Keys) != 1 {
		t.Fatal("localized provider has no public signing key")
	}
	return f
}

// This shared request path also serves the RP handler: it returns bounded,
// sanitized errors instead of calling testing.Fatal from a server goroutine.
func localizationHTTP(ctx context.Context, client *http.Client, method, target string, form url.Values, headers http.Header) (oidcRPResponse, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return oidcRPResponse{}, fmt.Errorf("cannot construct localization request")
	}
	if headers != nil {
		req.Header = headers.Clone()
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := client.Do(req)
	if err != nil {
		return oidcRPResponse{}, fmt.Errorf("localization TLS request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return oidcRPResponse{}, fmt.Errorf("localization response was not bounded and verified")
	}
	return oidcRPResponse{response.StatusCode, response.Header.Clone(), data}, nil
}

func (f *localizationFixture) request(t *testing.T, client *http.Client, method, target string, form url.Values, headers http.Header) oidcRPResponse {
	t.Helper()
	response, err := localizationHTTP(t.Context(), client, method, target, form, headers)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range (&http.Response{Header: response.header}).Cookies() {
		f.remember(cookie.Value)
	}
	return response
}

func (f *localizationFixture) remember(values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, value := range values {
		if value != "" {
			f.secrets = append(f.secrets, value)
		}
	}
}

func localizationText(node *html.Node) string {
	var text strings.Builder
	for n := range node.Descendants() {
		if n.Type == html.TextNode {
			text.WriteString(n.Data)
		}
	}
	return strings.TrimSpace(text.String())
}

func localizationAttr(node *html.Node, name string) string {
	for _, attr := range node.Attr {
		if attr.Key == name {
			return attr.Val
		}
	}
	return ""
}

func localizationPage(t *testing.T, response oidcRPResponse, p localizationPortal, login bool) *html.Node {
	t.Helper()
	// Ordinary login GETs retain their existing absence of a cache directive;
	// OP error pages explicitly prohibit storage. Localization changes neither.
	cache := "no-store"
	if login {
		cache = ""
	}
	if response.header.Get("Content-Type") != "text/html; charset=utf-8" || response.header.Get("Cache-Control") != cache {
		t.Fatal("localized page changed its HTML/cache policy")
	}
	doc, err := html.Parse(bytes.NewReader(response.body))
	if err != nil {
		t.Fatal("cannot parse localized HTML")
	}
	direction := "ltr"
	if p.Language == "ar" {
		direction = "rtl"
	}
	var document, title, description, label bool
	for n := range doc.Descendants() {
		if n.Type != html.ElementNode {
			continue
		}
		switch n.Data {
		case "html":
			document = localizationAttr(n, "lang") == p.Language && localizationAttr(n, "dir") == direction
		case "title":
			title = strings.HasPrefix(localizationText(n), p.title+" - ")
		case "meta":
			if localizationAttr(n, "name") == "description" {
				description = localizationAttr(n, "content") == p.description
			}
		case "label":
			if localizationAttr(n, "for") == "username" {
				label = localizationText(n) == p.label
			}
		}
		if strings.HasPrefix(localizationAttr(n, "id"), "localization-") {
			t.Fatal("operator display text became an HTML element")
		}
	}
	if !document || !title || !description || login && !label {
		t.Fatal("localized document language, branding, metadata or login label changed")
	}
	return doc
}

func (f *localizationFixture) testSnapshots(t *testing.T) {
	for _, index := range []int{0, 1, 2, 1, 0, 2} {
		p := f.portals[index]
		response := f.request(t, f.client, "GET", f.base+p.Mount+"/login", nil, http.Header{"Accept-Language": {"ja, de;q=0.9"}})
		response.requireStatus(t, 200)
		localizationPage(t, response, p, true)
	}
}

func (f *localizationFixture) testRejectedReload(t *testing.T) {
	bad := strings.Replace(f.input, `language " FRENCH "`, "language unsupported-localization", 1)
	if bad == f.input {
		t.Fatal("unsupported language candidate was not constructed")
	}
	// The candidate must reach UI validation rather than the independent
	// prohibition on opening the live root's local identity file twice.
	bad = strings.Replace(bad, fmt.Sprintf("path %q", f.database), "path :memory:", 1)
	config, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(bad), nil)
	if err != nil {
		t.Fatal("unsupported language should reach runtime validation")
	}
	err = caddy.Load(config, true)
	if err == nil || !strings.Contains(err.Error(), "user interface validation for fr portal failed: unsupported-localization language not found") {
		t.Fatal("candidate reload did not fail specifically at language validation")
	}
	f.testSnapshots(t)
	// A new real login proves the rejected candidate retained more than cached
	// HTML: the old runtime can still authenticate and authorize its resource.
	p := f.portals[1]
	client := *f.client
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal("cannot create localization browser cookie jar")
	}
	login := f.base + p.Mount + "/login?redirect_url=" + url.QueryEscape(p.Resource)
	f.request(t, &client, "GET", login, nil, nil).requireStatus(t, 200)
	headers := http.Header{"Origin": {f.base}}
	start := f.request(t, &client, "POST", login, url.Values{"username": {"alice"}, "realm": {"local"}}, headers)
	start.requireStatus(t, 303)
	sandbox := start.header.Get("Location")
	location, parseErr := url.Parse(sandbox)
	if parseErr != nil || location.Scheme+"://"+location.Host != f.base || !strings.HasPrefix(location.Path, p.Mount+"/sandbox/") {
		t.Fatal("old portal did not create a mounted authentication checkpoint")
	}
	f.request(t, &client, "POST", sandbox, url.Values{"secret": {lifecyclePassword}}, headers).requireStatus(t, 303)
	f.request(t, &client, "GET", sandbox, nil, nil).requireStatus(t, 303)
	resource := f.request(t, &client, "GET", p.Resource, nil, nil)
	resource.requireStatus(t, 200)
	if string(resource.body) != "localized resource" {
		t.Fatal("old portal no longer authorized its protected resource")
	}
}

func (f *localizationFixture) testOPErrors(t *testing.T) {
	page := f.request(t, f.client, "GET", f.issuer+"/oidc/authorize", nil, http.Header{"Accept": {"text/html"}, "Accept-Language": {"ar"}})
	page.requireStatus(t, 400)
	page.noStore(t)
	doc := localizationPage(t, page, f.portals[1], false)
	if !strings.Contains(localizationText(doc), "Impossible de continuer") || !strings.Contains(localizationText(doc), "Cette demande de connexion est invalide ou a expiré.") {
		t.Fatal("localized OP error did not use its portal language")
	}
	for n := range doc.Descendants() {
		if n.Type == html.ElementNode && n.Data == "form" {
			t.Fatal("invalid OP request exposed a form")
		}
	}
	policy, err := normalizeOIDCPagePolicy(page.header.Get("Content-Security-Policy"))
	want := "default-src 'none'; style-src 'self' 'nonce-PER_RESPONSE'; img-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	if err != nil || policy != want {
		t.Fatal("localized OP error changed its CSP")
	}
	f.request(t, f.client, "GET", f.issuer+"/oidc/authorize", nil, http.Header{"Accept": {"application/json"}, "Accept-Language": {"fr"}}).failure(t, 400, "invalid_request")
}

func (f *localizationFixture) authorization(outcome string) string {
	params := (&oidcRPFixture{}).authorization("localized")
	params.Set("redirect_uri", f.rp.URL+"/callback")
	params.Set("prompt", "consent")
	f.mu.Lock()
	f.expected[outcome] = params
	f.mu.Unlock()
	f.remember(params.Get("state"), params.Get("nonce"))
	return f.issuer + "/oidc/authorize?" + params.Encode()
}

// Only a real, bound browser callback can produce the success marker. The
// allow marker additionally requires a redeemed code and verified OP identity.
func (f *localizationFixture) callback(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/callback" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	finish := func(outcome string, err error) {
		select {
		case f.callbacks <- localizationCallback{outcome, err}:
		default:
		}
		if err != nil {
			http.Error(w, "callback rejected", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<!doctype html><title>Application</title><h1 id="localization-callback" data-outcome="%s">Application</h1>`, outcome)
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || r.Method != http.MethodGet || r.TLS == nil {
		finish("", fmt.Errorf("invalid callback transport"))
		return
	}
	for _, key := range []string{"state", "iss", "code", "error", "error_description", "error_uri"} {
		if len(values[key]) > 1 {
			finish("", fmt.Errorf("ambiguous callback field"))
			return
		}
	}
	var outcome string
	var expected url.Values
	f.mu.Lock()
	for name, params := range f.expected {
		if values.Get("state") == params.Get("state") && !f.used[name] {
			outcome, expected = name, params
			f.used[name] = true
			break
		}
	}
	f.mu.Unlock()
	if outcome == "" || values.Get("iss") != f.issuer {
		finish("", fmt.Errorf("callback binding or replay rejected"))
		return
	}
	if outcome == "deny" {
		if values.Get("error") != "access_denied" || values.Has("code") {
			finish(outcome, fmt.Errorf("deny did not preserve the protocol error"))
			return
		}
		finish(outcome, nil)
		return
	}
	if outcome != "allow" || values.Get("code") == "" || values.Has("error") {
		finish(outcome, fmt.Errorf("allow did not return an authorization code"))
		return
	}
	f.remember(values.Get("code"))
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {values.Get("code")}, "redirect_uri": {expected.Get("redirect_uri")}, "code_verifier": {oidcRPVerifier}}
	response, err := localizationHTTP(ctx, f.client, "POST", f.issuer+"/oidc/token", form, oidcRPAuth("localized", form))
	if err != nil || response.status != 200 || response.header.Get("Cache-Control") != "no-store" {
		finish(outcome, fmt.Errorf("localized authorization code redemption failed"))
		return
	}
	var tokens oidcRPTokens
	if json.Unmarshal(response.body, &tokens) != nil || tokens.Type != "Bearer" || tokens.Expires <= 0 || tokens.Access == "" || tokens.ID == "" {
		finish(outcome, fmt.Errorf("localized token response was invalid"))
		return
	}
	f.remember(tokens.Access, tokens.ID)
	claims, _, err := verifyOIDCRPToken(tokens.ID, tokens.Access, f.issuer, expected.Get("client_id"), expected.Get("nonce"), f.keys, time.Now())
	if err != nil || !slices.Contains(claims.Methods, "pwd") {
		finish(outcome, fmt.Errorf("localized OP identity validation failed"))
		return
	}
	userinfo, err := localizationHTTP(ctx, f.client, "GET", f.issuer+"/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens.Access}})
	var identity map[string]any
	if err != nil || userinfo.status != 200 || userinfo.header.Get("Cache-Control") != "no-store" || json.Unmarshal(userinfo.body, &identity) != nil || identity["sub"] != claims.Subject || identity["email"] != "alice@example.test" {
		finish(outcome, fmt.Errorf("localized UserInfo binding failed"))
		return
	}
	finish(outcome, nil)
}

func (f *localizationFixture) runBrowser(t *testing.T, cert string) {
	t.Helper()
	repository, err := os.Getwd()
	if err != nil {
		t.Fatal("cannot resolve localization fixture root")
	}
	screenshots, err := crossDeviceScreenshotDirectory(repository, os.Getenv("CADDY_SECURITY_LOCALIZATION_SCREENSHOT_DIR"), "full")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("tmp", 0700); err != nil {
		t.Fatal("cannot create localization browser working directory")
	}
	profile, err := os.MkdirTemp("tmp", "localization-browser-")
	if err != nil {
		t.Fatal("cannot create private localization browser profile")
	}
	profile, err = filepath.Abs(profile)
	if err != nil {
		t.Fatal("cannot resolve localization browser profile")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(profile); err != nil {
			t.Error("cannot remove localization browser profile")
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	trust := exec.CommandContext(ctx, "node", "testdata/browser/token_refresh_browser_trust.cjs", profile, cert)
	trust.WaitDelay = time.Second
	if _, err := trust.CombinedOutput(); err != nil {
		t.Fatal("cannot prepare private localization Chrome trust")
	}
	chrome := exec.CommandContext(ctx, caddyRefreshBrowserExecutable(t), "--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startCaddyRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal("cannot start trusted localization Chrome")
	}
	defer stop()
	config, err := json.Marshal(struct {
		Origin        string               `json:"origin"`
		Portals       []localizationPortal `json:"portals"`
		OP            map[string]string    `json:"op"`
		ScreenshotDir string               `json:"screenshotDir"`
	}{f.base, f.portals[1:], map[string]string{
		"language": "fr", "authorizeDeny": f.authorization("deny"), "authorizeAllow": f.authorization("allow"),
		"callbackURL": f.rp.URL + "/callback", "clientName": localizationClientName, "errorURL": f.issuer + "/oidc/authorize",
	}, screenshots})
	if err != nil {
		t.Fatal("cannot encode localization browser configuration")
	}
	passwords, _ := json.Marshal(map[string]string{"password": lifecyclePassword, "wrongPassword": localizationWrongPassword})
	driver := exec.CommandContext(ctx, "node", "testdata/browser/localization_browser_e2e.cjs", endpoint, string(config))
	driver.Stdin = bytes.NewReader(passwords)
	driver.WaitDelay = time.Second
	output, err := driver.CombinedOutput()
	f.mu.Lock()
	secrets := append([]string(nil), f.secrets...)
	f.mu.Unlock()
	assertAdminRedacted(t, output, secrets)
	if err != nil {
		t.Fatalf("trusted localization browser: %v\n%s", err, output)
	}
	var result struct {
		Passed bool `json:"passed"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed {
		t.Fatal("browser did not confirm localization")
	}
	seen := make(map[string]bool)
	for range 2 {
		select {
		case callback := <-f.callbacks:
			if callback.err != nil || callback.outcome == "" || seen[callback.outcome] {
				t.Fatal("localized RP callback was not independently validated")
			}
			seen[callback.outcome] = true
		default:
			t.Fatal("missing real localized RP callback")
		}
	}
	if !seen["allow"] || !seen["deny"] {
		t.Fatal("localized decisions did not exercise both outcomes")
	}
}
