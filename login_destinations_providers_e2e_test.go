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
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/html"
)

// Signature/issuer/PKCE matrices remain in TestCaddyOAuthE2E and signed SAML
// provider coverage. These journeys qualify concurrent destination ownership
// through Caddy, with the original proofs retained for spent-state rejection.
func TestCaddyLoginDestinationsProvidersE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyLoginDestinationsProvidersProcess$", "-test.v", "-test.timeout=170s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_DESTINATIONS_PROVIDERS_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	assertAdminRedacted(t, output, []string{lifecyclePassword, localIdentityBobPassword, applicationTestSecret, oauthE2ESecret, oauthE2EPortalKey, "BEGIN PRIVATE KEY"})
	if err != nil {
		t.Fatalf("Caddy provider destinations: %v\n%s", err, output)
	}
}

func TestCaddyLoginDestinationsProvidersProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_DESTINATIONS_PROVIDERS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal("cannot load provider destination TLS fixture")
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Fatal("cannot initialize fixture trust")
	}
	oauthE2ESystemRoots = roots
	t.Run("OAuth", func(t *testing.T) { testProviderDestinationsOAuth(t, cert, key, roots, pair) })
	t.Run("SAML", func(t *testing.T) { testProviderDestinationsSAML(t, cert, key, roots, pair) })
	t.Run("cross_device", func(t *testing.T) { testProviderDestinationsCrossDevice(t, cert, key, roots) })
}

// Do not print request errors: their URL can contain state or a credential.
func providerDestinationRequest(t *testing.T, b *oidcRPFixture, method, target string, form url.Values, headers http.Header) oidcRPResponse {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = b.issuer + target
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal("cannot construct provider destination request")
	}
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := b.client.Do(req)
	if err != nil {
		t.Fatal("verified provider destination request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(data) > 2<<20 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("provider destination response was not bounded and TLS verified")
	}
	return oidcRPResponse{response.StatusCode, response.Header.Clone(), data}
}

func providerDestinationURL(base, path, label string) string {
	// The portal removes login_hint using url.Values.Encode, which also sorts
	// query keys. Compare the canonical URL while retaining escaped value data
	// and the fragment, rather than requiring the initiating key order to survive.
	query := url.Values{"tab": {label}, "path": {"/one/two"}, "literal": {"one&two"}}
	return base + path + "?" + query.Encode() + "#part%202"
}

func providerDestinationLegacyCookie(t *testing.T, b *oidcRPFixture, destination string) {
	t.Helper()
	// A fresh competing visit sets the return cookie through the actual host.
	// Its ordinary access-cookie deletion must not consume pending provider proof.
	response := providerDestinationRequest(t, b, "GET", "/login?fresh=1&redirect_url="+url.QueryEscape(destination), nil, nil)
	response.requireStatus(t, http.StatusOK)
	if crossDeviceCookie(b, "AUTHP_REDIRECT_URL") != destination {
		t.Fatal("competing login visit did not set its trusted return cookie")
	}
}

func providerDestinationProof(t *testing.T, b *oidcRPFixture, name string) string {
	t.Helper()
	u, _ := url.Parse(b.issuer + "/portal")
	var proof string
	for _, cookie := range b.client.Jar.Cookies(u) {
		if cookie.Name == name {
			if proof != "" || cookie.Value == "" {
				t.Fatal("ambiguous or empty fixture browser proof")
			}
			proof = cookie.Name + "=" + cookie.Value
		}
	}
	if proof == "" {
		t.Fatal("missing fixture browser proof")
	}
	return proof
}

func providerDestinationReplayBrowser(b *oidcRPFixture) *oidcRPFixture {
	replay := *b
	client := *b.client
	client.Jar = nil
	replay.client = &client
	return &replay
}

func providerDestinationNoIssuance(t *testing.T, response oidcRPResponse) {
	t.Helper()
	if response.header.Get("Authorization") != "" {
		t.Fatal("rejected provider proof published authorization")
	}
	for _, cookie := range (&http.Response{Header: response.header}).Cookies() {
		if cookie.Value != "" && cookie.MaxAge >= 0 && (strings.HasSuffix(cookie.Name, "_ACCESS_TOKEN") || strings.HasSuffix(cookie.Name, "_REFRESH_TOKEN") || strings.HasSuffix(cookie.Name, "_OIDC_SESSION_ID")) {
			t.Fatal("rejected provider proof published a credential cookie")
		}
	}
}

func providerDestinationLocation(t *testing.T, response oidcRPResponse, destination string) {
	t.Helper()
	response.requireStatus(t, http.StatusSeeOther)
	if response.header.Get("Location") != destination {
		t.Fatal("completion lost its original destination")
	}
}

func providerDestinationResource(t *testing.T, b *oidcRPFixture, destination, expected string) {
	t.Helper()
	response := providerDestinationRequest(t, b, "GET", destination, nil, nil)
	response.requireStatus(t, 200)
	if string(response.body) != expected {
		t.Fatal("destination did not reach the protected resource")
	}
}

func providerDestinationLocalConfig(t *testing.T, input string) string {
	t.Helper()
	var base string
	for _, line := range strings.Split(input, "\n") {
		if strings.HasPrefix(line, "https://") {
			base = strings.Fields(line)[0]
		}
	}
	if base == "" {
		t.Fatal("missing fixture site origin")
	}
	trust := "trust login redirect uri domain exact " + strings.TrimPrefix(base, "https://") + " path exact /resource\n"
	input = strings.Replace(input, "authentication portal myportal {", "authentication portal myportal {\n"+trust, 1)
	// Provider state and activation codes must not enter test diagnostics.
	input = strings.Replace(input, "level DEBUG", "level INFO", 1)
	return strings.Replace(input, "resp_headers>Location delete", "resp_headers>Location delete\nrequest>uri delete", 1)
}

func testProviderDestinationsOAuth(t *testing.T, cert, key string, roots *x509.CertPool, pair tls.Certificate) {
	u := newOAuthE2EUpstream(t, pair, "EdDSA")
	f := newCaddyOAuthFixture(t, u, "discovery", u.server.URL, "resource-api", cert, key, roots, func(f *caddyOAuthFixture) {
		trust := "trust login redirect uri domain exact " + strings.TrimPrefix(f.base, "https://") + " path exact /protected\n"
		f.input = strings.Replace(f.input, "authentication portal portal {", "authentication portal portal {\n"+trust, 1)
	})
	b := crossDeviceBrowser(t, &oidcRPFixture{client: f.client, base: f.base, mount: "/auth", issuer: f.base + "/auth"})
	destinations := []string{providerDestinationURL(f.base, "/protected", "A"), providerDestinationURL(f.base, "/protected", "B")}
	var callbacks, proofs []string
	for _, destination := range destinations {
		start := providerDestinationRequest(t, b, "GET", "/oauth2/upstream?redirect_url="+url.QueryEscape(destination), nil, nil)
		start.requireStatus(t, 302)
		if !strings.HasPrefix(start.header.Get("Location"), u.server.URL+"/authorize?") {
			t.Fatal("OAuth initiation escaped the fixture issuer")
		}
		authorized := providerDestinationRequest(t, b, "GET", start.header.Get("Location"), nil, nil)
		authorized.requireStatus(t, 302)
		callback := authorized.header.Get("Location")
		if !strings.HasPrefix(callback, f.base+"/auth/oauth2/upstream/authorization-code-callback?") {
			t.Fatal("OAuth response escaped the fixture callback")
		}
		callbacks = append(callbacks, callback+"&redirect_url="+url.QueryEscape(providerDestinationURL(f.base, "/protected", "callback")))
		proofs = append(proofs, providerDestinationProof(t, b, "AUTHP_SESSION_ID"))
	}
	wrong := crossDeviceBrowser(t, b)
	denied := providerDestinationRequest(t, wrong, "GET", callbacks[1], nil, nil)
	denied.requireStatus(t, 401)
	providerDestinationNoIssuance(t, denied)
	for _, index := range []int{1, 0} {
		providerDestinationLegacyCookie(t, b, providerDestinationURL(f.base, "/protected", "other-tab"))
		completed := providerDestinationRequest(t, b, "GET", callbacks[index], nil, nil)
		providerDestinationLocation(t, completed, destinations[index])
		token := crossDeviceCookie(b, "AUTHP_ACCESS_TOKEN")
		parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return []byte(oauthE2EPortalKey), nil }, jwt.WithValidMethods([]string{"HS512"}), jwt.WithExpirationRequired())
		if err != nil || !parsed.Valid || parsed.Claims.(jwt.MapClaims)["email"] != fmt.Sprintf("external-user-%d@example.test", index+1) {
			t.Fatal("OAuth completion did not publish the independently verified flow identity")
		}
		providerDestinationResource(t, b, destinations[index], "allowed")
		replay := providerDestinationRequest(t, providerDestinationReplayBrowser(b), "GET", callbacks[index], nil, http.Header{"Cookie": {proofs[index]}})
		replay.requireStatus(t, 401)
		providerDestinationNoIssuance(t, replay)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.authorizations != 2 || u.exchanges != 2 {
		t.Fatal("rejected OAuth proof consumed or repeated an issuer exchange")
	}
}

func providerDestinationSAMLForm(t *testing.T, body []byte) oidcRPBrowserForm {
	t.Helper()
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		t.Fatal("cannot parse fixture IdP document")
	}
	var forms int
	var encoded bytes.Buffer
	for node := range doc.Descendants() {
		if node.Type == html.ElementNode && node.Data == "form" {
			forms++
			if html.Render(&encoded, node) != nil {
				t.Fatal("cannot extract fixture IdP form")
			}
		}
	}
	if forms != 1 {
		t.Fatal("fixture IdP did not return exactly one signed response form")
	}
	form := oidcRPForm(t, encoded.Bytes())
	if form.values.Get("SAMLResponse") == "" || form.values.Get("RelayState") == "" {
		t.Fatal("fixture IdP omitted its signed response or transaction state")
	}
	return form
}

func providerDestinationIdentity(t *testing.T, f *localIdentityFixture, b *oidcRPFixture, email string) string {
	t.Helper()
	token := crossDeviceCookie(b, "AUTHP_ACCESS_TOKEN")
	claims := verifyCaddyJWKSSignature(t, f.keys, token, "RS512", f.keys[0]["kid"])
	expires, ok := claims["exp"].(float64)
	if !ok || expires <= float64(time.Now().Unix()) || claims["email"] != email {
		t.Fatal("destination completion did not publish a current verified identity")
	}
	f.secrets = append(f.secrets, token)
	f.assertResource(t, token)
	return token
}

func testProviderDestinationsSAML(t *testing.T, cert, key string, roots *x509.CertPool, pair tls.Certificate) {
	f, idpURL := newCrossDeviceSAMLFixture(t, cert, key, roots, pair, func(input string) string { return providerDestinationLocalConfig(t, input) })
	b := crossDeviceBrowser(t, f.oidcRPFixture)
	destinations := []string{providerDestinationURL(f.base, "/resource", "A"), providerDestinationURL(f.base, "/resource", "B")}
	var forms []oidcRPBrowserForm
	var proofs []string
	for _, destination := range destinations {
		start := providerDestinationRequest(t, b, "GET", "/saml/cross-device?redirect_url="+url.QueryEscape(destination), nil, nil)
		start.requireStatus(t, 302)
		if !strings.HasPrefix(start.header.Get("Location"), idpURL+"/sso?") {
			t.Fatal("SAML initiation escaped its fixture IdP")
		}
		assertion := providerDestinationRequest(t, b, "GET", start.header.Get("Location"), nil, nil)
		assertion.requireStatus(t, 200)
		form := providerDestinationSAMLForm(t, assertion.body)
		if form.action != f.issuer+"/saml/cross-device" {
			t.Fatal("SAML assertion escaped its configured ACS")
		}
		name := "AUTHP_SAML_SESSION_ID_" + form.values.Get("RelayState")
		var bound bool
		for _, cookie := range (&http.Response{Header: start.header}).Cookies() {
			if cookie.Name == name {
				bound = cookie.Secure && cookie.HttpOnly && cookie.Domain == "" && cookie.Path == "/" && cookie.SameSite == http.SameSiteNoneMode && cookie.MaxAge == 300
				f.secrets = append(f.secrets, cookie.Value)
			}
		}
		if !bound {
			t.Fatal("SAML transaction did not receive its scoped browser proof")
		}
		proofs = append(proofs, providerDestinationProof(t, b, name))
		forms = append(forms, form)
		f.secrets = append(f.secrets, form.values.Get("SAMLResponse"), form.values.Get("RelayState"))
	}
	headers := http.Header{"Origin": {idpURL}, "Sec-Fetch-Site": {"cross-site"}}
	wrong := crossDeviceBrowser(t, b)
	denied := providerDestinationRequest(t, wrong, "POST", forms[1].action, forms[1].values, headers)
	denied.requireStatus(t, 401)
	providerDestinationNoIssuance(t, denied)
	for _, index := range []int{1, 0} {
		providerDestinationLegacyCookie(t, b, providerDestinationURL(f.base, "/resource", "other-tab"))
		callback := forms[index].action + "?redirect_url=" + url.QueryEscape(providerDestinationURL(f.base, "/resource", "callback"))
		completed := providerDestinationRequest(t, b, "POST", callback, forms[index].values, headers)
		providerDestinationLocation(t, completed, destinations[index])
		providerDestinationIdentity(t, f, b, "saml-user@example.test")
		providerDestinationResource(t, b, destinations[index], "identity resource")
		deleted := false
		for _, cookie := range (&http.Response{Header: completed.header}).Cookies() {
			if cookie.Name == "AUTHP_SAML_SESSION_ID_"+forms[index].values.Get("RelayState") && cookie.MaxAge < 0 {
				deleted = true
			}
		}
		if !deleted {
			t.Fatal("SAML completion retained its consumed proof cookie")
		}
		if index == 1 {
			providerDestinationProof(t, b, "AUTHP_SAML_SESSION_ID_"+forms[0].values.Get("RelayState"))
		}
		replayHeaders := headers.Clone()
		replayHeaders.Set("Cookie", proofs[index])
		replay := providerDestinationRequest(t, providerDestinationReplayBrowser(b), "POST", callback, forms[index].values, replayHeaders)
		replay.requireStatus(t, 401)
		providerDestinationNoIssuance(t, replay)
	}
}

func testProviderDestinationsCrossDevice(t *testing.T, cert, key string, roots *x509.CertPool) {
	f := crossDeviceFixture(t, localIdentityOptions{mount: "/tenant/auth", configure: func(input string) string { return providerDestinationLocalConfig(t, input) }}, "enable cross-device login", cert, key, roots)
	requesters := []*oidcRPFixture{crossDeviceBrowser(t, f.oidcRPFixture), crossDeviceBrowser(t, f.oidcRPFixture)}
	destinations := []string{providerDestinationURL(f.base, "/resource", "A"), providerDestinationURL(f.base, "/resource", "B")}
	interactions := make([]crossDeviceInteraction, 2)
	for index, b := range requesters {
		start := providerDestinationRequest(t, b, "POST", "/cross-device/start?redirect_url="+url.QueryEscape(destinations[index]), url.Values{}, http.Header{"Origin": {b.base}})
		start.requireStatus(t, 200)
		start.noStore(t)
		if json.Unmarshal(start.body, &interactions[index]) != nil || interactions[index].Code == "" || interactions[index].Secret == "" || interactions[index].Code == interactions[index].Secret {
			t.Fatal("invalid destination-bound transfer")
		}
		f.secrets = append(f.secrets, interactions[index].Code, interactions[index].Secret)
	}
	// The public activation code and another request's secret cannot redeem B.
	wrong := interactions[1].values()
	wrong.Set("secret", interactions[0].Secret)
	denied := providerDestinationRequest(t, requesters[0], "POST", "/cross-device/poll", wrong, http.Header{"Origin": {f.base}})
	denied.requireStatus(t, 410)
	providerDestinationNoIssuance(t, denied)
	var tokens [2]string
	for _, index := range []int{1, 0} {
		approver := crossDeviceBrowser(t, f.oidcRPFixture)
		crossDeviceBegin(t, approver, interactions[index])
		approverDestination := providerDestinationURL(f.base, "/resource", "approver")
		providerDestinationRequest(t, approver, "GET", "/login?fresh=1&redirect_url="+url.QueryEscape(approverDestination), nil, nil).requireStatus(t, 200)
		username, password := "alice", lifecyclePassword
		if index == 1 {
			username, password = "bob", localIdentityBobPassword
		}
		confirmation := crossDeviceLogin(t, approver, username, password, false, f.database)
		form := oidcRPForm(t, confirmation.body)
		form.values.Set("decision", "approve")
		wrongBrowser := crossDeviceBrowser(t, approver)
		denied = providerDestinationRequest(t, wrongBrowser, "POST", crossDeviceAction(t, approver, form.action), form.values, http.Header{"Origin": {f.base}})
		denied.requireStatus(t, 410)
		providerDestinationNoIssuance(t, denied)
		crossDeviceDecision(t, approver, confirmation, "approve").requireStatus(t, 200)
		b := requesters[index]
		providerDestinationLegacyCookie(t, b, providerDestinationURL(f.base, "/resource", "other-tab"))
		poll := providerDestinationRequest(t, b, "POST", "/cross-device/poll?redirect_url="+url.QueryEscape(approverDestination), interactions[index].values(), http.Header{"Origin": {f.base}})
		poll.requireStatus(t, 200)
		poll.noStore(t)
		var result struct{ Status, Next string }
		if json.Unmarshal(poll.body, &result) != nil || result.Status != "approved" || result.Next != destinations[index] {
			t.Fatal("transfer did not retain its requester destination")
		}
		tokens[index] = providerDestinationIdentity(t, f, b, username+"@example.test")
		if tokens[index] == crossDeviceCookie(approver, "AUTHP_ACCESS_TOKEN") {
			t.Fatal("transfer reused the approver credential")
		}
		providerDestinationResource(t, b, result.Next, "identity resource")
		// The exact original capability is retried without any newly issued JWT.
		replay := providerDestinationRequest(t, providerDestinationReplayBrowser(b), "POST", "/cross-device/poll", interactions[index].values(), http.Header{"Origin": {f.base}})
		replay.requireStatus(t, 410)
		providerDestinationNoIssuance(t, replay)
		if index == 1 && crossDeviceCookie(requesters[0], "AUTHP_ACCESS_TOKEN") != "" {
			t.Fatal("another requester received the completed flow's credential")
		}
	}
	if tokens[0] == tokens[1] {
		t.Fatal("independent requester flows shared credentials")
	}
}
