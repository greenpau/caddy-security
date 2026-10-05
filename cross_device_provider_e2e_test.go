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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	samllib "github.com/crewjam/saml"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/html"
)

func TestCaddyCrossDeviceProvidersE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyCrossDeviceProvidersProcess$", "-test.v", "-test.timeout=110s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_CROSS_DEVICE_PROVIDERS_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy cross-device providers: %v\n%s", err, output)
	}
}

func TestCaddyCrossDeviceProvidersProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_CROSS_DEVICE_PROVIDERS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Fatal(err)
	}
	oauthE2ESystemRoots = roots
	for _, mode := range []string{"enabled", "disabled", "mixed"} {
		t.Run("OAuth "+mode, func(t *testing.T) {
			u := newOAuthE2EUpstream(t, pair, "EdDSA")
			f := newCaddyOAuthFixture(t, u, "discovery", u.server.URL, "resource-api", cert, key, roots, func(f *caddyOAuthFixture) {
				f.input = strings.Replace(f.input, "realm upstream", "realm cross-device", 1)
				directive := "enable cross-device login"
				if mode == "disabled" {
					directive = "disable cross-device login"
				}
				// An access-only custom sid is not a locally issued refresh family.
				extra := directive + "\ntransform user {\nmatch any\nadd sid external-session as string\n}\n"
				if mode == "mixed" {
					f.input = strings.Replace(f.input, "security {", "security {\nlocal identity store localdb {\nrealm local\npath :memory:\n}\n", 1)
					extra += "enable identity store localdb\n"
				}
				f.input = strings.Replace(f.input, "authentication portal portal {", "authentication portal portal {\n"+extra, 1)
			})
			u.mu.Lock()
			u.callback = f.base + "/auth/oauth2/cross-device/authorization-code-callback"
			u.mu.Unlock()
			requester := crossDeviceBrowser(t, &oidcRPFixture{client: f.client, base: f.base, mount: "/auth", issuer: f.base + "/auth"})
			approver := crossDeviceBrowser(t, requester)
			login := requester.request(t, "GET", "/login", nil, nil)
			if bytes.Contains(login.body, []byte("Sign in on another device")) != (mode != "disabled") || !bytes.Contains(login.body, []byte("Company Login")) {
				t.Fatal("provider login links did not preserve their independent visibility")
			}
			var interaction crossDeviceInteraction
			if mode != "disabled" {
				interaction = crossDeviceStart(t, requester)
				crossDeviceBegin(t, approver, interaction)
			} else {
				requester.request(t, "GET", "/cross-device", nil, nil).requireStatus(t, 404)
			}
			location := approver.issuer + "/oauth2/cross-device"
			for range 2 {
				r := approver.request(t, "GET", location, nil, nil)
				r.requireStatus(t, 302)
				location = r.header.Get("Location")
			}
			callback := approver.request(t, "GET", location, nil, nil)
			callback.requireStatus(t, 303)
			if mode == "disabled" {
				approver.request(t, "GET", f.base+"/protected", nil, nil).requireStatus(t, 200)
				return
			}
			if callback.header.Get("Location") != "/auth/cross-device/confirm" {
				t.Fatal("OAuth did not enter explicit approval")
			}
			confirmation := approver.request(t, "GET", "/cross-device/confirm", nil, nil)
			confirmation.requireStatus(t, 200)
			crossDeviceDecision(t, approver, confirmation, "approve").requireStatus(t, 200)
			crossDevicePost(t, requester, "poll", interaction.values()).requireStatus(t, 200)
			own, other := crossDeviceCookie(requester, "AUTHP_ACCESS_TOKEN"), crossDeviceCookie(approver, "AUTHP_ACCESS_TOKEN")
			if own == "" || own == other {
				t.Fatal("OAuth devices shared access credentials")
			}
			parsed, err := jwt.Parse(own, func(*jwt.Token) (any, error) { return []byte(oauthE2EPortalKey), nil }, jwt.WithValidMethods([]string{"HS512"}), jwt.WithExpirationRequired())
			if err != nil || !parsed.Valid || parsed.Claims.(jwt.MapClaims)["sid"] != "external-session" {
				t.Fatal("custom access sid was confused with a refresh family")
			}
			if crossDeviceCookie(requester, "AUTHP_ID_TOKEN") != "" {
				t.Fatal("upstream identity token was transferred")
			}
			requester.request(t, "GET", f.base+"/protected", nil, nil).requireStatus(t, 200)
			u.mu.Lock()
			defer u.mu.Unlock()
			if u.exchanges != 1 || u.authorizations != 1 {
				t.Fatal("OAuth callback did not verify fresh upstream evidence")
			}
		})
	}
	t.Run("signed SAML", func(t *testing.T) { testCaddyCrossDeviceSAML(t, cert, key, roots, pair) })
}

type crossDeviceSAMLProvider struct{ metadata *samllib.EntityDescriptor }

func (p *crossDeviceSAMLProvider) GetServiceProvider(_ *http.Request, entity string) (*samllib.EntityDescriptor, error) {
	if p.metadata != nil && p.metadata.EntityID == entity {
		return p.metadata, nil
	}
	return nil, os.ErrNotExist
}

type crossDeviceSAMLSession struct{}

func (crossDeviceSAMLSession) GetSession(_ http.ResponseWriter, _ *http.Request, _ *samllib.IdpAuthnRequest) *samllib.Session {
	now := time.Now()
	return &samllib.Session{ID: "cross-device-idp-session", Index: "cross-device-idp-index", CreateTime: now, ExpireTime: now.Add(time.Hour), NameID: "saml-user@example.test", UserName: "saml-user", UserEmail: "saml-user@example.test", UserCommonName: "SAML User", CustomAttributes: []samllib.Attribute{
		{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", Values: []samllib.AttributeValue{{Type: "xs:string", Value: "saml-user@example.test"}}},
		{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname", Values: []samllib.AttributeValue{{Type: "xs:string", Value: "SAML User"}}},
	}}
}

func testCaddyCrossDeviceSAML(t *testing.T, cert, key string, roots *x509.CertPool, pair tls.Certificate) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(506), Subject: pkix.Name{CommonName: "Caddy Cross-device SAML IdP"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &signingKey.PublicKey, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	signingCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sp := &crossDeviceSAMLProvider{}
	idpServer := httptest.NewUnstartedServer(nil)
	idpURL := "https://" + idpServer.Listener.Addr().String()
	parseURL := func(value string) url.URL {
		u, err := url.Parse(value)
		if err != nil {
			t.Fatal(err)
		}
		return *u
	}
	idp := &samllib.IdentityProvider{Key: signingKey, Certificate: signingCert, MetadataURL: parseURL(idpURL + "/metadata"), SSOURL: parseURL(idpURL + "/sso"), ServiceProviderProvider: sp, SessionProvider: crossDeviceSAMLSession{}, Logger: log.New(io.Discard, "", 0)}
	idpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sso" {
			idp.ServeSSO(w, r)
			return
		}
		http.NotFound(w, r)
	})
	idpServer.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	idpServer.StartTLS()
	t.Cleanup(idpServer.Close)
	dir := t.TempDir()
	metadataPath, signingPath := filepath.Join(dir, "idp.xml"), filepath.Join(dir, "idp.pem")
	metadata, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, metadata, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signingPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	options := localIdentityOptions{mount: "/auth", configure: func(input string) string {
		var base string
		for _, line := range strings.Split(input, "\n") {
			if strings.HasPrefix(line, "https://") {
				base = strings.Fields(line)[0]
			}
		}
		if base == "" {
			t.Fatal("missing Caddy TLS site")
		}
		serviceProvider := &samllib.ServiceProvider{EntityID: "urn:caddy:cross-device", MetadataURL: parseURL(base + "/auth/saml/metadata"), AcsURL: parseURL(base + "/auth/saml/cross-device")}
		sp.metadata = serviceProvider.Metadata()
		provider := fmt.Sprintf("saml identity provider saml_upstream {\nrealm cross-device\ndriver generic\nentity_id urn:caddy:cross-device\nidp_login_url %s/sso\nidp_metadata_location %q\nidp_sign_cert_location %q\nacs_url %s/auth/saml/cross-device\n}\n", idpURL, metadataPath, signingPath, base)
		input = strings.Replace(input, "security {", "security {\n"+provider, 1)
		return strings.Replace(input, "enable identity stores localdb excludeddb", "enable identity provider saml_upstream", 1)
	}}
	f := crossDeviceFixture(t, options, "enable cross-device login\ntransform user {\nmatch realm cross-device\naction add role authp/user\n}", cert, key, roots)
	requester, approver := crossDeviceBrowser(t, f.oidcRPFixture), crossDeviceBrowser(t, f.oidcRPFixture)
	i := crossDeviceStart(t, requester)
	crossDeviceBegin(t, approver, i)
	begin := approver.request(t, "GET", "/saml/cross-device", nil, nil)
	begin.requireStatus(t, 302)
	assertion := approver.request(t, "GET", begin.header.Get("Location"), nil, nil)
	assertion.requireStatus(t, 200)
	// The IdP's ordinary auto-submit scripts do not use the portal OP's CSP
	// nonces. Parse only its form with the shared successful-controls parser.
	document, err := html.Parse(bytes.NewReader(assertion.body))
	if err != nil {
		t.Fatal(err)
	}
	var formHTML bytes.Buffer
	var forms int
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "form" {
			forms++
			if err := html.Render(&formHTML, node); err != nil {
				t.Fatal(err)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	if forms != 1 {
		t.Fatal("IdP did not return one SAML POST form")
	}
	form := oidcRPForm(t, formHTML.Bytes())
	if form.values.Get("SAMLResponse") == "" || form.values.Get("RelayState") == "" {
		t.Fatal("IdP omitted signed response or browser state")
	}
	callback := approver.request(t, "POST", form.action, form.values, http.Header{"Origin": {idpURL}, "Sec-Fetch-Site": {"cross-site"}})
	callback.requireStatus(t, 303)
	if callback.header.Get("Location") != "/auth/cross-device/confirm" {
		t.Fatal("signed SAML callback lost the cross-site binding")
	}
	confirmation := approver.request(t, "GET", "/cross-device/confirm", nil, nil)
	confirmation.requireStatus(t, 200)
	if !bytes.Contains(confirmation.body, []byte("saml-user@example.test")) {
		t.Fatal("approval omitted verified SAML account")
	}
	crossDeviceDecision(t, approver, confirmation, "approve").requireStatus(t, 200)
	crossDevicePost(t, requester, "poll", i.values()).requireStatus(t, 200)
	access := crossDeviceCookie(requester, "AUTHP_ACCESS_TOKEN")
	if access == "" || access == crossDeviceCookie(approver, "AUTHP_ACCESS_TOKEN") {
		t.Fatal("SAML devices shared credentials")
	}
	f.assertResource(t, access)
}
