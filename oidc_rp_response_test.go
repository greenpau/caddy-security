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
	"encoding/base64"
	"fmt"
	"mime"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// Browser pages generate a fresh 256-bit style nonce for every response.
// Normalize only that value when comparing independently rendered policies;
// all directive names, sources, and callback origins remain significant.
func normalizeOIDCPagePolicy(policy string) (string, error) {
	pattern := regexp.MustCompile(`'nonce-([A-Za-z0-9_-]{43})'`)
	matches := pattern.FindAllStringSubmatch(policy, -1)
	if len(matches) != 1 || strings.Count(policy, "'nonce-") != 1 {
		return "", fmt.Errorf("expected one unpredictable page style nonce")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(matches[0][1])
	if err != nil || len(nonce) != 32 {
		return "", fmt.Errorf("invalid page style nonce")
	}
	return strings.Replace(policy, matches[0][0], "'nonce-PER_RESPONSE'", 1), nil
}

func TestOIDCPagePolicyNonce(t *testing.T) {
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	policy := "default-src 'none'; style-src 'self' 'nonce-" + nonce + "'; form-action 'self' https://rp.example.test"
	normalized, err := normalizeOIDCPagePolicy(policy)
	if err != nil || normalized != strings.Replace(policy, nonce, "PER_RESPONSE", 1) {
		t.Fatal("policy normalization changed more than the per-response nonce")
	}
	for _, bad := range []string{"", strings.Replace(policy, nonce, "short", 1), policy + "; script-src 'nonce-" + nonce + "'"} {
		if _, err := normalizeOIDCPagePolicy(bad); err == nil {
			t.Fatal("accepted a missing, weak or additional nonce")
		}
	}
}

type oidcRPBrowserForm struct {
	action    string
	values    url.Values
	decisions []string
	nonces    []string
}

// Parse the OP's single POST form. Only enabled hidden controls inside that
// form participate; collecting every input in the document can hide broken
// consent or form-post templates. This is deliberately not a general browser.
func parseOIDCRPForm(body []byte) (oidcRPBrowserForm, error) {
	form := oidcRPBrowserForm{values: make(url.Values)}
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return form, fmt.Errorf("invalid response HTML")
	}
	var forms int
	var walk func(*html.Node, bool) error
	walk = func(node *html.Node, inside bool) error {
		if node.Type == html.ElementNode {
			attrs := make(map[string]string)
			for _, attr := range node.Attr {
				if _, exists := attrs[attr.Key]; exists {
					return fmt.Errorf("ambiguous HTML attribute")
				}
				attrs[attr.Key] = attr.Val
			}
			_, disabled := attrs["disabled"]
			switch node.Data {
			case "base":
				return fmt.Errorf("unexpected base URL override")
			case "form":
				forms++
				if forms != 1 || !strings.EqualFold(attrs["method"], "post") || attrs["action"] == "" || (attrs["enctype"] != "" && attrs["enctype"] != "application/x-www-form-urlencoded") {
					return fmt.Errorf("expected a single POST form with an action")
				}
				form.action, inside = attrs["action"], true
			case "fieldset":
				if inside && disabled {
					return fmt.Errorf("disabled form controls")
				}
			case "input", "button":
				if attrs["form"] != "" || attrs["formaction"] != "" || attrs["formmethod"] != "" {
					return fmt.Errorf("unexpected form override")
				}
				if inside && !disabled && attrs["name"] != "" {
					if node.Data == "input" && strings.EqualFold(attrs["type"], "hidden") {
						form.values.Add(attrs["name"], attrs["value"])
					}
					if node.Data == "button" && attrs["name"] == "decision" && (attrs["type"] == "" || strings.EqualFold(attrs["type"], "submit")) {
						form.decisions = append(form.decisions, attrs["value"])
					}
				}
			case "script":
				if attrs["src"] != "" || attrs["nonce"] == "" {
					return fmt.Errorf("unexpected script without an inline nonce")
				}
				form.nonces = append(form.nonces, attrs["nonce"])
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child, inside); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(doc, false); err != nil {
		return form, err
	}
	if forms != 1 {
		return form, fmt.Errorf("missing response form")
	}
	return form, nil
}

func verifyOIDCRPCallback(r oidcRPResponse, params url.Values, issuer, failure string) (string, error) {
	if r.header.Get("Cache-Control") != "no-store" || r.header.Get("Pragma") != "no-cache" {
		return "", fmt.Errorf("callback lost no-store/no-cache")
	}
	registered, err := url.Parse(params.Get("redirect_uri"))
	if err != nil || !registered.IsAbs() || registered.Host == "" || registered.User != nil || registered.Fragment != "" {
		return "", fmt.Errorf("invalid registered callback")
	}
	var values url.Values
	if params.Get("response_mode") == "form_post" {
		mediaType, _, err := mime.ParseMediaType(r.header.Get("Content-Type"))
		if err != nil || mediaType != "text/html" || r.status != 200 || len(r.header.Values("Location")) != 0 || r.header.Get("Referrer-Policy") != "no-referrer" {
			return "", fmt.Errorf("invalid form-post response headers")
		}
		form, err := parseOIDCRPForm(r.body)
		if err != nil {
			return "", err
		}
		if form.action != params.Get("redirect_uri") || len(form.nonces) != 1 {
			return "", fmt.Errorf("form-post destination or submission script changed")
		}
		// Compare directive tokens, not origin/nonce substrings: lookalike
		// origins and additional script sources must not pass the test oracle.
		directives := make(map[string][]string)
		if len(r.header.Values("Content-Security-Policy")) != 1 {
			return "", fmt.Errorf("ambiguous form-post CSP")
		}
		for _, directive := range strings.Split(r.header.Get("Content-Security-Policy"), ";") {
			fields := strings.Fields(directive)
			if len(fields) == 0 {
				continue
			}
			if _, exists := directives[fields[0]]; exists {
				return "", fmt.Errorf("duplicate CSP directive")
			}
			directives[fields[0]] = fields[1:]
		}
		expected := map[string][]string{
			"default-src": {"'none'"}, "frame-ancestors": {"'none'"}, "base-uri": {"'none'"},
			"script-src": {"'nonce-" + form.nonces[0] + "'"}, "form-action": {registered.Scheme + "://" + registered.Host},
		}
		if _, themed := directives["style-src"]; themed {
			expected["style-src"] = []string{"'self'", "'nonce-" + form.nonces[0] + "'"}
			expected["img-src"] = []string{"'self'"}
			expected["font-src"] = []string{"'self'"}
		}
		if len(directives) != len(expected) {
			return "", fmt.Errorf("unexpected form-post CSP directives")
		}
		for directive, want := range expected {
			if !slices.Equal(directives[directive], want) {
				return "", fmt.Errorf("form-post CSP missing or weakened")
			}
		}
		values = form.values
	} else {
		if r.status != 302 || len(r.header.Values("Location")) != 1 {
			return "", fmt.Errorf("invalid query callback response")
		}
		location, err := url.Parse(r.header.Get("Location"))
		if err != nil || location.Scheme != registered.Scheme || location.Host != registered.Host || location.User != nil || location.Opaque != "" || location.EscapedPath() != registered.EscapedPath() || strings.Contains(r.header.Get("Location"), "#") {
			return "", fmt.Errorf("callback URI changed")
		}
		values, err = url.ParseQuery(location.RawQuery)
		if err != nil {
			return "", fmt.Errorf("malformed callback query")
		}
		registeredValues, err := url.ParseQuery(registered.RawQuery)
		if err != nil {
			return "", fmt.Errorf("malformed registered callback query")
		}
		for key, want := range registeredValues {
			if !slices.Equal(values[key], want) {
				return "", fmt.Errorf("registered callback query changed")
			}
		}
	}
	for _, key := range []string{"state", "iss", "code", "error", "error_description", "error_uri"} {
		if len(values[key]) > 1 {
			return "", fmt.Errorf("duplicate authorization response parameter")
		}
	}
	if values.Get("state") != params.Get("state") || values.Get("iss") != issuer || values.Get("error") != failure {
		return "", fmt.Errorf("callback state, issuer or error mismatch")
	}
	if failure == "" {
		if values.Get("code") == "" || values.Has("error") {
			return "", fmt.Errorf("invalid successful callback")
		}
	} else if values.Has("code") {
		return "", fmt.Errorf("error callback contains a code")
	}
	return values.Get("code"), nil
}

func TestOIDCRPResponse(t *testing.T) {
	const issuer = "https://issuer.example/auth"
	params := url.Values{"redirect_uri": {oidcRPCallback}, "state": {"state"}}
	valid := oidcRPResponse{status: 302, header: map[string][]string{
		"Cache-Control": {"no-store"}, "Pragma": {"no-cache"},
		"Location": {oidcRPCallback + "&state=state&iss=" + url.QueryEscape(issuer) + "&code=code"},
	}}
	if code, err := verifyOIDCRPCallback(valid, params, issuer, ""); err != nil || code != "code" {
		t.Fatalf("valid query callback rejected: %v", err)
	}
	for _, tc := range []struct{ name, location string }{
		{"state", valid.header.Get("Location") + "&state=other"},
		{"issuer", valid.header.Get("Location") + "&iss=" + url.QueryEscape(issuer)},
		{"code", valid.header.Get("Location") + "&code=other"},
		{"empty error", valid.header.Get("Location") + "&error="},
		{"fragment", valid.header.Get("Location") + "#"},
		{"query escape", valid.header.Get("Location") + "&extra=%zz"},
		{"query separator", valid.header.Get("Location") + "&extra=a;b"},
		{"userinfo", strings.Replace(valid.header.Get("Location"), "https://", "https://attacker@", 1)},
		{"path", strings.Replace(valid.header.Get("Location"), "/callback", "/other", 1)},
		{"registered query", strings.Replace(valid.header.Get("Location"), "registered=yes", "registered=no", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			r.header = valid.header.Clone()
			r.header.Set("Location", tc.location)
			if _, err := verifyOIDCRPCallback(r, params, issuer, ""); err == nil {
				t.Fatal("accepted invalid callback")
			}
		})
	}
	const body = `<input type="hidden" name="outside" value="ignored"><form method="post" action="https://rp.example.test/callback?registered=yes"><input type="hidden" name="state" value="state"><input type="hidden" name="iss" value="https://issuer.example/auth"><input type="hidden" name="code" value="code"><input type="hidden" name="disabled" disabled value="ignored"><button name="decision" value="allow">Allow</button></form><script nonce="test-nonce">submit();</script>`
	form, err := parseOIDCRPForm([]byte(body))
	if err != nil || form.values.Has("outside") || form.values.Has("disabled") || !slices.Equal(form.decisions, []string{"allow"}) {
		t.Fatalf("incorrect form controls: %v", err)
	}
	params.Set("response_mode", "form_post")
	valid = oidcRPResponse{status: 200, body: []byte(body), header: map[string][]string{
		"Cache-Control": {"no-store"}, "Pragma": {"no-cache"}, "Content-Type": {"text/html; charset=utf-8"}, "Referrer-Policy": {"no-referrer"},
		"Content-Security-Policy": {"default-src 'none'; script-src 'nonce-test-nonce'; frame-ancestors 'none'; base-uri 'none'; form-action https://rp.example.test"},
	}}
	if code, err := verifyOIDCRPCallback(valid, params, issuer, ""); err != nil || code != "code" {
		t.Fatalf("valid form-post callback rejected: %v", err)
	}
	valid.header.Set("Content-Security-Policy", valid.header.Get("Content-Security-Policy")+"; style-src 'self' 'nonce-test-nonce'; img-src 'self'; font-src 'self'")
	if code, err := verifyOIDCRPCallback(valid, params, issuer, ""); err != nil || code != "code" {
		t.Fatalf("valid themed form-post callback rejected: %v", err)
	}
	for _, tc := range []struct{ name, old, replacement string }{
		{"GET", `method="post"`, `method="get"`},
		{"default method", `method="post"`, ""},
		{"encoding", `method="post"`, `method="post" enctype="text/plain"`},
		{"missing form", "<form", "<div"},
		{"multiple forms", "</form>", `</form><form method="post" action="/other"></form>`},
		{"duplicate attribute", `method="post"`, `method="get" method="post"`},
		{"base URL", "<form", `<base href="https://attacker.example"><form`},
		{"wrong destination", `action="https://rp.example.test/`, `action="https://attacker.example/`},
		{"disabled code", `name="code"`, `name="code" disabled`},
		{"disabled fieldset", `<input type="hidden" name="code"`, `<fieldset disabled><input type="hidden" name="code"`},
		{"misplaced code", `<input type="hidden" name="code"`, `</form><input type="hidden" name="code"`},
		{"duplicate state", `name="code"`, `name="state"`},
		{"nonce", `nonce="test-nonce"`, `nonce="other"`},
		{"external script", `<script nonce=`, `<script src="/external.js" nonce=`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			r.body = []byte(strings.Replace(body, tc.old, tc.replacement, 1))
			if _, err := verifyOIDCRPCallback(r, params, issuer, ""); err == nil {
				t.Fatal("accepted broken form-post HTML")
			}
		})
	}
	for _, csp := range []string{
		valid.header.Get("Content-Security-Policy") + ".attacker.example",
		valid.header.Get("Content-Security-Policy") + " https://attacker.example",
		valid.header.Get("Content-Security-Policy") + "; script-src *",
		valid.header.Get("Content-Security-Policy") + "; script-src-elem *",
		strings.Replace(valid.header.Get("Content-Security-Policy"), "img-src 'self'", "img-src *", 1),
		strings.Replace(valid.header.Get("Content-Security-Policy"), "font-src 'self'", "font-src https://attacker.example", 1),
		strings.Replace(valid.header.Get("Content-Security-Policy"), "style-src 'self' 'nonce-test-nonce'", "style-src 'self' 'unsafe-inline'", 1),
		strings.Replace(valid.header.Get("Content-Security-Policy"), "script-src 'nonce-test-nonce'", "script-src 'nonce-test-nonce' 'unsafe-inline'", 1),
	} {
		r := valid
		r.header = valid.header.Clone()
		r.header.Set("Content-Security-Policy", csp)
		if _, err := verifyOIDCRPCallback(r, params, issuer, ""); err == nil {
			t.Fatal("accepted weakened form-post CSP")
		}
	}
}
