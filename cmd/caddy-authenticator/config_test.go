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
	"bytes"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestProfilesRoundTrip(t *testing.T) {
	data := []byte("# profiles\r\n[work]\r\nbase_url = https://example.test/auth\r\nrealm = local\r\nusername = alice\r\npassword = \" spaces = # ; \\\"quote\\\" \\t\"\r\n\r\n[default]\nbase_url=https://example.test\nrealm=local\napi_key=example-key\n")
	all, err := parseProfiles(data)
	if err != nil {
		t.Fatal(err)
	}
	again, err := parseProfiles(encodeProfiles(all))
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(all, again); diff != "" {
		t.Fatal("profile serialization changed values:", diff)
	}
	cfg, err := all["work"].config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != " spaces = # ; \"quote\" \t" || cfg.TOTPCodeLength != 6 || cfg.RefreshTransport != "cookie" {
		t.Fatal("credential bytes or upstream defaults changed")
	}
	if !bytes.HasPrefix(encodeProfiles(all), []byte("[default]\n")) {
		t.Fatal("profiles are not sorted")
	}
}

func TestProfilesRejectAmbiguity(t *testing.T) {
	for _, data := range []string{
		"key=secret", "[default]\n[default]\n", "[../escape]\n", "[MixedCase]\n", "[nul]\n",
		"[default]\npassword=first\npassword=second", "[default]\nunknown=secret",
		"[default] trailing", "[default]\npassword=\"unterminated", "[default]\npassword=\"secret\\nvalue\"",
		"[default]\npassword=\"secret\\x00value\"", "[default]\npassword=\"secret\\xff\"", "[default]\npassword=secret\xff",
		strings.Repeat("x", maxFileSize+1),
	} {
		if _, err := parseProfiles([]byte(data)); err == nil {
			t.Fatal("accepted invalid credentials syntax")
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("parser leaked a value")
		}
	}
	for _, name := range []string{"", "../work", "a/b", "a\\b", ".", "..", " a", "UPPER", "con", "com1", "lpt9", strings.Repeat("a", 65)} {
		if validProfileName(name) == nil {
			t.Fatalf("accepted invalid profile %q", name)
		}
	}
	for _, name := range []string{"default", "work-1", "0_test", "com10", strings.Repeat("a", 64)} {
		if err := validProfileName(name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProfileConfigUsesSharedParser(t *testing.T) {
	base := profile{"base_url": "https://example.test/auth/", "realm": "local", "username": "alice"}
	for key, value := range map[string]string{"refresh_transport": "body ", "base_url": "https://example.test/auth\t", "totp_code_length": "three", "totp_code_lifetime": "-1", "access_token_name": "bad name", "password": "\t"} {
		p := profile{}
		for k, v := range base {
			p[k] = v
		}
		p[key] = value
		if _, err := p.config(); err == nil {
			t.Fatalf("accepted invalid %s", key)
		}
	}
	base["totp_secret"] = "raw secret\u2003"
	cfg, err := base.config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TOTPSecret != base["totp_secret"] || cfg.BaseURL != "https://example.test/auth" {
		t.Fatal("upstream configuration contract changed")
	}
	base["api_key"] = "synthetic-key"
	if _, err := base.config(); err == nil {
		t.Fatal("accepted mixed API key and username")
	}
}
