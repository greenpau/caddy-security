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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"golang.org/x/crypto/ssh"
)

func profileUnsupportedSSHKey(t *testing.T) string {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatal("cannot encode synthetic Ed25519 public key")
	}
	return string(ssh.MarshalAuthorizedKey(public))
}

func TestProfilePublicKeyParserCompatibility(t *testing.T) {
	data, err := os.ReadFile("testdata/identity/legacy_pgp_public.pem")
	if err != nil {
		t.Fatal(err)
	}
	armored := strings.TrimSpace(string(data))
	request := &requests.Request{Key: requests.Key{Usage: "gpg", Payload: "\n" + armored + "\n", Comment: "Fixture key"}}
	key, err := identity.NewPublicKey(request)
	if err != nil || key.ID != "a040830f7fac5991" || key.Fingerprint != "4cca1eaf950cee4ab83976dca040830f7fac5991" || key.Type != "dsa" || key.Comment != "Fixture key" || key.Payload != armored {
		t.Fatal("historical public metadata compatibility changed")
	}
	// Decode the known fixture's base64 between its header and CRC. Test actual
	// binary packets directly: JSON strings would normalize invalid UTF-8.
	_, payload, ok := strings.Cut(armored, "\n\n")
	if !ok {
		t.Fatal("fixture armor header missing")
	}
	payload, _, ok = strings.Cut(payload, "\n=")
	if !ok {
		t.Fatal("fixture armor checksum missing")
	}
	binary, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(payload, "\n", ""))
	if err != nil || len(binary) == 0 {
		t.Fatal("invalid public fixture packets")
	}
	for name, value := range map[string]string{
		"binary packets": string(binary),
		"private armor":  strings.ReplaceAll(armored, "PUBLIC KEY BLOCK", "PRIVATE KEY BLOCK"),
		"malformed":      "-----BEGIN PGP PUBLIC KEY BLOCK-----\ninvalid\n-----END PGP PUBLIC KEY BLOCK-----",
	} {
		t.Run(name, func(t *testing.T) {
			request := &requests.Request{Key: requests.Key{Usage: "gpg", Payload: value}}
			if key, err := identity.NewPublicKey(request); err == nil || key != nil {
				t.Fatal("unsupported public-key input accepted")
			}
		})
	}
	t.Run("unsupported SSH algorithm", func(t *testing.T) {
		payload := profileUnsupportedSSHKey(t)
		// The negative fixture must be valid SSH, so rejection establishes the
		// library's supported format boundary rather than malformed encoding.
		public, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(payload))
		if err != nil || len(rest) != 0 || public.Type() != ssh.KeyAlgoED25519 {
			t.Fatal("invalid unsupported-algorithm fixture")
		}
		request := &requests.Request{Key: requests.Key{Usage: "ssh", Payload: payload}}
		if key, err := identity.NewPublicKey(request); err == nil || key != nil {
			t.Fatal("unsupported SSH algorithm accepted")
		}
	})
	t.Run("RSA formats", func(t *testing.T) {
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal("cannot generate synthetic RSA key")
		}
		public, err := ssh.NewPublicKey(&private.PublicKey)
		if err != nil {
			t.Fatal("cannot encode RSA public key")
		}
		for _, tc := range []struct{ name, payload, fingerprint, comment string }{
			{"PKCS1 PEM", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&private.PublicKey)})), strings.TrimPrefix(ssh.FingerprintSHA256(public), "SHA256:"), "Fixture key"},
			{"authorized_keys", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))) + " fixture@example.test", ssh.FingerprintSHA256(public), "fixture@example.test"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				request := &requests.Request{Key: requests.Key{Usage: "ssh", Payload: tc.payload, Comment: "Fixture key"}}
				key, err := identity.NewPublicKey(request)
				if err != nil || key == nil || key.Type != ssh.KeyAlgoRSA || key.Usage != "ssh" || key.Fingerprint != tc.fingerprint || key.FingerprintMD5 != ssh.FingerprintLegacyMD5(public) || key.Comment != tc.comment {
					t.Fatal("historical RSA metadata compatibility changed")
				}
				parsed, _, _, rest, err := ssh.ParseAuthorizedKey([]byte("ssh-rsa " + key.OpenSSH))
				if err != nil || len(rest) != 0 || !bytes.Equal(parsed.Marshal(), public.Marshal()) {
					t.Fatal("stored OpenSSH representation changed the RSA public key")
				}
				if tc.name == "PKCS1 PEM" && key.Payload != tc.payload {
					t.Fatal("stored PKCS1 payload changed")
				}
			})
		}
	})
}
