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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"golang.org/x/crypto/ssh"
)

func (f *localIdentityFixture) publicKeys(t *testing.T, usage string) []*identity.PublicKey {
	t.Helper()
	r := f.profile(t, map[string]any{"kind": "fetch_user_" + usage + "_keys"}, 200)
	var list struct{ Entries []*identity.PublicKey }
	if json.Unmarshal(r.body, &list) != nil || list.Entries == nil {
		t.Fatal("invalid public-key inventory")
	}
	for _, key := range list.Entries {
		if key == nil || key.ID == "" || key.Usage != usage {
			t.Fatal("invalid public-key inventory entry")
		}
	}
	return list.Entries
}

func testLocalIdentityPublicKeys(t *testing.T, cert, key string, roots *x509.CertPool) {
	f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/auth"}, cert, key, roots)
	pgp, err := os.ReadFile("testdata/identity/legacy_pgp_public.pem")
	if err != nil {
		t.Fatal(err)
	}
	// RSA PEM and OpenSSH are separate keys to exercise each historical format.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)}))
	sshRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(&sshRSA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sshKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic))) + " fixture@example.test"
	add := func(usage, payload string) map[string]any {
		// Client-supplied ownership fields must never change the profile owner.
		return map[string]any{"kind": "add_user_" + usage + "_key", "content": payload, "title": "Fixture key", "description": "Compatibility fixture", "username": "bob", "email": "bob@example.test"}
	}
	f.json(t, f.plain, "/api/profile", add("gpg", string(pgp)), "").requireStatus(t, 403)
	f.formLogin(t, "alice", lifecyclePassword, false)
	for _, tc := range []struct{ usage, payload string }{
		{"gpg", "-----BEGIN PGP PUBLIC KEY BLOCK-----\ninvalid\n-----END PGP PUBLIC KEY BLOCK-----"},
		{"gpg", strings.ReplaceAll(string(pgp), "PUBLIC KEY BLOCK", "PRIVATE KEY BLOCK")},
		{"gpg", string([]byte{0x99, 0x01, 0x0d, 0x04, 0, 1, 2})},
		{"ssh", profileUnsupportedSSHKey(t)},
		{"ssh", "-----BEGIN RSA PUBLIC KEY-----\ninvalid\n-----END RSA PUBLIC KEY-----"},
		{"ssh", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))},
	} {
		f.profile(t, add(tc.usage, tc.payload), 400)
	}
	// Keep the key valid: malformed content would be rejected even if the
	// request-size limit disappeared. Unknown JSON fields are ignored.
	boundary := add("gpg", string(pgp))
	boundary["padding"] = ""
	encoded, err := json.Marshal(boundary)
	if err != nil {
		t.Fatal(err)
	}
	padding := strings.Repeat("x", (1<<20)-len(encoded))
	boundary["padding"] = padding + "x"
	f.profile(t, boundary, 400)
	if len(f.publicKeys(t, "gpg")) != 0 || len(f.publicKeys(t, "ssh")) != 0 {
		t.Fatal("rejected public key altered inventory")
	}
	for _, tc := range []struct{ usage, payload string }{{"gpg", string(pgp)}, {"ssh", pemKey}, {"ssh", sshKey}} {
		if tc.usage == "gpg" {
			// The same valid operation succeeds exactly at the 1 MiB limit.
			boundary["padding"] = padding
			f.profile(t, boundary, 200)
		} else {
			f.profile(t, add(tc.usage, tc.payload), 200)
		}
		f.profile(t, add(tc.usage, tc.payload), 400)
	}
	gpgKeys, sshKeys := f.publicKeys(t, "gpg"), f.publicKeys(t, "ssh")
	if len(gpgKeys) != 1 || len(sshKeys) != 2 {
		t.Fatal("public-key duplicate rejection or format support changed")
	}
	pgpKey := gpgKeys[0]
	if pgpKey.ID != "a040830f7fac5991" || pgpKey.Fingerprint != "4cca1eaf950cee4ab83976dca040830f7fac5991" || pgpKey.Type != "dsa" || pgpKey.Usage != "gpg" || pgpKey.Payload != strings.TrimSpace(string(pgp)) || pgpKey.Comment != "Fixture key" || !strings.Contains(pgpKey.Description, "DSA") {
		t.Fatal("historical armored PGP metadata changed")
	}
	foundOpenSSH := false
	for _, public := range sshKeys {
		if public.Type != "ssh-rsa" || public.Fingerprint == "" || public.OpenSSH == "" || public.Usage != "ssh" {
			t.Fatal("RSA public-key metadata lost")
		}
		if public.Fingerprint == ssh.FingerprintSHA256(sshPublic) {
			foundOpenSSH = true
			if public.Comment != "fixture@example.test" {
				t.Fatal("OpenSSH comment changed")
			}
		}
	}
	if !foundOpenSSH {
		t.Fatal("OpenSSH fingerprint changed")
	}
	// Reopen the actual file without changing the live Caddy database.
	reopened, err := identity.NewDatabase(f.database)
	if err != nil {
		t.Fatal(err)
	}
	for usage, expected := range map[string][]*identity.PublicKey{"gpg": gpgKeys, "ssh": sshKeys} {
		r := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, Key: requests.Key{Usage: usage}}
		if err := reopened.GetPublicKeys(r); err != nil {
			t.Fatal("could not reopen persisted key inventory")
		}
		bundle, ok := r.Response.Payload.(*identity.PublicKeyBundle)
		if !ok || !cmp.Equal(expected, bundle.Get()) {
			t.Fatal("reopened public-key metadata differs")
		}
	}
	if err := caddy.Stop(); err != nil {
		t.Fatal(err)
	}
	f.load(t)
	f.formLogin(t, "alice", lifecyclePassword, false)
	if !cmp.Equal(gpgKeys, f.publicKeys(t, "gpg")) || !cmp.Equal(sshKeys, f.publicKeys(t, "ssh")) {
		t.Fatal("Caddy restart changed public-key inventory")
	}
	f.formLogin(t, "bob", localIdentityBobPassword, false)
	if len(f.publicKeys(t, "gpg")) != 0 || len(f.publicKeys(t, "ssh")) != 0 {
		t.Fatal("another user inherited Alice's public keys")
	}
	for _, usage := range []string{"gpg", "ssh"} {
		id := pgpKey.ID
		if usage == "ssh" {
			id = sshKeys[0].ID
		}
		response := f.profile(t, map[string]any{"kind": "fetch_user_" + usage + "_key", "id": id, "username": "alice", "email": "alice@example.test"}, 500)
		var result struct{ Entry json.RawMessage }
		if json.Unmarshal(response.body, &result) != nil || len(result.Entry) != 0 && string(result.Entry) != "null" {
			t.Fatal("foreign key fetch exposed an entry despite its failure status")
		}
		f.profile(t, map[string]any{"kind": "delete_user_" + usage + "_key", "id": id}, 500)
	}
	// Fingerprints identify public material, not its owner: two users may
	// store the same public key, with duplicate rejection scoped to each user.
	f.profile(t, add("gpg", string(pgp)), 200)
	f.profile(t, add("gpg", string(pgp)), 400)
	bobKeys := f.publicKeys(t, "gpg")
	if len(bobKeys) != 1 || bobKeys[0].ID != pgpKey.ID {
		t.Fatal("shared public material lost its per-user ownership")
	}
	f.formLogin(t, "alice", lifecyclePassword, false)
	if !cmp.Equal(gpgKeys, f.publicKeys(t, "gpg")) || !cmp.Equal(sshKeys, f.publicKeys(t, "ssh")) {
		t.Fatal("another user's requests changed Alice's public keys")
	}
	// Positive controls prevent an unconditionally broken fetch/delete route
	// from satisfying the preceding isolation assertions.
	for _, keys := range [][]*identity.PublicKey{gpgKeys, sshKeys} {
		for _, expected := range keys {
			response := f.profile(t, map[string]any{"kind": "fetch_user_" + expected.Usage + "_key", "id": expected.ID}, 200)
			var result struct{ Entry *identity.PublicKey }
			if json.Unmarshal(response.body, &result) != nil || !cmp.Equal(result.Entry, expected) {
				t.Fatal("owner could not fetch the persisted public-key metadata")
			}
			f.profile(t, map[string]any{"kind": "delete_user_" + expected.Usage + "_key", "id": expected.ID}, 200)
		}
	}
	if len(f.publicKeys(t, "gpg")) != 0 || len(f.publicKeys(t, "ssh")) != 0 || len(localIdentityRecord(t, f.database, "alice").PublicKeys) != 0 {
		t.Fatal("owner deletion did not remove persisted public keys")
	}
	f.formLogin(t, "bob", localIdentityBobPassword, false)
	if !cmp.Equal(bobKeys, f.publicKeys(t, "gpg")) || len(f.publicKeys(t, "ssh")) != 0 {
		t.Fatal("Alice's deletion affected Bob's independent public-key inventory")
	}
}
