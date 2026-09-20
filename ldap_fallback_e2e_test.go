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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

// A disposable LDAPS peer implements only the Bind/Search/Unbind operations
// consumed by the real upstream LDAP client. No mapped groups are returned.
func challengeLDAPServer(t *testing.T, cert, key string) (string, *atomic.Int32) {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	var verified atomic.Int32
	done := make(chan struct{})
	failures := make(chan error, 1)
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if err := challengeLDAPConnection(conn, &verified); err != nil {
				select {
				case failures <- err:
				default:
				}
			}
			conn.Close()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("LDAPS fixture did not stop")
		}
		select {
		case err := <-failures:
			t.Error(err)
		default:
		}
	})
	return "ldaps://" + listener.Addr().String(), &verified
}

func challengeLDAPConnection(conn net.Conn, verified *atomic.Int32) error {
	if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return err
	}
	var serviceBound bool
	for {
		packet, err := ber.ReadPacket(conn)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(packet.Children) != 2 {
			return fmt.Errorf("invalid LDAP envelope")
		}
		id, ok := packet.Children[0].Value.(int64)
		if !ok {
			return fmt.Errorf("invalid LDAP message ID")
		}
		op := packet.Children[1]
		send := func(response *ber.Packet) error {
			envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "message")
			envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "id"))
			envelope.AppendChild(response)
			_, err := conn.Write(envelope.Bytes())
			return err
		}
		result := func(tag ber.Tag, code int) error {
			response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "result")
			response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "code"))
			response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "dn"))
			response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "message"))
			return send(response)
		}
		switch op.Tag {
		case 0: // BindRequest
			if len(op.Children) != 3 {
				return fmt.Errorf("invalid LDAP bind")
			}
			dn, _ := op.Children[1].Value.(string)
			password := op.Children[2].Data.String()
			code := 49
			if dn == "cn=service,dc=example,dc=test" && password == "SyntheticBindPassword42!" {
				code = 0
				serviceBound = true
			}
			if serviceBound && dn == "cn=alice,dc=example,dc=test" && password == lifecyclePassword {
				code = 0
				verified.Add(1)
			}
			if err := result(1, code); err != nil {
				return err
			}
		case 3: // SearchRequest
			if !serviceBound {
				return fmt.Errorf("LDAP search preceded service authentication")
			}
			entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "entry")
			entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=alice,dc=example,dc=test", "dn"))
			attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
			for _, pair := range [][2]string{{"sAMAccountName", "alice"}, {"givenName", "Alice"}, {"sn", "Example"}, {"mail", "alice@example.test"}} {
				attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
				attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, pair[0], "name"))
				values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
				values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, pair[1], "value"))
				attr.AppendChild(values)
				attrs.AppendChild(attr)
			}
			entry.AppendChild(attrs)
			if err := send(entry); err != nil {
				return err
			}
			if err := result(5, 0); err != nil {
				return err
			}
		case 2:
			return nil // UnbindRequest
		default:
			return fmt.Errorf("unexpected LDAP operation %d", op.Tag)
		}
	}
}

func testCaddyLDAPFallback(t *testing.T, cert, key string, roots *x509.CertPool) {
	address, verified := challengeLDAPServer(t, cert, key)
	f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/auth"}, cert, key, roots)
	store := fmt.Sprintf(`ldap identity store directory {
 realm directory
 servers {
  %s
 }
 trusted_authority %q
 username cn=service,dc=example,dc=test
 password SyntheticBindPassword42!
 search_base_dn dc=example,dc=test
 enable full automatic group mapping
 fallback roles authp/user directory/member
}
`, address, cert)
	f.input = strings.Replace(f.input, "authentication portal myportal {", store+"authentication portal myportal {\nenable identity store directory", 1)
	challengeRestart(t, f)
	req := apiauth.AuthRequest{Username: "alice", Realm: "directory"}
	result := localIdentityAuth(t, f.json(t, f.client, "/login", req, ""))
	if result.NextChallenge != "password" {
		t.Fatal("LDAP did not require password")
	}
	req.SandboxID, req.SandboxSecret, req.ChallengeKind, req.ChallengeResponse = result.SandboxID, result.SandboxSecret, "password", lifecyclePassword
	result = localIdentityAuth(t, f.json(t, f.client, "/login", req, ""))
	if !result.Authenticated || verified.Load() == 0 {
		t.Fatal("LDAP login omitted real credential verification")
	}
	claims := challengeClaims(t, f, result.AccessToken, "pwd")
	roles, ok := claims["roles"].([]any)
	if !ok {
		t.Fatal("LDAP roles missing")
	}
	// Upstream materializes roles from a map, so compare membership, not order.
	got := map[string]bool{}
	for _, role := range roles {
		value, ok := role.(string)
		if !ok {
			t.Fatal("invalid LDAP role")
		}
		got[value] = true
	}
	if diff := cmp.Diff(map[string]bool{"authp/user": true, "directory/member": true}, got); diff != "" {
		t.Fatal(diff)
	}
	f.assertResource(t, result.AccessToken)
}
