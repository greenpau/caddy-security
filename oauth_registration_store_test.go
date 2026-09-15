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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
)

const registrationTestSecret = "synthetic-durable-rotation-secret-0123456789"

func registrationTestDirectory(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func registrationTestStore(t *testing.T) (*OAuthRegistrationStoreConfig, *oauthRegistrationStore) {
	t.Helper()
	cfg := &OAuthRegistrationStoreConfig{Path: filepath.Join(registrationTestDirectory(t), "registrations")}
	if err := cfg.initialize(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := cfg.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.root.Close() })
	return cfg, store
}

func registrationTestInput(cfg *OAuthRegistrationStoreConfig, extra ...string) *provisioningInput {
	body := []string{"redirect_uri https://rp.example.test/callback", "skip_consent on"}
	body = append(body, extra...)
	return &provisioningInput{store: cfg, applications: map[string][]string{"website": body}}
}

func registrationTestCreate(t *testing.T, cfg *OAuthRegistrationStoreConfig, extra ...string) string {
	t.Helper()
	path, err := provisionRegistration(t.Context(), registrationTestInput(cfg, extra...), "create", "website", "v1", "")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func registrationSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]string)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = fmt.Sprintf("%x:%d:%s", sha256.Sum256(data), info.Mode(), info.ModTime())
	}
	return result
}

func TestRegistrationCreationAndRotation(t *testing.T) {
	for _, method := range []string{"client_secret_basic", "client_secret_post", "none"} {
		t.Run(method, func(t *testing.T) {
			cfg, store := registrationTestStore(t)
			path := registrationTestCreate(t, cfg, "token_endpoint_auth_method "+method)
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("registration is not private")
			}
			first, err := store.application(t.Context(), "website", "v1")
			if err != nil {
				t.Fatal(err)
			}
			if len(first.Client.ClientID) < 32 || (first.Client.ClientSecret == "") != (method == "none") {
				t.Fatal("incorrect generated credentials")
			}
			for _, revision := range []string{"v1", "different"} {
				if _, err := provisionRegistration(t.Context(), registrationTestInput(cfg), "create", "website", revision, ""); !errors.Is(err, fs.ErrExist) {
					t.Fatalf("create overwrote registration: %v", err)
				}
			}
			input := registrationTestInput(cfg, "client_secret "+registrationTestSecret)
			if _, err := provisionRegistration(t.Context(), input, "rotate", "website", "v2", "v1"); err != nil {
				t.Fatal(err)
			}
			rotated, err := store.application(t.Context(), "website", "v2")
			if err != nil {
				t.Fatal(err)
			}
			if rotated.Client.ClientID != first.Client.ClientID || rotated.Client.ClientSecret != registrationTestSecret {
				t.Fatal("rotation lost stable identity or explicit secret")
			}
			old, err := store.application(t.Context(), "website", "v1")
			if err != nil || old.Client.ClientSecret != first.Client.ClientSecret {
				t.Fatal("rotation replaced recoverable prior revision")
			}
			if _, err := provisionRegistration(t.Context(), registrationTestInput(cfg), "rotate", "website", "v3", "v2"); err == nil {
				t.Fatal("rotation silently reused secret")
			}
			if _, err := provisionRegistration(t.Context(), registrationTestInput(cfg, "client_id changed", "client_secret "+registrationTestSecret), "rotate", "website", "v3", "v2"); err == nil {
				t.Fatal("rotation changed ID")
			}
		})
	}
}

func TestRegistrationWriterConcurrency(t *testing.T) {
	cfg, store := registrationTestStore(t)
	var wins atomic.Int32
	var winner atomic.Int32
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Go(func() {
			// Distinct filenames exercise nickname reservation under the writer
			// lock; no-replace publication alone cannot serialize this operation.
			_, err := provisionRegistration(t.Context(), registrationTestInput(cfg), "create", "website", fmt.Sprintf("v%d", i), "")
			if err == nil {
				wins.Add(1)
				winner.Store(int32(i))
			} else if !errors.Is(err, fs.ErrExist) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("concurrent writers did not have exactly one winner")
	}
	if _, err := store.application(t.Context(), "website", fmt.Sprintf("v%d", winner.Load())); err != nil {
		t.Fatal(err)
	}
	if len(registrationSnapshot(t, cfg.Path)) != 1 {
		t.Fatal("competing first revisions left additional registrations")
	}
	unlock, err := store.lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Millisecond)
	defer cancel()
	if _, err := store.lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("writer lock was not bounded")
	}
	unlock()
}

func TestRegistrationWriterLockRejectsUnsafeEntries(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "nonprivate directory"} {
		t.Run(kind, func(t *testing.T) {
			cfg, _ := registrationTestStore(t)
			path := registrationTestCreate(t, cfg)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lock := filepath.Join(cfg.Path, ".writer-lock")
			switch kind {
			case "file":
				err = os.WriteFile(lock, []byte("do not replace"), 0600)
			case "symlink":
				err = os.Symlink(registrationTestDirectory(t), lock)
			case "nonprivate directory":
				err = os.Mkdir(lock, 0755)
				if err == nil {
					err = os.Chmod(lock, 0755)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			original, err := os.Lstat(lock)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			_, err = provisionRegistration(ctx, registrationTestInput(cfg, "client_secret "+registrationTestSecret), "rotate", "website", "v2", "v1")
			if err == nil || err.Error() != "invalid registration writer lock" {
				t.Fatal("unsafe lock was accepted or mistaken for ordinary contention")
			}
			current, err := os.Lstat(lock)
			if err != nil || !os.SameFile(original, current) || original.Mode() != current.Mode() {
				t.Fatal("rejected writer modified the existing lock entry")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected writer modified the usable registration")
			}
			entries, err := os.ReadDir(cfg.Path)
			if err != nil || len(entries) != 2 {
				t.Fatal("rejected writer left a candidate or temporary file")
			}
		})
	}
}

func TestRegistrationPublicCredentialTransitions(t *testing.T) {
	cfg, store := registrationTestStore(t)
	registrationTestCreate(t, cfg)
	first, err := store.application(t.Context(), "website", "v1")
	if err != nil {
		t.Fatal(err)
	}
	publicInput := registrationTestInput(cfg, "token_endpoint_auth_method none")
	if _, err := provisionRegistration(t.Context(), publicInput, "rotate", "website", "v2", "v1"); err != nil {
		t.Fatal(err)
	}
	source := &OAuthApplicationSource{Name: "website", Revision: "v2", Directives: publicInput.applications["website"]}
	public, err := source.load(t.Context(), store)
	if err != nil || public.Client.ClientID != first.Client.ClientID || public.Client.ClientSecret != "" || !public.Client.RequirePKCE {
		t.Fatal("public rotation lost the stable ID, inherited a secret, or disabled PKCE", err)
	}
	for _, input := range []*provisioningInput{publicInput, registrationTestInput(cfg)} {
		if _, err := provisionRegistration(t.Context(), input, "rotate", "website", "v3", "v2"); err == nil {
			t.Fatal("public rotation without a new explicit confidential secret succeeded")
		}
	}
	if entries := registrationSnapshot(t, cfg.Path); len(entries) != 2 {
		t.Fatal("rejected public rotation wrote a candidate")
	}
	if _, err := provisionRegistration(t.Context(), registrationTestInput(cfg, "client_secret "+registrationTestSecret), "rotate", "website", "v3", "v2"); err != nil {
		t.Fatal(err)
	}
	source = &OAuthApplicationSource{Name: "website", Revision: "v3", Directives: registrationTestInput(cfg).applications["website"]}
	confidential, err := source.load(t.Context(), store)
	if err != nil || confidential.Client.ClientID != first.Client.ClientID || confidential.Client.ClientSecret != registrationTestSecret {
		t.Fatal("public-to-confidential rotation failed to persist the explicit secret", err)
	}
	previous, err := store.application(t.Context(), "website", "v1")
	if err != nil || previous.Client.ClientSecret != first.Client.ClientSecret {
		t.Fatal("credential transitions replaced the original recovery record", err)
	}
}

func TestRegistrationAtomicPublicationFailures(t *testing.T) {
	cfg, store := registrationTestStore(t)
	path := registrationTestCreate(t, cfg)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"empty", "write", "sync", "cancel", "collision"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			name := "candidate.json"
			if failure == "collision" {
				name = filepath.Base(path)
			}
			err := store.publish(ctx, name, func(f *os.File) error {
				if failure == "empty" {
					return nil
				}
				if _, err := f.WriteString("partial credential record"); err != nil {
					return err
				}
				switch failure {
				case "write":
					return fmt.Errorf("injected write failure")
				case "sync":
					return f.Close()
				case "cancel":
					cancel()
				}
				return nil
			})
			if err == nil {
				t.Fatal("failed atomic write reported success")
			}
			if _, err := store.root.Lstat("candidate.json"); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("partial revision published")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed publication damaged existing registration")
			}
			entries, err := os.ReadDir(cfg.Path)
			if err != nil || len(entries) != 1 {
				t.Fatal("failed publication left temporary artifacts")
			}
		})
	}
	// A competing entry created after the preflight check must still win.
	err = store.publish(t.Context(), "race.json", func(f *os.File) error {
		if err := os.WriteFile(filepath.Join(cfg.Path, "race.json"), []byte("winner"), 0600); err != nil {
			return err
		}
		_, err := f.WriteString("loser")
		return err
	})
	if !errors.Is(err, fs.ErrExist) {
		t.Fatal("publication replaced a competing entry")
	}
}

func TestRegistrationPublishedRevisionRecovery(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory read-permission fault requires an unprivileged owner")
	}
	cfg, store := registrationTestStore(t)
	path := registrationTestCreate(t, cfg)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.application(t.Context(), "website", "v1")
	if err != nil {
		t.Fatal(err)
	}
	first.Client.ClientSecret = registrationTestSecret
	candidate, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	name, err := registrationFilename("application", "website", "uncertain")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfg.Path, 0700) })
	err = func() error {
		unlock, err := store.lock(t.Context())
		if err != nil {
			return err
		}
		defer unlock()
		return store.publish(t.Context(), name, func(f *os.File) error {
			if _, err := f.Write(candidate); err != nil {
				return err
			}
			// Write+execute allows the atomic link, but opening the directory
			// for syncing requires read permission. Fail after publication.
			return os.Chmod(cfg.Path, 0300)
		})
	}()
	if restoreErr := os.Chmod(cfg.Path, 0700); restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if err == nil || !strings.Contains(err.Error(), "registration published; directory sync unavailable") || strings.Contains(err.Error(), registrationTestSecret) {
		t.Fatal("post-publication failure did not report recoverable state safely")
	}
	if data, err := store.read(t.Context(), name); err != nil || !bytes.Equal(data, candidate) {
		t.Fatal("post-publication failure lost or truncated the complete candidate")
	}
	if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, before) {
		t.Fatal("post-publication failure changed the prior registration")
	}
	if len(registrationSnapshot(t, cfg.Path)) != 2 {
		t.Fatal("post-publication failure left a lock or temporary file")
	}
	if err := store.publish(t.Context(), name, func(*os.File) error {
		t.Fatal("retry attempted to overwrite the recoverable revision")
		return nil
	}); !errors.Is(err, fs.ErrExist) {
		t.Fatal("retry did not preserve the recoverable revision")
	}
	// Explicit local recovery confirms durability before the revision is used.
	dir, err := store.root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.application(t.Context(), "website", "uncertain")
	if err != nil || recovered.Client.ClientSecret != registrationTestSecret || recovered.Client.ClientID != first.Client.ClientID {
		t.Fatal("complete candidate could not be recovered with its original credentials")
	}
}

func TestRegistrationStoreRejectsUnsafeStorage(t *testing.T) {
	cfg, store := registrationTestStore(t)
	path := registrationTestCreate(t, cfg)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, contents := range []string{"", "{", "null", `{"name":"website","client":null}`, string(original) + "{}", strings.Replace(string(original), `"website"`, `"wrong"`, 1), strings.Replace(string(original), `"name":`, `"unknown":`, 1)} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.application(t.Context(), "website", "v1"); err == nil {
			t.Fatal("corrupt storage was accepted")
		}
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []fs.FileMode{0000, 0640, 0644, 0666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := store.application(t.Context(), "website", "v1"); err == nil {
			t.Fatal("unsafe or unreadable record was accepted")
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.application(t.Context(), "website", "v1"); err == nil {
		t.Fatal("symlink record was accepted")
	}
	if err := store.publish(t.Context(), filepath.Base(path), func(*os.File) error { t.Fatal("symlink target opened for writing"); return nil }); !errors.Is(err, fs.ErrExist) {
		t.Fatal("symlink was overwritten")
	}
	if _, err := store.application(t.Context(), "missing", "v1"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("missing storage did not fail closed")
	}
	for _, revision := range []string{"", "../escape", "/absolute", "a/b", ".", "a.b", "a*", strings.Repeat("a", 65)} {
		if _, err := registrationFilename("application", "website", revision); err == nil {
			t.Fatal("invalid revision accepted")
		}
	}
	if err := cfg.initialize(t.Context()); !errors.Is(err, fs.ErrExist) {
		t.Fatal("init overwrote store")
	}
	if err := os.Chmod(cfg.Path, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.open(t.Context()); err == nil {
		t.Fatal("nonprivate directory accepted")
	}
	if err := os.Chmod(cfg.Path, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(cfg.Path), "link")
	if err := os.Symlink(cfg.Path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (&OAuthRegistrationStoreConfig{Path: link}).open(t.Context()); err == nil {
		t.Fatal("symlink storage identity accepted")
	}
	if _, err := (&OAuthRegistrationStoreConfig{Path: "relative"}).open(t.Context()); err == nil {
		t.Fatal("CWD-dependent storage accepted")
	}
}

type registrationNoRandomness struct{}

func (registrationNoRandomness) Read([]byte) (int, error) { panic("adaptation requested randomness") }

func TestRegistrationAdaptationIsReadOnlyAndRedacted(t *testing.T) {
	cfg, store := registrationTestStore(t)
	registrationTestCreate(t, cfg)
	previous, err := store.application(t.Context(), "website", "v1")
	if err != nil {
		t.Fatal(err)
	}
	input := fmt.Sprintf("{\nsecurity {\noauth application website {\nregistration v1\nredirect_uri https://new.example.test/callback\nscopes openid\nrequire_pkce off\n}\noauth registration store {\npath %s\n}\n}\n}\n", cfg.Path)
	before, _ := json.Marshal(registrationSnapshot(t, cfg.Path))
	reader := rand.Reader
	rand.Reader = registrationNoRandomness{}
	defer func() { rand.Reader = reader }()
	var adapted []byte
	for range 5 {
		data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(previous.Client.ClientSecret)) || bytes.Contains(data, []byte(previous.Client.ClientID)) {
			t.Fatal("stored credential leaked in adapted JSON")
		}
		if adapted != nil && !bytes.Equal(data, adapted) {
			t.Fatal("adaptation is nondeterministic")
		}
		adapted = data
		var config struct {
			Apps struct {
				Security App `json:"security"`
			} `json:"apps"`
		}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatal(err)
		}
		app := &config.Apps.Security
		if err := app.resolveOAuthRegistrationConfig(t.Context(), app.Config); err != nil {
			t.Fatal(err)
		}
		client := app.Config.OAuthApplications[0].Client
		if client.ClientID != previous.Client.ClientID || client.ClientSecret != previous.Client.ClientSecret || client.RedirectURIs[0] != "https://new.example.test/callback" || client.RequirePKCE || client.SkipConsent || len(client.Scopes) != 1 {
			t.Fatal("current policy or stored credential inheritance was lost")
		}
	}
	after, _ := json.Marshal(registrationSnapshot(t, cfg.Path))
	if !bytes.Equal(before, after) {
		t.Fatal("adaptation wrote storage")
	}
	matching := strings.Replace(input, "registration v1", "registration v1\nclient_id "+previous.Client.ClientID+"\nclient_secret "+previous.Client.ClientSecret, 1)
	withExplicit, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(matching), nil)
	if err != nil || !bytes.Equal(adapted, withExplicit) {
		t.Fatal("matching explicit credentials leaked or changed the stored reference")
	}
	for _, setting := range []string{"client_secret " + registrationTestSecret, "token_endpoint_auth_method none", "client_id changed"} {
		invalid := strings.Replace(input, "registration v1", "registration v1\n"+setting, 1)
		if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(invalid), nil); err == nil || strings.Contains(err.Error(), registrationTestSecret) {
			t.Fatal("unpersisted credential change accepted or leaked")
		}
	}
}

func TestRegistrationDigestGuardsAdaptToActivation(t *testing.T) {
	cfg, store := registrationTestStore(t)
	path := registrationTestCreate(t, cfg)
	source := &OAuthApplicationSource{Name: "website", Revision: "v1", Directives: []string{"redirect_uri https://rp.example.test/callback"}}
	if _, err := source.load(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	changed, err := oidc.NewClientConfig(oidc.ClientConfig{RedirectURIs: []string{"https://rp.example.test/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(&oidc.OAuthApplicationConfig{Name: "website", Client: changed})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := source.load(t.Context(), store); err == nil {
		t.Fatal("changed credentials bypassed adapted digest")
	}
}

func TestRegistrationRejectsOversizedPublication(t *testing.T) {
	cfg, _ := registrationTestStore(t)
	// JSON escapes ampersands, so a valid input below the input-size limit can
	// expand beyond the size the registration reader accepts.
	directives := oversizedRegistrationDirectives()
	client, err := oidcparser.NewOIDCClientConfigFromDirectives("website", directives)
	if err != nil {
		t.Fatal("size fixture is not a valid registration", err)
	}
	encoded, err := json.Marshal(&oidc.OAuthApplicationConfig{Name: "website", Client: client})
	if err != nil || len(encoded) <= 1<<20 || len(strings.Join(directives, "\n")) >= 1<<20 {
		t.Fatal("size fixture does not cross the serialization boundary")
	}
	input := &provisioningInput{store: cfg, applications: map[string][]string{"website": directives}}
	if _, err := provisionRegistration(t.Context(), input, "create", "website", "v1", ""); err == nil || !strings.Contains(err.Error(), "file must contain") {
		t.Fatal("oversized valid registration did not fail publication", err)
	}
	if entries := registrationSnapshot(t, cfg.Path); len(entries) != 0 {
		t.Fatal("oversized publication left a record")
	}
}

func oversizedRegistrationDirectives() []string {
	var directives []string
	for i := range 200 {
		directives = append(directives, fmt.Sprintf("redirect_uri https://rp.example.test/callback/%d?%s", i, strings.Repeat("&", 1500)))
	}
	return directives
}

func TestRegistrationRejectsAmbiguousJSON(t *testing.T) {
	cfg, store := registrationTestStore(t)
	path := registrationTestCreate(t, cfg, "client_secret "+registrationTestSecret)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"duplicate nickname", bytes.Replace(original, []byte(`"name":`), []byte(`"name":"wrong","name":`), 1)},
		{"duplicate credential", bytes.Replace(original, []byte(`"client_secret":`), []byte(`"client_secret":"wrong","client_secret":`), 1)},
		{"case alias", bytes.Replace(original, []byte(`"client_secret":`), []byte(`"CLIENT_SECRET":"wrong","client_secret":`), 1)},
		{"invalid UTF-8", bytes.Replace(original, []byte(registrationTestSecret), append([]byte(registrationTestSecret), 0xff), 1)},
		{"unpaired high surrogate", bytes.Replace(original, []byte(registrationTestSecret), []byte(registrationTestSecret+`\ud800`), 1)},
		{"unpaired low surrogate", bytes.Replace(original, []byte(registrationTestSecret), []byte(registrationTestSecret+`\udfff`), 1)},
		{"invalid surrogate pair", bytes.Replace(original, []byte(registrationTestSecret), []byte(registrationTestSecret+`\ud800\u0041`), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.application(t.Context(), "website", "v1"); err == nil {
				t.Fatal("ambiguous or malformed credential JSON was accepted")
			}
		})
	}
}

func TestRegistrationUnicodeJSONRoundTrip(t *testing.T) {
	cfg, store := registrationTestStore(t)
	secret := registrationTestSecret + "�🚀" + `\ud800`
	path := registrationTestCreate(t, cfg, encodeOAuthDirective([]string{"client_secret", secret}))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{original, bytes.Replace(original, []byte("�🚀"), []byte(`\uFFFD\uD83D\uDE80`), 1)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		application, err := store.application(t.Context(), "website", "v1")
		if err != nil || application.Client.ClientSecret != secret {
			t.Fatal("valid Unicode or literal escape changed the stored credential", err)
		}
	}
}
