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
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	_ "modernc.org/sqlite"
)

// These modules exist only in the test executable. All metadata and operations
// delegate to the actual bundled implementations. The only fault is a real SQL
// read transaction acquired after genuine signing, before Rotate commits.
type sqliteCommitSignerModule struct{ RSAPSSAccessSigner }
type sqliteCommitStoreModule struct{ SQLiteRefreshStore }
type sqliteCommitSignerFactory struct {
	AccessSignerFactory
	witness *sqliteCommitWitness
}
type sqliteCommitStoreFactory struct {
	RefreshStoreFactory
	witness *sqliteCommitWitness
}
type sqliteCommitSigner struct {
	kms.AccessSigner
	witness *sqliteCommitWitness
}
type sqliteCommitManagedStore struct {
	tokenrefresh.ManagedStore
	witness *sqliteCommitWitness
}
type sqliteCommitActiveStore struct {
	tokenrefresh.ActiveStore
	witness *sqliteCommitWitness
}

type sqliteCommitObservation struct {
	SignCalls, ReaderLocks, RotateCalls, Uncertain, Canceled      int
	RefreshRequests, Lookups, LoginPosts, StoreOpens, StoreCloses int
	Staged                                                        string
	Tokens                                                        []string
	RefreshDigests                                                [][32]byte
	Responses                                                     []oidcRPResponse
}
type sqliteCommitWitness struct {
	mu            sync.Mutex
	observation   sqliteCommitObservation
	managed       tokenrefresh.ManagedStore
	reader        *sql.DB
	readerContext context.Context
	readerCancel  context.CancelFunc
	held          *sql.Tx
	armed         bool
}

var sqliteCommitWitnesses sync.Map

func init() {
	caddy.RegisterModule(sqliteCommitSignerModule{})
	caddy.RegisterModule(sqliteCommitStoreModule{})
	caddy.RegisterModule(sqliteCommitHTTPProbe{})
	httpcaddyfile.RegisterHandlerDirective("fixture_sqlite_commit", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		h.Next()
		args := h.RemainingArgs()
		if len(args) != 2 || h.NextBlock(0) {
			return nil, h.Err("invalid SQLite COMMIT fixture directive")
		}
		return &sqliteCommitHTTPProbe{Name: args[0], Mount: args[1]}, nil
	})
}
func (sqliteCommitSignerModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.access_signers.fixture_sqlite_commit", New: func() caddy.Module { return new(sqliteCommitSignerModule) }}
}
func (sqliteCommitStoreModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.refresh_stores.fixture_sqlite_commit", New: func() caddy.Module { return new(sqliteCommitStoreModule) }}
}
func sqliteCommitFind(name string) (*sqliteCommitWitness, error) {
	value, ok := sqliteCommitWitnesses.Load(name)
	if !ok {
		return nil, errors.New("SQLite COMMIT fixture is unavailable")
	}
	return value.(*sqliteCommitWitness), nil
}
func (m *sqliteCommitSignerModule) PrepareAccessSigner() (AccessSignerFactory, error) {
	factory, err := m.RSAPSSAccessSigner.PrepareAccessSigner()
	if err != nil {
		return nil, err
	}
	witness, err := sqliteCommitFind(m.Name)
	if err != nil {
		return nil, err
	}
	return &sqliteCommitSignerFactory{AccessSignerFactory: factory, witness: witness}, nil
}
func (m *sqliteCommitStoreModule) PrepareRefreshStore() (RefreshStoreFactory, error) {
	factory, err := m.SQLiteRefreshStore.PrepareRefreshStore()
	if err != nil {
		return nil, err
	}
	witness, err := sqliteCommitFind(m.Name)
	if err != nil {
		return nil, err
	}
	return &sqliteCommitStoreFactory{RefreshStoreFactory: factory, witness: witness}, nil
}
func (f *sqliteCommitSignerFactory) NewAccessSigner(ctx context.Context) (kms.AccessSigner, error) {
	delegate, err := f.AccessSignerFactory.NewAccessSigner(ctx)
	if err != nil {
		return delegate, err
	}
	return &sqliteCommitSigner{AccessSigner: delegate, witness: f.witness}, nil
}
func (f *sqliteCommitStoreFactory) NewRefreshStore(ctx context.Context) (tokenrefresh.ManagedStore, error) {
	delegate, err := f.RefreshStoreFactory.NewRefreshStore(ctx)
	if err != nil {
		return delegate, err
	}
	f.witness.mu.Lock()
	f.witness.managed = delegate
	f.witness.observation.StoreOpens++
	f.witness.mu.Unlock()
	return &sqliteCommitManagedStore{ManagedStore: delegate, witness: f.witness}, nil
}
func (s *sqliteCommitManagedStore) ActivateGeneration(ctx context.Context, generation tokenrefresh.Generation) (tokenrefresh.ActiveStore, error) {
	delegate, err := s.ManagedStore.ActivateGeneration(ctx, generation)
	if err != nil {
		return delegate, err
	}
	return &sqliteCommitActiveStore{ActiveStore: delegate, witness: s.witness}, nil
}
func (s *sqliteCommitManagedStore) Close() error {
	err := s.ManagedStore.(io.Closer).Close()
	s.witness.mu.Lock()
	s.witness.observation.StoreCloses++
	s.witness.mu.Unlock()
	return err
}
func (s *sqliteCommitActiveStore) Rotate(ctx context.Context, session tokenrefresh.Session, next [32]byte, idle, access int64) error {
	err := s.ActiveStore.Rotate(ctx, session, next, idle, access)
	s.witness.mu.Lock()
	defer s.witness.mu.Unlock()
	s.witness.observation.RotateCalls++
	if errors.Is(err, tokenrefresh.ErrCommitUncertain) {
		s.witness.observation.Uncertain++
	}
	if ctx.Err() != nil {
		s.witness.observation.Canceled++
	}
	return err
}
func (s *sqliteCommitSigner) Sign(ctx context.Context, claims map[string]any) (string, error) {
	token, err := s.AccessSigner.Sign(ctx, claims)
	if err != nil {
		return token, err
	}
	w := s.witness
	w.mu.Lock()
	defer w.mu.Unlock()
	w.observation.SignCalls++
	w.observation.Tokens = append(w.observation.Tokens, token)
	if !w.armed {
		return token, nil
	}
	w.armed = false
	w.observation.Staged = token
	if w.reader == nil || w.held != nil || w.readerContext == nil {
		return "", errors.New("COMMIT reader was not ready")
	}
	held, err := w.reader.BeginTx(w.readerContext, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", errors.New("COMMIT reader could not begin")
	}
	var count int
	if err := held.QueryRowContext(w.readerContext, "SELECT count(*) FROM sqlite_schema").Scan(&count); err != nil {
		_ = held.Rollback()
		return "", errors.New("COMMIT reader could not acquire a read lock")
	}
	w.held = held
	w.observation.ReaderLocks++
	return token, nil
}
func (w *sqliteCommitWitness) snapshot() sqliteCommitObservation {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := w.observation
	result.Tokens = append([]string(nil), result.Tokens...)
	result.RefreshDigests = append([][32]byte(nil), result.RefreshDigests...)
	result.Responses = append([]oidcRPResponse(nil), result.Responses...)
	return result
}

// Counts and captures only. No test control route, synthetic response, retry or
// transport fault exists here. A recorder preserves the real finite portal
// response, including every header/body byte, before forwarding it unchanged.
type sqliteCommitHTTPProbe struct {
	Name  string `json:"name"`
	Mount string `json:"mount"`
}

func (sqliteCommitHTTPProbe) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.fixture_sqlite_commit", New: func() caddy.Module { return new(sqliteCommitHTTPProbe) }}
}
func (m *sqliteCommitHTTPProbe) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	witness, err := sqliteCommitFind(m.Name)
	if err != nil {
		return err
	}
	refresh := r.URL.Path == m.Mount+"/api/refresh_token"
	lookup := r.URL.Path == m.Mount+"/api/refresh_session"
	login := r.URL.Path == m.Mount+"/login" && r.Method == http.MethodPost
	witness.mu.Lock()
	if refresh {
		witness.observation.RefreshRequests++
	}
	if lookup {
		witness.observation.Lookups++
	}
	if login {
		witness.observation.LoginPosts++
	}
	witness.mu.Unlock()
	if !refresh {
		return next.ServeHTTP(w, r)
	}
	// Preserve the finite request body unchanged while recording only a digest.
	// This proves no later request re-exchanged the original credential; it does
	// not expose the raw next refresh value staged only inside the manager.
	data, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(data) > 4096 {
		return errors.New("refresh fixture request exceeded its bound")
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(data))
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if json.Unmarshal(data, &body) != nil {
		return errors.New("refresh fixture request is malformed")
	}
	credential := body.RefreshToken
	if cookie, err := r.Cookie("AUTHP_REFRESH_TOKEN"); err == nil {
		credential = cookie.Value
	}
	witness.mu.Lock()
	witness.observation.RefreshDigests = append(witness.observation.RefreshDigests, sha256.Sum256([]byte(credential)))
	witness.mu.Unlock()
	record := httptest.NewRecorder()
	if err := next.ServeHTTP(record, r); err != nil {
		return err
	}
	if record.Body.Len() > 128<<10 {
		return errors.New("refresh fixture response exceeded its bound")
	}
	result := oidcRPResponse{status: record.Code, header: record.Header().Clone(), body: bytes.Clone(record.Body.Bytes())}
	witness.mu.Lock()
	witness.observation.Responses = append(witness.observation.Responses, result)
	witness.mu.Unlock()
	for name, values := range record.Header() {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(record.Code)
	_, err = w.Write(record.Body.Bytes())
	return err
}

type sqliteCommitFixture struct {
	*accessSignerFixture
	witness         *sqliteCommitWitness
	storePath, cert string
	running         bool
}

func newSQLiteCommitFixture(t *testing.T, cert, key string, roots *x509.CertPool) *sqliteCommitFixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("cannot prepare private SQLite COMMIT directory")
	}
	witness := new(sqliteCommitWitness)
	sqliteCommitWitnesses.Store("selected", witness)
	t.Cleanup(func() { sqliteCommitWitnesses.Delete("selected") })
	f := &sqliteCommitFixture{witness: witness, storePath: filepath.Join(dir, "refresh.sqlite"), cert: cert}
	options := accessSignerOptions{mount: "/tenant/auth", refresh: true, maximum: 180, lifetime: 120}
	options.configure = func(input string) string {
		input = strings.Replace(input, "access signer rsapss selected", "access signer fixture_sqlite_commit selected", 1)
		declarations := fmt.Sprintf("state {\ndirectory %q\n}\ntoken refresh store fixture_sqlite_commit selected {\npath %q\nmax sessions 4\nmax rotations 32\ntimeout 2s\n}\n", filepath.Join(dir, "root-state"), f.storePath)
		input = strings.Replace(input, "security {", "security {\n"+declarations, 1)
		input = strings.Replace(input, "token refresh {", "token refresh {\nstore selected\nmax sessions 4\nmax rotations 32\n", 1)
		input = strings.Replace(input, "access lifetime 600", "access lifetime 120", 1)
		input = strings.Replace(input, " route {", " route {\n  fixture_sqlite_commit selected /tenant/auth", 1)
		return input
	}
	f.accessSignerFixture = newAccessSignerFixture(t, options, cert, key, roots)
	f.running = true
	t.Cleanup(func() {
		f.ReleaseReader(t)
		f.stop(t)
		f.capture()
		snapshot := witness.snapshot()
		if snapshot.StoreOpens != snapshot.StoreCloses {
			t.Error("selected refresh handles did not close exactly once")
		}
	})
	return f
}
func (f *sqliteCommitFixture) capture() {
	snapshot := f.witness.snapshot()
	f.secrets = append(f.secrets, snapshot.Tokens...)
	for _, response := range snapshot.Responses {
		accessSignerCapture(f.localIdentityFixture, response)
	}
}
func (f *sqliteCommitFixture) ArmCommitFailure(t *testing.T) sqliteCommitObservation {
	t.Helper()
	f.witness.mu.Lock()
	defer f.witness.mu.Unlock()
	if !f.running || f.witness.reader != nil || f.witness.armed {
		t.Fatal("COMMIT fixture cannot be armed twice")
	}
	endpoint := (&url.URL{Scheme: "file", Path: f.storePath}).String() + "?mode=rw"
	reader, err := sql.Open("sqlite", endpoint)
	if err != nil {
		t.Fatal("cannot open the private COMMIT reader")
	}
	reader.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	var journal string
	if err := reader.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil || journal != "delete" {
		cancel()
		_ = reader.Close()
		t.Fatal("COMMIT fixture requires an ordinary rollback journal")
	}
	f.witness.reader, f.witness.readerContext, f.witness.readerCancel = reader, ctx, cancel
	f.witness.armed = true
	return f.witness.observation
}
func (f *sqliteCommitFixture) ReleaseReader(t *testing.T) {
	t.Helper()
	f.witness.mu.Lock()
	held, reader, cancel := f.witness.held, f.witness.reader, f.witness.readerCancel
	f.witness.held, f.witness.reader, f.witness.readerCancel = nil, nil, nil
	f.witness.armed = false
	f.witness.mu.Unlock()
	if held != nil {
		if err := held.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Error("cannot release the COMMIT reader transaction")
		}
	}
	if cancel != nil {
		cancel()
	}
	if reader != nil {
		if err := reader.Close(); err != nil {
			t.Error("cannot close the COMMIT reader")
		}
	}
}
func (f *sqliteCommitFixture) AssertUncertain(t *testing.T, before sqliteCommitObservation) {
	t.Helper()
	f.capture()
	now := f.witness.snapshot()
	if now.SignCalls != before.SignCalls+1 || now.ReaderLocks != before.ReaderLocks+1 || now.RotateCalls != before.RotateCalls+1 || now.Uncertain != before.Uncertain+1 || now.Canceled != before.Canceled || now.RefreshRequests != before.RefreshRequests+1 {
		t.Fatal("refresh did not reach one real, live-context uncertain COMMIT")
	}
	if now.Staged == "" || len(now.Responses) != len(before.Responses)+1 {
		t.Fatal("uncertain COMMIT omitted its private staging evidence")
	}
	f.verify(t, now.Staged)
	response := now.Responses[len(now.Responses)-1]
	response.requireStatus(t, http.StatusServiceUnavailable)
	providerDestinationNoIssuance(t, response)
	var body apiauth.AuthResponse
	if json.Unmarshal(response.body, &body) != nil || body.Authenticated || body.AccessToken != "" || body.RefreshToken != "" || body.SessionID != "" || response.header.Get("Location") != "" || !strings.Contains(response.header.Get("Cache-Control"), "no-store") || bytes.Contains(response.body, []byte(now.Staged)) {
		t.Fatal("uncertain COMMIT published staged authority")
	}
}
func (f *sqliteCommitFixture) assertNoExchange(t *testing.T, before sqliteCommitObservation) {
	t.Helper()
	now := f.witness.snapshot()
	if now.RefreshRequests != before.RefreshRequests || now.Lookups != before.Lookups || now.RotateCalls != before.RotateCalls || now.SignCalls != before.SignCalls || now.LoginPosts != before.LoginPosts {
		t.Fatal("uncertain client repeated a refresh or started unsolicited authentication")
	}
}
func (f *sqliteCommitFixture) RestartSameConfig(t *testing.T) {
	t.Helper()
	f.ReleaseReader(t)
	f.witness.mu.Lock()
	managed := f.witness.managed
	f.witness.mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	err := managed.CheckReady(ctx)
	cancel()
	if err == nil {
		t.Fatal("real COMMIT failure did not quarantine its handle")
	}
	before := f.witness.snapshot()
	f.stop(t)
	if f.witness.snapshot().StoreCloses != before.StoreCloses+1 {
		t.Fatal("root drain did not close the quarantined refresh handle")
	}
	f.localIdentityFixture.load(t)
	f.running = true
	response := f.request(t, "GET", "/.well-known/jwks.json", nil, nil)
	response.requireStatus(t, http.StatusOK)
	f.witness.mu.Lock()
	managed = f.witness.managed
	f.witness.mu.Unlock()
	ctx, cancel = context.WithTimeout(t.Context(), 2*time.Second)
	err = managed.CheckReady(ctx)
	cancel()
	if err != nil || f.witness.snapshot().StoreOpens != before.StoreOpens+1 {
		t.Fatal("identical configuration did not reopen a healthy selected store")
	}
}
func (f *sqliteCommitFixture) stop(t *testing.T) {
	t.Helper()
	if !f.running {
		return
	}
	if err := caddy.Stop(); err != nil {
		t.Error("cannot drain the selected refresh fixture")
	}
	f.running = false
}

var _ AccessSignerBackendModule = (*sqliteCommitSignerModule)(nil)
var _ RefreshStoreBackendModule = (*sqliteCommitStoreModule)(nil)
var _ tokenrefresh.ManagedStore = (*sqliteCommitManagedStore)(nil)
var _ tokenrefresh.ActiveStore = (*sqliteCommitActiveStore)(nil)

func (f *sqliteCommitFixture) resource(t *testing.T, token string, status int) {
	t.Helper()
	actual, _, body := registrationHTTP(t, f.plain, "GET", f.base+"/resource", nil, http.Header{"Authorization": {"Bearer " + token}})
	if actual != status || (actual == 200 && string(body) != "identity resource") {
		t.Fatal("selected refresh grant did not reach its protected resource")
	}
}
func (f *sqliteCommitFixture) assertOriginalExchangedOnce(t *testing.T, original string) {
	t.Helper()
	expected := sha256.Sum256([]byte(original))
	count := 0
	for _, digest := range f.witness.snapshot().RefreshDigests {
		if digest == expected {
			count++
		}
	}
	if count != 1 {
		t.Fatal("the original refresh credential was absent or re-exchanged")
	}
}
