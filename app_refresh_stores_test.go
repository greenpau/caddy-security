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
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
)

const refreshStorePrivateDiagnostic = "private-store-diagnostic"

type refreshStoreMockModule struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	Failure string `json:"failure,omitempty"`
	probe   *refreshStoreMockProbe
}
type refreshStoreMockProbe struct {
	module               *refreshStoreMockModule
	constructed, cleaned int
	instances            []*refreshStoreMockRuntime
	closes               []string
}

var refreshStoreMockProbes sync.Map

func (refreshStoreMockModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.refresh_stores.app_test", New: func() caddy.Module { return new(refreshStoreMockModule) }}
}
func (m *refreshStoreMockModule) Provision(caddy.Context) error {
	value, ok := refreshStoreMockProbes.Load(m.Label)
	if !ok {
		return fmt.Errorf("missing store probe")
	}
	m.probe = value.(*refreshStoreMockProbe)
	m.probe.module = m
	return nil
}
func (m *refreshStoreMockModule) Cleanup() error {
	if m.probe != nil {
		m.probe.cleaned++
	}
	return nil
}
func (m *refreshStoreMockModule) PrepareRefreshStore() (RefreshStoreFactory, error) {
	switch m.Failure {
	case "prepare_error":
		return nil, fmt.Errorf("%s", refreshStorePrivateDiagnostic)
	case "prepare_panic":
		panic(refreshStorePrivateDiagnostic)
	case "prepare_nil":
		return nil, nil
	case "prepare_typed_nil":
		return (*refreshStoreMockFactory)(nil), nil
	}
	descriptor, err := tokenrefresh.NewExternalStoreConfig(m.Name, "app_test", 2, 3, struct{ Label string }{m.Label})
	if err != nil {
		return nil, err
	}
	return &refreshStoreMockFactory{config: *descriptor, failure: m.Failure, probe: m.probe}, nil
}

type refreshStoreMockFactory struct {
	config  tokenrefresh.ExternalStoreConfig
	failure string
	probe   *refreshStoreMockProbe
}

func (f *refreshStoreMockFactory) RefreshStoreConfig() (tokenrefresh.ExternalStoreConfig, error) {
	switch f.failure {
	case "descriptor_error":
		return tokenrefresh.ExternalStoreConfig{}, fmt.Errorf("%s", refreshStorePrivateDiagnostic)
	case "descriptor_panic":
		panic(refreshStorePrivateDiagnostic)
	case "descriptor_invalid":
		copy := f.config
		copy.ConfigDigest = "bad"
		return copy, nil
	}
	return f.config, nil
}
func (f *refreshStoreMockFactory) NewRefreshStore(context.Context) (tokenrefresh.ManagedStore, error) {
	f.probe.constructed++
	switch f.failure {
	case "nil":
		return nil, nil
	case "typed_nil":
		return (*refreshStoreMockRuntime)(nil), nil
	case "typed_nil_partial":
		return (*refreshStoreMockRuntime)(nil), fmt.Errorf("%s", refreshStorePrivateDiagnostic)
	}
	runtime := &refreshStoreMockRuntime{config: f.config, failure: f.failure, probe: f.probe}
	f.probe.instances = append(f.probe.instances, runtime)
	if f.failure == "partial" {
		return runtime, fmt.Errorf("%s", refreshStorePrivateDiagnostic)
	}
	if f.failure == "resource_free" {
		return &refreshStoreResourceFree{inner: runtime}, nil
	}
	return runtime, nil
}

type refreshStoreMockRuntime struct {
	config  tokenrefresh.ExternalStoreConfig
	failure string
	probe   *refreshStoreMockProbe
	closed  bool
}

func (s *refreshStoreMockRuntime) CheckReady(context.Context) error { return nil }
func (s *refreshStoreMockRuntime) ActivateGeneration(context.Context, tokenrefresh.Generation) (tokenrefresh.ActiveStore, error) {
	return nil, tokenrefresh.ErrUnavailable
}
func (s *refreshStoreMockRuntime) Metadata() (tokenrefresh.StoreMetadata, error) {
	switch s.failure {
	case "metadata_error":
		return tokenrefresh.StoreMetadata{}, fmt.Errorf("%s", refreshStorePrivateDiagnostic)
	case "metadata_panic":
		panic(refreshStorePrivateDiagnostic)
	}
	out := tokenrefresh.StoreMetadata{Kind: s.config.Kind, ConfigDigest: s.config.ConfigDigest, MaxSessions: s.config.MaxSessions, MaxRotations: s.config.MaxRotations}
	switch s.failure {
	case "kind":
		out.Kind = "other"
	case "digest":
		out.ConfigDigest = strings.Repeat("0", 64)
	case "sessions":
		out.MaxSessions++
	case "rotations":
		out.MaxRotations++
	}
	return out, nil
}
func (s *refreshStoreMockRuntime) Close() error {
	// Intentionally nil-unsafe: the host must contain only this cleanup boundary.
	s.closed = true
	s.probe.closes = append(s.probe.closes, s.config.Name)
	switch s.failure {
	case "close_panic":
		panic(refreshStorePrivateDiagnostic)
	case "close_error":
		return fmt.Errorf("%s", refreshStorePrivateDiagnostic)
	}
	return nil
}

type refreshStoreResourceFree struct{ inner *refreshStoreMockRuntime }

func (s *refreshStoreResourceFree) CheckReady(ctx context.Context) error {
	return s.inner.CheckReady(ctx)
}
func (s *refreshStoreResourceFree) ActivateGeneration(ctx context.Context, g tokenrefresh.Generation) (tokenrefresh.ActiveStore, error) {
	return s.inner.ActivateGeneration(ctx, g)
}
func (s *refreshStoreResourceFree) Metadata() (tokenrefresh.StoreMetadata, error) {
	return s.inner.Metadata()
}

type refreshStoreWrongModule struct{}

func (refreshStoreWrongModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.refresh_stores.app_wrong", New: func() caddy.Module { return new(refreshStoreWrongModule) }}
}
func init() {
	caddy.RegisterModule(refreshStoreMockModule{})
	caddy.RegisterModule(refreshStoreWrongModule{})
}

func refreshStoreMockApp(t *testing.T, failures ...string) (*App, caddy.Context, []*refreshStoreMockProbe) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	app := &App{}
	var probes []*refreshStoreMockProbe
	for i, failure := range failures {
		label := fmt.Sprintf("%s/%d", t.Name(), i)
		probe := new(refreshStoreMockProbe)
		refreshStoreMockProbes.Store(label, probe)
		t.Cleanup(func() { refreshStoreMockProbes.Delete(label) })
		probes = append(probes, probe)
		app.RefreshStoreConfigs = append(app.RefreshStoreConfigs, caddyconfig.JSONModuleObject(&refreshStoreMockModule{Name: fmt.Sprintf("store%d", i), Label: label, Failure: failure}, "driver", "app_test", nil))
	}
	return app, ctx, probes
}
func refreshStoreCloseAll(t *testing.T, closers []io.Closer) {
	t.Helper()
	for _, closer := range slices.Backward(closers) {
		if err := closer.Close(); err != nil && strings.Contains(err.Error(), refreshStorePrivateDiagnostic) {
			t.Fatal("cleanup exposed plugin diagnostic")
		}
	}
}

func TestAppRefreshStorePreparation(t *testing.T) {
	app, ctx, probes := refreshStoreMockApp(t, "")
	declared := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", RefreshTokens: &authn.TokenRefreshConfig{Enabled: true, Store: "store0"}}}}
	app.Config = declared
	before, _ := json.Marshal(app)
	resolved := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", RefreshTokens: &authn.TokenRefreshConfig{Enabled: true, Store: "store0"}}}}
	if err := app.prepareRefreshStores(ctx, resolved); err != nil {
		t.Fatal(err)
	}
	if len(resolved.ExternalRefreshStores) != 1 || len(app.refreshStores) != 1 || probes[0].constructed != 0 {
		t.Fatal("preparation did not freeze metadata without construction")
	}
	resolved.ExternalRefreshStores[0].MaxSessions = 99
	if app.refreshStores[0].config.MaxSessions != 2 {
		t.Fatal("root descriptor aliases private factory snapshot")
	}
	after, _ := json.Marshal(app)
	if !bytes.Equal(before, after) {
		t.Fatal("preparation mutated declarative App or raw modules")
	}
	probes[0].module.Name = "changed"
	probes[0].module.Failure = "nil"
	handles, closers, err := app.attachRefreshStores(t.Context())
	if err != nil || len(closers) != 1 || handles["store0"] != probes[0].instances[0] {
		t.Fatal("factory lost exact instance or read mutated module")
	}
	second, secondClosers, err := app.attachRefreshStores(t.Context())
	if err != nil || second["store0"] == handles["store0"] {
		t.Fatal("factory reused an owned runtime")
	}
	refreshStoreCloseAll(t, secondClosers)
	refreshStoreCloseAll(t, closers)
	if probes[0].constructed != 2 || !slices.Equal(probes[0].closes, []string{"store0", "store0"}) {
		t.Fatal("runtime ownership was not independent")
	}
}

func TestAppRefreshStorePreflightRejects(t *testing.T) {
	for _, failure := range []string{"prepare_error", "prepare_panic", "prepare_nil", "prepare_typed_nil", "descriptor_error", "descriptor_panic", "descriptor_invalid", "duplicate", "unknown_selection", "native_descriptor", "wrong_interface", "bad_raw_utf8"} {
		t.Run(failure, func(t *testing.T) {
			mode := failure
			if slices.Contains([]string{"duplicate", "unknown_selection", "native_descriptor", "wrong_interface", "bad_raw_utf8"}, failure) {
				mode = ""
			}
			app, ctx, probes := refreshStoreMockApp(t, mode)
			config := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", RefreshTokens: &authn.TokenRefreshConfig{Enabled: true, Store: "store0"}}}}
			switch failure {
			case "duplicate":
				app.RefreshStoreConfigs = append(app.RefreshStoreConfigs, slices.Clone(app.RefreshStoreConfigs[0]))
			case "unknown_selection":
				config.AuthenticationPortals[0].RefreshTokens.Store = "absent"
			case "native_descriptor":
				config.ExternalRefreshStores = []*tokenrefresh.ExternalStoreConfig{nil}
			case "wrong_interface":
				app.RefreshStoreConfigs = []json.RawMessage{json.RawMessage(`{"driver":"app_wrong"}`)}
			case "bad_raw_utf8":
				app.RefreshStoreConfigs = []json.RawMessage{[]byte("{\"driver\":\"sqlite\",\"name\":\"\xff\"}")}
			}
			rawBefore := slices.Clone(app.RefreshStoreConfigs[0])
			before, _ := json.Marshal(config)
			err := app.prepareRefreshStores(ctx, config)
			if err == nil || strings.Contains(err.Error(), refreshStorePrivateDiagnostic) {
				t.Fatal("invalid store preflight accepted or disclosed")
			}
			after, _ := json.Marshal(config)
			if !bytes.Equal(before, after) || !bytes.Equal(rawBefore, app.RefreshStoreConfigs[0]) || len(app.refreshStores) != 0 || probes[0].constructed != 0 {
				t.Fatal("rejected candidate mutated config or constructed runtime")
			}
		})
	}
	app, ctx, _ := refreshStoreMockApp(t)
	config := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", RefreshTokens: &authn.TokenRefreshConfig{Enabled: true, Store: "absent"}}}}
	if app.prepareRefreshStores(ctx, config) == nil {
		t.Fatal("missing selection accepted without modules")
	}
}

func TestAppRefreshStoreRuntimeFailures(t *testing.T) {
	for _, failure := range []string{"nil", "typed_nil", "typed_nil_partial", "partial", "metadata_error", "metadata_panic", "kind", "digest", "sessions", "rotations"} {
		t.Run(failure, func(t *testing.T) {
			app, ctx, probes := refreshStoreMockApp(t, "close_panic", failure, "")
			config := &authcrunch.Config{}
			if app.prepareRefreshStores(ctx, config) != nil {
				t.Fatal("cannot prepare failure fixture")
			}
			handles, closers, err := app.attachRefreshStores(t.Context())
			if err == nil || handles != nil || strings.Contains(err.Error(), refreshStorePrivateDiagnostic) {
				t.Fatal("invalid runtime accepted or disclosed")
			}
			expected := 2
			if failure == "nil" {
				expected = 1
			}
			if len(closers) != expected || probes[2].constructed != 0 {
				t.Fatal("partial acquisition was lost or construction continued")
			}
			refreshStoreCloseAll(t, closers)
			if !probes[0].instances[0].closed {
				t.Fatal("later cleanup error prevented earlier release")
			}
			if len(probes[1].instances) > 0 && !probes[1].instances[0].closed {
				t.Fatal("partial failed runtime leaked")
			}
		})
	}
}

func TestAppRefreshStoreOptionalCloser(t *testing.T) {
	app, ctx, probes := refreshStoreMockApp(t, "resource_free", "close_error", "")
	if app.prepareRefreshStores(ctx, &authcrunch.Config{}) != nil {
		t.Fatal("cannot prepare closer fixture")
	}
	handles, closers, err := app.attachRefreshStores(t.Context())
	if err != nil || len(handles) != 3 || len(closers) != 2 {
		t.Fatal("optional closer contract rejected")
	}
	order := []string{}
	for i, closer := range slices.Backward(closers) {
		err := closer.Close()
		if err != nil && strings.Contains(err.Error(), refreshStorePrivateDiagnostic) {
			t.Fatal("cleanup diagnostic leaked")
		}
		order = append(order, probes[i+1].closes...)
	}
	if !slices.Equal(order, []string{"store2", "store1"}) || probes[0].instances[0].closed {
		t.Fatal("cleanup order or optional ownership changed")
	}
}

var _ tokenrefresh.ManagedStore = (*refreshStoreMockRuntime)(nil)
