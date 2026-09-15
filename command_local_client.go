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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const securityLocalMaxResponse = 8 << 20

type securityLocalConfig struct {
	authclient.Config `yaml:",inline"`
	TokenPath         string `yaml:"token_path,omitempty"`
	// Accepted for compatibility with authdbctl; token header names come from
	// the login response or access_token_name, never the browser cookie setting.
	CookieName string `yaml:"cookie_name,omitempty"`
}

type securityLocalClient struct {
	baseURL, tokenPath string
	http               *http.Client
	authenticator      *authclient.Client
	store              *authclient.FileTokenStore
}

// Read credential inputs only from bounded regular files. Errors deliberately
// omit paths and parser details because either may contain misplaced secrets.
func readSecurityLocalFile(ctx context.Context, path string, limit int64, private bool) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("input must be an existing regular file")
	}
	if private && runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("credential input must have owner-only permissions (0600)")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open input file")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("input file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("cannot read input file or size limit exceeded")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func parseSecurityLocalConfig(data []byte) (*securityLocalConfig, error) {
	cfg := &securityLocalConfig{}
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(cfg); err != nil {
		return nil, fmt.Errorf("invalid authentication client YAML")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("expected one authentication client YAML document")
	}
	// YAML !!binary can decode valid source text into invalid UTF-8. JSON
	// would replace those bytes, changing credentials or cache identities.
	for _, value := range []string{
		cfg.BaseURL, cfg.Username, cfg.Realm, cfg.Password, cfg.APIKey,
		cfg.TOTPSecret, cfg.AccessTokenName, cfg.RefreshTransport,
		cfg.TokenPath, cfg.CookieName,
	} {
		if !utf8.ValidString(value) {
			return nil, fmt.Errorf("authentication client values must be valid UTF-8")
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func newSecurityLocalClient(ctx context.Context, cmd *cobra.Command) (*securityLocalClient, error) {
	configPath, _ := cmd.Flags().GetString("config")
	data, err := readSecurityLocalFile(ctx, configPath, 1<<20, true)
	if err != nil {
		return nil, fmt.Errorf("read client config: %w", err)
	}
	cfg, err := parseSecurityLocalConfig(data)
	if err != nil {
		return nil, err
	}
	// Resolve filesystem traversal before any lexical cleaning. Otherwise a
	// symlink followed by .. can change the directory used for relative caches
	// and even defeat the protection against overwriting this config.
	configPath, err = identityFilePath(configPath)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve client config path")
	}
	tokenPath, _ := cmd.Flags().GetString("token-path")
	if !utf8.ValidString(tokenPath) {
		return nil, fmt.Errorf("token path must be valid UTF-8")
	}
	if cmd.Flags().Changed("token-path") && strings.TrimSpace(tokenPath) == "" {
		return nil, fmt.Errorf("token path must not be empty")
	}
	if tokenPath == "" {
		tokenPath = cfg.TokenPath
		if tokenPath != "" && !filepath.IsAbs(tokenPath) {
			// Join would clean link/.. before the filesystem follows the link.
			tokenPath = filepath.Dir(configPath) + string(filepath.Separator) + tokenPath
		}
	}
	if tokenPath == "" {
		// Legacy token files are not bound to a server. Isolate default caches by
		// portal and login identity, including API-key identity, before loading.
		identity, _ := json.Marshal([]string{cfg.BaseURL, cfg.Realm, cfg.Username, cfg.APIKey, cfg.AccessTokenName})
		tokenPath = filepath.Join(filepath.Dir(configPath), ".security-tokens", fmt.Sprintf("%x.json", sha256.Sum256(identity)))
	}
	// Reject a symlink at the leaf before resolving its ancestors. The shared
	// identity-file resolver also supports not-yet-created cache directories.
	if _, err := os.Lstat(tokenPath); err == nil {
		if _, err := readSecurityLocalFile(ctx, tokenPath, 1<<20, true); err != nil {
			return nil, fmt.Errorf("read token file: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("cannot inspect token file")
	}
	tokenPath, err = identityFilePath(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve token file path")
	}
	caPath, _ := cmd.Flags().GetString("ca-file")
	for _, input := range []string{configPath, caPath} {
		if input == "" {
			continue
		}
		abs, err := identityFilePath(input)
		if err != nil || abs == tokenPath {
			return nil, fmt.Errorf("token output must not replace an input file")
		}
		a, ae := os.Stat(input)
		b, be := os.Stat(tokenPath)
		if ae == nil && be == nil && os.SameFile(a, b) {
			return nil, fmt.Errorf("token output must not replace an input file")
		}
	}
	// Own the transport: other modules may customize DefaultTransport with
	// insecure TLS settings, client certificates, or a different TLS dialer.
	// All connection, handshake, and request work uses the command's context
	// deadline, including when --timeout permits more than ten seconds.
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true,
		MaxIdleConns:      10,
		IdleConnTimeout:   30 * time.Second,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if caPath != "" {
		pemData, err := readSecurityLocalFile(ctx, caPath, 1<<20, false)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("CA file contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	hc := &http.Client{Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var prompt authclient.PromptFunc
	// A configured TOTP secret supports unattended MFA selection upstream.
	// Installing a prompt unconditionally would override that behavior.
	if cfg.Password == "" || cfg.TOTPSecret == "" {
		prompt = func(ctx context.Context, kind authclient.PromptKind) (string, error) {
			if kind == authclient.PromptMFA && cfg.TOTPSecret != "" {
				return "totp", nil
			}
			label := "Password: "
			switch kind {
			case authclient.PromptPassword:
			case authclient.PromptTOTP:
				label = "Authenticator code: "
			case authclient.PromptMFA:
				label = "MFA method (totp or webauthn): "
			default:
				return "", authclient.ErrUnsupportedChallenge
			}
			return readSecuritySecret(ctx, cmd.InOrStdin(), cmd.ErrOrStderr(), label)
		}
	}
	authenticator, err := authclient.NewClient(&cfg.Config, authclient.Options{HTTPClient: hc, Prompt: prompt, UserAgent: "caddy-security"})
	if err != nil {
		return nil, err
	}
	store, err := authclient.NewFileTokenStore(tokenPath)
	if err != nil {
		return nil, err
	}
	return &securityLocalClient{baseURL: cfg.BaseURL, tokenPath: tokenPath, http: hc, authenticator: authenticator, store: store}, nil
}

func (c *securityLocalClient) authenticate(ctx context.Context) error {
	credentials, err := c.authenticator.Authenticate(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("authentication interrupted: %w", ctx.Err())
		}
		var httpErr *authclient.HTTPError
		if errors.As(err, &httpErr) {
			return httpErr
		}
		if errors.Is(err, authclient.ErrNativeTransportRequired) {
			return authclient.ErrNativeTransportRequired
		}
		if errors.Is(err, authclient.ErrUnsupportedChallenge) {
			return authclient.ErrUnsupportedChallenge
		}
		if errors.Is(err, errSecurityTerminalEncoding) {
			return errSecurityTerminalEncoding
		}
		return fmt.Errorf("portal authentication failed; check client settings and required password/MFA input")
	}
	if err := c.store.Save(credentials); err != nil {
		return fmt.Errorf("authenticated, but could not save private credentials")
	}
	return nil
}

func (c *securityLocalClient) request(ctx context.Context, endpoint string, body []byte, mutation bool) (data []byte, err error) {
	credentials, err := c.store.Load()
	if errors.Is(err, os.ErrNotExist) {
		if err := c.authenticate(ctx); err != nil {
			return nil, err
		}
		credentials, err = c.store.Load()
	}
	if err != nil {
		return nil, fmt.Errorf("cannot load credentials; use local connect to replace the token file")
	}
	authorization, err := credentials.Authorization()
	if err != nil {
		return nil, err
	}
	method := http.MethodPost
	if endpoint == "metadata" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/api/server/"+endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cannot create admin API request")
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	// Once a mutation is sent, neither a transport failure nor a negative API
	// response proves that the backend left its state unchanged. In particular,
	// a proxy can return an error after the backend has committed the change.
	defer func() {
		if err != nil && mutation {
			err = fmt.Errorf("%w; outcome may be unknown; inspect the user or realm before repeating", err)
		}
	}()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("admin API request failed; check connectivity and TLS trust")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("admin API returned HTTP %d", resp.StatusCode)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			err = fmt.Errorf("%w; verify enable admin api, admin role, and credentials (local connect renews them)", err)
		}
		return nil, err
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, securityLocalMaxResponse+1))
	if err != nil || len(data) > securityLocalMaxResponse {
		return nil, fmt.Errorf("cannot read admin API response or size limit exceeded")
	}
	if err := validateSecurityLocalResponse(endpoint, mutation, data); err != nil {
		return nil, err
	}
	return data, nil
}

func validateSecurityLocalResponse(endpoint string, mutation bool, data []byte) error {
	var result map[string]json.RawMessage
	// encoding/json repairs malformed Unicode. A generated password must never
	// be reported successfully after decoding has changed its contents.
	if !utf8.Valid(data) || !registrationJSONUnicodeValid(data) || json.Unmarshal(data, &result) != nil || result == nil {
		return fmt.Errorf("invalid admin API response")
	}
	var status string
	if raw, ok := result["status"]; ok {
		if json.Unmarshal(raw, &status) != nil || status != "success" {
			return fmt.Errorf("admin API operation failed")
		}
	}
	if _, ok := result["error"]; ok {
		return fmt.Errorf("admin API operation failed")
	}
	if mutation && status != "success" {
		return fmt.Errorf("admin API did not confirm the operation; verify the target realm")
	}
	if !mutation {
		field := map[string]string{"metadata": "version", "realms": "realms", "users": "users", "info": "policy", "user": "username"}[endpoint]
		raw, ok := result[field]
		valid := ok
		switch endpoint {
		case "metadata", "user":
			var value string
			valid = valid && json.Unmarshal(raw, &value) == nil && value != ""
		case "realms", "users":
			var values []map[string]json.RawMessage
			valid = valid && json.Unmarshal(raw, &values) == nil && values != nil
			for _, value := range values {
				valid = valid && value != nil
			}
		case "info":
			var value map[string]json.RawMessage
			valid = valid && json.Unmarshal(raw, &value) == nil && value != nil
		default:
			valid = false
		}
		if !valid {
			return fmt.Errorf("incomplete admin API response; verify the target realm and user")
		}
	}
	return nil
}
