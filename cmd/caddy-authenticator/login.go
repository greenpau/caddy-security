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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/spf13/cobra"
)

func loginProfile(cmd *cobra.Command, s *state, o *options) error {
	p, err := s.selectedProfile()
	if err != nil {
		return err
	}
	if err := s.openProfile(true); err != nil {
		return err
	}
	if _, err := checkFile(s.pendingPath(), true, true); err != nil {
		return err
	}
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		store, err := s.tokenStore()
		if err != nil {
			return err
		}
		cached, err := store.Load()
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("cannot load cached credentials; use login --force to authenticate again")
		}
		if err == nil {
			expires, err := credentialExpiry(cached)
			if err != nil {
				return err
			}
			remaining := time.Until(expires)
			if remaining > 0 {
				if remaining < 3*time.Minute && cached.RefreshToken != "" {
					if err := s.runLogged("refresh", func() error { return refreshProfile(cmd, s, p, store, cached) }); err != nil {
						return err
					}
					return writeOutput(cmd.OutOrStdout(), "Refreshed. Credentials saved to "+s.tokenPath())
				}
				if err := s.logEvent("login", "cached"); err != nil {
					return err
				}
				message := "Using cached credentials."
				if remaining < 3*time.Minute {
					message += " Token expires soon; no refresh credential is available."
				}
				return writeOutput(cmd.OutOrStdout(), message)
			}
		}
	}
	if err := s.runLogged("login", func() error { return authenticateProfile(cmd, s, o, p) }); err != nil {
		return err
	}
	return writeOutput(cmd.OutOrStdout(), "Authenticated. Credentials saved to "+s.tokenPath())
}

func authenticateProfile(cmd *cobra.Command, s *state, o *options, p profile) error {
	if cmd.Flags().Changed("password-file") {
		path, _ := cmd.Flags().GetString("password-file")
		value, err := readSecretFile(cmd.Context(), cmd.InOrStdin(), path)
		if err != nil {
			return err
		}
		p["password"] = value
	}
	cfg, err := p.config()
	if err != nil {
		return err
	}
	hc, cleanup, err := profileHTTPClient(cmd, s, p, cfg)
	if err != nil {
		return err
	}
	defer cleanup()
	var prompt authclient.PromptFunc
	if o.interactive {
		terminal := newTerminalInput(cmd.InOrStdin(), cmd.ErrOrStderr())
		prompt = func(ctx context.Context, kind authclient.PromptKind) (string, error) {
			switch kind {
			case authclient.PromptPassword:
				return terminal.read(ctx, "Password: ", true)
			case authclient.PromptMFA:
				return "totp", nil
			case authclient.PromptTOTP:
				return terminal.read(ctx, "Authenticator code: ", true)
			default:
				return "", authclient.ErrUnsupportedChallenge
			}
		}
	}
	client, err := authclient.NewClient(cfg, authclient.Options{HTTPClient: hc, Prompt: prompt, UserAgent: "caddy-authenticator"})
	if err != nil {
		return err
	}
	store, err := s.tokenStore()
	if err != nil {
		return err
	}
	credentials, err := client.Authenticate(cmd.Context())
	if err != nil {
		return loginError(cmd.Context(), err)
	}
	if err := cmd.Context().Err(); err != nil {
		return err
	}
	if err := store.Save(credentials); err != nil {
		return errors.New("authenticated, but could not save token.jwt")
	}
	if err := removePrivate(s.pendingPath()); err != nil {
		return errors.New("authenticated and saved token.jwt, but could not clear refresh.pending")
	}
	return nil
}

func profileHTTPClient(cmd *cobra.Command, s *state, p profile, cfg *authclient.Config) (*http.Client, func(), error) {
	// Cleartext credentials are allowed only over literal loopback addresses
	// or localhost for local development. DNS aliases do not establish locality.
	u, _ := url.Parse(cfg.BaseURL)
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, nil, errors.New("HTTPS is required except for localhost or loopback IP addresses")
	}
	ca := p["ca_file"]
	if cmd.Flags().Changed("ca-file") {
		ca, _ = cmd.Flags().GetString("ca-file")
	} else if ca != "" {
		var err error
		ca, err = absoluteInputPath(ca, s.home)
		if err != nil {
			return nil, nil, err
		}
	}
	return httpClient(ca)
}

func httpClient(caFile string) (*http.Client, func(), error) {
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if caFile != "" {
		data, err := readFile(caFile, false)
		if err != nil {
			return nil, nil, errors.New("cannot read CA file")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, nil, errors.New("CA file contains no PEM certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport.CloseIdleConnections, nil
}

func loginError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("authentication interrupted: %w", ctx.Err())
	}
	var status *authclient.HTTPError
	if errors.As(err, &status) {
		return status
	}
	for _, known := range []error{authclient.ErrNativeTransportRequired, authclient.ErrUnsupportedChallenge, errTerminalEncoding} {
		if errors.Is(err, known) {
			return known
		}
	}
	if errors.Is(err, authclient.ErrInputRequired) {
		return errors.New("authentication input required; configure credentials or use --interactive")
	}
	// Transport errors can contain URLs or untrusted server data; never echo them.
	return errors.New("portal authentication failed; check credentials, password/MFA input, connectivity and TLS trust")
}

func showToken(cmd *cobra.Command, s *state, _ *options) error {
	if _, err := s.selectedProfile(); err != nil {
		return err
	}
	if err := s.openProfile(false); err != nil {
		return err
	}
	store, err := s.tokenStore()
	if err != nil {
		return err
	}
	credentials, err := store.Load()
	if err != nil {
		return errors.New("cannot load token.jwt; run login for this profile")
	}
	pathOnly, _ := cmd.Flags().GetBool("path")
	if pathOnly {
		return writeOutput(cmd.OutOrStdout(), s.tokenPath())
	}
	header, _ := cmd.Flags().GetBool("header")
	if header {
		value, err := credentials.Authorization()
		if err != nil {
			return errors.New("invalid saved credentials; run login")
		}
		return writeOutput(cmd.OutOrStdout(), "Authorization: "+value)
	}
	return writeOutput(cmd.OutOrStdout(), credentials.AccessToken)
}
