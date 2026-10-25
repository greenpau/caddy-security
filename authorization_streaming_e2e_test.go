// Copyright 2022 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package security

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch"
	"golang.org/x/net/websocket"
)

func TestCaddyAuthorizationStreamingE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyAuthorizationStreamingProcess$", "-test.v", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_AUTHORIZATION_STREAMING_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy streaming authorization reload: %v\n%s", err, output)
	}
}

func TestCaddyAuthorizationStreamingProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_AUTHORIZATION_STREAMING_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, mode := range []string{"authorized", "bypassed"} {
		for _, http2 := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/http2=%t", mode, http2), func(t *testing.T) {
				testAuthorizationStreamingReload(t, mode, http2)
			})
		}
	}
}

func testAuthorizationStreamingReload(t *testing.T, mode string, http2 bool) {
	t.Helper()
	advance := make(chan struct{}, 1)
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Query().Get("stream") {
		case "websocket":
			websocket.Handler(func(conn *websocket.Conn) {
				for {
					var message string
					if err := websocket.Message.Receive(conn, &message); err != nil {
						return
					}
					if err := websocket.Message.Send(conn, message); err != nil {
						return
					}
				}
			}).ServeHTTP(w, r)
		case "sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("X-Upstream-Role", r.Header.Get("X-Reload-Role"))
			for event := 0; ; event++ {
				if _, err := fmt.Fprintf(w, "data: %d\n\n", event); err != nil {
					return
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					return
				}
				select {
				case <-advance:
				case <-r.Context().Done():
					return
				}
			}
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(upstream.Close)
	cert, key, roots := cookieTLSCertificate(t)
	base, admin := "https://"+lifecycleAddress(t), "http://"+lifecycleAddress(t)
	roleHeader := ""
	if mode == "authorized" {
		roleHeader = "header_up X-Reload-Role {http.auth.user.roles}"
	}
	config := func(generation int) []byte {
		input := fmt.Sprintf(`{
 admin %s
 persist_config off
 auto_https off
 grace_period 10ms
 log {
  level ERROR
 }
 security {
  authorization policy streaming {
   crypto key verify %s
   disable auth redirect
   validate bearer header
   allow roles viewer
   bypass uri exact /public
  }
 }
}
%s {
 tls %q %q
 route {
  authorize with streaming
  header X-Reload-Generation %d
  reverse_proxy %s {
   %s
  }
 }
}`, strings.TrimPrefix(admin, "http://"), authorizationPathKey, base, cert, key, generation, upstream.URL, roleHeader)
		data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if err := caddy.Load(config(0), true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: http2,
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	adminTransport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(adminTransport.CloseIdleConnections)
	adminClient := &http.Client{Transport: adminTransport, Timeout: 5 * time.Second}
	token := authorizationPathToken(t)
	path, wantRole := "/protected", "viewer"
	if mode == "bypassed" {
		path, wantRole = "/public", ""
	}
	request := func(target, credential string) *http.Request {
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if credential != "" {
			r.Header.Set("Authorization", "Bearer "+credential)
		}
		return r
	}
	for _, credential := range []string{"", "invalid-synthetic-token"} {
		resp, err := client.Do(request("/protected", credential))
		if err != nil {
			t.Fatal("unauthorized request", err)
		}
		_, readErr := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Cache-Control") != "no-store" || hits.Load() != 0 {
			t.Fatal("unauthorized request reached the streaming upstream or changed denial behavior")
		}
	}
	if mode == "bypassed" {
		token = ""
	}
	// Keep a real response open across both replacements. Unlike a WebSocket,
	// this stream does not depend on the random reverse-proxy cleanup order.
	streamCtx, cancelStream := context.WithCancel(t.Context())
	defer cancelStream()
	streamRequest := request(path+"?stream=sse", token).WithContext(streamCtx)
	stream, err := client.Do(streamRequest)
	if err != nil {
		t.Fatal("open stream", err)
	}
	defer stream.Body.Close()
	if stream.StatusCode != http.StatusOK || stream.Header.Get("X-Upstream-Role") != wantRole || stream.TLS == nil || len(stream.TLS.VerifiedChains) == 0 || (stream.ProtoMajor == 2) != http2 {
		t.Fatalf("stream contract: status=%d role=%q protocol=%s verified_TLS=%t", stream.StatusCode, stream.Header.Get("X-Upstream-Role"), stream.Proto, stream.TLS != nil && len(stream.TLS.VerifiedChains) > 0)
	}
	reader := bufio.NewReader(stream.Body)
	readEvent := func(event int) {
		line, err := reader.ReadString('\n')
		if err != nil || line != fmt.Sprintf("data: %d\n", event) {
			t.Fatalf("stream event %d changed or ended: %v", event, err)
		}
		blank, err := reader.ReadString('\n')
		if err != nil || blank != "\n" {
			t.Fatal("incomplete stream event", err)
		}
	}
	readEvent(0)
	for generation := 1; generation <= 2; generation++ {
		wsConfig, err := websocket.NewConfig("wss"+strings.TrimPrefix(base, "https")+path+"?stream=websocket", base)
		if err != nil {
			t.Fatal(err)
		}
		wsConfig.TlsConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		if token != "" {
			wsConfig.Header.Set("Authorization", "Bearer "+token)
		}
		dialCtx, cancelDial := context.WithTimeout(t.Context(), 5*time.Second)
		ws, err := wsConfig.DialContext(dialCtx)
		cancelDial()
		if err != nil {
			t.Fatal("open WebSocket", err)
		}
		t.Cleanup(func() { _ = ws.Close() })
		if err := ws.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := websocket.Message.Send(ws, "before reload"); err != nil {
			t.Fatal(err)
		}
		var message string
		if err := websocket.Message.Receive(ws, &message); err != nil || message != "before reload" {
			t.Fatal("WebSocket did not reach its protected upstream", err)
		}
		active, err := caddy.ActiveContext().AppIfConfigured("security")
		if err != nil {
			t.Fatal(err)
		}
		old := active.(*App)
		reload, err := http.NewRequestWithContext(t.Context(), http.MethodPost, admin+"/load", bytes.NewReader(config(generation)))
		if err != nil {
			t.Fatal(err)
		}
		reload.Header.Set("Content-Type", "application/json")
		resp, err := adminClient.Do(reload)
		if err != nil {
			t.Fatal("reload blocked with an open stream and WebSocket", err)
		}
		_, readErr := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			t.Fatal("reload failed", resp.StatusCode, readErr)
		}
		if _, err := old.server.GetGatekeeperByName("streaming"); !errors.Is(err, authcrunch.ErrServerClosed) {
			t.Fatal("reload left the retired runtime open")
		}
		if err := websocket.Message.Receive(ws, &message); err == nil {
			t.Fatal("retired proxy kept its WebSocket open")
		} else {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Fatal("WebSocket closure timed out")
			}
		}
		// The same SSE response must still deliver data after its security app
		// was disposed. No stream timeout or client disconnect unblocks reload.
		advance <- struct{}{}
		readEvent(generation)
		resp, err = adminClient.Get(admin + "/config/")
		if err != nil {
			t.Fatal("admin configuration lock remained held", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK || !json.Valid(data) {
			t.Fatal("admin configuration unavailable after reload")
		}
		resp, err = client.Do(request(path, token))
		if err != nil {
			t.Fatal("replacement request", err)
		}
		_, readErr = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusNoContent || resp.Header.Get("X-Reload-Generation") != fmt.Sprint(generation) {
			t.Fatal("replacement route did not serve the new configuration")
		}
	}
}
