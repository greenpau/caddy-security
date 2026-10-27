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
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPasswordCaddyReadiness(t *testing.T) {
	t.Run("waits for verified HTTPS login", func(t *testing.T) {
		var probes atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/auth/login" {
				http.NotFound(w, r)
				return
			}
			if probes.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		exited, err := waitPasswordCaddyReady(ctx, server.Client(), server.URL+"/auth/login", nil)
		if exited || err != nil || probes.Load() < 2 {
			t.Fatalf("readiness did not wait for HTTPS login: exited=%v, err=%v", exited, err)
		}
	})

	for _, status := range []int{http.StatusServiceUnavailable, http.StatusFound} {
		t.Run(fmt.Sprintf("HTTP %d diagnostics", status), func(t *testing.T) {
			const secret = "readiness-response-secret"
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/"+secret)
				w.Header().Set("Set-Cookie", "token="+secret)
				w.WriteHeader(status)
				fmt.Fprint(w, secret)
			}))
			defer server.Close()
			client := server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			exited, err := waitPasswordCaddyReady(ctx, client, server.URL+"/auth/login", nil)
			if exited || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("readiness did not retain deadline failure: exited=%v, err=%v", exited, err)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("last HTTP status: %d", status)) || strings.Contains(err.Error(), secret) {
				t.Fatal("readiness lost HTTP status or disclosed response credentials")
			}
		})
	}

	t.Run("cancels an outstanding probe", func(t *testing.T) {
		started := make(chan struct{}, 1)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-r.Context().Done()
		}))
		defer server.Close()
		deadline, stop := context.WithTimeout(t.Context(), 5*time.Second)
		defer stop()
		ctx, cancel := context.WithCancel(deadline)
		defer cancel()
		result := make(chan error, 1)
		go func() {
			_, err := waitPasswordCaddyReady(ctx, server.Client(), server.URL+"/auth/login", nil)
			result <- err
		}()
		select {
		case <-started:
		case <-deadline.Done():
			t.Fatal("HTTPS readiness probe did not reach the server")
		}
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("outstanding readiness probe ignored cancellation: %v", err)
			}
		case <-deadline.Done():
			t.Fatal("readiness outlived cancellation")
		}
	})

	t.Run("reports process exit", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		done := make(chan error, 1)
		done <- errors.New("fixture process exit")
		exited, err := waitPasswordCaddyReady(ctx, server.Client(), server.URL+"/auth/login", done)
		if !exited || err == nil || !strings.Contains(err.Error(), "fixture process exit") {
			t.Fatalf("readiness lost process completion: exited=%v, err=%v", exited, err)
		}
		if len(done) != 0 {
			t.Fatal("reported process completion was not consumed")
		}
	})

	t.Run("rejects unverified transport", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		exited, err := waitPasswordCaddyReady(ctx, server.Client(), server.URL+"/auth/login", nil)
		if exited || err == nil || !strings.Contains(err.Error(), "TLS was not verified") {
			t.Fatalf("readiness accepted unverified transport: exited=%v, err=%v", exited, err)
		}
	})
}
