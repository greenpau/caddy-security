// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

// Package consultest starts isolated, disposable Consul agents for integration tests.
package consultest

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Start uses CADDY_SECURITY_TEST_CONSUL_BINARY or consul on PATH. Tests needing
// this external service explicitly skip when no binary is installed.
func Start(t testing.TB) string {
	t.Helper()
	binary := os.Getenv("CADDY_SECURITY_TEST_CONSUL_BINARY")
	if binary == "" {
		var err error
		binary, err = exec.LookPath("consul")
		if err != nil {
			t.Skip("Consul integration requires CADDY_SECURITY_TEST_CONSUL_BINARY or consul on PATH")
		}
	}
	directory := t.TempDir()
	logfile, err := os.OpenFile(filepath.Join(directory, "consul.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logfile.Close() })
	allocated := make(map[int]bool)
	port := func() string {
		for range 30 {
			tcp, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			n := tcp.Addr().(*net.TCPAddr).Port
			udp, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(n))
			_ = tcp.Close()
			if err != nil {
				continue
			}
			_ = udp.Close()
			if !allocated[n] {
				allocated[n] = true
				return strconv.Itoa(n)
			}
		}
		t.Fatal("no free Consul port")
		return ""
	}
	address := "127.0.0.1:" + port()
	cmd := exec.Command(binary, "agent", "-dev", "-bind=127.0.0.1", "-client=127.0.0.1", "-node=issue508-"+port(), "-data-dir="+filepath.Join(directory, "data"),
		"-http-port="+address[len("127.0.0.1:"):], "-dns-port=0", "-grpc-port=0", "-grpc-tls-port=0", "-serf-lan-port="+port(), "-serf-wan-port="+port(), "-server-port="+port(), "-log-level=warn")
	cmd.Stdout, cmd.Stderr = logfile, logfile
	if err := cmd.Start(); err != nil {
		t.Fatal("start Consul:", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGINT)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			data, _ := os.ReadFile(filepath.Join(directory, "consul.log"))
			if len(data) > 6000 {
				data = data[len(data)-6000:]
			}
			t.Logf("Consul agent log: %s", data)
		}
	})
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("http://" + address + "/v1/status/leader")
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			var leader string
			if response.StatusCode == 200 && json.Unmarshal(body, &leader) == nil && leader != "" {
				return address
			}
		}
		select {
		case <-done:
			t.Fatal("Consul exited during startup")
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("Consul did not elect a leader before startup deadline")
	return ""
}
