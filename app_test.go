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
	"fmt"
	"github.com/caddyserver/caddy/v2/caddytest"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

var (
	scheme     string = "https"
	host       string = "127.0.0.1"
	securePort string = "8443"
)

func initCaddyTester(t *testing.T, configFile string) (*caddytest.Tester, map[string]string, error) {
	hostPort := fmt.Sprintf("%s:%s", host, securePort)
	baseURL := fmt.Sprintf("%s://%s", scheme, hostPort)
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, nil, err
	}

	tester := caddytest.NewTester(t)
	tester.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Do not follow redirects.
		return http.ErrUseLastResponse
	}
	tester.InitServer(string(configContent), "caddyfile")

	params := make(map[string]string)
	params["base_url"] = baseURL
	params["version_path"] = fmt.Sprintf("%s/version", baseURL)
	return tester, params, nil
}

func TestApp(t *testing.T) {
	tester, config, err := initCaddyTester(t, "assets/config/Caddyfile")
	if err != nil {
		t.Fatalf("failed to init caddy tester instance: %v", err)
	}
	resp, respBody := tester.AssertGetResponse(config["version_path"], 200, "1.0.0")
	t.Logf("%v", resp)
	t.Logf("%v", respBody)
	time.Sleep(1 * time.Second)
}
