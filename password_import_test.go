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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Synthetic library-generated imports include $, + and / to catch encoding loss.
const argon2FixturePlaintext = "Argon2FixturePassword42!"
const bcryptFixturePlaintext = "BcryptFixturePassword42!"
const argon2FixtureHash = "argon2:$argon2id$v=19$m=1024,t=2,p=2$mjBUxIgaxCd2UQA9tzdTUQ$z5MrHTVraToXYev67Zg47cpvqEWp/WufD0u4oyK+V+c"
const bcryptFixtureHash = "bcrypt:8:$2a$08$CiSseGjDibS3jp0ZVKut/u1BdLXh9UgaixdLkr9VUWk.zvCSBeOP."

func passwordImportApp(t *testing.T, input string) *App {
	t.Helper()
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal("password fixture adaptation failed", err)
	}
	var cfg struct{ Apps struct{ Security *App } }
	if err := json.Unmarshal(data, &cfg); err != nil || cfg.Apps.Security == nil {
		t.Fatal("password fixture JSON decode failed")
	}
	return cfg.Apps.Security
}

func TestPasswordImportAdaptAndResolve(t *testing.T) {
	t.Setenv("SECURITY_ARGON2_PASSWORD", argon2FixtureHash)
	input, err := os.ReadFile("testdata/caddyfile_adapt/testcase_authenticate_with_argon2.Caddyfile")
	if err != nil {
		t.Fatal(err)
	}
	app := passwordImportApp(t, string(input))
	assertValues := func(runtime bool) {
		t.Helper()
		users, ok := app.Config.IdentityStores[0].Params["users"].([]any)
		if !ok || len(users) != 5 {
			t.Fatal("local-user configuration lost")
		}
		for i, want := range []string{argon2FixtureHash, argon2FixtureHash, "{env.SECURITY_ARGON2_PASSWORD}", bcryptFixtureHash, "PlaintextFixturePassword42!"} {
			if runtime && i == 2 {
				want = argon2FixtureHash
			}
			user := users[i].(map[string]any)
			if user["password"] != want {
				t.Errorf("password value changed for fixture %d, runtime=%v", i, runtime)
			}
			if i == 0 && user["password_overwrite_enabled"] != true {
				t.Fatal("overwrite intent lost")
			}
		}
	}
	assertValues(false)
	if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, app.Config, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	assertValues(true)
	// Round-trip native JSON after resolution as well as the Caddyfile output.
	data, err := json.Marshal(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, app); err != nil {
		t.Fatal(err)
	}
	assertValues(true)
	// Cross the host's typed local.User provisioning boundary using the resolved
	// fixture, including default bcrypt creation from ordinary plaintext.
	path := filepath.Join(t.TempDir(), "users.json")
	app.Config.IdentityStores[0].Params["path"] = path
	runtime := provisionLifecycleApp(t, app.Config)
	if err := runtime.Cleanup(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ username, plaintext, algorithm, encoded string }{
		{"alice", argon2FixturePlaintext, "argon2", argon2FixtureHash},
		{"environment", argon2FixturePlaintext, "argon2", argon2FixtureHash},
		{"runtime", argon2FixturePlaintext, "argon2", argon2FixtureHash},
		{"bob", bcryptFixturePlaintext, "bcrypt", bcryptFixtureHash},
		{"plain", "PlaintextFixturePassword42!", "bcrypt", ""},
	} {
		password := localIdentityActivePassword(t, localIdentityRecord(t, path, tc.username))
		if password.Algorithm != tc.algorithm || !password.Match(tc.plaintext) {
			t.Fatalf("provisioned credential changed for fixture user %s", tc.username)
		}
		if tc.encoded != "" && password.EncodedHash() != tc.encoded {
			t.Fatal("provisioning reencoded an imported hash")
		}
	}
}

func TestPasswordImportProvisioningRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"argon2i":              strings.Replace(argon2FixtureHash, "argon2id$", "argon2i$", 1),
		"argon2d":              strings.Replace(argon2FixtureHash, "argon2id$", "argon2d$", 1),
		"version":              strings.Replace(argon2FixtureHash, "v=19", "v=16", 1),
		"outer cost":           "argon2:2:" + strings.TrimPrefix(argon2FixtureHash, "argon2:"),
		"memory":               strings.Replace(argon2FixtureHash, "m=1024", "m=262145", 1),
		"work":                 strings.Replace(argon2FixtureHash, "m=1024,t=2", "m=262144,t=5", 1),
		"lanes":                strings.Replace(argon2FixtureHash, "p=2", "p=17", 1),
		"passes":               strings.Replace(argon2FixtureHash, "t=2", "t=11", 1),
		"minimum memory":       strings.Replace(argon2FixtureHash, "m=1024", "m=8", 1),
		"decimal":              strings.Replace(argon2FixtureHash, "m=1024", "m=01024", 1),
		"field order":          strings.Replace(argon2FixtureHash, "m=1024,t=2,p=2", "t=2,m=1024,p=2", 1),
		"base64":               strings.Replace(argon2FixtureHash, "mjBUxIgaxCd2UQA9tzdTUQ", "invalid!", 1),
		"padded base64":        strings.Replace(argon2FixtureHash, "tzdTUQ$", "tzdTUQ==$", 1),
		"missing fields":       "argon2:$argon2id$v=19$m=1024,t=2,p=2",
		"extra fields":         argon2FixtureHash + "$extra",
		"bcrypt cost mismatch": strings.Replace(bcryptFixtureHash, "bcrypt:8:", "bcrypt:10:", 1),
		"bcrypt cost decimal":  strings.Replace(bcryptFixtureHash, "bcrypt:8:", "bcrypt:08:", 1),
		"bcrypt header":        strings.Replace(bcryptFixtureHash, "$2a$", "$2z$", 1),
		"bcrypt separator":     strings.Replace(bcryptFixtureHash, "$2a$", "$2a!", 1),
		"bcrypt checksum":      bcryptFixtureHash[:len(bcryptFixtureHash)-1] + "!",
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			app := passwordImportApp(t, fmt.Sprintf(`{
 security {
  local identity store localdb {
   realm local
   path %q
   user alice {
    email alice@example.test
    password %q
   }
  }
 }
}`, path, candidate))
			if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, app.Config, zap.NewNop()); err != nil {
				t.Fatal("adapter should defer hash validation", err)
			}
			var logs bytes.Buffer
			logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&logs), zap.DebugLevel))
			store, err := ids.NewIdentityStore(app.Config.IdentityStores[0], logger)
			if err != nil {
				t.Fatal("cannot construct local store")
			}
			err = store.Configure()
			if err == nil {
				t.Fatal("invalid password import provisioned")
			}
			// Check both full credentials and distinctive encoded fragments.
			for _, secret := range []string{candidate, "mjBUxIgaxCd2UQA9tzdTUQ", "CiSseGjDibS3jp0ZVKut/u1"} {
				if strings.Contains(err.Error(), secret) || strings.Contains(logs.String(), secret) {
					t.Fatal("provisioning diagnostic disclosed a credential")
				}
			}
			data, err := os.ReadFile(path)
			if os.IsNotExist(err) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var db struct{ Users []json.RawMessage }
			if json.Unmarshal(data, &db) != nil || len(db.Users) != 0 {
				t.Fatal("rejected import persisted a user")
			}
		})
	}
}

func TestPasswordImportDirectiveErrorsRedact(t *testing.T) {
	for _, body := range []string{
		"password",
		fmt.Sprintf("password %q %q", argon2FixtureHash, bcryptFixtureHash),
		fmt.Sprintf("password %q overwrite %q", argon2FixtureHash, argon2FixturePlaintext),
	} {
		input := fmt.Sprintf("{\n security {\n local identity store localdb {\n realm local\n path :memory:\n user alice {\n %s\n }\n }\n }\n }\n", body)
		_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
		if err == nil {
			t.Fatal("malformed password directive accepted")
		}
		for _, secret := range []string{argon2FixtureHash, bcryptFixtureHash, argon2FixturePlaintext} {
			if strings.Contains(err.Error(), secret) {
				t.Fatal("password directive diagnostic disclosed credential")
			}
		}
	}
}
