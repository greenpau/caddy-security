package security

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"
	caddyfileadapter "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func TestParseAuthnPluginCaddyfilePreservesPlaceholders(t *testing.T) {
	t.Setenv("AUTH_PORTAL_NAME", "myportal")

	cfg, err := parseAuthnPluginCaddyfile(httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser("authenticate /app/* with {env.AUTH_PORTAL_NAME}"),
	})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	if got := cfg["path"]; got != "/app/*" {
		t.Fatalf("unexpected path: got %q", got)
	}
	if got := cfg["portal_name"]; got != "{env.AUTH_PORTAL_NAME}" {
		t.Fatalf("unexpected portal_name: got %q", got)
	}
}

func TestParseAuthzPluginCaddyfilePreservesPlaceholders(t *testing.T) {
	t.Setenv("AUTHZ_POLICY_NAME", "mypolicy")

	cfg, err := parseAuthzPluginCaddyfile(httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser("authorize /app/* with {env.AUTHZ_POLICY_NAME}"),
	})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	if got := cfg["path"]; got != "/app/*" {
		t.Fatalf("unexpected path: got %q", got)
	}
	if got := cfg["gatekeeper_name"]; got != "{env.AUTHZ_POLICY_NAME}" {
		t.Fatalf("unexpected gatekeeper_name: got %q", got)
	}
}

func TestAuthenticateDirectiveProvisionResolvesPlaceholders(t *testing.T) {
	t.Setenv("AUTH_PORTAL_NAME", "myportal")

	err := validateCaddyfile(t, `
		{
			admin off
			security {
				local identity store localdb {
					realm local
					path /tmp/localdb.json
				}

				authentication portal {env.AUTH_PORTAL_NAME} {
					enable identity store localdb
				}
			}
		}

		http://localhost {
			route {
				authenticate /auth/* with {env.AUTH_PORTAL_NAME}
				respond "ok"
			}
		}
	`)
	if err != nil {
		t.Fatalf("expected authenticate directive to provision successfully, got: %v", err)
	}
}

func TestAuthorizeDirectiveProvisionResolvesPlaceholders(t *testing.T) {
	t.Setenv("AUTHZ_POLICY_NAME", "mypolicy")

	err := validateCaddyfile(t, `
		{
			admin off
			security {
				authorization policy {env.AUTHZ_POLICY_NAME} {
					crypto key verify 0e2fdcf8-6868-41a7-884b-7308795fc286
					set auth url /auth
					allow roles authp/admin authp/user
				}
			}
		}

		http://localhost {
			route {
				authorize /app/* with {env.AUTHZ_POLICY_NAME}
				respond "ok"
			}
		}
	`)
	if err != nil {
		t.Fatalf("expected authorize directive to provision successfully, got: %v", err)
	}
}

func validateCaddyfile(t *testing.T, input string) error {
	t.Helper()

	adapter := caddyfileadapter.Adapter{ServerType: httpcaddyfile.ServerType{}}
	out, _, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		return err
	}

	var cfg caddy.Config
	if err := json.Unmarshal(out, &cfg); err != nil {
		return err
	}

	return caddy.Validate(&cfg)
}
