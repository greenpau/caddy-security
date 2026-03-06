package security

import (
	"testing"

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
