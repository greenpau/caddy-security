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
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/greenpau/go-authcrunch"
	"golang.org/x/net/idna"
)

// validateOIDCProviderMounts keeps independently configured portals from owning
// overlapping provider routes/cookie paths on the same browser host. Cookies do
// not distinguish ports, so different listener ports do not isolate providers.
// AuthCrunch owns provider grammar and validation. The host additionally checks
// usable, canonical origins and isolation across its complete set of portals.
func validateOIDCProviderMounts(cfg *authcrunch.Config) error {
	type mount struct {
		portal, host, path string
	}
	var mounts []mount
	for _, portal := range cfg.AuthenticationPortals {
		if portal == nil || portal.OIDCProvider == nil || !portal.OIDCProvider.Enabled {
			continue
		}
		provider := portal.OIDCProvider
		if err := provider.Validate(); err != nil {
			return fmt.Errorf("portal %q oidc provider: %w", portal.Name, err)
		}
		issuer, err := url.Parse(provider.Issuer)
		if err != nil {
			return fmt.Errorf("portal %q has an invalid oidc issuer", portal.Name)
		}
		// net/url accepts empty and out-of-range explicit ports. Neither can
		// identify the canonical HTTPS endpoint advertised by this provider.
		if port := issuer.Port(); port != "" {
			value, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return fmt.Errorf("portal %q oidc issuer port is outside 0-65535", portal.Name)
			}
			if value == 443 || port != strconv.FormatUint(value, 10) {
				return fmt.Errorf("portal %q oidc issuer requires a canonical HTTPS origin: omit port 443 and leading zeroes", portal.Name)
			}
		} else if strings.HasSuffix(issuer.Host, ":") {
			return fmt.Errorf("portal %q oidc issuer port is empty", portal.Name)
		}
		host, err := oidcIssuerCookieHost(issuer.Hostname())
		if err != nil {
			return fmt.Errorf("portal %q oidc issuer hostname: %w", portal.Name, err)
		}
		canonicalHost := host
		if _, err := netip.ParseAddr(host); err != nil && strings.HasSuffix(issuer.Hostname(), ".") {
			// DNS trailing dots survive browser URL serialization, but do not
			// isolate cookie scopes. A trailing dot on IPv4 does not survive.
			canonicalHost += "."
		}
		// Browsers serialize IDNs as ASCII and IP literals in canonical form.
		// AuthCrunch compares origins exactly; accepting other spellings would
		// publish a provider that rejects its own discovery and login requests.
		if issuer.Hostname() != canonicalHost {
			return fmt.Errorf("portal %q oidc issuer requires a canonical ASCII hostname or IP address", portal.Name)
		}
		for _, previous := range mounts {
			if host != previous.host {
				continue
			}
			if issuer.Path == previous.path || strings.HasPrefix(issuer.Path, previous.path+"/") || strings.HasPrefix(previous.path, issuer.Path+"/") {
				return fmt.Errorf("oidc providers for portals %q and %q require distinct non-overlapping issuer mounts on the same host", previous.portal, portal.Name)
			}
		}
		mounts = append(mounts, mount{portal.Name, host, issuer.Path})
	}
	return nil
}

// Compare cookie hosts independently of issuer spelling. Keep the issuer itself
// unchanged: protocol clients compare it exactly. Host-only cookies ignore DNS
// trailing dots and use ASCII domain names; browsers also normalize IP literals.
func oidcIssuerCookieHost(host string) (string, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return oidcIPHost(addr), nil
	}
	// Lookup alone permits empty and overlong DNS labels. Validate the DNS
	// structure as well, including after IDNA mapping removes ignored codepoints.
	profile := idna.New(idna.MapForLookup(), idna.BidiRule(), idna.VerifyDNSLength(true))
	ascii, err := profile.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("invalid issuer hostname")
	}
	ascii = strings.TrimSuffix(ascii, ".")
	if ascii == "" || strings.HasSuffix(ascii, ".") {
		return "", fmt.Errorf("invalid issuer hostname")
	}
	if addr, err := netip.ParseAddr(ascii); err == nil {
		return oidcIPHost(addr), nil
	}
	// Browsers interpret numeric final labels as IPv4, including shortened,
	// octal, and hexadecimal forms that Go's URL/cookie handling treats as DNS.
	// Require the standard IP spelling instead of accepting different scopes in
	// different clients. This is a host-boundary check, not issuer rewriting.
	last := ascii[strings.LastIndexByte(ascii, '.')+1:]
	digits := last
	base := "0123456789"
	if strings.HasPrefix(last, "0x") {
		digits, base = last[2:], "0123456789abcdef"
	}
	if last != "" && strings.Trim(digits, base) == "" {
		return "", fmt.Errorf("noncanonical IPv4 hostname; use a dotted-decimal IP address")
	}
	return ascii, nil
}

// Browser URL serialization uses hexadecimal IPv6 words even for IPv4-mapped
// addresses; netip.String uses a dotted-decimal suffix for that one case.
func oidcIPHost(addr netip.Addr) string {
	if addr.Is4In6() {
		bytes := addr.As16()
		return fmt.Sprintf("::ffff:%x:%x", uint16(bytes[12])<<8|uint16(bytes[13]), uint16(bytes[14])<<8|uint16(bytes[15]))
	}
	return addr.String()
}
