# Trusted request metadata at the Caddy boundary

Read this reference when deploying behind a reverse proxy or changing source
address, origin, issuer, or path trust. Source/test paths are repository-relative.

## Edge Trust

The `authenticate` and `authorize` plugins normalize forwarded metadata before
AuthCrunch reads it. Configure Caddy's server-level `trusted_proxies` with the
actual proxy networks and use `trusted_proxies_strict` for append-style proxy
chains. `client_ip_headers` determines which address header Caddy resolves.
Do not trust arbitrary clients merely to make an authentication fixture pass.

For trusted peers, both plugins use Caddy's resolved `client_ip` as the single
`X-Forwarded-For` value. Direct peers use the original `RemoteAddr`, preserving
Go's bracketed IPv6 representation. They remove raw `X-Real-IP`, `Forwarded`, `X-Forwarded-Port` and
`X-Forwarded-Prefix`: these must not override Caddy's address decision or change
the configured mount. An explicitly configured `X-Real-IP` address source can
still contribute through Caddy's `client_ip_headers` resolution.

The selected go-authcrunch forwarded-address parser still has an upstream IPv6
limit: an uncompressed address such as `2001:db8:1:2:3:4:5:6` becomes `2001`,
and a short address such as `::1` falls back to the peer. Caddy's trust decision
does not repair that library parser. The suite qualifies forwarded IPv4 and
`2001:db8::1`; do not claim complete forwarded IPv6 support pending an upstream
fix. Direct IPv6 peer addresses do not traverse that parser.

For untrusted connections, forwarded host/protocol are stripped. For trusted
connections, the last field value of `X-Forwarded-Host` and `X-Forwarded-Proto`
is retained, matching Caddy's reverse-proxy field selection; comma lists are
not silently split into a chosen origin. The library still validates the
configured issuer/public origin, Origin/Fetch Metadata, path, and secure
transport. No Origin header, TLS state, or rewritten issuer mount is invented.
The trusted proxy must normalize client-supplied metadata before forwarding.

Use exact portal mount plus mount-slash matchers, such as `/auth /auth/*`.
A broad `/auth*` also selects look-alike paths such as `/authentic`. Never add
an authorization bypass for all OP or refresh-looking paths. Keep the
protected catch-all after the portal route and retain separate signing keys
for portal access and OP ID tokens.

`TestSecurityRequestMetadata` verifies the library's view of normalized data;
`TestAuthzSourceTrust` verifies source-address denials with cached identities,
missing resolved addresses, trusted peers and untrusted spoofing. Source-address
mismatch returns an authentication error without a handled response; Caddy's
authentication chain supplies 401, and the protected upstream stays unreachable.
`TestCaddyCompositionE2E` exercises Caddy's actual trust calculation, direct
TLS, cleartext rejection, a verified TLS proxy, duplicate values and encoded
paths, including source-bound authorization after proxy trust is removed.
See the [qualification map](../../testing-and-ci/references/composition-qualification.md)
for browser, reload and transaction limits.
