# System API encryption keys

Read this reference when a policy forwards Basic/API-key authentication to a
remote portal. These keys encrypt assertions and are separate from JWT keys.

## System API Keys

`system` keys are not JWT signing keys. They encrypt and decrypt PASETO
`v4.local` System API messages used by remote Basic/API-key authentication.
They require a non-empty key ID and a 32-byte key encoded as 64 hex characters.

Configure the same `system` key ID and value on the remote policy and the
receiving portal:

```caddyfile
authentication portal myportal {
	crypto key sys1 system {env.SYSTEM_API_SECRET}
	enable identity store localdb
}

authorization policy api_policy {
	crypto key jwt1 verify {env.JWT_SHARED_KEY}
	crypto key sys1 system {env.SYSTEM_API_SECRET}
	allow roles authp/user
	with api key auth portal https://auth.example.com/auth realm local
	with basic auth portal https://auth.example.com/auth realm local
}
```

For file-backed System API keys, use a Caddy replacer that resolves to the file
content, such as `crypto key sys1 system {file./etc/caddy/security_system.key}`.
Do not use `crypto key sys1 system from file ...`; KMS file loading is for PEM
JWT keys, not raw System API hex keys.

Portals with System API keys cannot use `match any` transforms in v1.3.3:
upstream assertion claims omit the timestamp used by that matcher. Use explicit
realm matchers; see the [compatibility restriction](../../configuration-authentication-user-transforms/SKILL.md#unconditional-matcher-restriction-in-v133).

The portal chooses the `system` key from the encrypted message footer `kid`.
The authorize-side remote authenticator currently picks the first configured
`system` key in key-store order for remote calls, so keep rotation plans simple
and test them explicitly.
