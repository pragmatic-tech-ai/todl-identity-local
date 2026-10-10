# @pragmatic-tech-ai/todl-identity-local

The built-in **local** identity provider pack implementing the `todl-identity`
phase-4 authN contracts with vetted cryptography:

- `Argon2PasswordHasher` — argon2id password hashing via `hash-wasm`.
- `EncryptedSecretStore` — AES-256-GCM secret storage at rest (secrets by reference).
- `LocalAccountStore` — writable local accounts + principal directory.
- `LocalSessionManager` — opaque high-entropy sessions (SHA-256-keyed, TTL + revoke).
- `ServiceTokenStore` + `ServiceTokenAuthenticator` — scoped, revocable service/API tokens.
- `LocalPasswordAuthenticator` — fail-closed, timing-equalized email/password auth.
- `LocalIdentityProviderPack` + `LocalAccountRegistrar` — the bundled pack.

Depends on `@pragmatic-tech-ai/todl-identity` (contracts, consumed from its root
barrel) and `hash-wasm`. Passwords use argon2id; high-entropy tokens use SHA-256
lookup; secrets, tokens, and the master key never appear in logs, errors, audit,
or config — only references into the encrypted store.
