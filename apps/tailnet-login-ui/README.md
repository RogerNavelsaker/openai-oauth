# Tailnet OAuth login UI

A small Bun service that lets an authorized user start, monitor, and cancel OpenAI device-code login, or complete browser OAuth by pasting the localhost callback URL. It talks to the OAuth service over server-side HTTP; the browser never receives the control bearer token or OAuth tokens. The OAuth service remains the only process that exchanges and stores credentials.

Users explicitly choose between device-code sign-in and browser OAuth; enabling the UI never starts authentication automatically. Browser OAuth completes by pasting the localhost callback URL, which the service validates and exchanges server-side.

## Build and run

From the repository root:

```sh
bun install --frozen-lockfile
bun run --cwd apps/tailnet-login-ui build
```

Configure the sidecar and UI with the same random control secret (at least 32 bytes):

```sh
export OPENAI_OAUTH_CONTROL_TOKEN="$(openssl rand -hex 32)"
# Sidecar defaults: OPENAI_OAUTH_CONTROL_HOST=127.0.0.1, OPENAI_OAUTH_CONTROL_PORT=10532

export SIDECAR_CONTROL_TOKEN="$OPENAI_OAUTH_CONTROL_TOKEN"
export SIDECAR_CONTROL_URL="http://127.0.0.1:10532"
export LOGIN_UI_PUBLIC_ORIGIN="https://oauth-login.example.ts.net"
# UI defaults: LOGIN_UI_HOST=127.0.0.1, LOGIN_UI_PORT=10533
# UI/database mode also requires these deployment-provisioned values:
# OPENAI_OAUTH_DATABASE_PATH=/absolute/path/to/auth.db
# OPENAI_OAUTH_DATABASE_KEY=<64 hexadecimal characters>
# AUTH_SESSION_SECRET=<at least 32 bytes>
# On first initialization only: AUTH_BOOTSTRAP_USERNAME and AUTH_BOOTSTRAP_PASSWORD
bun run --cwd apps/tailnet-login-ui start
```

`LOGIN_UI_PUBLIC_ORIGIN` must exactly match the browser-visible origin. The UI rejects mutations with a different `Origin` and requires a same-site CSRF token. The UI host defaults to loopback; do not change that unless the network path is restricted to the trusted reverse proxy.

## Same-image OCI deployment

The OpenAI OAuth OCI image includes this UI. Set `OPENAI_OAUTH_LOGIN_UI=1` to have the image entrypoint supervise the sidecar and Bun UI in the same container; leaving it unset preserves the existing CLI-only auth-file workflow. UI mode requires `OPENAI_OAUTH_CONTROL_TOKEN` (at least 32 bytes), `LOGIN_UI_PUBLIC_ORIGIN`, an absolute `OPENAI_OAUTH_DATABASE_PATH`, a 64-hex-character `OPENAI_OAUTH_DATABASE_KEY`, and an `AUTH_SESSION_SECRET` of at least 32 bytes. Supply the database key and session secret from deployment secrets; never bake them into the image or regenerate them on restart. On first database initialization, also provide `AUTH_BOOTSTRAP_USERNAME` and `AUTH_BOOTSTRAP_PASSWORD` from deployment secrets; the first administrator must change both before accessing the dashboard. When present, existing `auth.json` OAuth credentials are imported idempotently into the encrypted database and the source file is not modified. The UI fails closed when required encryption or session configuration is absent. The control listener remains loopback-only (`127.0.0.1:10532` by default), the UI defaults to `127.0.0.1:10533`, and the inference API remains on `10531`.
Database mode currently depends on pre-1.0 `@tursodatabase/database` with experimental encryption and multiprocess-WAL support. The tested support envelope is 64-bit Unix on a local filesystem; Windows, 32-bit, WASM, and network filesystems are not supported. This candidate still needs explicit operational-risk approval and is not an approved production database design.


Provision the database key, Better Auth session secret, control token, and first-run bootstrap credentials through a deployment secret manager such as SOPS or systemd credentials; never put them in the image, repository, or checked-in environment file. Back up the encrypted database together with a separately protected copy of its encryption key. Losing the key makes the database unrecoverable; changing the configured key alone will prevent startup. Key rotation requires an explicit verified re-encryption/migration procedure and is not an in-place environment-variable change.

For an isolated smoke test, use a new empty test volume and disposable database, encryption-key, session, bootstrap, and control-token secrets; bind the inference and UI listeners to `127.0.0.1` and access the UI through an SSH port-forward. Administrator sign-in is always required in UI mode. Do not reuse production credentials or volumes, expose these ports publicly, or initiate OAuth automatically; the user must explicitly choose a sign-in method.


When UI/database mode is active, the authenticated dashboard can create labeled API bearer keys, list their non-secret metadata, and revoke each key individually. The full key is revealed only in the creation response; copy it immediately because it cannot be retrieved later. Only a SHA-256 verifier and a display prefix are stored. Keys do not expire automatically and have no per-key quota or rate limit; revoke a key promptly if it may have been exposed, and keep the inference listener on a trusted network. Send the key as `Authorization: Bearer <key>` to every `/v1/*` endpoint (including `/v1/models`); `/health` remains unauthenticated. Configure compatible clients to use the inference base URL (default `http://127.0.0.1:10531/v1`) and the created key. CLI-only mode without the encrypted database preserves its existing no-API-key behavior.

For any reverse-proxy or shared-network deployment, set the UI listener to an address reachable only by the trusted proxy, restrict the network path, and require identity-based user authorization at the proxy. The internal control bearer token is not human authentication.

## Caddy and network requirements

**Do not expose this UI on a public or unrestricted listener.** Configure the existing Caddy site so it is reachable only over the tailnet, and protect the route with a Tailscale identity ACL, Caddy `basic_auth`, or equivalent user authorization. Tailnet membership by itself may be broader than the set of people authorized to replace credentials. For example, add the following to an already tailnet-restricted HTTPS listener after replacing the placeholders:

```caddyfile
oauth-login.example.ts.net {
    basic_auth {
        <authorized-user> <bcrypt-password-hash>
    }
    reverse_proxy 127.0.0.1:10533
}
```

Generate the hash with `caddy hash-password`. Keep the Bun listener private; the application does not implement a separate human username/password system and relies on the authenticated Caddy route for user authorization.

The sidecar control listener is separate from inference, disabled unless `OPENAI_OAUTH_CONTROL_TOKEN` is configured, defaults to `127.0.0.1:10532`, and authenticates every request with the bearer token. In same-image OCI mode, the entrypoint passes that token to the UI and connects over loopback. When the UI runs separately, use a dedicated private network path, set the sidecar control host and `SIDECAR_CONTROL_URL` for that path, and never publish the control port. The bearer token is defense in depth, not a substitute for network isolation or human authorization.

The control token has no automatic expiry. Rotate it by generating a new random value, updating both service environments, and restarting both services; after restart, the sidecar rejects the old value.
There is no per-client rate limit; never expose the control listener outside trusted loopback or private service networks.

The package includes optional UI and OCI entrypoint support but does not configure Caddy or the host deployment. Confirm actual listener, firewall, container-network, and identity-ACL behavior before any shared or proxied deployment.

## Behavior and safety

- A login starts only when the user explicitly chooses device-code or browser sign-in; enabling the UI never authenticates automatically.
- The one-time code is kept in memory by the sidecar and displayed only while that login is awaiting approval. Cancellation aborts the sidecar's existing device-code flow.
- In UI/database mode, OAuth credentials, admin state, and API-key verifiers live in the encrypted database; an existing auth.json is imported idempotently and never rewritten. CLI-only mode retains the auth-file workflow.
- Status responses and pages are non-cacheable; the UI uses local HTMX and Hyperscript assets and generated UnoCSS, with a restrictive content-security policy.
- OAuth and control-token secrets stay server-side. A newly created API key is shown only once in the authenticated creation response; list responses contain metadata and never the key.
- Errors are mapped to fixed, sanitized messages. OAuth tokens, device-auth IDs, control tokens, and raw upstream response bodies are not exposed; a newly minted API key is the only secret shown in its one-time creation response.
- OpenAI may disable device-code login for a client/account. In that case the UI reports that the flow is unavailable; it does not silently fall back to browser OAuth.

Never test with production credentials or mount production auth data into a test container. No OAuth request is made by tests or automated image smoke checks. The local-only loopback smoke mode may omit human password authentication only while access is limited to loopback/SSH forwarding; any shared or proxied access requires identity-based authorization.
