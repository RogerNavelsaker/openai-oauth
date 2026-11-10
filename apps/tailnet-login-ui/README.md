# Tailnet OAuth login UI

A small Bun service that lets an authorized user start, monitor, and cancel the sidecar's existing OpenAI device-code login. It talks to the sidecar control listener over server-side HTTP; the browser never receives the control bearer token or OAuth tokens. The sidecar remains the only process that exchanges and stores credentials.

This first version supports **device-code sign-in only**. Browser-redirect OAuth is intentionally deferred until the OpenAI callback URL is verified for the actual tailnet hostname and proxy setup.

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
bun run --cwd apps/tailnet-login-ui start
```

`LOGIN_UI_PUBLIC_ORIGIN` must exactly match the browser-visible origin. The UI rejects mutations with a different `Origin` and requires a same-site CSRF token. The UI host defaults to loopback; do not change that unless the network path is restricted to the trusted reverse proxy.

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

The sidecar control listener is a different service and port from the OpenAI-compatible inference API. It is disabled unless `OPENAI_OAUTH_CONTROL_TOKEN` is configured, defaults to `127.0.0.1:10532`, and authenticates every request with the bearer token. If the UI and sidecar run in separate containers, arrange a dedicated private path between them, set `OPENAI_OAUTH_CONTROL_HOST` to an address reachable only on that path, set `SIDECAR_CONTROL_URL` to that address, and do not publish the control port. Do not attach the UI to a general-purpose Bifrost network unless its access policy prevents other workloads from reaching the UI. The bearer token is defense in depth, not a substitute for network isolation or Caddy user authorization.

The control token has no automatic expiry. Rotate it by generating a new random value, updating both service environments, and restarting both services; after restart, the sidecar rejects the old value.
There is no per-client rate limit; never expose the control listener outside trusted loopback or private service networks.

No Caddy or container deployment configuration is changed by this package. Confirm the actual listener, firewall, container-network, and identity-ACL behavior before deployment.

## Behavior and safety

- A login starts only after the user presses **Start device-code sign-in**.
- The one-time code is kept in memory by the sidecar and displayed only while that login is awaiting approval. Cancellation aborts the sidecar's existing device-code flow.
- The sidecar writes credentials through its existing locked, atomic auth-file writer. The UI never mounts or reads the auth file.
- Status responses and pages are non-cacheable; the UI uses local HTMX and Hyperscript assets and generated UnoCSS, with a restrictive content-security policy.
- Errors are mapped to fixed, sanitized messages. Device-auth IDs, token values, and raw upstream response bodies are not included in control responses or rendered HTML.
- OpenAI may disable device-code login for a client/account. In that case the UI reports that the flow is unavailable; it does not silently fall back to browser OAuth.

Do not test this against production credentials or deploy the control listener until the private network and Caddy authorization are in place. No live OAuth request is made by the test suite.
