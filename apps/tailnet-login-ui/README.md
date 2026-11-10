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

## Same-image OCI deployment

The OpenAI OAuth OCI image includes this UI. Set `OPENAI_OAUTH_LOGIN_UI=1` to have the image entrypoint supervise the sidecar and Bun UI in the same container; leaving it unset preserves the existing CLI-only image behavior. The opt-in mode requires `OPENAI_OAUTH_CONTROL_TOKEN` (at least 32 bytes) and `LOGIN_UI_PUBLIC_ORIGIN`. It passes the control token to the UI internally and keeps the control listener on loopback (`127.0.0.1:10532` by default); the UI defaults to `127.0.0.1:10533` and the inference API remains on `10531`.

For a one-host smoke test only, run the container with host networking, bind the inference and UI listeners to `127.0.0.1`, use a new empty auth volume, and access the UI through an SSH port-forward. Human password authentication may be omitted only while the UI is reachable exclusively through loopback/that tunnel. Do not reuse a production auth volume or expose these ports on a public or tailnet interface. Do not start sign-in automatically; the user must click **Start device-code sign-in**.

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

- A login starts only after the user presses **Start device-code sign-in**.
- The one-time code is kept in memory by the sidecar and displayed only while that login is awaiting approval. Cancellation aborts the sidecar's existing device-code flow.
- The sidecar writes credentials through its existing locked, atomic auth-file writer. The UI never mounts or reads the auth file.
- Status responses and pages are non-cacheable; the UI uses local HTMX and Hyperscript assets and generated UnoCSS, with a restrictive content-security policy.
- Errors are mapped to fixed, sanitized messages. Device-auth IDs, token values, and raw upstream response bodies are not included in control responses or rendered HTML.
- OpenAI may disable device-code login for a client/account. In that case the UI reports that the flow is unavailable; it does not silently fall back to browser OAuth.

Never test with production credentials or mount production auth data into a test container. No OAuth request is made by tests or automated image smoke checks. The local-only loopback smoke mode may omit human password authentication only while access is limited to loopback/SSH forwarding; any shared or proxied access requires identity-based authorization.
