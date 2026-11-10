# Tailnet OAuth Login UI — implementation plan

## Goal
Add an opt-in, sidecar-owned device-code login control API and a Bun/HTMX/Hyperscript/UnoCSS web UI so an authorized user can start, monitor, and cancel login without using a CLI or exposing OAuth tokens to the browser.

## Status
Implementation and local verification are complete; the feature remains opt-in and has not been deployed. `bun run test`, `bun run typecheck`, `bun run build`, `bun run format-and-lint`, and `nix flake check` passed. The formatter/linter reports four pre-existing CSS specificity warnings in `apps/demo/app/styles.css`. No live OAuth request or production change was performed.

## Non-goals
- Do not implement browser-redirect OAuth until the OpenAI redirect/callback compatibility has been verified; v1 uses the existing device-code flow only.
- Do not change the production Caddy configuration, Bifrost deployment, or production credentials in this change.
- Do not let the web app read, mount, or write the sidecar auth file; the sidecar remains the only credential owner.
- Do not return, log, or persist access tokens, refresh tokens, device-auth IDs, or raw upstream errors in the control API/UI.
- Do not start a login automatically from a page load; require an explicit user action.

## Context checked
- Working in a clean worktree at `/workspace/RogerNavelsaker/openai-oauth-tailnet-ui`, branch `feat/tailnet-oauth-login-ui`, based on `origin/main`; the existing worktree and its untracked maintenance plan remain untouched.
- `packages/openai-oauth/src/login.ts` already implements `runOpenAIOAuthDeviceCodeLogin`, accepts an `AbortSignal`, saves through `saveAuthTokens`, and only exposes the device URL/code through a free-form `onMessage` callback.
- `packages/openai-oauth/src/server.ts` currently exposes inference/health routes on one listener and eagerly resolves models during startup. `packages/openai-oauth/src/cli-app.ts` performs an interactive login before starting the service when no auth file exists.
- `packages/local/src/auth-file.ts` provides locked/atomic token persistence. `loadAuthTokens({ ensureFresh: false })` can detect configured credentials without refreshing them; any status result must discard the returned token data.
- Root uses Bun workspaces, Vitest, Biome, Turbo, and a Nix flake. Existing device-flow tests are in `packages/openai-oauth/test/login.test.ts`; server tests are in `packages/openai-oauth/test/server.test.ts`.
- The earlier environment inspection found no Caddy configuration in the Bifrost repository. Deployment wiring must therefore be documented, not guessed or applied here.

## Blast radius
- Login helper callback contract and tests.
- CLI/server startup behavior only when the control API is explicitly enabled; the normal CLI path must remain unchanged.
- A new separately bound control listener, its lifecycle, and its tests. It must require a long random bearer token and default to loopback; it must not share the inference listener/routes.
- A new `apps/tailnet-login-ui` Bun workspace app that proxies only to a configured control API URL and keeps its control token server-side. UI network access should default to loopback so Caddy is the only intended entry point.
- Root Bun lock/workspace metadata, app build/typecheck/test scripts, and deployment/security documentation.

## Steps
1. **Expose structured device-code progress.** Add a typed device-code callback to `OpenAIOAuthLoginOptions` and invoke it with only the verification URL and user code. Preserve the CLI's existing text output. Add a focused test that verifies the callback contains the user-facing code but not the private `device_auth_id`.
2. **Add the sidecar control plane.** Create an isolated control-server module with authenticated `GET /status`, `POST /login`, and `POST /login/:id/cancel` routes. Permit one active login, retain only the current job state, cancel via `AbortController`, and map failures to fixed safe messages. Require a ≥32-character control token; default host to `127.0.0.1`; do not enable the listener without an explicit token. Add tests for auth rejection, successful mocked device login, cancellation, concurrent starts, and sanitized errors. Ensure close/shutdown aborts an in-flight login and closes the control listener.
3. **Allow controlled bootstrap without credentials.** Wire optional control-server settings into `OpenAIOAuthServerOptions` and CLI environment parsing. When explicitly enabled, let the server start without a valid auth file so the UI can bootstrap; skip or defer startup model discovery only on this opt-in path. Keep the ordinary CLI's current login-before-start behavior unchanged when the control API is disabled. Add tests for disabled defaults, no-auth bootstrap, and regular CLI startup behavior.
4. **Build the Bun UI.** Add `apps/tailnet-login-ui` with Bun's HTTP server, HTMX-rendered fragments, local HTMX and Hyperscript assets, UnoCSS-generated styles, and server-side proxy calls using `SIDECAR_CONTROL_TOKEN`. The browser must never call the sidecar control port directly. Render only safe status fields, require an explicit start action, poll while a job is active, provide cancellation, and prevent caching of pages/status responses. Add tests for route behavior, HTML escaping, server-side authorization, and absence of token/device-auth-ID data in UI output.
5. **Document and verify.** Document required environment variables, loopback binding, Caddy tailnet/user-authorization requirements, control-token sharing between services, and the device-code-only scope. Do not add a guessed Caddy site config. Run the focused tests, app build/typecheck, full repository tests, formatting/lint, and the repository's Nix verification gate where available.

## Tests and verification
- Red/green focused tests first: `bun run --cwd packages/openai-oauth test -- test/login.test.ts` (or the equivalent Vitest filter used by the repository) and the new control-server test file.
- App gate: `bun run --cwd apps/tailnet-login-ui typecheck`, `bun run --cwd apps/tailnet-login-ui test`, and `bun run --cwd apps/tailnet-login-ui build`.
- Repository gates: `bun run typecheck`, `bun run test`, `bun run format-and-lint`, and `nix flake check /workspace/RogerNavelsaker/openai-oauth-tailnet-ui`.
- Inspect `git diff --check`, the complete diff, and `git status --short` before commit. Do not run live OAuth, use real credentials, contact OpenAI, or deploy without separate explicit authorization.

## Rollback
Revert only the task-owned commit. Since the control listener is opt-in and no production config is changed, existing deployments remain on their current behavior. Remove the new app/control settings from deployment if a later opt-in test fails.

## Open questions / safe assumptions
- V1 deliberately uses the existing device-code flow; hosted browser OAuth remains out of scope until callback compatibility is demonstrated.
- Human authorization is enforced by the Caddy/tailnet route configuration. The UI server binds to loopback by default, and deployment instructions must require a Caddy identity ACL or equivalent user authentication; tailnet membership alone must not be assumed to authorize credential changes.
- Production Caddy/container wiring is not included because the existing Caddy configuration and network topology are outside this repository and were not verified.

### For Executor
Read order:
1. This plan.
2. `packages/openai-oauth/src/login.ts`, `packages/openai-oauth/src/server.ts`, `packages/openai-oauth/src/types.ts`, `packages/openai-oauth/src/cli-app.ts`.
3. Their neighboring tests plus root `package.json`, `turbo.json`, `biome.json`, and `flake.nix`.

Assumed working state: clean worktree `/workspace/RogerNavelsaker/openai-oauth-tailnet-ui`, branch `feat/tailnet-oauth-login-ui`.

Owned files: login helper and tests; server/control API and types/CLI wiring and tests; new `apps/tailnet-login-ui/**`; root workspace lock/config as needed; this plan/documentation.

Verification commands: focused login/control tests, app build/typecheck/tests, `bun run typecheck`, `bun run test`, `bun run format-and-lint`, `nix flake check /workspace/RogerNavelsaker/openai-oauth-tailnet-ui`, and `git diff --check`.
