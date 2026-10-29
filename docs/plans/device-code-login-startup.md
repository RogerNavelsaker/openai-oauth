# Device-code login and container startup wait

## Goal
Make the OCI image start normally when stored credentials work, but initiate headless OpenAI device-code login and wait before serving when credentials are missing or a startup refresh is rejected.

## Non-goals
- Do not change the default browser/loopback flow for ordinary CLI users.
- Do not expose the OAuth callback port or start the API before credentials are usable.
- Do not initiate a new login for transient network errors or upstream 5xx failures.
- Do not publish npm packages; this fork cannot publish them and the user has authorized only OCI publication.
- User follow-up authorizes committing and pushing the branch, merging via GitHub PR after CI, publishing the main-branch `latest` OCI image, then pulling and deploying it to `agent-alex`.
- Do not inspect or expose credential contents. Let the existing atomic auth-file writer persist a credential only after successful OAuth completion.

## Context and evidence
- Current `cli-app.ts` exits in non-interactive mode when no auth file exists; an existing file proceeds to worker startup.
- `startOpenAIOAuthServer` resolves models before binding/listening, so a rejected startup refresh propagates to the CLI parent.
- Current `login.ts` supports only authorization-code PKCE via a loopback callback at `localhost:1455`.
- OpenAI Codex CLI currently implements device login in [device_code_auth.rs](https://github.com/openai/codex/blob/main/codex-rs/login/src/device_code_auth.rs): request user code from `/api/accounts/deviceauth/usercode`, poll `/api/accounts/deviceauth/token`, then exchange the returned authorization code at `/oauth/token` using `/deviceauth/callback`. Its login command treats HTTP 404 on the initial user-code request as device login being disabled, not as a pending poll. The Codex source currently uses the same public OAuth client ID as this fork.
- The existing `saveAuthTokens` path is the only credential write path; it writes after successful token exchange.
- Work is isolated in `/home/rona/workspace/RogerNavelsaker/openai-oauth-device-code`, branch `feat/device-code-login-startup`, based on `origin/main`. Preserve the separate `chore/linux-x64-ci-target` worktree and its untracked `docs/plans/roger-navelsaker-fork-maintenance.md`.

## Blast radius
- `packages/openai-oauth/src/login.ts`: implement device-code request/poll/exchange, cancellation, timeout, and safe user-facing instructions.
- `packages/openai-oauth/src/cli-app.ts`: add an explicit device-auth option; use it for missing credentials and retry exactly once after a classified OAuth refresh rejection during worker startup.
- `packages/openai-oauth/test/**`: mocked protocol, timeout/disabled-endpoint behavior, CLI option and startup retry regression coverage.
- `flake.nix`: make the OCI image pass the device-auth startup option by default.
- `README.md` and `packages/openai-oauth/README.md`: document headless image behavior, device-code availability/failure, and that the server starts only after login.
- `.github/workflows/container.yml`: assert that the built OCI image retains `--device-auth` in its default command.
- Publish the mutable `latest` tag produced by the main-branch workflow; do not move immutable version tags or bump package versions as part of this deployment.

## Steps
1. Add failing mocked tests for the device authorization request, pending poll, code exchange, auth persistence, timeout/cancellation, and unsupported-endpoint response. Run the focused test first.
2. Implement `runOpenAIOAuthDeviceCodeLogin` in `login.ts`, using the existing token exchange and auth-file save functions. Do not log token responses or device-auth identifiers.
3. Add the `--device-auth` CLI mode. For a missing file, wait on the device flow. For an existing file, only retry after startup failure clearly identifies a refresh-token HTTP 401; retry server startup once after successful login. Leave ordinary network/server failures untouched.
4. Set the OCI image's default command to include `--device-auth`, assert it in the OCI smoke test, and update docs with log-based instructions and the 404/unsupported limitation.
5. Run focused tests, full tests, typecheck, lint/format, build, Nix CLI/image builds, and a local image help/metadata smoke test. Inspect the full diff.
6. After local verification, commit and push the feature branch, open and merge a PR only after required CI passes, then verify the main-branch workflow publishes `latest`.
7. Pull that image on `agent-alex` via the existing `devenv` environment, preserve the service's volume/network/hardening, pin the deployed image by digest, and start the service. Use `browser-cli` to complete device-code login if the service requests it; verify health before restarting the keepalive timer.

## Verification
- `bun test packages/openai-oauth/test/login.test.ts packages/openai-oauth/test/cli.test.ts`
- `bun run test`
- `bun run typecheck`
- `bun run format-and-lint`
- `bun run build`
- `nix build .#openai-oauth-cli .#openai-oauth-image`
- Run the built CLI's `--help`; inspect the OCI archive to verify its default command includes `--device-auth`.
- After deployment, use browser-cli only for the user's authorized OpenAI login; never print or persist auth-file contents.

## Rollback
Before merge, close the PR or revert the feature commit. After merge, revert it on main and allow the main workflow to publish a corrected `latest`. On `agent-alex`, preserve the existing auth volume and service backup; if the new service fails, stop it and restore the pre-change unit/image pin. Do not replace or overwrite `auth.json` manually.

## Open questions
- The device authorization endpoint is feature-gated (official Codex treats initial HTTP 404 as unsupported). The image reports a clear actionable error in that case; if observed, use the user's authorized browser login via an isolated temporary auth file rather than silently falling back inside the headless sidecar.

### For Executor
Read order: this plan, `login.ts`, `cli-app.ts`, their tests, `flake.nix`, both READMEs.
Assumed working state: clean feature worktree based on `origin/main`; keep the other worktree's files untouched.
Owned files: `packages/openai-oauth/src/login.ts`, focused tests, `packages/openai-oauth/src/cli-app.ts`, `flake.nix`, `.github/workflows/container.yml`, root/package READMEs.
Verification commands: those listed above; no push/deploy.
