# Tailnet login UI in the OAuth OCI image — parallel test

## Goal
Build the optional Tailnet login UI into the existing OpenAI OAuth OCI image and run that same image as an isolated, loopback-only test instance alongside the current `agent-alex` sidecar.

## Non-goals and safety boundaries
- Do not replace, restart, reconfigure, or attach the test instance to the current production sidecar or Bifrost provider.
- Do not mount or reuse the production auth volume; create a new empty test volume.
- Do not expose the UI or API on a public/tailnet interface, add Caddy configuration, or add human password authentication for this local-only test. Access is through SSH port forwarding to host loopback.
- Keep the sidecar-to-UI control bearer token enabled; it is distinct from human UI authentication.
- Do not start OAuth login or make an OpenAI request during deployment/smoke checks. The UI must require an explicit user action; the user may initiate the test login from the loopback-only UI.
- Do not publish a release tag or overwrite `latest`/a version tag in GHCR. Transfer a uniquely named local OCI image archive to the host.

## Context checked
- Worktree: `/workspace/RogerNavelsaker/openai-oauth-tailnet-ui`, branch `feat/tailnet-oauth-login-ui`, clean at `999d7b2`.
- `flake.nix` already packages the CLI into `openai-oauth-image`; the current image entrypoint directly execs the CLI and the default command uses `--device-auth` on port 10531.
- The new UI is in `apps/tailnet-login-ui`; its Bun server reads its generated `dist/styles.css` and local HTMX/Hyperscript assets. It proxies to the authenticated control API using `SIDECAR_CONTROL_TOKEN`.
- The CLI already starts an opt-in control listener from `OPENAI_OAUTH_CONTROL_TOKEN`; defaults are loopback and port 10532. The UI defaults to loopback and port 10533.
- On `agent-alex`, `openai-oauth.service` is active, the current container is named `openai-oauth`, and the dedicated test ports 11531–11533 and test container/volume names were not yet created. The existing service and its credential volume must remain untouched.
- Use the existing Podman binary on the host: `/home/alex/.config/agent-proxies/.devenv/profile/bin/podman`.

## Scope / blast radius
- `flake.nix`: include UI sources and built assets in the CLI/image output; add an opt-in container entrypoint mode that supervises the sidecar and UI in one container while preserving the current CLI-only default.
- `scripts/` and tests: implement and exercise the minimal opt-in supervisor, validating required configuration and keeping the control API loopback-only when the bundled UI is enabled.
- `apps/tailnet-login-ui` and docs: ensure the existing app assets can be built and served from the image; document opt-in environment variables, ports, and loopback-only test access.
- `agent-alex`: load a uniquely tagged OCI archive, create a dedicated empty volume and a separate container using host networking with all three listeners bound to 127.0.0.1 on ports 11531–11533. Do not change the existing service, its units, its volume, Bifrost, or GHCR tags.

## Steps
1. **Add a tested opt-in image supervisor.** Create `scripts/oci-entrypoint.sh` to preserve direct CLI execution by default. When `OPENAI_OAUTH_LOGIN_UI=1`, require the sidecar control token and UI public origin, require the control listener host to be loopback, pass the same control token/URL to the UI, start the CLI and UI as supervised children, and terminate the peer when either exits. Add a small script-level smoke/test for default argument forwarding and invalid UI configuration. Verify the script test fails before implementation and passes afterward.
2. **Package UI and supervisor into the existing image.** Update `flake.nix` to copy the UI source and generated CSS into the runtime output, build the CSS, install the supervisor and Bash runtime, and use the supervisor entrypoint while preserving the image's CLI-only default. Extend the OCI-image smoke gate to cover CLI-only `--help`, an opt-in `--network=none` container with a disposable control token, the no-credentials status page, and bundled CSS. Do not start login. Run `nix flake check` and inspect the image configuration.
3. **Document the mode.** Update the deployment/security documentation with `OPENAI_OAUTH_LOGIN_UI`, control-token sharing, control/UI ports, the default loopback binding, and the distinction between the internal control token and human authorization. State that a user behind an actual proxy still needs an identity-authenticated access policy.
4. **Run local gates and inspect scope.** Run focused tests, UI build/typecheck, root typecheck/tests/lint, `nix flake check`, and `git diff --check`; review the full diff and preserve unrelated work.
5. **Build and transfer a non-release OCI image.** Build the existing `openai-oauth-image` output locally, load it in Podman, retag it with a unique test-only name, save as OCI archive, and transfer/load it on `agent-alex` over SSH. Do not push to GHCR or use `latest`/a semantic-version tag.
6. **Start the parallel isolated test instance.** Recheck host service/container state and port availability. Generate a new random control token in a mode-0600 test-only environment file; create only the unique empty test auth volume; start the image with `--network=host`, loopback bindings (`--host 127.0.0.1 --port 11531`, control 11532, UI 11533), and that test volume. Do not use production auth data.
7. **Smoke test without login.** Verify container health/process state and fetch the UI/status page via host loopback. Confirm the status reports no credentials and the existing `openai-oauth.service` remains active with no restart. Do not press Start or send OAuth requests. Provide the user the SSH tunnel command and URL so they can initiate the disposable login themselves if desired.
8. **Commit and push the task branch.** Stage only this task's files, commit to `feat/tailnet-oauth-login-ui`, and push normally. Do not modify `nixpkg-bifrost`.

## Verification commands
- `bun run --cwd packages/openai-oauth test -- test/oci-entrypoint.test.ts`.
- `bun run --cwd apps/tailnet-login-ui typecheck`, `bun run --cwd apps/tailnet-login-ui test`, `bun run --cwd apps/tailnet-login-ui build`.
- `bun run typecheck`, `bun run test`, `bun run format-and-lint`.
- `nix flake check /workspace/RogerNavelsaker/openai-oauth-tailnet-ui` and `nix build /workspace/RogerNavelsaker/openai-oauth-tailnet-ui#openai-oauth-image`.
- OCI image runtime smoke checks for both default CLI behavior and opt-in bundled UI behavior; on the host, `curl http://127.0.0.1:11533/` and `curl http://127.0.0.1:11533/_status`.
- `git diff --check`; compare `systemctl --user is-active openai-oauth.service` before and after deployment.

## Rollback
Stop and remove only `openai-oauth-tailnet-ui-test`; delete only its dedicated test volume and test-only environment file if cleanup is requested. The production `openai-oauth` container, service, and volume remain untouched. Revert the task-owned commit to remove optional UI packaging; the default CLI behavior remains unchanged.

## For Executor
Read order: this plan; `flake.nix`; `apps/tailnet-login-ui/src/server.ts`; `packages/openai-oauth/src/cli-app.ts`; `packages/openai-oauth/src/cli-worker.ts`; current OCI workflow and docs.

Assumed working state: clean worktree on `feat/tailnet-oauth-login-ui` at `999d7b2`; current `agent-alex` OAuth service is active and must not be modified.

Owned files: `flake.nix`, `scripts/oci-entrypoint.sh`, its tests, UI/deployment docs, and this plan; on `agent-alex`, unique test-only environment file/container/volume only.

Verification commands: see the list above. Never run an OAuth login automatically or use production credentials.
