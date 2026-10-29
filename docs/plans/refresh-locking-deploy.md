# Refresh locking upgrade and deployment plan

## Goal
Ship the existing verbose refresh diagnostics plus cross-process auth-file locking and re-read-before-refresh behavior to `agent-alex`, then make a separate upstream dependency-upgrade change after that deployment.

## Non-goals
- Do not change OAuth grant/refresh payloads, device-code login flow, model behavior, or the existing 55-minute/5-minute refresh policy.
- Do not inspect, print, or copy credentials.
- Do not publish npm packages, move immutable OCI tags, or make inference/model-completion calls.
- Do not combine dependency upgrades with the lock/diagnostics deployment.

## Context
- Active worktree: `/home/rona/workspace/RogerNavelsaker/openai-oauth-verbose-refresh-diagnostics`, branch `fix/verbose-refresh-diagnostics`, based on `ba9ff86`.
- Existing uncommitted diagnostics changes in README, core runtime, local auth-file, and tests are intentional and must be preserved.
- Current local coalescing map only coordinates callers in one Node process. The refresh path re-reads once before refresh but does not hold an inter-process lock; it can reuse stale credentials if another process refreshed with an unchanged refresh token.
- Pi's installed `@mariozechner/pi-coding-agent@0.73.1` uses `proper-lockfile`, re-reads auth while holding the lock, and refreshes only if the latest credentials are still expired.
- User authorized deploy and requested upstream dependency upgrades only after the lock/diagnostics deployment. Keep those upgrades in a separate follow-up branch.
- Remote baseline: `openai-oauth.service` and `openai-oauth-keepalive.timer` are active; the current service uses digest `sha256:b44f7830df83e50ac5968a9e7c9caf1fa101731dfa31462e0b81463b3ded67c3`, named volume `bifrost-openai-oauth-data:/data`, network alias `openai-oauth`, all capabilities dropped, read-only root, and 10 MB k8s-file logs.
- The earlier `invalid_grant` cause is unknown; cross-process locking cannot repair an invalid or revoked refresh token.

## Blast radius
- `packages/local/src/auth-file.ts`: hold a lock on the auth file across latest-state read, refresh, and credential write; also serialize login token writes with that same lock.
- `packages/local/test/auth-file.test.ts`: cover lock contention and a prior process writing fresh access credentials while retaining the same refresh token.
- `packages/local/package.json`, `bun.lock`, and `flake.nix`: add the small locking dependency and update the Nix fixed-output hash if required.
- `README.md`: document the finalized diagnostics only if behavior needs an update.
- OCI workflow and remote user service: publish main's mutable `latest` only, pin the fetched digest on the existing service, preserve /data volume/network/hardening/10 MB log limit.
- Follow-up: after deployment, upgrade the directly relevant upstream SDK packages in a separate branch; do not mix with this release.

## Steps
1. Add a failing regression test that holds the auth-file lock, updates auth.json to a fresh access token while retaining the same refresh token, then releases the lock; expect the waiting loader to return the latest token without calling the provider.
2. Add `proper-lockfile` to `@openai-oauth/local` and the type package as needed. Implement an auth-file lock helper that creates a missing file safely, uses stale-lock/heartbeat handling, and always releases. Use it for login writes and refresh.
3. Inside the refresh lock, re-read auth.json and recompute whether refresh is still due. If another process has already installed a fresh token, return that state without refreshing again; otherwise refresh using the newest refresh token and persist before releasing. Keep current in-process promise coalescing and preserve refresh diagnostics.
4. Run focused auth tests, then full build/tests/typecheck/lint/audit. Build CLI/image, update Nix fixed-output hash from a fresh derivation result if necessary, and rerun the image build.
5. Commit, push a PR, wait for required CI and main-branch image publication; use the main workflow's `latest` digest only.
6. Deploy that digest to `agent-alex`: back up the active unit, pause the already-active keepalive timer only for the service restart, pull the immutable digest with the existing devenv Podman, and change only the image reference. Preserve /data, network, hardening, and log cap. Verify service/health, run the existing model-list keepalive one-shot (not inference), then resume the timer. If device login is requested, complete it without exposing the one-time code.
7. Only after deployment, start a separate dependency-upgrade branch for the relevant upstream SDK packages and verify it independently. Report the candidate version changes before making any unrelated/tooling upgrades.

## Tests
- Lock-contention regression proves the latest on-disk token wins even when refresh_token is unchanged, and no redundant token request is made.
- A waiting refresh uses the latest refresh token and preserves concurrent non-token auth-file fields when persisting.
- Existing same-process coalescing, successful refresh persistence, and secret-safe diagnostics tests remain green.

## Verification
- Focused: `bun --cwd packages/local test --run test/auth-file.test.ts`
- Full: `bun run build`, `bun run test`, `bun run typecheck`, `bun run format-and-lint`, `bun audit`, `git diff --check`
- Package: `nix build .#openai-oauth-cli .#openai-oauth-image`
- Release/deploy: PR CI and successful main OCI workflow; verify fetched image digest matches service, `/health` succeeds, service remains active, volume/network/hardening/log cap are preserved.

## Rollback
If CI or deployment fails, leave main and the current deployed image untouched. Do not mutate or remove /data. If a deployed image fails health checks, restore the backed-up user service unit/image digest and verify the previous service state.

## Open questions
- None for the lock behavior. Dependency upgrade scope is limited to the direct upstream SDK packages previously identified; do not include unrelated toolchain packages without asking.

### For Executor
Read order: this plan; current auth-file and tests; `packages/local/package.json`; `flake.nix`; current container workflow; active remote service unit before deployment.
Assumed working state: preserve four existing uncommitted diagnostics files; do not touch the other worktrees.
Owned files: the listed auth-file/package/lock/flake/readme/test files; only the service unit's image reference remotely after backing up the unit.
Verification commands: those in the Verification section above.
