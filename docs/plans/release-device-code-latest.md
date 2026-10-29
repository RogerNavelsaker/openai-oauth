# OCI latest deployment plan: device-code login

## Goal
Publish the merged device-code startup change through the repository's main-branch OCI workflow and deploy the resulting image to `agent-alex`.

## Release decision
- Channel: mutable `ghcr.io/rogernavelsaker/openai-oauth:latest` only.
- Version bump: none. The repository workflow intentionally builds `latest` from main and reserves immutable `vX.Y.Z` tags for separate releases. Do not move the existing `v2.1.0` tag.
- npm: not published; this fork does not own npm publication.
- Changelog/release-note draft: “Added headless device-code login to the OCI image. Startup waits for missing credentials and retries once after a rejected startup token refresh. Transient failures do not initiate login. The one-time code appears in service logs; users must protect log access.”
- Build/publish gate: local Nix CLI/image builds and smoke checks, PR CI green, then verify the main push's OCI workflow and fetched `latest` digest.

## Commit list since v2.1.0
Use `git log --oneline --no-merges v2.1.0..origin/main` immediately before merge, then add the device-code feature commit. Current main contains the audit, Linux-x64 CI, and reproducible OCI updates; the new feature commit will be added by the PR.

## Deployment
1. Confirm the merged main workflow published `latest`; record its digest.
2. In `/home/alex/.config/agent-proxies` on `agent-alex`, pull the image inside `devenv shell`.
3. Back up the current user service unit, preserve its data volume, network alias, and hardening, update only the image reference to the new digest, and start the service.
4. If device login is requested, use `browser-cli` at the printed verification URL; do not expose or persist the one-time code outside this session.
5. Verify successful login, service health, and Bifrost connectivity before restarting the keepalive timer.

## Rollback
Stop the sidecar, restore the saved user unit and its prior image digest, and leave the auth volume untouched. If the merged code needs correction, revert it on main and let the workflow rebuild `latest`.

## For executor
Read order: this plan, `docs/plans/device-code-login-startup.md`, the container workflow, and the active remote user-service unit.
Assumed working state: local feature worktree on `feat/device-code-login-startup`; remote sidecar is stopped and the keepalive timer is inactive.
Owned files: feature code/tests/docs and the OCI workflow; on the remote host, only the sidecar unit's image reference after a backup.
Verification: `bun run test`, `bun run typecheck`, `bun run build`, `bun run format-and-lint`, `bun audit`, `nix build .#openai-oauth-cli .#openai-oauth-image`, plus CI and post-deploy health checks.
