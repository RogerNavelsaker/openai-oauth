# Next release plan: 2.1.1

## Goal
Prepare the dependency-upgrade branch as the next patch release candidate, with a reproducible OCI image versioned `2.1.1`.

## Release decision
- Version: `2.1.1` (patch; `v2.1.0` already exists and must not be moved).
- Destination: `ghcr.io/rogernavelsaker/openai-oauth`; a push to `main` updates `latest`, while a separately authorized `v2.1.1` git tag publishes the immutable `v2.1.1` image.
- No npm publication. Do not deploy to `agent-alex` or perform OAuth login, credential access, or inference as part of this preparation.
- Release is not authorized by this plan. Merge/tag/publish/deploy remain separate actions requiring explicit user authorization.

## Context and evidence
- Dependency-upgrade PR #17 (`chore/all-dependency-bumps`) changes the Vercel AI SDK/provider major versions and related workspace dependencies. Its CI checks were green at the PR head before syncing.
- At preparation time PR #17 was open and conflicted with current `main`, which had advanced through atomic auth-file persistence and OCI hash refresh (`ae985d9`). The only predicted merge conflict was `flake.nix`'s fixed-output Bun dependency hash.
- The GHCR workflow builds the image on pushes to `main` and tags matching `v*.*.*`; its version source comes from `packages/openai-oauth/package.json`, and the Nix image tag comes from `flake.nix`.
- Workspace packages currently share version `2.1.0`; the existing immutable `v2.1.0` release must remain unchanged.

## Scope
- Merge current `origin/main` into the dependency-upgrade branch without rewriting shared history; resolve the OCI dependency hash from the combined workspace source.
- Bump the seven workspace package manifests under `packages/` and the Nix image version from `2.1.0` to `2.1.1`.
- Keep app versions and unrelated files unchanged.
- Recompute `bunDeps.outputHash` after all source/version edits; use the actual Nix mismatch hash, never copy a hash from the pre-merge tree.
- Commit and push the candidate branch for PR review only. Do not merge, tag, publish, or deploy.

## Verification
Run from the repository root after the final hash is set:
1. `bun run test`
2. `bun run typecheck`
3. `bun run build`
4. `bun run format-and-lint`
5. `bun audit`
6. `nix flake check --no-build`
7. `nix build .#openai-oauth-cli .#openai-oauth-image`
8. Smoke-test the built CLI with `--help` and inspect the image's user, entrypoint, `/data` volume, and `v2.1.1` tag.
9. `git diff --check`, inspect the complete diff, and confirm PR CI is green after push.

No live OAuth or authenticated inference checks are part of this release-preparation gate.

## Rollback
If the merged dependency changes or versioned build is invalid, revert only the release-preparation commit(s) on the task branch. Do not alter `v2.1.0`, the production image reference, credentials, or deployment state.

### For Executor
Read order: this plan; `docs/plans/oci-image.md`; `.github/workflows/container.yml`; `flake.nix`; package manifests under `packages/`.
Assumed working state: `chore/all-dependency-bumps`, synced with `origin/main` by a normal merge; the existing `v2.1.0` tag remains untouched.
Owned files: the seven `packages/*/package.json` manifests, `flake.nix`, this plan, and only the regenerated Bun dependency hash if required.
Verification commands: the numbered verification commands above.
