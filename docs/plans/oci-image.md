# OCI image build and ownership

## Goal
Build the fork's OCI image from its Bun workspace and publish it from this repository, retaining the existing `bifrost-openai-oauth` GHCR package while consumers migrate.

## Decisions
- Use the repository's pinned Bun version and `bun.lock`.
- Fetch dependencies with Bun in a Nix fixed-output derivation; Nix checks the dependency tree hash.
- Run as UID/GID 10001, retain `/data` as the credentials volume, and keep host-port publication outside the image.
- Keep package version `v2.0.0` until the fork declares a release version. Main publishes `v2.0.0` and `latest`; a version tag publishes that tag and preserves `v2.0.0` for compatibility.
- Use CLI `--help` smoke test. HTTP health probing requires auth-backed server startup; authenticated runtime verification remains a separate authorized step.

## Verification
- `nix flake check --no-build`
- `nix build .#openai-oauth-cli --no-link`
- `nix build .#openai-oauth-image --no-link --print-out-paths`
- Load image with Podman; inspect user, entrypoint, volume; run CLI help.
- Run `bun run test`, `bun run typecheck`, `bun run format-and-lint`, and `git diff --check`.

## Current state
Local Bun dependency derivation, CLI, and OCI image build successfully. Podman loads the image; CLI help works and image metadata shows UID/GID 10001 and `/data`. OCI workflow publishes versioned tags after a Podman CLI-help smoke test. Commit `3b1286b` adds the Bun/Nix image, `42eea2e` adds explicit immutable version-tag publishing, and `0e16c39` fixes workflow output references. Branch `feat/oci-image-ownership` is pushed. Workflow run `40745933549` passed and published public `ghcr.io/rogernavelsaker/openai-oauth:v2.0.0` (digest `sha256:d58dc9370f98f8f827ad514d38d9ecdfae15539ba638fde97c4658ea6d6cd219`). Existing `ghcr.io/rogernavelsaker/bifrost-openai-oauth:v2.0.0` remains present and unchanged. The separate `nixpkg-bifrost` worktree and prior maintenance plan remain untouched. No authenticated HTTP or live OAuth test ran.
