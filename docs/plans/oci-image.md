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
Local Bun dependency derivation, CLI, and OCI image build successfully. Podman loads the image; CLI help works and image metadata shows UID/GID 10001 and `/data`. OCI workflow is drafted with explicit version-tag mapping and main-only `latest` publishing. Changes are uncommitted on `feat/oci-image-ownership`. No commit, push, registry publish, or live auth verification has occurred.
