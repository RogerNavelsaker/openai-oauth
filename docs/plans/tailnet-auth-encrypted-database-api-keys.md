# Tailnet auth, encrypted database, and API keys

## Goal

Make the optional Tailnet login UI a protected administration plane backed by one whole-file-encrypted local database, and allow authenticated OpenAI-compatible API clients to use individually revocable keys.

## Non-goals

- Do not alter or deploy the production service or use production OAuth credentials for tests.
- Do not make encrypted storage mandatory for ordinary CLI-only use; preserve the existing auth-file workflow when the UI/database mode is disabled.
- Do not expose the UI publicly or relax the existing HTTPS/CSRF/reverse-proxy boundary.
- Do not store plaintext API keys, hardcoded initial credentials, or OAuth secrets in browser JavaScript, logs, or database-adjacent files.
- Do not add remote Turso synchronization; this feature uses a local encrypted database file only.

## Context and decisions

- Current branch is `feat/oauth-ui-auth-metadata`, clean and tracking `origin/feat/oauth-ui-auth-metadata` at inspection time.
- `packages/local/src/auth-file.ts` implements auth.json persistence, advisory file locking, refresh-on-expiry, and token rotation. `packages/local/src/index.ts` exposes it through `openaiCredentials()`.
- `packages/openai-oauth/src/server.ts` creates the OAuth provider and serves `/v1/models`, `/v1/responses`, `/v1/chat/completions`, and image routes without API-key authentication. `packages/openai-oauth/src/auth-control.ts` serves the loopback UI control API and currently uses the auth-file functions for status, login, refresh, and sign-out.
- `apps/tailnet-login-ui/src/server.ts` serves the current unauthenticated login-management UI (with CSRF checks and a control-token-protected sidecar connection). `scripts/oci-entrypoint.sh` starts the UI and sidecar as separate processes. `flake.nix` packages the Bun app and OCI image.
- Existing tests include `packages/openai-oauth/test/auth-control.test.ts` and `apps/tailnet-login-ui/src/server.test.ts`; package scripts are wired through root `bun run test`, `bun run typecheck`, and `bun run format-and-lint`.
- User decisions: make every Refresh action force an upstream refresh, serialize concurrent refreshes and persist rotations before success; use Better Auth rather than deprecated Lucia; encrypt the entire database; mint labeled API bearer keys server-side, show once, store only verifiers, support revocation; bootstrap the initial username/password from deployment secrets and require both to be changed.
- Prototype finding (2026-11-11): `@libsql/client` 0.18.0 with its local encryption key worked under Bun and created a Better Auth user with the Drizzle adapter, but 4-process concurrent writes failed with `SQLITE_BUSY`. Do not use this client for the shared store. The alternative `@tursodatabase/database` 0.8.3 passed an isolated Bun 1.4.4 and Nix-packaged runtime prototype using AES-256-GCM, the experimental encryption and multiprocess-WAL features, four concurrent writer processes (80/80 writes), wrong-key rejection, and a plaintext-marker scan. Its `compat` API also worked with Drizzle's `better-sqlite3` dialect and Better Auth 1.7.20 to create an admin test user. Its sub-1.0 status and experimental features remain operational risks. A repeated open failure was traced to upstream Turso issue #10114: simultaneous flagged opens in 0.8.3 can falsely report a legacy-mode conflict. `openEncryptedDatabase` now retries only that exact error three times at 500 ms intervals; persistent mixed-mode access still fails closed. The in-repository encrypted-database suite passed 20 consecutive direct `direnv exec /workspace bun ...` runs and tests the persistent mixed-mode rejection explicitly. The shell Bun versions differ (devenv 1.4.2, outside 1.4.4); that observation alone does not explain the upstream-matched race. Preserve encrypted backups and revalidate after driver upgrades. Never fall back to plaintext SQLite.

## Blast radius

- Persistence and token refresh: `packages/local/src/auth-file.ts`, `packages/local/src/index.ts`, a new shared persistence package/module, login and control-server call sites, and related tests.
- Administration/authentication: `apps/tailnet-login-ui/src/server.ts`, `views.ts`, tests, dependencies, and schema/migration code.
- Inference authorization and API-key lifecycle: `packages/openai-oauth/src/server.ts`, control API and types, and server/control tests.
- Runtime packaging/configuration: `scripts/oci-entrypoint.sh`, CLI option/environment plumbing, `flake.nix`, Bun lockfile, image tests, and deployment documentation.
- Existing CLI behavior and its auth-file tests must continue to pass when database mode is off.

## Steps

1. **Prove the encrypted database/auth adapter stack before integrating it.** The `@libsql/client` local-encryption prototype passed user creation and wrong-key checks but failed 4-process writes with `SQLITE_BUSY`, so reject it. `@tursodatabase/database` 0.8.3 passed synthetic-data checks using whole-file AES-256-GCM, wrong-key rejection, ciphertext marker scan, and 80 writes from four processes with multiprocess WAL. Its compatibility API also worked with Better Auth's Drizzle adapter through the `better-sqlite3` dialect. Both Bun and the Nix-packaged runtime passed. Retain these as regression tests and account for the package's pre-1.0/experimental risks. Never substitute unencrypted `bun:sqlite`.
   - Tests: prototype covered create/read/reopen/wrong-key, Better Auth user creation, cross-process write contention, and ciphertext markers; add durable in-repo coverage of the guarantees.
   - Verification: `bun run <prototype>` under project Bun and Nix development runtime.
   - Tests: isolated Bun smoke test for create/reopen/wrong-key; Nix build/runtime smoke test; two-process concurrent write test.
   - Verification: `bun test <prototype-test>`; `nix build .#openai-oauth-image` (or the repository's configured flake check).

2. **Add a shared encrypted persistence layer and schema.** Add a small package/module that owns the single local database connection, validates the required encryption-key format, applies migrations, and exposes typed operations for OAuth credentials, Better Auth tables, API-key metadata/verifiers, and bootstrap state. Require a `file:` database URL and fail startup for absent/invalid keys or unreadable databases. Keep the key outside the database and outside image defaults. Add a tested import path for existing auth.json data when database mode is explicitly enabled; do not delete or rewrite an existing credential file until import success has been verified and the migration behavior is documented.
   - Tests: schema migration/reopen, key missing/invalid/wrong, atomic auth import, existing CLI auth-file behavior unchanged.
   - Verification: focused persistence tests and `bun run typecheck`.

3. **Add Better Auth admin login and one-time bootstrap.** Configure Better Auth against the encrypted database. On first initialization only, read the bootstrap username/password from deployment secrets, create the initial admin account, and mark it as requiring a change to both values. Gate all administrative routes until both changes complete. Do not recreate/reset the account if bootstrap environment values change on later starts. Preserve HttpOnly/Secure/SameSite session cookies, CSRF validation, and the current control-plane isolation.
   - Tests: bootstrap once, restart idempotency, both fields must change, admin routes reject logged-out/forced-change sessions, session cookie flags and CSRF checks.
   - Verification: focused auth/UI tests and `bun run typecheck`.

4. **Move UI-mode OAuth credentials into the encrypted store and implement forced refresh.** Keep file-backed credentials as the default for CLI-only mode. In UI/database mode, route login, status, sign-out, and inference credential reads through the shared store. Add an explicit force-refresh operation used by every UI Refresh click; it must call the provider even if the access token is not near expiry, serialize concurrent requests (including cross-process access), and commit rotated access/refresh tokens before returning success. A failed provider request must leave the previous stored credentials intact.
   - Tests: force refresh of a still-valid token calls provider; simultaneous requests perform one upstream refresh; rotated tokens are committed before HTTP success; error leaves persisted state unchanged; login and sign-out use the database in UI mode.
   - Verification: `bun test packages/openai-oauth/test/auth-control.test.ts` plus relevant `packages/local` tests.

5. **Implement server-side API-key lifecycle and inference authorization.** Add authenticated admin actions to create a labeled key, list key metadata, and revoke a specific key. Generate high-entropy bearer secrets server-side, return the full value once, store only a one-way verifier and a non-secret display prefix, and never include it in logs or later list responses. Require a valid key on every `/v1/*` inference route when protected UI/database mode is enabled; keep health checks separate. Recheck revocation on each request (or use a bounded cache with immediate invalidation).
   - Tests: key appears only in creation response; database contains verifier but not raw key; invalid/revoked keys are rejected on every inference route; valid key reaches existing handlers; labels and individual revocation behave correctly; health remains available.
   - Verification: focused API-key/server tests and `bun run typecheck`.

6. **Update the HTMX UI and runtime packaging/docs.** Add login/logout, mandatory bootstrap credential-change, and API-key create/list/revoke screens. Refresh copy must say that a provider refresh was forced only after successful persistence. Add required encryption/bootstrap env handling to `scripts/oci-entrypoint.sh` and `flake.nix`; UI-enabled startup fails closed when required secrets are absent. Document provisioning via SOPS/systemd credentials, key backup/rotation implications, encrypted-file location, and the protected-reverse-proxy requirement. Do not expose the UI on a public interface by default.
   - Tests: UI server tests for auth gates/forms/key-once response; entrypoint configuration tests; Nix image build and smoke test with dummy secrets and an empty test volume.
   - Verification: `bun run test`, `bun run typecheck`, `bun run format-and-lint`, `bun run build`, `nix flake check`, `nix build .#openai-oauth-image`.

7. **Review and ship task-owned changes only.** Inspect the full diff and `git status --short`, preserve unrelated work, run the full verification gate, commit the feature on the task branch, and push. Any isolated container smoke test must use a new empty test volume and dummy bootstrap secrets; do not reuse the existing OAuth test volume or trigger real provider refreshes.
   - Verification: repeat the full gate above, review the final diff, then verify commit and push status.

## Current progress

- The multiprocess-WAL regression gate was instrumented to report the test-runner process, Bun executable/version, and the loaded native Turso addon path/SHA-256. The Vitest parent is Node 26.13.0 in both environments. Host workers use Bun 1.4.4 at `/nix/store/7py3q3rn0qbcyzwqk6mdbyd8r1m9x54r-bun-1.4.4/bin/bun`; `direnv` workers use Bun 1.4.2 at `/nix/store/qkydg77xf2s395md9fq0a6djjpq7fzh4-bun-1.4.2/bin/bun`. Both load `/workspace/RogerNavelsaker/openai-oauth-tailnet-ui/node_modules/@tursodatabase/database-linux-x64-gnu/turso.linux-x64-gnu.node`, SHA-256 `927ddb19494c622734c72aff87ed2126f020d6e3c80f544b8576efafa30ed6a2`. The runtime-version difference is understood, but it has not explained the earlier intermittency: the focused four-process/80-write gate passed 20/20 runs with host Bun and 20/20 with `direnv` Bun.
- Step 2 has an initial shared persistence implementation under `packages/local/src/persistence*.ts`, exposed as `@openai-oauth/local/persistence`. It opens only encrypted `file:` URLs with 64-hex keys, enables WAL and foreign keys, applies versioned Better Auth/OAuth/API-key/bootstrap schema migrations, and provides typed OAuth credential operations plus idempotent, read-only auth.json import. It uses Drizzle's sqlite-proxy adapter to avoid requiring a separate `better-sqlite3` native addon. Focused tests cover migration/reopen/wrong-key, private directory/file modes and symlink rejection, encrypted token persistence, Drizzle reads/writes/transactions, FK enforcement, and import preservation.

- Step 4 implementation progress: `packages/openai-oauth/src/cli-worker.ts` opens an encrypted local database when `OPENAI_OAUTH_DATABASE_PATH` and `OPENAI_OAUTH_DATABASE_KEY` are configured; `openaiCredentials` and the control server use the same store for inference, status, device/browser-login writes, sign-out, and manual Refresh. Manual Refresh forces the provider call and persists rotated tokens under a `proper-lockfile` lock, using `refresh_generation` to coalesce requests that waited on another refresh; a provider failure leaves stored credentials unchanged. Migration v2 adds the generation column without rewriting v1. Synthetic tests cover DB login, sign-out, fresh-token forced refresh, concurrent control requests, failure preservation, and v1→v2 upgrade. A separate-Bun-process regression test releases two concurrent forced refreshers against one encrypted DB and confirms one provider request with rotated credentials persisted; cross-process concurrency is covered on the tested local filesystem. UI database/admin-auth initialization now opens the shared encrypted store, imports auth.json idempotently under its lock, and provisions Better Auth from deployment credentials; the OCI entrypoint fails closed when database or session secrets are absent.
- `nix build .#openai-oauth-image --no-link` passed after refreshing the `bunDeps` fixed-output hash. The full repository gate is still to be rerun after the latest diagnostic-only edits.


- Step 5 implementation is now present: the encrypted store creates and lists API-key metadata, stores only a SHA-256 verifier and display prefix, and timestamps individual revocations. The control API generates 256-bit `sk-oai-oauth-` bearer keys and reveals each only in its 201 creation response; the Tailnet dashboard provides labeled create/list/revoke actions behind completed Better Auth bootstrap and CSRF/origin checks. The HTTP server requires a currently active bearer key on every `/v1/*` route when a persistent store is configured, while `/health` stays public and CLI-only/no-database behavior remains unchanged. Tests cover one-time key display, verifier-only storage, revocation, all inference routes, valid access to `/v1/models`, and health availability.
- Step 6 API-key UI and deployment documentation are implemented. The final local gate passed: `bun run test` (37 local-package tests, 89 openai-oauth tests plus 1 skipped, 14 UI tests, and the remaining workspace suites), root `typecheck`, `build`, and `format-and-lint` (four pre-existing CSS specificity warnings), `nix flake check`, and `nix build .#openai-oauth-image --no-link`. `bun audit --json` returned `{}`; `bun outdated` reported only the pre-existing TypeScript 6→7 update. A separate-process forced-refresh test now verifies one provider request. `podman` and `docker` are unavailable, so the OCI container smoke test was not run locally. No live OAuth/inference request or deployment occurred. The work remains an experimental prototype pending final diff review and explicit review of Turso's experimental encryption/WAL risks; it is not production-ready or deployed.

## Rollback

Disable UI/database mode and return to the existing CLI auth-file workflow. Keep the encrypted database untouched for recovery; never delete it automatically during rollback. If a schema or migration has written bad data, restore from a verified encrypted backup using the matching external key. Do not roll back by copying decrypted OAuth tokens into a plaintext file.

## Open questions / executor constraints

- Use the proven `@tursodatabase/database` embedded driver with its `compat` API and Drizzle's `better-sqlite3` dialect only while the prototype regressions pass. The tested libSQL client path is unsuitable due to concurrent-write `SQLITE_BUSY`. Document that Turso encryption and multiprocess WAL are experimental and the package is pre-1.0; do not silently switch to plaintext or a different encryption scope.
- The selected configuration names are `OPENAI_OAUTH_DATABASE_PATH`, `OPENAI_OAUTH_DATABASE_KEY`, `AUTH_SESSION_SECRET`, `AUTH_BOOTSTRAP_USERNAME`, and `AUTH_BOOTSTRAP_PASSWORD`; encryption/session/bootstrap secrets must come from deployment provisioning, never image defaults.
- Do not import, refresh, migrate, or inspect production/test OAuth credentials. Use synthetic tokens in tests.
- Maintain compatibility for users who run without the optional UI/database mode.

### For Executor

Read order:
1. This plan.
2. `packages/local/src/auth-file.ts`, `packages/local/src/index.ts`.
3. `packages/openai-oauth/src/server.ts`, `src/auth-control.ts`, `src/types.ts`, and their tests.
4. `apps/tailnet-login-ui/src/server.ts`, `src/views.ts`, and `src/server.test.ts`.
5. `scripts/oci-entrypoint.sh`, `flake.nix`, package manifests, and deployment docs.

Assumed working state: `/workspace/RogerNavelsaker/openai-oauth-tailnet-ui`, branch `feat/oauth-ui-auth-metadata`; clean at `df36b40c` at planning time. Recheck status before edits.

Owned files: new shared persistence module/package; auth-control and inference authorization; tailnet UI routes/views/tests; env/entrypoint and Nix packaging; lockfile and relevant docs. Preserve unrelated files and existing CLI-only auth-file behavior.

Verification commands: focused tests added at each step; final `bun run test`, `bun run typecheck`, `bun run format-and-lint`, `bun run build`, `nix flake check`, and `nix build .#openai-oauth-image` (adjust only if repository scripts or available Nix outputs differ, and report the exact commands/results).