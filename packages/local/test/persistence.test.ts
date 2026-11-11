import { promises as fs } from "node:fs"
import os from "node:os"
import path from "node:path"
import { pathToFileURL } from "node:url"
import { eq } from "drizzle-orm"
import { afterEach, describe, expect, it } from "vitest"
import { openPersistentStore } from "../src/persistence.js"
import { apiKeys, user } from "../src/persistence-schema.js"

const KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const WRONG_KEY =
	"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
const tempDirs: string[] = []

const createPaths = async () => {
	const directory = await fs.mkdtemp(
		path.join(os.tmpdir(), "oauth-persistence-"),
	)
	tempDirs.push(directory)
	const databasePath = path.join(directory, "auth.db")
	return {
		authFilePath: path.join(directory, "auth.json"),
		databasePath,
		databaseUrl: pathToFileURL(databasePath).href,
	}
}

afterEach(async () => {
	await Promise.all(
		tempDirs
			.splice(0)
			.map((directory) => fs.rm(directory, { recursive: true, force: true })),
	)
})

describe("encrypted persistence store", () => {
	it("requires a file URL and a 32-byte hexadecimal encryption key", async () => {
		await expect(
			openPersistentStore({
				databaseUrl: "libsql://example.invalid",
				encryptionKey: KEY,
			}),
		).rejects.toThrow("AUTH_DATABASE_URL must use the file: protocol")
		await expect(
			openPersistentStore({
				databaseUrl: "file:///tmp/auth.db",
				encryptionKey: "short",
			}),
		).rejects.toThrow(
			"AUTH_DATABASE_KEY must be exactly 64 hexadecimal characters",
		)
		await expect(
			openPersistentStore({
				databaseUrl: "file:///tmp/auth.db",
				encryptionKey: undefined as never,
			}),
		).rejects.toThrow("AUTH_DATABASE_KEY is required")
	})

	it("rejects a symlink database file without changing its target", async () => {
		const { databasePath, databaseUrl } = await createPaths()
		const targetPath = path.join(path.dirname(databasePath), "target.db")
		await fs.writeFile(targetPath, "not-a-database", { mode: 0o644 })
		await fs.symlink(targetPath, databasePath)

		await expect(
			openPersistentStore({ databaseUrl, encryptionKey: KEY }),
		).rejects.toThrow("AUTH_DATABASE_URL must identify a regular database file")
		expect((await fs.stat(targetPath)).mode & 0o777).toBe(0o644)
		expect(await fs.readFile(targetPath, "utf8")).toBe("not-a-database")
	})

	it("migrates schema, persists OAuth credentials encrypted, and reopens", async () => {
		const { databasePath, databaseUrl } = await createPaths()
		await fs.chmod(path.dirname(databasePath), 0o755)
		const store = await openPersistentStore({ databaseUrl, encryptionKey: KEY })
		expect((await fs.stat(databasePath)).mode & 0o777).toBe(0o600)
		expect((await fs.stat(path.dirname(databasePath))).mode & 0o777).toBe(0o700)
		try {
			store.saveOAuthCredentials({
				accessToken: "synthetic-access-token",
				refreshToken: "synthetic-refresh-token",
				idToken: "synthetic-id-token",
				accountId: "synthetic-account",
				lastRefresh: "2026-11-11T00:00:00.000Z",
			})
			expect(store.getOAuthCredentials()).toEqual({
				accessToken: "synthetic-access-token",
				refreshToken: "synthetic-refresh-token",
				idToken: "synthetic-id-token",
				accountId: "synthetic-account",
				isFedRamp: false,
				lastRefresh: "2026-11-11T00:00:00.000Z",
				refreshGeneration: 1,
			})

			const createdUsers = await store.drizzle
				.insert(user)
				.values({
					id: "admin-1",
					name: "Admin",
					email: "admin@example.invalid",
				})
				.returning()
			expect(createdUsers[0]?.email).toBe("admin@example.invalid")

			const selectedUsers = await store.drizzle
				.select({ email: user.email })
				.from(user)
			expect(selectedUsers).toEqual([{ email: "admin@example.invalid" }])
			const selectedUser = await store.drizzle
				.select({ email: user.email })
				.from(user)
				.where(eq(user.id, "admin-1"))
				.get()
			expect(selectedUser).toEqual({ email: "admin@example.invalid" })

			expect(() =>
				store.database
					.prepare(
						"INSERT INTO session (id, expires_at, token, user_id) VALUES (?, ?, ?, ?)",
					)
					.run("session-1", Date.now(), "session-token", "missing-user"),
			).toThrow()
			await store.drizzle.transaction(async (transaction) => {
				await transaction.insert(apiKeys).values({
					id: "key-1",
					label: "test client",
					prefix: "sk-test-",
					verifier: "sha256:synthetic-verifier",
				})
			})
			const savedKey = await store.drizzle
				.select({ label: apiKeys.label, verifier: apiKeys.verifier })
				.from(apiKeys)
				.where(eq(apiKeys.id, "key-1"))
				.get()
			expect(savedKey).toEqual({
				label: "test client",
				verifier: "sha256:synthetic-verifier",
			})

			const tables = store.database
				.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
				.all()
			expect(tables).toEqual(
				expect.arrayContaining([
					expect.objectContaining({ name: "user" }),
					expect.objectContaining({ name: "session" }),
					expect.objectContaining({ name: "account" }),
					expect.objectContaining({ name: "verification" }),
					expect.objectContaining({ name: "oauth_credentials" }),
					expect.objectContaining({ name: "api_keys" }),
					expect.objectContaining({ name: "bootstrap_state" }),
				]),
			)
		} finally {
			store.close()
		}

		const bytes = await fs.readFile(databasePath)
		expect(bytes.includes(Buffer.from("synthetic-access-token"))).toBe(false)
		expect(bytes.includes(Buffer.from("synthetic-refresh-token"))).toBe(false)

		const reopened = await openPersistentStore({
			databaseUrl,
			encryptionKey: KEY,
		})
		try {
			expect(reopened.getOAuthCredentials()?.accountId).toBe(
				"synthetic-account",
			)
		} finally {
			reopened.close()
		}
		await expect(
			openPersistentStore({ databaseUrl, encryptionKey: WRONG_KEY }),
		).rejects.toThrow()
	})

	it("upgrades a version-1 database by adding refresh generations", async () => {
		const { databaseUrl } = await createPaths()
		const legacyStore = await openPersistentStore({
			databaseUrl,
			encryptionKey: KEY,
		})
		legacyStore.saveOAuthCredentials({
			accessToken: "legacy-access-token",
			accountId: "legacy-account",
			refreshToken: "legacy-refresh-token",
		})
		legacyStore.database.exec(
			"ALTER TABLE oauth_credentials DROP COLUMN refresh_generation",
		)
		legacyStore.database.exec(
			"DELETE FROM auth_schema_migrations WHERE version = 2",
		)
		legacyStore.close()

		const store = await openPersistentStore({ databaseUrl, encryptionKey: KEY })
		try {
			expect(store.getOAuthCredentials()).toMatchObject({
				accessToken: "legacy-access-token",
				accountId: "legacy-account",
				refreshGeneration: 0,
			})
		} finally {
			store.close()
		}
	})

	it("allows concurrent connections to open and migrate the same encrypted database", async () => {
		const { databaseUrl } = await createPaths()
		const stores = await Promise.all(
			Array.from({ length: 4 }, () =>
				openPersistentStore({ databaseUrl, encryptionKey: KEY }),
			),
		)
		try {
			stores[0]?.saveOAuthCredentials({
				accessToken: "parallel-access-token",
				accountId: "parallel-account",
			})
			expect(stores[3]?.getOAuthCredentials()?.accountId).toBe(
				"parallel-account",
			)
		} finally {
			for (const store of stores) store.close()
		}
	})

	it("imports synthetic auth.json tokens idempotently without modifying the source", async () => {
		const { authFilePath, databaseUrl } = await createPaths()
		const original = JSON.stringify(
			{
				preserved_setting: "keep-me",
				tokens: {
					access_token: "synthetic-file-access",
					refresh_token: "synthetic-file-refresh",
					id_token: "synthetic-file-id",
					account_id: "synthetic-file-account",
				},
				last_refresh: "2026-11-10T23:00:00.000Z",
			},
			null,
			2,
		)
		await fs.writeFile(authFilePath, original, { mode: 0o600 })
		const store = await openPersistentStore({ databaseUrl, encryptionKey: KEY })
		try {
			expect(await store.importAuthFile({ authFilePath })).toEqual({
				imported: true,
			})
			expect(await store.importAuthFile({ authFilePath })).toEqual({
				imported: false,
			})
			expect(store.getOAuthCredentials()).toEqual({
				accessToken: "synthetic-file-access",
				refreshToken: "synthetic-file-refresh",
				idToken: "synthetic-file-id",
				accountId: "synthetic-file-account",
				isFedRamp: false,
				lastRefresh: "2026-11-10T23:00:00.000Z",
				refreshGeneration: 0,
			})
		} finally {
			store.close()
		}
		expect(await fs.readFile(authFilePath, "utf8")).toBe(original)
	})

	it("does not import when no OAuth credentials exist", async () => {
		const { authFilePath, databaseUrl } = await createPaths()
		await fs.writeFile(
			authFilePath,
			JSON.stringify({ OPENAI_API_KEY: "unrelated" }),
		)
		const store = await openPersistentStore({ databaseUrl, encryptionKey: KEY })
		try {
			expect(await store.importAuthFile({ authFilePath })).toEqual({
				imported: false,
			})
			expect(store.getOAuthCredentials()).toBeUndefined()
		} finally {
			store.close()
		}
	})
	it("stores only API-key verifiers and revokes keys individually", async () => {
		const { databasePath, databaseUrl } = await createPaths()
		const store = await openPersistentStore({ databaseUrl, encryptionKey: KEY })
		const token = `sk-oai-oauth-${"x".repeat(43)}`
		try {
			const created = store.createApiKey({
				id: "key-1",
				label: "Bifrost",
				prefix: token.slice(0, 16),
				token,
				createdAt: new Date("2026-11-11T00:00:00.000Z"),
			})
			expect(created).toMatchObject({
				id: "key-1",
				label: "Bifrost",
				prefix: token.slice(0, 16),
			})
			expect(store.verifyApiKey(token)).toBe(true)
			expect(store.verifyApiKey("invalid-key")).toBe(false)
			const row = store.database
				.prepare("SELECT verifier FROM api_keys WHERE id = ?")
				.get("key-1") as { verifier: string }
			expect(row.verifier).not.toBe(token)
			expect(store.listApiKeys()).toEqual([created])
			expect(store.revokeApiKey("key-1")).toBe(true)
			expect(store.revokeApiKey("key-1")).toBe(false)
			expect(store.verifyApiKey(token)).toBe(false)
			expect(store.listApiKeys()[0]?.revokedAt).toBeDefined()
		} finally {
			store.close()
		}
		const bytes = await fs.readFile(databasePath)
		expect(bytes.includes(Buffer.from(token))).toBe(false)
	})
})
