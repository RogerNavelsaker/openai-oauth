import { spawn } from "node:child_process"
import { existsSync, promises as fs, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"
import { afterEach, describe, expect, it, vi } from "vitest"
import {
	clearAuthTokens,
	forceRefreshAuthTokens,
	loadAuthTokens,
	saveAuthTokens,
} from "../src/auth-file.js"
import { openPersistentStore } from "../src/persistence.js"

const KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const NOW = new Date("2026-11-11T12:00:00.000Z")
const tempDirs: string[] = []

const createStore = async () => {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), "persistent-auth-"))
	tempDirs.push(directory)
	return openPersistentStore({
		databaseUrl: pathToFileURL(path.join(directory, "auth.db")).href,
		encryptionKey: KEY,
	})
}

afterEach(async () => {
	await Promise.all(
		tempDirs
			.splice(0)
			.map((directory) => fs.rm(directory, { recursive: true, force: true })),
	)
})

describe("persistent OAuth refresh", () => {
	it("stores, loads, and clears OAuth tokens without using auth.json", async () => {
		const store = await createStore()
		try {
			const saved = await saveAuthTokens({
				store,
				now: () => NOW,
				token: {
					accessToken: "saved-access-token",
					refreshToken: "saved-refresh-token",
					accountId: "acct-1",
					raw: {},
				},
			})
			expect(saved.path).toBe("encrypted auth database")
			expect(store.getOAuthCredentials()).toMatchObject({
				accessToken: "saved-access-token",
				refreshToken: "saved-refresh-token",
				accountId: "acct-1",
			})
			const loaded = await loadAuthTokens({
				store,
				fetch: async () => {
					throw new Error("unexpected refresh")
				},
				ensureFresh: false,
			})
			expect(loaded.accessToken).toBe("saved-access-token")
			await clearAuthTokens({ store })
			expect(store.getOAuthCredentials()).toBeUndefined()
		} finally {
			store.close()
		}
	})

	it("forces refresh for a valid access token and persists rotated tokens before success", async () => {
		const store = await createStore()
		try {
			store.saveOAuthCredentials({
				accessToken: "still-valid-access-token",
				accountId: "acct-1",
				refreshToken: "old-refresh-token",
				lastRefresh: NOW.toISOString(),
			})
			const fetch = vi.fn(async () =>
				Response.json({
					access_token: "rotated-access-token",
					refresh_token: "rotated-refresh-token",
				}),
			)

			const refreshed = await forceRefreshAuthTokens({
				store,
				fetch,
				now: () => NOW,
				clientId: "test-client",
			})
			expect(fetch).toHaveBeenCalledTimes(1)
			expect(refreshed.accessToken).toBe("rotated-access-token")
			expect(store.getOAuthCredentials()).toMatchObject({
				accessToken: "rotated-access-token",
				refreshToken: "rotated-refresh-token",
				accountId: "acct-1",
				lastRefresh: NOW.toISOString(),
			})
		} finally {
			store.close()
		}
	})

	it("coalesces simultaneous forced refresh requests", async () => {
		const store = await createStore()
		try {
			store.saveOAuthCredentials({
				accessToken: "still-valid-access-token",
				accountId: "acct-1",
				refreshToken: "old-refresh-token",
				lastRefresh: NOW.toISOString(),
			})
			let releaseFetch: () => void = () => {}
			let markFetchStarted: () => void = () => {}
			const fetchGate = new Promise<void>((resolve) => {
				releaseFetch = resolve
			})
			const fetchStarted = new Promise<void>((resolve) => {
				markFetchStarted = resolve
			})
			const fetch = vi.fn(async () => {
				markFetchStarted()
				await fetchGate
				return Response.json({
					access_token: "rotated-access-token",
					refresh_token: "rotated-refresh-token",
				})
			})

			const options = { store, fetch, now: () => NOW, clientId: "test-client" }
			const first = forceRefreshAuthTokens(options)
			await fetchStarted
			const second = forceRefreshAuthTokens(options)
			releaseFetch()
			const [firstResult, secondResult] = await Promise.all([first, second])
			expect(fetch).toHaveBeenCalledTimes(1)
			expect(firstResult.accessToken).toBe("rotated-access-token")
			expect(secondResult.accessToken).toBe("rotated-access-token")
		} finally {
			store.close()
		}
	})

	it("coalesces forced refreshes across separate Bun processes", async () => {
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "persistent-auth-processes-"),
		)
		tempDirs.push(directory)
		const databasePath = path.join(directory, "auth.db")
		const readyDirectory = path.join(directory, "ready")
		const releasePath = path.join(directory, "release")
		const refreshCallsPath = path.join(directory, "refresh-calls")
		await fs.mkdir(readyDirectory)
		const initialStore = await openPersistentStore({
			databaseUrl: pathToFileURL(databasePath).href,
			encryptionKey: KEY,
		})
		initialStore.saveOAuthCredentials({
			accessToken: "still-valid-access-token",
			accountId: "acct-1",
			refreshToken: "old-refresh-token",
			lastRefresh: NOW.toISOString(),
		})
		expect(initialStore.getOAuthCredentials()?.refreshGeneration).toBe(1)
		initialStore.close()

		const workerPath = fileURLToPath(
			new URL("./persistent-auth-worker.ts", import.meta.url),
		)
		const workerPromises = ["one", "two"].map(
			(workerId) =>
				new Promise<void>((resolve, reject) => {
					const child = spawn(
						"bun",
						[
							"run",
							workerPath,
							databasePath,
							workerId,
							readyDirectory,
							releasePath,
							refreshCallsPath,
						],
						{
							stdio: "inherit",
							env: { ...process.env, TEST_DATABASE_KEY: KEY },
						},
					)
					child.once("error", reject)
					child.once("exit", (code) =>
						code === 0
							? resolve()
							: reject(new Error(`persistent-auth worker exited with ${code}`)),
					)
				}),
		)
		const workersComplete = Promise.all(workerPromises)
		try {
			const deadline = Date.now() + 15_000
			while (
				(!existsSync(path.join(readyDirectory, "one.ready")) ||
					!existsSync(path.join(readyDirectory, "two.ready"))) &&
				Date.now() < deadline
			) {
				await new Promise((resolve) => setTimeout(resolve, 10))
			}
			expect(existsSync(path.join(readyDirectory, "one.ready"))).toBe(true)
			expect(existsSync(path.join(readyDirectory, "two.ready"))).toBe(true)
			writeFileSync(releasePath, "release")
			await workersComplete
		} finally {
			writeFileSync(releasePath, "release")
			await workersComplete.catch(() => undefined)
		}

		const verify = await openPersistentStore({
			databaseUrl: pathToFileURL(databasePath).href,
			encryptionKey: KEY,
		})
		try {
			const refreshCalls = (await fs.readFile(refreshCallsPath, "utf8"))
				.trim()
				.split("\n")
			expect(refreshCalls).toHaveLength(1)
			expect(verify.getOAuthCredentials()).toMatchObject({
				accessToken: "rotated-cross-process-access",
				refreshToken: "rotated-cross-process-refresh",
				refreshGeneration: 2,
			})
		} finally {
			verify.close()
		}
	})

	it("leaves stored credentials unchanged when upstream refresh fails", async () => {
		const store = await createStore()
		try {
			store.saveOAuthCredentials({
				accessToken: "still-valid-access-token",
				accountId: "acct-1",
				refreshToken: "old-refresh-token",
				lastRefresh: NOW.toISOString(),
			})
			const before = store.getOAuthCredentials()
			await expect(
				forceRefreshAuthTokens({
					store,
					fetch: async () => {
						throw new Error("upstream failure")
					},
					now: () => NOW,
				}),
			).rejects.toThrow("upstream failure")
			expect(store.getOAuthCredentials()).toEqual(before)
		} finally {
			store.close()
		}
	})
})
