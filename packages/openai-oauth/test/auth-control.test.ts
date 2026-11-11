import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { pathToFileURL } from "node:url"
import { openPersistentStore } from "@openai-oauth/local/persistence"
import { afterEach, describe, expect, test, vi } from "vitest"
import { startOpenAIOAuthControlServer } from "../src/auth-control.js"

const CONTROL_TOKEN = "control-token-for-tests-0123456789abcdef"
const jwt = (claims: Record<string, unknown>): string =>
	`e30.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.sig`
const response = (body: unknown, status = 200): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	})
const authorized = {
	Authorization: `Bearer ${CONTROL_TOKEN}`,
}

const waitForState = async (
	url: string,
	state: string,
): Promise<Record<string, unknown>> => {
	for (let attempt = 0; attempt < 100; attempt += 1) {
		const response = await fetch(`${url}/status`, { headers: authorized })
		const status = (await response.json()) as {
			login: { state: string }
		}
		if (status.login.state === state) return status as Record<string, unknown>
		await new Promise((resolve) => setTimeout(resolve, 5))
	}
	throw new Error(`Timed out waiting for login state ${state}`)
}

describe("OpenAI OAuth control server", () => {
	const servers: Array<{ close: () => Promise<void> }> = []
	const tempDirs: string[] = []
	const stores: Array<{ close: () => void }> = []

	afterEach(async () => {
		await Promise.all(servers.splice(0).map((server) => server.close()))
		for (const store of stores.splice(0)) store.close()
		await Promise.all(
			tempDirs
				.splice(0)
				.map((root) => rm(root, { recursive: true, force: true })),
		)
		vi.restoreAllMocks()
	})

	test("requires the control bearer token", async () => {
		const server = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
		})
		servers.push(server)

		const response = await fetch(`${server.url}/status`)
		expect(response.status).toBe(401)
		expect(response.headers.get("cache-control")).toContain("no-store")
	})

	test("requires sign-out before beginning another sign-in", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "oauth-replacement-login-"))
		tempDirs.push(root)
		const authFilePath = path.join(root, "auth.json")
		await writeFile(
			authFilePath,
			JSON.stringify({
				tokens: {
					access_token: jwt({ exp: Math.floor(Date.now() / 1000) + 3600 }),
					refresh_token: "refresh-token",
					account_id: "acct-existing",
				},
			}),
		)
		const fetchMock = vi.fn<typeof fetch>()
		const server = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
			authFilePath,
			fetch: fetchMock,
		})
		servers.push(server)
		const login = await fetch(`${server.url}/login`, {
			method: "POST",
			headers: authorized,
		})
		expect(login.status).toBe(409)
		expect(fetchMock).not.toHaveBeenCalled()
	})

	test("refreshes an access token that is close to expiry", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "oauth-refresh-action-"))
		tempDirs.push(root)
		const authFilePath = path.join(root, "auth.json")
		const expiringAccessToken = jwt({ exp: Math.floor(Date.now() / 1000) + 30 })
		await writeFile(
			authFilePath,
			JSON.stringify({
				auth_mode: "chatgpt",
				last_refresh: "2020-01-01T00:00:00.000Z",
				tokens: {
					access_token: expiringAccessToken,
					refresh_token: "refresh-token",
					account_id: "acct-refresh",
				},
			}),
		)
		const refreshedAccessToken = jwt({
			exp: Math.floor(Date.now() / 1000) + 3600,
		})
		const fetchMock = vi.fn<typeof fetch>(async () =>
			response({
				access_token: refreshedAccessToken,
				refresh_token: "rotated-refresh-token",
				expires_in: 3600,
			}),
		)
		const server = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
			authFilePath,
			fetch: fetchMock,
		})
		servers.push(server)
		const refreshed = await fetch(`${server.url}/refresh`, {
			method: "POST",
			headers: authorized,
		})
		expect(refreshed.status).toBe(200)
		expect(fetchMock).toHaveBeenCalledTimes(1)
		expect(JSON.parse(await readFile(authFilePath, "utf8"))).toMatchObject({
			tokens: {
				access_token: refreshedAccessToken,
				refresh_token: "rotated-refresh-token",
			},
		})
	})

	test("forces a provider refresh and serializes concurrent requests across store handles", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "oauth-db-refresh-"))
		tempDirs.push(root)
		const databaseUrl = pathToFileURL(path.join(root, "auth.db")).href
		const encryptionKey = "b".repeat(64)
		const store = await openPersistentStore({ databaseUrl, encryptionKey })
		const secondStore = await openPersistentStore({
			databaseUrl,
			encryptionKey,
		})
		stores.push(store, secondStore)
		store.saveOAuthCredentials({
			accessToken: jwt({ exp: Math.floor(Date.now() / 1000) + 3600 }),
			accountId: "acct-db-refresh",
			refreshToken: "initial-refresh-token",
			lastRefresh: new Date().toISOString(),
		})

		let markStarted!: () => void
		const refreshStarted = new Promise<void>((resolve) => {
			markStarted = resolve
		})
		let completeRefresh!: (value: Response) => void
		const pendingResponse = new Promise<Response>((resolve) => {
			completeRefresh = resolve
		})
		const refreshedAccessToken = jwt({
			exp: Math.floor(Date.now() / 1000) + 3600,
		})
		const fetchMock = vi.fn<typeof fetch>(async () => {
			markStarted()
			return pendingResponse
		})
		const firstServer = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
			store,
			fetch: fetchMock,
		})
		const secondServer = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
			store: secondStore,
			fetch: fetchMock,
		})
		servers.push(firstServer, secondServer)

		const firstRequest = fetch(`${firstServer.url}/refresh`, {
			method: "POST",
			headers: authorized,
		})
		await refreshStarted
		const secondRequest = fetch(`${secondServer.url}/refresh`, {
			method: "POST",
			headers: authorized,
		})
		await new Promise((resolve) => setTimeout(resolve, 25))
		completeRefresh(
			response({
				access_token: refreshedAccessToken,
				refresh_token: "rotated-refresh-token",
				expires_in: 3600,
			}),
		)
		const responses = await Promise.all([firstRequest, secondRequest])
		for (const result of responses) expect(result.status).toBe(200)
		expect(fetchMock).toHaveBeenCalledTimes(1)
		expect(secondStore.getOAuthCredentials()).toMatchObject({
			accessToken: refreshedAccessToken,
			refreshToken: "rotated-refresh-token",
		})
		const signedOut = await fetch(`${firstServer.url}/sign-out`, {
			method: "POST",
			headers: authorized,
		})
		expect(signedOut.status).toBe(200)
		expect(secondStore.getOAuthCredentials()).toBeUndefined()
	})

	test("creates, lists, and revokes API keys without persisting or relisting plaintext", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "oauth-api-keys-"))
		tempDirs.push(root)
		const store = await openPersistentStore({
			databaseUrl: pathToFileURL(path.join(root, "auth.db")).href,
			encryptionKey: "d".repeat(64),
		})
		stores.push(store)
		const server = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
			store,
		})
		servers.push(server)

		const createdResponse = await fetch(`${server.url}/api-keys`, {
			method: "POST",
			headers: { ...authorized, "Content-Type": "application/json" },
			body: JSON.stringify({ label: "Bifrost" }),
		})
		expect(createdResponse.status).toBe(201)
		const created = (await createdResponse.json()) as {
			id: string
			label: string
			apiKey: string
			prefix: string
		}
		expect(created.apiKey).toMatch(/^sk-oai-oauth-[A-Za-z0-9_-]{43}$/)
		expect(created).toMatchObject({
			label: "Bifrost",
			prefix: created.apiKey.slice(0, 16),
		})
		expect(store.verifyApiKey(created.apiKey)).toBe(true)
		const verifier = store.database
			.prepare("SELECT verifier FROM api_keys WHERE id = ?")
			.get(created.id) as { verifier: string }
		expect(verifier.verifier).not.toBe(created.apiKey)

		const listResponse = await fetch(`${server.url}/api-keys`, {
			headers: authorized,
		})
		const listed = await listResponse.text()
		expect(listResponse.status).toBe(200)
		expect(listed).toContain("Bifrost")
		expect(listed).not.toContain(created.apiKey)
		expect(listed).not.toContain("verifier")

		const revokedResponse = await fetch(
			`${server.url}/api-keys/${created.id}`,
			{
				method: "DELETE",
				headers: authorized,
			},
		)
		expect(revokedResponse.status).toBe(200)
		expect(store.verifyApiKey(created.apiKey)).toBe(false)
	})

	test("signs out by clearing local OAuth credentials while preserving other auth settings", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "oauth-sign-out-"))
		tempDirs.push(root)
		const authFilePath = path.join(root, "auth.json")
		await writeFile(
			authFilePath,
			JSON.stringify({
				auth_mode: "chatgpt",
				OPENAI_API_KEY: "preserve",
				last_refresh: "2026-11-10T00:00:00.000Z",
				tokens: {
					access_token: "secret-access",
					refresh_token: "secret-refresh",
				},
			}),
		)
		const server = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
			authFilePath,
		})
		servers.push(server)
		const response = await fetch(`${server.url}/sign-out`, {
			method: "POST",
			headers: authorized,
		})
		expect(response.status).toBe(200)
		expect(JSON.parse(await readFile(authFilePath, "utf8"))).toEqual({
			OPENAI_API_KEY: "preserve",
		})
	})

	test("completes device login without returning credentials or private device IDs", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "oauth-control-"))
		tempDirs.push(root)
		const authFilePath = path.join(root, "auth.json")
		let pollCount = 0
		const idToken = jwt({
			"https://api.openai.com/auth": { chatgpt_account_id: "acct-control" },
		})
		const fetchMock = vi.fn<typeof fetch>(async (input) => {
			const url = String(input)
			if (url.endsWith("/api/accounts/deviceauth/usercode")) {
				return response({
					device_auth_id: "private-device-auth-id",
					user_code: "SAFE-CODE",
					interval: 0.001,
				})
			}
			if (url.endsWith("/api/accounts/deviceauth/token")) {
				pollCount += 1
				return response({
					authorization_code: "authorization-code",
					code_verifier: "server-issued-verifier",
				})
			}
			expect(url).toBe("https://auth.openai.com/oauth/token")
			return response({
				access_token: "secret-access-token",
				refresh_token: "secret-refresh-token",
				id_token: idToken,
				expires_in: 3600,
			})
		})
		const server = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
			authFilePath,
			fetch: fetchMock,
		})
		servers.push(server)

		const start = await fetch(`${server.url}/login`, {
			method: "POST",
			headers: authorized,
		})
		expect(start.status).toBe(202)
		const { id } = (await start.json()) as { id: string }
		const status = await waitForState(server.url, "complete")
		const serialized = JSON.stringify(status)
		expect(status).toMatchObject({
			credentialsConfigured: true,
			login: { id, state: "complete" },
		})
		expect(serialized).not.toContain("secret-access-token")
		expect(serialized).not.toContain("secret-refresh-token")
		expect(serialized).not.toContain("private-device-auth-id")
		expect(serialized).not.toContain("SAFE-CODE")
		expect(pollCount).toBeGreaterThan(0)
		expect(JSON.parse(await readFile(authFilePath, "utf8"))).toMatchObject({
			tokens: { access_token: "secret-access-token" },
		})
	})

	test("persists device-code login credentials in the encrypted store", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "oauth-db-login-"))
		tempDirs.push(root)
		const store = await openPersistentStore({
			databaseUrl: pathToFileURL(path.join(root, "auth.db")).href,
			encryptionKey: "c".repeat(64),
		})
		stores.push(store)
		const idToken = jwt({
			"https://api.openai.com/auth": { chatgpt_account_id: "acct-db-login" },
		})
		const fetchMock = vi.fn<typeof fetch>(async (input) => {
			const url = String(input)
			if (url.endsWith("/api/accounts/deviceauth/usercode")) {
				return response({
					device_auth_id: "private-device-id",
					user_code: "TEST-CODE",
					interval: 0.001,
				})
			}
			if (url.endsWith("/api/accounts/deviceauth/token")) {
				return response({
					authorization_code: "authorization-code",
					code_verifier: "server-issued-verifier",
				})
			}
			return response({
				access_token: "database-login-access",
				refresh_token: "database-login-refresh",
				id_token: idToken,
				expires_in: 3600,
			})
		})
		const server = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
			store,
			fetch: fetchMock,
		})
		servers.push(server)
		const start = await fetch(`${server.url}/login`, {
			method: "POST",
			headers: authorized,
		})
		expect(start.status).toBe(202)
		await waitForState(server.url, "complete")
		expect(store.getOAuthCredentials()).toMatchObject({
			accessToken: "database-login-access",
			refreshToken: "database-login-refresh",
			accountId: "acct-db-login",
		})
	})

	test("allows one active login and cancels it", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "oauth-active-login-"))
		tempDirs.push(root)
		const authFilePath = path.join(root, "auth.json")
		await writeFile(authFilePath, "{}")
		const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
			if (String(input).endsWith("/api/accounts/deviceauth/usercode")) {
				return response({
					device_auth_id: "private-device-auth-id",
					user_code: "SAFE-CODE",
					interval: 60,
				})
			}
			return await new Promise<Response>((_resolve, reject) => {
				init?.signal?.addEventListener(
					"abort",
					() => reject(new Error("aborted")),
					{ once: true },
				)
			})
		})
		const server = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
			authFilePath,
			fetch: fetchMock,
		})
		servers.push(server)

		const first = await fetch(`${server.url}/login`, {
			method: "POST",
			headers: authorized,
		})
		const { id } = (await first.json()) as { id: string }
		await waitForState(server.url, "awaiting_user")
		const second = await fetch(`${server.url}/login`, {
			method: "POST",
			headers: authorized,
		})
		expect(second.status).toBe(409)

		const cancel = await fetch(`${server.url}/login/${id}/cancel`, {
			method: "POST",
			headers: authorized,
		})
		expect(cancel.status).toBe(200)
		await expect(cancel.json()).resolves.toMatchObject({
			id,
			state: "cancelled",
		})
	})

	test("maps upstream failures to a fixed sanitized message", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "oauth-failed-login-"))
		tempDirs.push(root)
		const authFilePath = path.join(root, "auth.json")
		await writeFile(authFilePath, "{}")
		const fetchMock = vi.fn<typeof fetch>(async () =>
			response({ error: "secret upstream detail" }, 500),
		)
		const server = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
			authFilePath,
			fetch: fetchMock,
		})
		servers.push(server)

		await fetch(`${server.url}/login`, {
			method: "POST",
			headers: authorized,
		})
		const status = await waitForState(server.url, "failed")
		expect(status).toMatchObject({
			login: {
				state: "failed",
				error: "Sign-in failed. Start a new login or check the sidecar logs.",
			},
		})
		expect(JSON.stringify(status)).not.toContain("secret upstream detail")
	})
	test("validates and exchanges a pending browser callback URL", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "oauth-browser-control-"))
		tempDirs.push(root)
		const authFilePath = path.join(root, "auth.json")
		const fetchMock = vi.fn<typeof fetch>(async () =>
			response({
				access_token: "browser-access-token",
				refresh_token: "browser-refresh-token",
				id_token: jwt({
					"https://api.openai.com/auth": { chatgpt_account_id: "acct-browser" },
				}),
				expires_in: 3600,
			}),
		)
		const server = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
			authFilePath,
			fetch: fetchMock,
		})
		servers.push(server)
		const started = await fetch(`${server.url}/browser-login`, {
			method: "POST",
			headers: authorized,
		})
		expect(started.status).toBe(202)
		const pending = (await started.json()) as {
			id: string
			authorizationUrl: string
		}
		const authUrl = new URL(pending.authorizationUrl)
		const callback = new URL("http://localhost:1455/auth/callback")
		callback.searchParams.set("code", "browser-code")
		const state = authUrl.searchParams.get("state")
		if (!state) throw new Error("OAuth state missing from authorization URL.")
		callback.searchParams.set("state", state)
		const submitted = await fetch(
			`${server.url}/browser-login/${pending.id}/callback`,
			{
				method: "POST",
				headers: { ...authorized, "Content-Type": "application/json" },
				body: JSON.stringify({ callbackUrl: callback.href }),
			},
		)
		expect(submitted.status).toBe(200)
		expect(await submitted.json()).toMatchObject({
			id: pending.id,
			state: "complete",
		})
		expect(fetchMock).toHaveBeenCalledTimes(1)
		expect(JSON.parse(await readFile(authFilePath, "utf8"))).toMatchObject({
			tokens: { access_token: "browser-access-token" },
		})
	})

	test("rejects callback URLs with invalid state before token exchange", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "oauth-invalid-callback-"))
		tempDirs.push(root)
		const authFilePath = path.join(root, "auth.json")
		await writeFile(authFilePath, "{}")
		const fetchMock = vi.fn<typeof fetch>()
		const server = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
			authFilePath,
			fetch: fetchMock,
		})
		servers.push(server)
		const started = await fetch(`${server.url}/browser-login`, {
			method: "POST",
			headers: authorized,
		})
		const pending = (await started.json()) as { id: string }
		const submitted = await fetch(
			`${server.url}/browser-login/${pending.id}/callback`,
			{
				method: "POST",
				headers: { ...authorized, "Content-Type": "application/json" },
				body: JSON.stringify({
					callbackUrl:
						"http://localhost:1455/auth/callback?code=bad&state=wrong",
				}),
			},
		)
		expect(submitted.status).toBe(400)
		expect(fetchMock).not.toHaveBeenCalled()
	})
})
