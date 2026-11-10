import { mkdtemp, readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
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

	afterEach(async () => {
		await Promise.all(servers.splice(0).map((server) => server.close()))
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

	test("allows one active login and cancels it", async () => {
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
		const fetchMock = vi.fn<typeof fetch>(async () =>
			response({ error: "secret upstream detail" }, 500),
		)
		const server = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
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
		callback.searchParams.set("state", authUrl.searchParams.get("state")!)
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
		const fetchMock = vi.fn<typeof fetch>()
		const server = await startOpenAIOAuthControlServer({
			host: "127.0.0.1",
			port: 0,
			token: CONTROL_TOKEN,
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
