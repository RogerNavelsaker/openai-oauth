import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { describe, expect, test, vi } from "vitest"
import { runOpenAIOAuthDeviceCodeLogin } from "../src/login.js"

const jwt = (claims: Record<string, unknown>): string =>
	`e30.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.sig`

const response = (body: unknown, status = 200): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	})

describe("OpenAI OAuth device-code login", () => {
	test("polls, exchanges the device authorization code, and saves credentials", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "openai-oauth-device-"))
		const authFilePath = path.join(root, "auth.json")
		const messages: string[] = []
		let pollRequests = 0
		const idToken = jwt({
			"https://api.openai.com/auth": { chatgpt_account_id: "acct-device" },
		})
		const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
			const url = String(input)
			if (url.endsWith("/api/accounts/deviceauth/usercode")) {
				expect(init?.method).toBe("POST")
				expect(JSON.parse(String(init?.body))).toEqual({
					client_id: "client-device",
				})
				return response({
					device_auth_id: "private-device-auth-id",
					user_code: "ABCD-EFGH",
					interval: 0.001,
				})
			}

			if (url.endsWith("/api/accounts/deviceauth/token")) {
				pollRequests += 1
				expect(JSON.parse(String(init?.body))).toEqual({
					device_auth_id: "private-device-auth-id",
					user_code: "ABCD-EFGH",
				})
				if (pollRequests === 1) return response({}, 404)
				return response({
					authorization_code: "authorization-code",
					code_verifier: "server-issued-verifier",
					code_challenge: "server-issued-challenge",
				})
			}

			expect(url).toBe("https://auth.openai.com/oauth/token")
			const body = new URLSearchParams(String(init?.body))
			expect(body.get("grant_type")).toBe("authorization_code")
			expect(body.get("code")).toBe("authorization-code")
			expect(body.get("client_id")).toBe("client-device")
			expect(body.get("code_verifier")).toBe("server-issued-verifier")
			expect(body.get("redirect_uri")).toBe(
				"https://auth.openai.com/deviceauth/callback",
			)
			return response({
				access_token: "access-device",
				refresh_token: "refresh-device",
				id_token: idToken,
				expires_in: 3600,
			})
		})

		try {
			const saved = await runOpenAIOAuthDeviceCodeLogin({
				authFilePath,
				clientId: "client-device",
				fetch: fetchMock,
				timeoutMs: 10_000,
				onMessage: (message) => messages.push(message),
			})

			expect(fetchMock).toHaveBeenCalledTimes(4)
			expect(saved.path).toBe(authFilePath)
			expect(saved.auth.accountId).toBe("acct-device")
			expect(messages.join("\n")).toContain(
				"https://auth.openai.com/codex/device",
			)
			expect(messages.join("\n")).toContain("ABCD-EFGH")
			expect(messages.join("\n")).not.toContain("private-device-auth-id")
			expect(JSON.parse(await readFile(authFilePath, "utf8"))).toMatchObject({
				auth_mode: "chatgpt",
				tokens: {
					access_token: "access-device",
					refresh_token: "refresh-device",
					account_id: "acct-device",
				},
			})
			expect((await stat(authFilePath)).mode & 0o777).toBe(0o600)
		} finally {
			await rm(root, { recursive: true, force: true })
		}
	})

	test("times out while the user code is still pending", async () => {
		const fetchMock = vi.fn<typeof fetch>(async (input) => {
			const url = String(input)
			if (url.endsWith("/api/accounts/deviceauth/usercode")) {
				return response({
					device_auth_id: "id",
					user_code: "CODE",
					interval: 0.001,
				})
			}
			return response({}, 404)
		})

		await expect(
			runOpenAIOAuthDeviceCodeLogin({
				fetch: fetchMock,
				timeoutMs: 10,
				onMessage: () => undefined,
			}),
		).rejects.toThrow(/device-code login timed out/i)
	})

	test("cancels polling when the login is aborted", async () => {
		const controller = new AbortController()
		const fetchMock = vi.fn<typeof fetch>(async (input) => {
			const url = String(input)
			if (url.endsWith("/api/accounts/deviceauth/usercode")) {
				return response({
					device_auth_id: "id",
					user_code: "CODE",
					interval: 5,
				})
			}
			controller.abort()
			return response({}, 403)
		})

		await expect(
			runOpenAIOAuthDeviceCodeLogin({
				fetch: fetchMock,
				signal: controller.signal,
				onMessage: () => undefined,
			}),
		).rejects.toThrow(/login cancelled/i)
		expect(fetchMock).toHaveBeenCalledTimes(2)
	})

	test("fails clearly when the server has device-code login disabled", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "openai-oauth-device-"))
		const authFilePath = path.join(root, "auth.json")
		const previousAuth = '{"keep":true}\n'
		await writeFile(authFilePath, previousAuth)
		const fetchMock = vi.fn<typeof fetch>(async () => response({}, 404))

		try {
			await expect(
				runOpenAIOAuthDeviceCodeLogin({
					authFilePath,
					fetch: fetchMock,
					onMessage: () => undefined,
				}),
			).rejects.toThrow(/device.code login is not enabled/i)
			expect(fetchMock).toHaveBeenCalledTimes(1)
			expect(await readFile(authFilePath, "utf8")).toBe(previousAuth)
		} finally {
			await rm(root, { recursive: true, force: true })
		}
	})
})
