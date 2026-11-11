import { promises as fs } from "node:fs"
import os from "node:os"
import path from "node:path"
import { pathToFileURL } from "node:url"
import {
	openPersistentStore,
	type PersistentStore,
} from "@openai-oauth/local/persistence"
import { afterEach, describe, expect, test, vi } from "vitest"
import { createAdminAuth, initializeAdminBootstrap } from "./admin-auth.js"
import { startLoginUiServer } from "./server.js"
import { renderStatus } from "./views.js"

const CONTROL_TOKEN = "server-only-control-secret-with-32-bytes-plus"
const activeId = "a".repeat(32)
const servers: Array<{ close: () => Promise<void> }> = []

const statusResponse = (state: "idle" | "starting") =>
	Response.json({
		credentialsConfigured: false,
		login: state === "idle" ? { state } : { id: activeId, state },
	})

const options = (fetch: typeof globalThis.fetch) => ({
	host: "127.0.0.1",
	port: 0,
	controlUrl: "http://127.0.0.1:10532",
	controlToken: CONTROL_TOKEN,
	publicOrigin: "https://login.example.ts.net",
	fetch,
})

const ADMIN_AUTH_SECRET =
	"test-only-admin-session-secret-with-at-least-32-bytes"
const ADMIN_BOOTSTRAP_PASSWORD = "temporary-bootstrap-password-123"
const adminStores: Array<{ store: PersistentStore; directory: string }> = []

const adminOptions = async (fetch: typeof globalThis.fetch) => {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), "oauth-admin-ui-"))
	const store = await openPersistentStore({
		databaseUrl: pathToFileURL(path.join(directory, "auth.db")).href,
		encryptionKey:
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	adminStores.push({ store, directory })
	const auth = createAdminAuth(store, {
		baseURL: "https://login.example.ts.net",
		secret: ADMIN_AUTH_SECRET,
	})
	await initializeAdminBootstrap(auth, store, {
		username: "bootstrap_admin",
		password: ADMIN_BOOTSTRAP_PASSWORD,
	})
	return { ...options(fetch), adminAuth: auth, store }
}
afterEach(async () => {
	await Promise.all(servers.splice(0).map((server) => server.close()))
	await Promise.all(
		adminStores.splice(0).map(async ({ store, directory }) => {
			store.close()
			await fs.rm(directory, { recursive: true, force: true })
		}),
	)
	vi.restoreAllMocks()
})

describe("tailnet OAuth login UI", () => {
	test("accepts loopback origins with an explicit port", async () => {
		const server = await startLoginUiServer({
			...options(async () => statusResponse("idle")),
			publicOrigin: "http://127.0.0.1:11533",
		})
		servers.push(server)
		expect(server.url).toMatch(/^http:\/\/127\.0\.0\.1:/)
	})

	test("serves the same-origin clipboard handler", async () => {
		const server = await startLoginUiServer(
			options(async () => statusResponse("idle")),
		)
		servers.push(server)

		const response = await globalThis.fetch(`${server.url}/assets/copy.js`)
		const script = await response.text()
		expect(response.status).toBe(200)
		expect(response.headers.get("content-type")).toContain("text/javascript")
		expect(script).toContain("navigator.clipboard.writeText")
	})

	test("proxies explicit sign-in server-side and keeps responses private", async () => {
		let started = false
		const sidecarFetch = vi.fn<typeof fetch>(async (input, init) => {
			const url = String(input)
			expect(new Headers(init?.headers).get("authorization")).toBe(
				`Bearer ${CONTROL_TOKEN}`,
			)
			if (url.endsWith("/status"))
				return statusResponse(started ? "starting" : "idle")
			if (url.endsWith("/login") && init?.method === "POST") {
				started = true
				return Response.json(
					{ id: activeId, state: "starting" },
					{ status: 202 },
				)
			}
			throw new Error(`Unexpected control request: ${url}`)
		})
		const server = await startLoginUiServer(options(sidecarFetch))
		servers.push(server)

		const page = await globalThis.fetch(server.url)
		const html = await page.text()
		expect(page.status).toBe(200)
		expect(page.headers.get("cache-control")).toContain("no-store")
		expect(page.headers.get("content-security-policy")).toContain(
			"frame-ancestors 'none'",
		)
		expect(html).toContain("Device-code")
		expect(html).toContain("/assets/copy.js")
		expect(html).toContain("OAuth credentials stay server-side")
		expect(html).not.toContain(CONTROL_TOKEN)
		expect(
			sidecarFetch.mock.calls.some(([, init]) => init?.method === "POST"),
		).toBe(false)

		const cookie = page.headers.get("set-cookie")?.split(";", 1)[0]
		const csrf = html.match(/name="csrf" value="([a-f0-9]{48})"/)?.[1]
		expect(cookie).toMatch(/^oauth_login_csrf=/)
		expect(csrf).toBeDefined()

		const startedPage = await globalThis.fetch(`${server.url}/_start`, {
			method: "POST",
			headers: {
				Cookie: cookie ?? "",
				Origin: "https://login.example.ts.net",
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({ csrf: csrf ?? "" }),
		})
		const fragment = await startedPage.text()
		expect(startedPage.status).toBe(200)
		expect(fragment).toContain("Requesting a one-time sign-in code")
		expect(fragment).not.toContain(CONTROL_TOKEN)
		expect(
			sidecarFetch.mock.calls.some(([, init]) => init?.method === "POST"),
		).toBe(true)
	})
	test("proxies refresh and sign-out lifecycle actions with CSRF protection", async () => {
		const mutations: string[] = []
		const sidecarFetch = vi.fn<typeof fetch>(async (input, init) => {
			const url = String(input)
			if (url.endsWith("/status")) {
				return Response.json({
					credentialsConfigured: true,
					accessTokenAppearsValid: true,
					refreshAvailable: true,
					login: { state: "idle" },
				})
			}
			if (init?.method === "POST" && /\/(refresh|sign-out)$/.test(url)) {
				mutations.push(url)
				return Response.json({})
			}
			throw new Error(`Unexpected control request: ${url}`)
		})
		const server = await startLoginUiServer(options(sidecarFetch))
		servers.push(server)

		for (const [route, endpoint, expectedNotice] of [
			["/_refresh", "/refresh", "Provider refresh completed"],
			["/_sign-out", "/sign-out", "Signed out"],
		] as const) {
			const page = await globalThis.fetch(server.url)
			const html = await page.text()
			const cookie = page.headers.get("set-cookie")?.split(";", 1)[0]
			const csrf = html.match(/name="csrf" value="([a-f0-9]{48})"/)?.[1]
			const result = await globalThis.fetch(`${server.url}${route}`, {
				method: "POST",
				headers: {
					Cookie: cookie ?? "",
					Origin: "https://login.example.ts.net",
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: new URLSearchParams({ csrf: csrf ?? "" }),
			})
			expect(result.status).toBe(200)
			expect(await result.text()).toContain(expectedNotice)
			expect(mutations.at(-1)).toBe(
				`${options(sidecarFetch).controlUrl}${endpoint}`,
			)
		}
	})

	test("rejects cross-origin mutations before contacting the sidecar", async () => {
		const sidecarFetch = vi.fn<typeof fetch>(async () => statusResponse("idle"))
		const server = await startLoginUiServer(options(sidecarFetch))
		servers.push(server)
		const page = await globalThis.fetch(server.url)
		const html = await page.text()
		const cookie = page.headers.get("set-cookie")?.split(";", 1)[0]
		const csrf = html.match(/name="csrf" value="([a-f0-9]{48})"/)?.[1]

		const response = await globalThis.fetch(`${server.url}/_start`, {
			method: "POST",
			headers: {
				Cookie: cookie ?? "",
				Origin: "https://attacker.example",
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({ csrf: csrf ?? "" }),
		})
		expect(response.status).toBe(403)
		expect(
			sidecarFetch.mock.calls.some(([, init]) => init?.method === "POST"),
		).toBe(false)
	})

	test("renders a copy button instead of a visibility toggle", () => {
		const fragment = renderStatus("a".repeat(48), {
			credentialsConfigured: false,
			login: {
				id: activeId,
				state: "awaiting_user",
				verificationUrl: "https://auth.openai.com/codex/device",
				userCode: "ABCD-EFGH",
			},
		})
		expect(fragment).toContain("data-copy-device-code")
		expect(fragment).toContain(">Copy</button>")
		expect(fragment).toMatch(
			/<button class="[^"]*bg-sky-400[^"]*" type="button" data-copy-device-code>Copy<\/button>/,
		)
		expect(fragment).toMatch(
			/<button class="[^"]*bg-red-500[^"]*" type="submit">Cancel<\/button>/,
		)
		expect(fragment).not.toContain("Toggle code visibility")
	})

	test("renders browser callback with a muted input and red Cancel button", () => {
		const fragment = renderStatus("a".repeat(48), {
			credentialsConfigured: false,
			login: {
				id: activeId,
				state: "awaiting_callback",
				authorizationUrl: "https://auth.openai.com/oauth/authorize?state=test",
			},
		})
		expect(fragment).toContain('id="callback-url"')
		expect(fragment).toMatch(
			/<input class="[^"]*text-zinc-300[^"]*" id="callback-url"/,
		)
		expect(fragment).toContain(">Submit callback URL</button>")
		expect(fragment).toMatch(
			/<button class="[^"]*bg-red-500[^"]*" type="submit">Cancel<\/button>/,
		)
	})

	test("renders credential status and lifecycle controls instead of direct replacement sign-in", () => {
		const updatedAt = "2026-11-10T20:15:00.000Z"
		const expiresAt = "2026-11-11T20:15:00.000Z"
		const fragment = renderStatus("a".repeat(48), {
			credentialsConfigured: true,
			credentialsUpdatedAt: updatedAt,
			accessTokenExpiresAt: expiresAt,
			accessTokenAppearsValid: true,
			refreshAvailable: true,
			login: { state: "idle" },
		})
		const buttonClasses = [
			...fragment.matchAll(
				/<button class="([^"]+)" type="submit">(Refresh|Sign out)<\/button>/g,
			),
		]
		const readableUpdatedAt = new Intl.DateTimeFormat(undefined, {
			dateStyle: "medium",
			timeStyle: "short",
		}).format(new Date(updatedAt))
		const readableExpiresAt = new Intl.DateTimeFormat(undefined, {
			dateStyle: "medium",
			timeStyle: "short",
		}).format(new Date(expiresAt))
		expect(buttonClasses).toHaveLength(2)
		expect(buttonClasses[0]?.[2]).toBe("Refresh")
		expect(buttonClasses[0]?.[1]).toContain("bg-emerald-400")
		expect(buttonClasses[1]?.[2]).toBe("Sign out")
		expect(buttonClasses[1]?.[1]).toContain("bg-red-500")
		expect(fragment).not.toContain(">Device-code</button>")
		expect(fragment).not.toContain("hx-confirm=")
		expect(fragment).toContain("grid-cols-[max-content_minmax(0,1fr)]")
		expect(fragment).toContain(
			`Access token updated:</dt><dd class="min-w-0 break-words">${readableUpdatedAt}`,
		)
		expect(fragment).toContain(
			`Access token expiry:</dt><dd class="min-w-0 break-words">${readableExpiresAt}`,
		)
		expect(fragment).toContain("bg-emerald-400")
	})

	test("shows unavailable token metadata and disables refresh when no refresh token is available", () => {
		const fragment = renderStatus("a".repeat(48), {
			credentialsConfigured: true,
			accessTokenAppearsValid: true,
			refreshAvailable: false,
			login: { state: "idle" },
		})
		expect(fragment.match(/>Unavailable<\/dd>/g)).toHaveLength(2)
		expect(fragment).toMatch(
			/<button class="[^"]*bg-zinc-700[^"]*" type="button" disabled aria-disabled="true">Refresh<\/button>/,
		)
		expect(fragment).not.toContain('hx-post="/_refresh"')
	})

	test("uses red, orange, and green token status colors for lifecycle state", () => {
		const signedOut = renderStatus("a".repeat(48), {
			credentialsConfigured: false,
			login: { state: "idle" },
		})
		expect(signedOut).toContain("bg-red-500")
		expect(signedOut).toContain(">Device-code</button>")
		expect(signedOut).toContain("bg-emerald-400")

		const expiring = renderStatus("a".repeat(48), {
			credentialsConfigured: true,
			accessTokenAppearsValid: true,
			isNearExpiry: true,
			refreshAvailable: true,
			login: { state: "idle" },
		})
		expect(expiring).toContain("bg-orange-400")
		expect(expiring).toContain(">Refresh</button>")
		expect(expiring).toContain(">Sign out</button>")
	})

	test("escapes device codes before rendering them as HTML", () => {
		const fragment = renderStatus("a".repeat(48), {
			credentialsConfigured: false,
			login: {
				id: activeId,
				state: "awaiting_user",
				verificationUrl: "https://auth.openai.com/codex/device",
				userCode: "<img src=x onerror=alert(1)>",
			},
		})
		expect(fragment).toContain("&lt;img src=x onerror=alert(1)&gt;")
		expect(fragment).not.toContain("<img src=x")
	})
	test("gates the control plane until admin login and both bootstrap credentials change", async () => {
		const apiKeyId = "b".repeat(32)
		const oneTimeApiKey = `sk-oai-oauth-${"z".repeat(43)}`
		let apiKeys: Array<{
			id: string
			label: string
			prefix: string
			createdAt: string
			revokedAt?: string
		}> = []
		const sidecarFetch = vi.fn<typeof fetch>(async (input, init) => {
			const url = String(input)
			const method = init?.method ?? "GET"
			if (url.endsWith("/status")) return statusResponse("idle")
			if (url.endsWith("/api-keys") && method === "GET")
				return Response.json({ keys: apiKeys })
			if (url.endsWith("/api-keys") && method === "POST") {
				const body = JSON.parse(String(init?.body)) as { label: string }
				apiKeys = [
					{
						id: apiKeyId,
						label: body.label,
						prefix: oneTimeApiKey.slice(0, 16),
						createdAt: "2026-11-11T00:00:00.000Z",
					},
				]
				return Response.json(
					{
						id: apiKeyId,
						label: body.label,
						prefix: oneTimeApiKey.slice(0, 16),
						createdAt: "2026-11-11T00:00:00.000Z",
						apiKey: oneTimeApiKey,
					},
					{ status: 201 },
				)
			}
			if (url.endsWith(`/api-keys/${apiKeyId}`) && method === "DELETE") {
				apiKeys = apiKeys.map((key) => ({
					...key,
					revokedAt: "2026-11-11T00:01:00.000Z",
				}))
				return Response.json({ id: apiKeyId, revoked: true })
			}
			throw new Error(`Unexpected control request: ${method} ${url}`)
		})
		const server = await startLoginUiServer(await adminOptions(sidecarFetch))
		servers.push(server)

		const loginPage = await globalThis.fetch(server.url)
		const loginHtml = await loginPage.text()
		const csrfCookie =
			loginPage.headers.get("set-cookie")?.split(";", 1)[0] ?? ""
		const csrf =
			loginHtml.match(/name="csrf" value="([a-f0-9]{48})"/)?.[1] ?? ""
		expect(loginHtml).toContain("Admin sign in")
		expect(loginHtml).not.toContain("Device-code")

		const lockedStart = await globalThis.fetch(`${server.url}/_start`, {
			method: "POST",
			headers: {
				Cookie: csrfCookie,
				Origin: "https://login.example.ts.net",
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({ csrf }),
		})
		expect(lockedStart.status).toBe(401)
		expect(sidecarFetch).not.toHaveBeenCalled()
		const crossOriginLogin = await globalThis.fetch(
			`${server.url}/_admin/login`,
			{
				method: "POST",
				headers: {
					Cookie: csrfCookie,
					Origin: "https://attacker.example",
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: new URLSearchParams({
					csrf,
					username: "bootstrap_admin",
					password: ADMIN_BOOTSTRAP_PASSWORD,
				}),
			},
		)
		expect(crossOriginLogin.status).toBe(403)

		const signIn = await globalThis.fetch(`${server.url}/_admin/login`, {
			method: "POST",
			redirect: "manual",
			headers: {
				Cookie: csrfCookie,
				Origin: "https://login.example.ts.net",
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({
				csrf,
				username: "bootstrap_admin",
				password: ADMIN_BOOTSTRAP_PASSWORD,
			}),
		})
		expect(signIn.status).toBe(303)
		const sessionSetCookie = signIn.headers
			.getSetCookie()
			.find((cookie) => !cookie.startsWith("oauth_login_csrf="))
		expect(sessionSetCookie).toBeDefined()
		expect(sessionSetCookie).toContain("HttpOnly")
		expect(sessionSetCookie).toContain("Secure")
		expect(sessionSetCookie).toMatch(/SameSite=Strict/i)
		const sessionCookie = sessionSetCookie?.split(";", 1)[0]
		expect(sessionCookie).toBeDefined()
		const adminCookie = `${csrfCookie}; ${sessionCookie}`

		const forcedChange = await globalThis.fetch(server.url, {
			headers: { Cookie: adminCookie },
		})
		const forcedHtml = await forcedChange.text()
		expect(forcedHtml).toContain("Change bootstrap credentials")
		expect(forcedHtml).not.toContain("Device-code")

		const bootstrap = await globalThis.fetch(`${server.url}/_admin/bootstrap`, {
			method: "POST",
			redirect: "manual",
			headers: {
				Cookie: adminCookie,
				Origin: "https://login.example.ts.net",
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({
				csrf,
				username: "real_admin",
				currentPassword: ADMIN_BOOTSTRAP_PASSWORD,
				newPassword: "new-admin-password-strong-789",
			}),
		})
		expect(bootstrap.status).toBe(303)

		const dashboard = await globalThis.fetch(server.url, {
			headers: { Cookie: adminCookie },
		})
		const dashboardHtml = await dashboard.text()
		expect(dashboardHtml).toContain("Signed in as <strong>real_admin</strong>")
		expect(dashboardHtml).toContain("Device-code")
		expect(sidecarFetch).toHaveBeenCalledTimes(1)

		const apiKeyPanel = await globalThis.fetch(`${server.url}/_api-keys`, {
			headers: { Cookie: adminCookie },
		})
		expect(apiKeyPanel.status).toBe(200)
		expect(await apiKeyPanel.text()).toContain("Create API key")
		const createApiKey = await globalThis.fetch(`${server.url}/_api-keys`, {
			method: "POST",
			headers: {
				Cookie: adminCookie,
				Origin: "https://login.example.ts.net",
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({ csrf, label: "Bifrost client" }),
		})
		expect(createApiKey.status).toBe(200)
		const createdKeyHtml = await createApiKey.text()
		expect(createdKeyHtml).toContain(oneTimeApiKey)
		expect(createdKeyHtml).toContain("Copy this API key now")
		expect(createdKeyHtml).not.toContain(CONTROL_TOKEN)

		const keyList = await globalThis.fetch(`${server.url}/_api-keys`, {
			headers: { Cookie: adminCookie },
		})
		const keyListHtml = await keyList.text()
		expect(keyListHtml).toContain("Bifrost client")
		expect(keyListHtml).not.toContain(oneTimeApiKey)
		expect(keyListHtml).toContain("Revoke")

		const revokeKey = await globalThis.fetch(
			`${server.url}/_api-keys/${apiKeyId}/revoke`,
			{
				method: "POST",
				headers: {
					Cookie: adminCookie,
					Origin: "https://login.example.ts.net",
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: new URLSearchParams({ csrf }),
			},
		)
		expect(revokeKey.status).toBe(200)
		const revokedKeyHtml = await revokeKey.text()
		expect(revokedKeyHtml).toContain("Revoked")
		expect(revokedKeyHtml).not.toContain("Revoke</button>")

		const logout = await globalThis.fetch(`${server.url}/_admin/sign-out`, {
			method: "POST",
			redirect: "manual",
			headers: {
				Cookie: adminCookie,
				Origin: "https://login.example.ts.net",
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({ csrf }),
		})
		expect(logout.status).toBe(303)
		const signedOutPage = await globalThis.fetch(server.url, {
			headers: { Cookie: adminCookie },
		})
		expect(await signedOutPage.text()).toContain("Admin sign in")
	})
})
