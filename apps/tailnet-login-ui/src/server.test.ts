import { afterEach, describe, expect, test, vi } from "vitest"
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

afterEach(async () => {
	await Promise.all(servers.splice(0).map((server) => server.close()))
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
		expect(html).toContain("Your credentials are never shown here")
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
			["/_refresh", "/refresh", "Refresh complete"],
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
		expect(fragment).toContain(">Copy code</button>")
		expect(fragment).not.toContain("Toggle code visibility")
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
		expect(fragment).toContain(
			`Credentials last updated: </dt><dd class="inline">${readableUpdatedAt}`,
		)
		expect(fragment).toContain(
			`Access token expiry: </dt><dd class="inline">${readableExpiresAt}`,
		)
		expect(fragment).toContain("bg-emerald-400")
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
})
