import { randomBytes, timingSafeEqual } from "node:crypto"
import { readFile } from "node:fs/promises"
import type {
	Server as HttpServer,
	IncomingMessage,
	ServerResponse,
} from "node:http"
import { createServer } from "node:http"
import { createRequire } from "node:module"
import type { AddressInfo } from "node:net"
import { dirname, isAbsolute, join, resolve } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"
import {
	openPersistentStore,
	type PersistentStore,
} from "@openai-oauth/local/persistence"
import { fromNodeHeaders } from "better-auth/node"
import {
	changeBootstrapCredentials,
	createAdminAuth,
	getAdminSession,
	initializeAdminBootstrap,
	readBootstrapState,
} from "./admin-auth.js"
import {
	type ApiKeyMetadata,
	type ControlStatus,
	type LoginState,
	renderAdminLoginPage,
	renderApiKeys,
	renderBootstrapPage,
	renderPage,
	renderStatus,
} from "./views.js"

export type LoginUiOptions = {
	host?: string
	port?: number
	controlUrl: string
	controlToken: string
	publicOrigin: string
	adminAuth?: ReturnType<typeof createAdminAuth>
	store?: PersistentStore
	fetch?: typeof fetch
}

type NormalizedOptions = {
	host: string
	port: number
	controlUrl: string
	controlToken: string
	publicOrigin: string
	adminAuth?: ReturnType<typeof createAdminAuth>
	store?: PersistentStore
	fetch: typeof fetch
}

const DEFAULT_HOST = "127.0.0.1"
const DEFAULT_PORT = 10533
const CSRF_COOKIE = "oauth_login_csrf"
const ALLOWED_STATES = new Set<LoginState>([
	"idle",
	"starting",
	"awaiting_user",
	"awaiting_callback",
	"complete",
	"failed",
	"cancelled",
])
const ALLOWED_LOGIN_ERRORS = new Set([
	"Sign-in timed out. Start a new login.",
	"Sign-in cancelled.",
	"Device-code sign-in is unavailable for this account.",
	"Sign-in failed. Start a new login or check the sidecar logs.",
])
const require = createRequire(import.meta.url)
const htmxPath = join(dirname(require.resolve("htmx.org")), "htmx.min.js")
const hyperscriptPath = join(
	dirname(require.resolve("hyperscript.org")),
	"_hyperscript.min.js",
)
const cssPath = fileURLToPath(new URL("../dist/styles.css", import.meta.url))
const copyScriptPath = fileURLToPath(new URL("./copy.js", import.meta.url))

const securityHeaders = {
	"Cache-Control": "no-store, private",
	"Content-Security-Policy":
		"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
	"Referrer-Policy": "same-origin",
	"X-Content-Type-Options": "nosniff",
	"X-Frame-Options": "DENY",
} as const

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value)

const normalizeOptions = (options: LoginUiOptions): NormalizedOptions => {
	if (Buffer.byteLength(options.controlToken, "utf8") < 32) {
		throw new Error("SIDECAR_CONTROL_TOKEN must be at least 32 bytes.")
	}
	if (Boolean(options.adminAuth) !== Boolean(options.store)) {
		throw new Error(
			"Admin authentication and its encrypted store must be configured together.",
		)
	}
	const control = new URL(options.controlUrl)
	if (
		(control.protocol !== "http:" && control.protocol !== "https:") ||
		control.username ||
		control.password ||
		control.search ||
		control.hash ||
		(control.pathname !== "/" && control.pathname !== "")
	) {
		throw new Error(
			"SIDECAR_CONTROL_URL must be an HTTP(S) origin without credentials or a path.",
		)
	}
	const origin = new URL(options.publicOrigin)
	if (
		origin.origin !== options.publicOrigin.replace(/\/$/, "") ||
		(origin.protocol !== "https:" &&
			!["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname))
	) {
		throw new Error(
			"LOGIN_UI_PUBLIC_ORIGIN must be an HTTPS origin (HTTP is allowed only on loopback).",
		)
	}
	return {
		host: options.host ?? DEFAULT_HOST,
		port: options.port ?? DEFAULT_PORT,
		controlUrl: control.origin,
		controlToken: options.controlToken,
		publicOrigin: origin.origin,
		...(options.adminAuth ? { adminAuth: options.adminAuth } : {}),
		...(options.store ? { store: options.store } : {}),
		fetch: options.fetch ?? globalThis.fetch.bind(globalThis),
	}
}

const parseControlStatus = (value: unknown): ControlStatus | undefined => {
	if (!isRecord(value) || typeof value.credentialsConfigured !== "boolean")
		return undefined
	if (!isRecord(value.login) || typeof value.login.state !== "string")
		return undefined
	if (!ALLOWED_STATES.has(value.login.state as LoginState)) return undefined

	const state = value.login.state as LoginState
	const id = value.login.id
	if (
		state !== "idle" &&
		(typeof id !== "string" || !/^[a-f0-9]{32}$/.test(id))
	) {
		return undefined
	}
	const login: ControlStatus["login"] = {
		state,
		...(typeof id === "string" ? { id } : {}),
	}
	if (state === "awaiting_user") {
		const verificationUrl = value.login.verificationUrl
		const userCode = value.login.userCode
		if (
			typeof verificationUrl !== "string" ||
			new URL(verificationUrl).origin !== "https://auth.openai.com" ||
			new URL(verificationUrl).pathname !== "/codex/device" ||
			typeof userCode !== "string" ||
			userCode.length > 64 ||
			!/^[A-Za-z0-9-]+$/.test(userCode)
		) {
			return undefined
		}
		login.verificationUrl = verificationUrl
		login.userCode = userCode
	}
	if (state === "awaiting_callback") {
		const authorizationUrl = value.login.authorizationUrl
		try {
			const parsed = new URL(String(authorizationUrl))
			if (
				parsed.origin !== "https://auth.openai.com" ||
				parsed.pathname !== "/oauth/authorize"
			)
				return undefined
		} catch {
			return undefined
		}
		login.authorizationUrl = authorizationUrl as string
	}
	if (state === "failed") {
		login.error =
			typeof value.login.error === "string" &&
			ALLOWED_LOGIN_ERRORS.has(value.login.error)
				? value.login.error
				: "Sign-in failed. Start a new login or check the sidecar logs."
	}
	const credentialsUpdatedAt = value.credentialsUpdatedAt
	const accessTokenExpiresAt = value.accessTokenExpiresAt
	return {
		credentialsConfigured: value.credentialsConfigured,
		...(typeof credentialsUpdatedAt === "string" &&
		Number.isFinite(Date.parse(credentialsUpdatedAt))
			? { credentialsUpdatedAt }
			: {}),
		...(typeof accessTokenExpiresAt === "string" &&
		Number.isFinite(Date.parse(accessTokenExpiresAt))
			? { accessTokenExpiresAt }
			: {}),
		accessTokenAppearsValid: value.accessTokenAppearsValid === true,
		isNearExpiry: value.isNearExpiry === true,
		refreshAvailable: value.refreshAvailable === true,
		login,
	}
}

const send = (
	res: ServerResponse,
	status: number,
	body: string,
	contentType = "text/html; charset=utf-8",
): void => {
	res.writeHead(status, { ...securityHeaders, "Content-Type": contentType })
	res.end(body)
}

const parseCookies = (header: string | undefined): Map<string, string> => {
	const cookies = new Map<string, string>()
	for (const piece of header?.split(";") ?? []) {
		const separator = piece.indexOf("=")
		if (separator < 1) continue
		cookies.set(
			piece.slice(0, separator).trim(),
			piece.slice(separator + 1).trim(),
		)
	}
	return cookies
}

const sameToken = (left: string, right: string): boolean => {
	const leftBytes = Buffer.from(left)
	const rightBytes = Buffer.from(right)
	return (
		leftBytes.length === rightBytes.length &&
		timingSafeEqual(leftBytes, rightBytes)
	)
}

const readForm = async (
	req: IncomingMessage,
): Promise<URLSearchParams | undefined> => {
	if (
		!req.headers["content-type"]?.startsWith(
			"application/x-www-form-urlencoded",
		)
	) {
		req.resume()
		return undefined
	}
	const chunks: Buffer[] = []
	let size = 0
	for await (const chunk of req) {
		const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
		size += buffer.length
		if (size > 2048) {
			req.resume()
			return undefined
		}
		chunks.push(buffer)
	}
	return new URLSearchParams(Buffer.concat(chunks).toString("utf8"))
}

const fetchStatus = async (
	options: NormalizedOptions,
): Promise<ControlStatus> => {
	const response = await options.fetch(`${options.controlUrl}/status`, {
		headers: { Authorization: `Bearer ${options.controlToken}` },
	})
	if (!response.ok) throw new Error("control service unavailable")
	const status = parseControlStatus(await response.json())
	if (!status) throw new Error("invalid control status")
	return status
}

const isApiKeyMetadata = (value: unknown): value is ApiKeyMetadata =>
	isRecord(value) &&
	typeof value.id === "string" &&
	/^[a-f0-9]{32}$/.test(value.id) &&
	typeof value.label === "string" &&
	typeof value.prefix === "string" &&
	typeof value.createdAt === "string" &&
	Number.isFinite(Date.parse(value.createdAt)) &&
	(value.revokedAt === undefined ||
		(typeof value.revokedAt === "string" &&
			Number.isFinite(Date.parse(value.revokedAt))))

const fetchApiKeys = async (
	options: NormalizedOptions,
): Promise<ApiKeyMetadata[]> => {
	const response = await options.fetch(`${options.controlUrl}/api-keys`, {
		headers: { Authorization: `Bearer ${options.controlToken}` },
	})
	if (!response.ok) throw new Error("control service unavailable")
	const value: unknown = await response.json()
	if (!isRecord(value) || !Array.isArray(value.keys))
		throw new Error("invalid API-key response")
	const keys = value.keys.filter(isApiKeyMetadata)
	if (keys.length !== value.keys.length)
		throw new Error("invalid API-key metadata")
	return keys
}

const csrfForRequest = (
	req: IncomingMessage,
	res: ServerResponse,
	options: NormalizedOptions,
): string => {
	const existing = parseCookies(req.headers.cookie).get(CSRF_COOKIE)
	if (existing && /^[a-f0-9]{48}$/.test(existing)) return existing
	const token = randomBytes(24).toString("hex")
	const secure = options.publicOrigin.startsWith("https:") ? "; Secure" : ""
	res.setHeader(
		"Set-Cookie",
		`${CSRF_COOKIE}=${token}; Path=/; Max-Age=3600; HttpOnly; SameSite=Strict${secure}`,
	)
	return token
}

const isValidPost = async (
	req: IncomingMessage,
	options: NormalizedOptions,
): Promise<URLSearchParams | undefined> => {
	if (req.headers.origin !== options.publicOrigin) {
		req.resume()
		return undefined
	}
	const form = await readForm(req)
	const cookie = parseCookies(req.headers.cookie).get(CSRF_COOKIE)
	if (!form || !cookie || !sameToken(form.get("csrf") ?? "", cookie))
		return undefined
	return form
}

const adminAccessForRequest = async (
	req: IncomingMessage,
	options: NormalizedOptions,
) => {
	if (!options.adminAuth || !options.store) return undefined
	const session = await getAdminSession(
		options.adminAuth,
		fromNodeHeaders(req.headers),
	)
	if (!session) return { session: null, bootstrapComplete: false }
	const bootstrap = await readBootstrapState(options.store)
	return {
		session,
		bootstrapComplete: Boolean(
			bootstrap?.adminUserId === session.user.id &&
				bootstrap.usernameChanged &&
				bootstrap.passwordChanged,
		),
	}
}

const requireCompletedAdmin = async (
	req: IncomingMessage,
	res: ServerResponse,
	options: NormalizedOptions,
): Promise<boolean> => {
	if (!options.adminAuth || !options.store) {
		send(
			res,
			503,
			"Admin authentication unavailable",
			"text/plain; charset=utf-8",
		)
		return false
	}
	try {
		const access = await adminAccessForRequest(req, options)
		if (access?.session && access.bootstrapComplete) return true
		send(
			res,
			401,
			"Administrator sign-in required",
			"text/plain; charset=utf-8",
		)
		return false
	} catch {
		send(
			res,
			503,
			"Admin authentication unavailable",
			"text/plain; charset=utf-8",
		)
		return false
	}
}

const setAuthCookies = (res: ServerResponse, response: Response): void => {
	const cookies = response.headers.getSetCookie()
	if (cookies.length === 0) return
	const existing = res.getHeader("Set-Cookie")
	const currentCookies = Array.isArray(existing)
		? existing.map(String)
		: typeof existing === "string"
			? [existing]
			: []
	res.setHeader("Set-Cookie", [...currentCookies, ...cookies])
}

const redirectToRoot = (res: ServerResponse): void => {
	res.writeHead(303, { ...securityHeaders, Location: "/" })
	res.end()
}

const serveAsset = async (
	res: ServerResponse,
	path: string,
	contentType: string,
): Promise<void> => {
	try {
		send(res, 200, await readFile(path, "utf8"), contentType)
	} catch {
		send(res, 503, "Asset unavailable", "text/plain; charset=utf-8")
	}
}

export const createLoginUiHandler = (input: LoginUiOptions) => {
	const options = normalizeOptions(input)
	return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
		const url = new URL(req.url ?? "/", options.publicOrigin)
		if (req.method === "GET" && url.pathname === "/health") {
			send(
				res,
				200,
				JSON.stringify({ ok: true }),
				"application/json; charset=utf-8",
			)
			return
		}
		if (req.method === "GET" && url.pathname === "/assets/styles.css") {
			await serveAsset(res, cssPath, "text/css; charset=utf-8")
			return
		}
		if (req.method === "GET" && url.pathname === "/assets/htmx.js") {
			await serveAsset(res, htmxPath, "text/javascript; charset=utf-8")
			return
		}
		if (req.method === "GET" && url.pathname === "/assets/hyperscript.js") {
			await serveAsset(res, hyperscriptPath, "text/javascript; charset=utf-8")
			return
		}
		if (req.method === "GET" && url.pathname === "/assets/copy.js") {
			await serveAsset(res, copyScriptPath, "text/javascript; charset=utf-8")
			return
		}
		if (
			req.method === "POST" &&
			["/_admin/login", "/_admin/sign-out", "/_admin/bootstrap"].includes(
				url.pathname,
			)
		) {
			if (!options.adminAuth || !options.store) {
				req.resume()
				send(res, 404, "Not found", "text/plain; charset=utf-8")
				return
			}
			const form = await isValidPost(req, options)
			if (!form) {
				send(res, 403, "Forbidden", "text/plain; charset=utf-8")
				return
			}
			if (url.pathname === "/_admin/login") {
				const username = form.get("username") ?? ""
				const password = form.get("password") ?? ""
				if (
					username.length > 64 ||
					password.length > 128 ||
					!username ||
					!password
				) {
					send(
						res,
						400,
						renderAdminLoginPage(
							form.get("csrf") ?? "",
							"Enter your username and password.",
						),
					)
					return
				}
				try {
					const response = await options.adminAuth.api.signInUsername({
						body: { username, password },
						headers: fromNodeHeaders(req.headers),
						asResponse: true,
					})
					if (!response.ok) {
						send(
							res,
							401,
							renderAdminLoginPage(
								form.get("csrf") ?? "",
								"Invalid username or password.",
							),
						)
						return
					}
					setAuthCookies(res, response)
					redirectToRoot(res)
				} catch {
					send(
						res,
						401,
						renderAdminLoginPage(
							form.get("csrf") ?? "",
							"Invalid username or password.",
						),
					)
				}
				return
			}
			if (url.pathname === "/_admin/sign-out") {
				try {
					const response = await options.adminAuth.api.signOut({
						headers: fromNodeHeaders(req.headers),
						asResponse: true,
					})
					setAuthCookies(res, response)
					redirectToRoot(res)
				} catch {
					send(
						res,
						503,
						"Authentication service unavailable",
						"text/plain; charset=utf-8",
					)
				}
				return
			}

			const access = await adminAccessForRequest(req, options)
			if (!access?.session) {
				redirectToRoot(res)
				return
			}
			if (access.bootstrapComplete) {
				redirectToRoot(res)
				return
			}
			try {
				await changeBootstrapCredentials(
					options.adminAuth,
					options.store,
					fromNodeHeaders(req.headers),
					{
						username: form.get("username") ?? "",
						currentPassword: form.get("currentPassword") ?? "",
						newPassword: form.get("newPassword") ?? "",
					},
				)
				redirectToRoot(res)
			} catch {
				send(
					res,
					400,
					renderBootstrapPage(
						form.get("csrf") ?? "",
						"Could not change both credentials. Verify the current password and choose new values.",
					),
				)
			}
			return
		}
		if (req.method === "GET" && url.pathname === "/") {
			const csrf = csrfForRequest(req, res, options)
			if (options.adminAuth && options.store) {
				try {
					const access = await adminAccessForRequest(req, options)
					if (!access?.session) {
						send(res, 200, renderAdminLoginPage(csrf))
					} else if (!access.bootstrapComplete) {
						send(res, 200, renderBootstrapPage(csrf))
					} else {
						const username =
							access.session.user.username ?? access.session.user.name
						try {
							send(
								res,
								200,
								renderPage(csrf, await fetchStatus(options), false, username),
							)
						} catch {
							send(res, 200, renderPage(csrf, undefined, true, username))
						}
					}
				} catch {
					send(
						res,
						503,
						"Admin authentication unavailable",
						"text/plain; charset=utf-8",
					)
				}
				return
			}
			try {
				send(res, 200, renderPage(csrf, await fetchStatus(options)))
			} catch {
				send(res, 200, renderPage(csrf, undefined, true))
			}
			return
		}
		if (req.method === "GET" && url.pathname === "/_status") {
			const csrf = csrfForRequest(req, res, options)
			if (options.adminAuth) {
				try {
					const access = await adminAccessForRequest(req, options)
					if (!access?.session || !access.bootstrapComplete) {
						send(
							res,
							401,
							"Administrator sign-in required",
							"text/plain; charset=utf-8",
						)
						return
					}
				} catch {
					send(
						res,
						503,
						"Admin authentication unavailable",
						"text/plain; charset=utf-8",
					)
					return
				}
			}
			try {
				send(res, 200, renderStatus(csrf, await fetchStatus(options)))
			} catch {
				send(res, 200, renderStatus(csrf, undefined, true))
			}
			return
		}
		if (req.method === "GET" && url.pathname === "/_api-keys") {
			if (!(await requireCompletedAdmin(req, res, options))) return
			const csrf = csrfForRequest(req, res, options)
			try {
				send(res, 200, renderApiKeys(csrf, await fetchApiKeys(options)))
			} catch {
				send(
					res,
					502,
					renderApiKeys(csrf, [], undefined, "API-key service is unavailable."),
				)
			}
			return
		}

		const revokeSuffix = "/revoke"
		const apiKeyRevokeId =
			url.pathname.startsWith("/_api-keys/") &&
			url.pathname.endsWith(revokeSuffix)
				? url.pathname.slice("/_api-keys/".length, -revokeSuffix.length)
				: undefined
		const validApiKeyRevokeId =
			apiKeyRevokeId && /^[a-f0-9]{32}$/.test(apiKeyRevokeId)
				? apiKeyRevokeId
				: undefined
		if (
			req.method === "POST" &&
			(url.pathname === "/_api-keys" || validApiKeyRevokeId !== undefined)
		) {
			const form = await isValidPost(req, options)
			if (!form) {
				send(res, 403, "Forbidden", "text/plain; charset=utf-8")
				return
			}
			if (!(await requireCompletedAdmin(req, res, options))) return
			const csrf = csrfForRequest(req, res, options)
			try {
				if (url.pathname === "/_api-keys") {
					const label = form.get("label")?.trim() ?? ""
					if (
						label.length === 0 ||
						label.length > 64 ||
						label.split("").some((character) => {
							const code = character.charCodeAt(0)
							return code < 32 || code === 127
						})
					) {
						send(
							res,
							400,
							"API-key labels must contain 1–64 printable characters.",
							"text/plain; charset=utf-8",
						)
						return
					}
					const response = await options.fetch(
						`${options.controlUrl}/api-keys`,
						{
							method: "POST",
							headers: {
								Authorization: `Bearer ${options.controlToken}`,
								"Content-Type": "application/json",
							},
							body: JSON.stringify({ label }),
						},
					)
					if (response.status !== 201) throw new Error("API-key create failed")
					const created: unknown = await response.json()
					if (!isRecord(created) || typeof created.apiKey !== "string")
						throw new Error("Invalid API-key response")
					let keys: ApiKeyMetadata[] = []
					let notice: string | undefined
					try {
						keys = await fetchApiKeys(options)
					} catch {
						notice =
							"The key was created, but the key list is temporarily unavailable."
					}
					send(res, 200, renderApiKeys(csrf, keys, created.apiKey, notice))
					return
				}

				const response = await options.fetch(
					`${options.controlUrl}/api-keys/${validApiKeyRevokeId}`,
					{
						method: "DELETE",
						headers: { Authorization: `Bearer ${options.controlToken}` },
					},
				)
				if (!response.ok) throw new Error("API-key revoke failed")
				let keys: ApiKeyMetadata[] = []
				let notice: string | undefined
				try {
					keys = await fetchApiKeys(options)
				} catch {
					notice =
						"The key was revoked, but the key list is temporarily unavailable."
				}
				send(res, 200, renderApiKeys(csrf, keys, undefined, notice))
			} catch {
				send(res, 502, "API-key operation failed.", "text/plain; charset=utf-8")
			}
			return
		}

		if (
			req.method === "POST" &&
			["/_browser-start", "/_browser-callback"].includes(url.pathname)
		) {
			const form = await isValidPost(req, options)
			if (!form) {
				send(res, 403, "Forbidden", "text/plain; charset=utf-8")
				return
			}
			if (options.adminAuth) {
				try {
					const access = await adminAccessForRequest(req, options)
					if (!access?.session || !access.bootstrapComplete) {
						send(
							res,
							401,
							"Administrator sign-in required",
							"text/plain; charset=utf-8",
						)
						return
					}
				} catch {
					send(
						res,
						503,
						"Admin authentication unavailable",
						"text/plain; charset=utf-8",
					)
					return
				}
			}
			try {
				let response: Response
				if (url.pathname === "/_browser-start") {
					response = await options.fetch(
						`${options.controlUrl}/browser-login`,
						{
							method: "POST",
							headers: { Authorization: `Bearer ${options.controlToken}` },
						},
					)
				} else {
					const id = form.get("id") ?? ""
					const callbackUrl = form.get("callbackUrl") ?? ""
					if (!/^[a-f0-9]{32}$/.test(id) || callbackUrl.length > 4096) {
						send(res, 400, "Invalid callback URL", "text/plain; charset=utf-8")
						return
					}
					response = await options.fetch(
						`${options.controlUrl}/browser-login/${id}/callback`,
						{
							method: "POST",
							headers: {
								Authorization: `Bearer ${options.controlToken}`,
								"Content-Type": "application/json",
							},
							body: JSON.stringify({ callbackUrl }),
						},
					)
				}
				if (!response.ok) throw new Error("control service unavailable")
				const csrf = csrfForRequest(req, res, options)
				send(res, 200, renderStatus(csrf, await fetchStatus(options)))
			} catch {
				const csrf = csrfForRequest(req, res, options)
				send(res, 200, renderStatus(csrf, undefined, true))
			}
			return
		}
		if (
			req.method === "POST" &&
			["/_start", "/_cancel", "/_refresh", "/_sign-out"].includes(url.pathname)
		) {
			const form = await isValidPost(req, options)
			if (!form) {
				send(res, 403, "Forbidden", "text/plain; charset=utf-8")
				return
			}
			if (options.adminAuth) {
				try {
					const access = await adminAccessForRequest(req, options)
					if (!access?.session || !access.bootstrapComplete) {
						send(
							res,
							401,
							"Administrator sign-in required",
							"text/plain; charset=utf-8",
						)
						return
					}
				} catch {
					send(
						res,
						503,
						"Admin authentication unavailable",
						"text/plain; charset=utf-8",
					)
					return
				}
			}
			let notice: string | undefined
			try {
				if (url.pathname === "/_start") {
					const response = await options.fetch(`${options.controlUrl}/login`, {
						method: "POST",
						headers: { Authorization: `Bearer ${options.controlToken}` },
					})
					if (response.status !== 202 && response.status !== 409) {
						throw new Error("control service unavailable")
					}
				} else if (url.pathname === "/_cancel") {
					const id = form.get("id") ?? ""
					if (!/^[a-f0-9]{32}$/.test(id)) {
						send(res, 400, "Invalid login id", "text/plain; charset=utf-8")
						return
					}
					const response = await options.fetch(
						`${options.controlUrl}/login/${id}/cancel`,
						{
							method: "POST",
							headers: { Authorization: `Bearer ${options.controlToken}` },
						},
					)
					if (!response.ok) throw new Error("control service unavailable")
				} else {
					const isRefresh = url.pathname === "/_refresh"
					const response = await options.fetch(
						`${options.controlUrl}/${isRefresh ? "refresh" : "sign-out"}`,
						{
							method: "POST",
							headers: { Authorization: `Bearer ${options.controlToken}` },
						},
					)
					notice = response.ok
						? isRefresh
							? "Provider refresh completed and the updated credentials were saved."
							: "Signed out. Saved local OAuth credentials were removed; the provider token was not revoked."
						: isRefresh
							? "Refresh failed. Sign out and sign in again, or check the sidecar logs."
							: "Sign out failed. Check the sidecar logs and try again."
				}
				const csrf = csrfForRequest(req, res, options)
				try {
					const updatedStatus = await fetchStatus(options)
					send(
						res,
						200,
						renderStatus(
							csrf,
							notice ? { ...updatedStatus, notice } : updatedStatus,
						),
					)
				} catch {
					send(res, 200, renderStatus(csrf, undefined, true))
				}
			} catch {
				const csrf = csrfForRequest(req, res, options)
				send(res, 200, renderStatus(csrf, undefined, true))
			}
			return
		}
		if (req.method !== "GET" && req.method !== "HEAD") req.resume()
		send(res, 404, "Not found", "text/plain; charset=utf-8")
	}
}

export const startLoginUiServer = async (input: LoginUiOptions) => {
	const options = normalizeOptions(input)
	const server: HttpServer = createServer(createLoginUiHandler(options))
	await new Promise<void>((resolveListen, reject) => {
		server.once("error", reject)
		server.listen(options.port, options.host, () => {
			server.off("error", reject)
			resolveListen()
		})
	})
	const address = server.address() as AddressInfo
	const host = address.address.includes(":")
		? `[${address.address}]`
		: address.address
	return {
		server,
		host: address.address,
		port: address.port,
		url: `http://${host}:${address.port}`,
		close: () =>
			new Promise<void>((resolveClose, reject) => {
				server.close((error) => (error ? reject(error) : resolveClose()))
				server.closeIdleConnections?.()
			}),
	}
}

const optionsFromEnv = async (): Promise<LoginUiOptions> => {
	const controlToken = process.env.SIDECAR_CONTROL_TOKEN
	const publicOrigin = process.env.LOGIN_UI_PUBLIC_ORIGIN
	if (!controlToken || !publicOrigin) {
		throw new Error(
			"SIDECAR_CONTROL_TOKEN and LOGIN_UI_PUBLIC_ORIGIN must be configured.",
		)
	}
	const portValue = process.env.LOGIN_UI_PORT
	const port = portValue === undefined ? DEFAULT_PORT : Number(portValue)
	if (!Number.isInteger(port) || port < 0 || port > 65535) {
		throw new Error("LOGIN_UI_PORT must be an integer from 0 to 65535.")
	}
	const databasePath = process.env.OPENAI_OAUTH_DATABASE_PATH
	const encryptionKey = process.env.OPENAI_OAUTH_DATABASE_KEY
	if (!databasePath || !encryptionKey) {
		throw new Error(
			"OPENAI_OAUTH_DATABASE_PATH and OPENAI_OAUTH_DATABASE_KEY are required for the login UI.",
		)
	}
	if (!isAbsolute(databasePath)) {
		throw new Error("OPENAI_OAUTH_DATABASE_PATH must be an absolute path.")
	}
	const sessionSecret = process.env.AUTH_SESSION_SECRET
	if (!sessionSecret)
		throw new Error("AUTH_SESSION_SECRET is required for the login UI.")

	const store = await openPersistentStore({
		databaseUrl: pathToFileURL(resolve(databasePath)).href,
		encryptionKey,
	})
	try {
		await store.withOAuthRefreshLock(async (assertLock) => {
			assertLock()
			await store.importAuthFile()
		})
		const adminAuth = createAdminAuth(store, {
			baseURL: new URL(publicOrigin).origin,
			secret: sessionSecret,
		})
		await initializeAdminBootstrap(adminAuth, store, {
			username: process.env.AUTH_BOOTSTRAP_USERNAME,
			password: process.env.AUTH_BOOTSTRAP_PASSWORD,
		})
		return {
			host: process.env.LOGIN_UI_HOST ?? DEFAULT_HOST,
			port,
			controlUrl: process.env.SIDECAR_CONTROL_URL ?? "http://127.0.0.1:10532",
			controlToken,
			publicOrigin,
			adminAuth,
			store,
		}
	} catch (error) {
		store.close()
		throw error
	}
}

if (
	process.argv[1] &&
	resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
	const options = await optionsFromEnv()
	let server: Awaited<ReturnType<typeof startLoginUiServer>>
	try {
		server = await startLoginUiServer(options)
	} catch (error) {
		options.store?.close()
		throw error
	}
	console.log(`Tailnet OAuth login UI listening at ${server.url}`)
	let stopping = false
	const shutdown = async () => {
		if (stopping) return
		stopping = true
		await server.close().catch(() => undefined)
		options.store?.close()
	}
	process.once("SIGTERM", () => void shutdown())
	process.once("SIGINT", () => void shutdown())
}
