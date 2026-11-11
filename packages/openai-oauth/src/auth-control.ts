import { createHash, randomBytes, timingSafeEqual } from "node:crypto"
import { createServer, type Server as HttpServer } from "node:http"
import type { AddressInfo } from "node:net"
import {
	createOpenAIOAuthRequest,
	exchangeOpenAIOAuthCode,
	parseJwtClaims,
} from "@openai-oauth/core"
import {
	clearAuthTokens,
	forceRefreshAuthTokens,
	loadAuthTokens,
	saveAuthTokens,
} from "@openai-oauth/local/auth-file"
import type { PersistentStore } from "@openai-oauth/local/persistence"
import { runOpenAIOAuthDeviceCodeLogin } from "./login.js"

export type AuthControlServerOptions = {
	host?: string
	port?: number
	token: string
	authFilePath?: string
	store?: PersistentStore
	clientId?: string
	tokenUrl?: string
	timeoutMs?: number
	fetch?: typeof fetch
}

type LoginState =
	| "starting"
	| "awaiting_user"
	| "awaiting_callback"
	| "complete"
	| "failed"
	| "cancelled"

type DeviceCode = {
	verificationUrl: string
	userCode: string
}

type LoginJob = {
	id: string
	state: LoginState
	abort: AbortController
	deviceCode?: DeviceCode
	authorizationUrl?: string
	stateToken?: string
	codeVerifier?: string
	error?: string
}

const TOKEN_EXPIRY_WARNING_MS = 5 * 60 * 1000
const CONTROL_TOKEN_MIN_LENGTH = 32
const DEFAULT_CONTROL_HOST = "127.0.0.1"
const DEFAULT_CONTROL_PORT = 10532
const MAX_CONTROL_BODY_BYTES = 64 * 1024

const responseHeaders = {
	"Cache-Control": "no-store, private",
	"Content-Type": "application/json; charset=utf-8",
	"X-Content-Type-Options": "nosniff",
} as const

const safeLoginError = (error: unknown): string => {
	const message = error instanceof Error ? error.message : ""
	if (/timed out/i.test(message)) return "Sign-in timed out. Start a new login."
	if (/cancelled/i.test(message)) return "Sign-in cancelled."
	if (/device-code login is not enabled|HTTP 404/i.test(message)) {
		return "Device-code sign-in is unavailable for this account."
	}
	return "Sign-in failed. Start a new login or check the sidecar logs."
}

const closeServer = async (server: HttpServer): Promise<void> => {
	if (!server.listening) return
	server.closeIdleConnections?.()
	await new Promise<void>((resolve, reject) => {
		server.close((error) => (error ? reject(error) : resolve()))
	})
}

export const startOpenAIOAuthControlServer = async (
	options: AuthControlServerOptions,
) => {
	if (Buffer.byteLength(options.token, "utf8") < CONTROL_TOKEN_MIN_LENGTH) {
		throw new Error(
			`The OpenAI OAuth control token must be at least ${CONTROL_TOKEN_MIN_LENGTH} bytes.`,
		)
	}
	const host = options.host ?? DEFAULT_CONTROL_HOST
	const port = options.port ?? DEFAULT_CONTROL_PORT
	const expectedTokenHash = createHash("sha256").update(options.token).digest()
	const fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis)
	let currentLogin: LoginJob | undefined

	const loginSnapshot = (job: LoginJob | undefined) => {
		if (!job) return { state: "idle" as const }
		return {
			id: job.id,
			...(job.state === "awaiting_callback" && job.authorizationUrl
				? { authorizationUrl: job.authorizationUrl }
				: {}),
			state: job.state,
			...(job.state === "awaiting_user" && job.deviceCode
				? {
						verificationUrl: job.deviceCode.verificationUrl,
						userCode: job.deviceCode.userCode,
					}
				: {}),
			...(job.state === "failed" && job.error ? { error: job.error } : {}),
		}
	}

	const credentialsStatus = async () => {
		try {
			const auth = await loadAuthTokens({
				authFilePath: options.authFilePath,
				store: options.store,
				clientId: options.clientId,
				tokenUrl: options.tokenUrl,
				fetch: fetchFn,
				ensureFresh: false,
			})
			const claims = parseJwtClaims(auth.accessToken)
			const expiry =
				claims && typeof claims.exp === "number" && Number.isFinite(claims.exp)
					? new Date(claims.exp * 1000)
					: undefined
			const expiresAt = expiry?.getTime()
			const accessTokenAppearsValid =
				expiresAt !== undefined && expiresAt > Date.now()
			return {
				credentialsConfigured: true,
				...(auth.lastRefresh ? { credentialsUpdatedAt: auth.lastRefresh } : {}),
				...(expiry && Number.isFinite(expiry.getTime())
					? { accessTokenExpiresAt: expiry.toISOString() }
					: {}),
				accessTokenAppearsValid,
				isNearExpiry:
					expiresAt !== undefined &&
					accessTokenAppearsValid &&
					expiresAt <= Date.now() + TOKEN_EXPIRY_WARNING_MS,
				refreshAvailable: Boolean(auth.refreshToken),
			}
		} catch {
			return {
				credentialsConfigured: false,
				accessTokenAppearsValid: false,
				isNearExpiry: false,
				refreshAvailable: false,
			}
		}
	}

	const sendJson = (
		res: import("node:http").ServerResponse,
		status: number,
		body: unknown,
	) => {
		res.writeHead(status, responseHeaders)
		res.end(JSON.stringify(body))
	}

	const readJson = async (
		req: import("node:http").IncomingMessage,
	): Promise<Record<string, unknown>> => {
		const chunks: Buffer[] = []
		let bodyBytes = 0
		for await (const chunk of req) {
			const bytes = Buffer.from(chunk)
			bodyBytes += bytes.length
			if (bodyBytes > MAX_CONTROL_BODY_BYTES) {
				req.resume()
				throw new Error("Request body too large")
			}
			chunks.push(bytes)
		}
		const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"))
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
			throw new Error("Invalid request")
		return parsed as Record<string, unknown>
	}

	const isAuthorized = (authorization: string | undefined): boolean => {
		if (!authorization?.startsWith("Bearer ")) return false
		const provided = authorization.slice("Bearer ".length)
		if (provided.length === 0) return false
		const providedHash = createHash("sha256").update(provided).digest()
		return timingSafeEqual(expectedTokenHash, providedHash)
	}

	const server = createServer(async (req, res) => {
		if (!isAuthorized(req.headers.authorization)) {
			res.setHeader("WWW-Authenticate", 'Bearer realm="openai-oauth-control"')
			sendJson(res, 401, { error: "Unauthorized" })
			return
		}

		const url = new URL(req.url ?? "/", "http://localhost")
		if (req.method === "POST" && url.pathname === "/browser-login") {
			req.resume()
			if ((await credentialsStatus()).credentialsConfigured) {
				sendJson(res, 409, { error: "Sign out before starting a new sign-in." })
				return
			}
			if (
				currentLogin?.state === "starting" ||
				currentLogin?.state === "awaiting_user" ||
				currentLogin?.state === "awaiting_callback"
			) {
				sendJson(res, 409, loginSnapshot(currentLogin))
				return
			}
			const request = await createOpenAIOAuthRequest({
				redirectUri: "http://localhost:1455/auth/callback",
				clientId: options.clientId,
			})
			const job: LoginJob = {
				id: randomBytes(16).toString("hex"),
				state: "awaiting_callback",
				abort: new AbortController(),
				authorizationUrl: request.authorizationUrl,
				stateToken: request.state,
				codeVerifier: request.codeVerifier,
			}
			currentLogin = job
			sendJson(res, 202, loginSnapshot(job))
			return
		}
		const callbackMatch =
			req.method === "POST" &&
			/^\/browser-login\/([a-f0-9]{32})\/callback$/.exec(url.pathname)
		if (callbackMatch) {
			const job = currentLogin
			if (
				!job ||
				job.id !== callbackMatch[1] ||
				job.state !== "awaiting_callback"
			) {
				req.resume()
				sendJson(res, 409, { error: "No pending browser login" })
				return
			}
			try {
				const body = await readJson(req)
				const callback = new URL(String(body.callbackUrl ?? ""))
				if (
					callback.origin !== "http://localhost:1455" ||
					callback.pathname !== "/auth/callback" ||
					callback.searchParams.get("state") !== job.stateToken
				)
					throw new Error("Invalid callback")
				const code = callback.searchParams.get("code")
				if (!code || !job.codeVerifier) throw new Error("Invalid callback")
				const token = await exchangeOpenAIOAuthCode({
					code,
					codeVerifier: job.codeVerifier,
					redirectUri: "http://localhost:1455/auth/callback",
					clientId: options.clientId,
					tokenUrl: options.tokenUrl,
					fetch: fetchFn,
				})
				await saveAuthTokens({
					token,
					authFilePath: options.authFilePath,
					store: options.store,
				})
				job.state = "complete"
				job.stateToken = undefined
				job.codeVerifier = undefined
				job.authorizationUrl = undefined
				sendJson(res, 200, loginSnapshot(job))
			} catch {
				job.state = "failed"
				job.error = "Callback URL was invalid or sign-in failed."
				job.stateToken = undefined
				job.codeVerifier = undefined
				sendJson(res, 400, loginSnapshot(job))
			}
			return
		}
		if (req.method === "GET" && url.pathname === "/status") {
			sendJson(res, 200, {
				...(await credentialsStatus()),
				login: loginSnapshot(currentLogin),
			})
			return
		}

		if (url.pathname === "/api-keys" && req.method === "GET") {
			if (!options.store) {
				sendJson(res, 503, { error: "Encrypted persistence is unavailable." })
				return
			}
			sendJson(res, 200, { keys: options.store.listApiKeys() })
			return
		}

		if (url.pathname === "/api-keys" && req.method === "POST") {
			if (!options.store) {
				req.resume()
				sendJson(res, 503, { error: "Encrypted persistence is unavailable." })
				return
			}
			let body: Record<string, unknown>
			try {
				body = await readJson(req)
			} catch {
				sendJson(res, 400, { error: "Invalid request body." })
				return
			}
			const label = typeof body.label === "string" ? body.label.trim() : ""
			if (
				label.length === 0 ||
				label.length > 64 ||
				label.split("").some((character) => {
					const code = character.charCodeAt(0)
					return code < 32 || code === 127
				})
			) {
				sendJson(res, 400, {
					error: "Label must contain 1–64 printable characters.",
				})
				return
			}
			const apiKey = `sk-oai-oauth-${randomBytes(32).toString("base64url")}`
			const metadata = options.store.createApiKey({
				id: randomBytes(16).toString("hex"),
				label,
				prefix: apiKey.slice(0, 16),
				token: apiKey,
			})
			sendJson(res, 201, { ...metadata, apiKey })
			return
		}

		const apiKeyId = url.pathname.startsWith("/api-keys/")
			? url.pathname.slice("/api-keys/".length)
			: undefined
		if (
			req.method === "DELETE" &&
			apiKeyId &&
			/^[a-f0-9]{32}$/.test(apiKeyId)
		) {
			req.resume()
			if (!options.store) {
				sendJson(res, 503, { error: "Encrypted persistence is unavailable." })
				return
			}
			if (!options.store.revokeApiKey(apiKeyId)) {
				sendJson(res, 404, { error: "API key not found." })
				return
			}
			sendJson(res, 200, { id: apiKeyId, revoked: true })
			return
		}

		if (req.method === "POST" && url.pathname === "/refresh") {
			req.resume()
			if (
				currentLogin?.state === "starting" ||
				currentLogin?.state === "awaiting_user" ||
				currentLogin?.state === "awaiting_callback"
			) {
				sendJson(res, 409, { error: "Sign-in is in progress." })
				return
			}
			try {
				const refreshOptions = {
					authFilePath: options.authFilePath,
					clientId: options.clientId,
					tokenUrl: options.tokenUrl,
					fetch: fetchFn,
					ensureFresh: true,
				}
				const auth = options.store
					? await forceRefreshAuthTokens({
							...refreshOptions,
							store: options.store,
						})
					: await loadAuthTokens(refreshOptions)
				sendJson(res, 200, { credentialsUpdatedAt: auth.lastRefresh })
			} catch {
				sendJson(res, 409, { error: "Refresh failed. Sign in again." })
			}
			return
		}

		if (req.method === "POST" && url.pathname === "/sign-out") {
			req.resume()
			if (
				currentLogin?.state === "starting" ||
				currentLogin?.state === "awaiting_user" ||
				currentLogin?.state === "awaiting_callback"
			) {
				sendJson(res, 409, { error: "Cancel the active sign-in first." })
				return
			}
			await clearAuthTokens({
				authFilePath: options.authFilePath,
				store: options.store,
			})
			sendJson(res, 200, { credentialsConfigured: false })
			return
		}

		if (req.method === "POST" && url.pathname === "/login") {
			req.resume()
			if ((await credentialsStatus()).credentialsConfigured) {
				sendJson(res, 409, { error: "Sign out before starting a new sign-in." })
				return
			}
			if (
				currentLogin?.state === "starting" ||
				currentLogin?.state === "awaiting_user"
			) {
				sendJson(res, 409, loginSnapshot(currentLogin))
				return
			}
			const job: LoginJob = {
				id: randomBytes(16).toString("hex"),
				state: "starting",
				abort: new AbortController(),
			}
			currentLogin = job
			void runOpenAIOAuthDeviceCodeLogin({
				authFilePath: options.authFilePath,
				store: options.store,
				clientId: options.clientId,
				tokenUrl: options.tokenUrl,
				timeoutMs: options.timeoutMs,
				fetch: fetchFn,
				signal: job.abort.signal,
				onMessage: () => undefined,
				onDeviceCode: (deviceCode) => {
					if (currentLogin !== job || job.abort.signal.aborted) return
					job.deviceCode = deviceCode
					job.state = "awaiting_user"
				},
			})
				.then(() => {
					if (currentLogin === job && !job.abort.signal.aborted) {
						job.deviceCode = undefined
						job.state = "complete"
					}
				})
				.catch((error: unknown) => {
					if (currentLogin !== job || job.abort.signal.aborted) return
					job.deviceCode = undefined
					job.error = safeLoginError(error)
					job.state = "failed"
				})
			sendJson(res, 202, loginSnapshot(job))
			return
		}

		const cancelMatch =
			req.method === "POST" &&
			/^\/login\/([a-f0-9]{32})\/cancel$/.exec(url.pathname)
		if (cancelMatch) {
			req.resume()
			const job = currentLogin
			if (!job || job.id !== cancelMatch[1]) {
				sendJson(res, 404, { error: "Login not found" })
				return
			}
			if (job.state !== "starting" && job.state !== "awaiting_user") {
				sendJson(res, 409, loginSnapshot(job))
				return
			}
			job.abort.abort()
			job.deviceCode = undefined
			job.state = "cancelled"
			sendJson(res, 200, loginSnapshot(job))
			return
		}

		req.resume()
		sendJson(res, 404, { error: "Not found" })
	})

	await new Promise<void>((resolve, reject) => {
		server.once("error", reject)
		server.listen(port, host, () => {
			server.off("error", reject)
			resolve()
		})
	})
	const address = server.address() as AddressInfo | null
	if (!address) {
		await closeServer(server)
		throw new Error(
			"OpenAI OAuth control listener address could not be resolved.",
		)
	}
	const actualHost = address.address
	const urlHost = actualHost.includes(":") ? `[${actualHost}]` : actualHost

	return {
		host: actualHost,
		port: address.port,
		url: `http://${urlHost}:${address.port}`,
		close: async () => {
			if (
				currentLogin?.state === "starting" ||
				currentLogin?.state === "awaiting_user"
			) {
				currentLogin.abort.abort()
				currentLogin.state = "cancelled"
				currentLogin.deviceCode = undefined
			}
			await closeServer(server)
		},
	}
}
