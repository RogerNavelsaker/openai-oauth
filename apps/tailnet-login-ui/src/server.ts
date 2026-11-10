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
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import {
	type ControlStatus,
	type LoginState,
	renderPage,
	renderStatus,
} from "./views.js"

export type LoginUiOptions = {
	host?: string
	port?: number
	controlUrl: string
	controlToken: string
	publicOrigin: string
	fetch?: typeof fetch
}

type NormalizedOptions = {
	host: string
	port: number
	controlUrl: string
	controlToken: string
	publicOrigin: string
	fetch: typeof fetch
}

const DEFAULT_HOST = "127.0.0.1"
const DEFAULT_PORT = 10533
const CSRF_COOKIE = "oauth_login_csrf"
const ALLOWED_STATES = new Set<LoginState>([
	"idle",
	"starting",
	"awaiting_user",
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
	"Referrer-Policy": "no-referrer",
	"X-Content-Type-Options": "nosniff",
	"X-Frame-Options": "DENY",
} as const

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value)

const normalizeOptions = (options: LoginUiOptions): NormalizedOptions => {
	if (Buffer.byteLength(options.controlToken, "utf8") < 32) {
		throw new Error("SIDECAR_CONTROL_TOKEN must be at least 32 bytes.")
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
	if (state === "failed") {
		login.error =
			typeof value.login.error === "string" &&
			ALLOWED_LOGIN_ERRORS.has(value.login.error)
				? value.login.error
				: "Sign-in failed. Start a new login or check the sidecar logs."
	}
	return { credentialsConfigured: value.credentialsConfigured, login }
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
		if (req.method === "GET" && url.pathname === "/") {
			const csrf = csrfForRequest(req, res, options)
			try {
				send(res, 200, renderPage(csrf, await fetchStatus(options)))
			} catch {
				send(res, 200, renderPage(csrf, undefined, true))
			}
			return
		}
		if (req.method === "GET" && url.pathname === "/_status") {
			const csrf = csrfForRequest(req, res, options)
			try {
				send(res, 200, renderStatus(csrf, await fetchStatus(options)))
			} catch {
				send(res, 200, renderStatus(csrf, undefined, true))
			}
			return
		}
		if (
			req.method === "POST" &&
			["/_start", "/_cancel"].includes(url.pathname)
		) {
			const form = await isValidPost(req, options)
			if (!form) {
				send(res, 403, "Forbidden", "text/plain; charset=utf-8")
				return
			}
			try {
				if (url.pathname === "/_start") {
					const response = await options.fetch(`${options.controlUrl}/login`, {
						method: "POST",
						headers: { Authorization: `Bearer ${options.controlToken}` },
					})
					if (response.status !== 202 && response.status !== 409) {
						throw new Error("control service unavailable")
					}
				} else {
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
				}
				const csrf = csrfForRequest(req, res, options)
				try {
					send(res, 200, renderStatus(csrf, await fetchStatus(options)))
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

const optionsFromEnv = (): LoginUiOptions => {
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
	return {
		host: process.env.LOGIN_UI_HOST ?? DEFAULT_HOST,
		port,
		controlUrl: process.env.SIDECAR_CONTROL_URL ?? "http://127.0.0.1:10532",
		controlToken,
		publicOrigin,
	}
}

if (
	process.argv[1] &&
	resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
	const server = await startLoginUiServer(optionsFromEnv())
	console.log(`Tailnet OAuth login UI listening at ${server.url}`)
}
