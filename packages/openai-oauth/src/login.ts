import { spawn } from "node:child_process"
import type { IncomingMessage, Server, ServerResponse } from "node:http"
import { createServer } from "node:http"
import { type AddressInfo, createConnection } from "node:net"
import {
	createOpenAIOAuthRequest,
	DEFAULT_OPENAI_OAUTH_CLIENT_ID,
	DEFAULT_OPENAI_OAUTH_ISSUER,
	exchangeOpenAIOAuthCode,
} from "@openai-oauth/core"
import {
	type SavedAuthTokens,
	saveAuthTokens,
} from "@openai-oauth/local/auth-file"
import callbackSuccessHtml from "./callback-success.html?raw"

const DEFAULT_LOGIN_REDIRECT_HOST = "localhost"
const DEFAULT_LOGIN_PORT = 1455
const DEFAULT_LOGIN_TIMEOUT_MS = 5 * 60 * 1000
const LOOPBACK_LISTEN_HOSTS = ["::1", "127.0.0.1"] as const

const isAddressInUseError = (
	error: unknown,
): error is Error & { code: string } =>
	error instanceof Error &&
	"code" in error &&
	(error as { code?: unknown }).code === "EADDRINUSE"

const isAddressUnavailableError = (
	error: unknown,
): error is Error & { code: string } =>
	error instanceof Error &&
	"code" in error &&
	["EADDRNOTAVAIL", "EAFNOSUPPORT"].includes(
		String((error as { code?: unknown }).code),
	)

export type OpenAIOAuthLoginOptions = {
	host?: string
	redirectHost?: string
	clientId?: string
	tokenUrl?: string
	authFilePath?: string
	openBrowser?: boolean
	timeoutMs?: number
	fetch?: typeof fetch
	onMessage?: (message: string) => void
	signal?: AbortSignal
}

type CallbackResult = {
	code: string
}

type LoginServer = Server<typeof IncomingMessage, typeof ServerResponse>

const createLoginCancelledError = (): Error =>
	new Error("OpenAI OAuth login cancelled.")

const toCallbackHtml = (title: string, message: string): string =>
	callbackSuccessHtml
		.replace("Sign-in complete", title)
		.replace(
			/Your ChatGPT credentials are saved locally\. You can close this\s+window and return to your terminal\./,
			message,
		)

const htmlHeaders = {
	"Content-Type": "text/html; charset=utf-8",
	Connection: "close",
} as const

const textHeaders = {
	"Content-Type": "text/plain; charset=utf-8",
	Connection: "close",
} as const

const openUrl = (url: string): void => {
	const platform = process.platform
	const command =
		platform === "darwin" ? "open" : platform === "win32" ? "cmd" : "xdg-open"
	const args = platform === "win32" ? ["/c", "start", '""', url] : [url]
	const child = spawn(command, args, {
		detached: true,
		stdio: "ignore",
	})
	child.on("error", () => undefined)
	child.unref()
}

const toCallbackPortInUseMessage = (
	redirectHost: string,
	port: number,
): string =>
	`OpenAI OAuth login needs http://${redirectHost}:${port}/auth/callback, but port ${port} is already in use. Stop the process using that port and try again.`

const listen = (
	server: LoginServer,
	port: number,
	host: string,
): Promise<void> =>
	new Promise((resolve, reject) => {
		server.once("error", reject)
		const onListening = () => {
			server.off("error", reject)
			resolve()
		}
		server.listen(port, host, onListening)
	})

const closeServers = async (servers: LoginServer[]): Promise<void> => {
	await Promise.all(servers.map((server) => closeServer(server)))
}

const listenOnCallbackPort = async (
	handler: (req: IncomingMessage, res: ServerResponse) => void,
	port: number,
	host: string | undefined,
): Promise<LoginServer[]> => {
	if (host) {
		const server = createServer(handler)
		await listen(server, port, host)
		return [server]
	}

	const servers: LoginServer[] = []
	for (const loopbackHost of LOOPBACK_LISTEN_HOSTS) {
		const server = createServer(handler)
		try {
			await listen(server, port, loopbackHost)
			servers.push(server)
		} catch (error) {
			await closeServer(server)
			if (isAddressUnavailableError(error)) {
				continue
			}
			await closeServers(servers)
			throw error
		}
	}

	if (servers.length === 0) {
		throw new Error("No loopback address is available for OpenAI OAuth login.")
	}

	return servers
}

const closeServer = (server: LoginServer): Promise<void> =>
	new Promise((resolve, reject) => {
		if (!server.listening) {
			resolve()
			return
		}

		server.close((error) => {
			if (error) {
				reject(error)
				return
			}
			resolve()
		})
		server.closeIdleConnections?.()
	})

const isCallbackHostReachable = (
	host: string,
	port: number,
	timeoutMs = 100,
): Promise<boolean> =>
	new Promise((resolve) => {
		let settled = false
		const socket = createConnection({ host, port })
		const settle = (value: boolean) => {
			if (settled) {
				return
			}
			settled = true
			socket.destroy()
			resolve(value)
		}

		socket.setTimeout(timeoutMs)
		socket.once("connect", () => settle(true))
		socket.once("error", () => settle(false))
		socket.once("timeout", () => settle(false))
	})

export const runOpenAIOAuthLogin = async (
	options: OpenAIOAuthLoginOptions = {},
): Promise<SavedAuthTokens> => {
	if (options.signal?.aborted) {
		throw createLoginCancelledError()
	}

	const redirectHost = options.redirectHost ?? DEFAULT_LOGIN_REDIRECT_HOST
	const listenHost = options.host
	const callbackPort = DEFAULT_LOGIN_PORT
	const timeoutMs = options.timeoutMs ?? DEFAULT_LOGIN_TIMEOUT_MS
	const onMessage = options.onMessage ?? console.log

	let expectedState = ""
	let redirectUri = ""
	let servers: LoginServer[] = []
	let settleCallback: ((result: CallbackResult) => void) | undefined
	let rejectCallback: ((error: Error) => void) | undefined
	let rejectAbort: ((error: Error) => void) | undefined

	const callbackPromise = new Promise<CallbackResult>((resolve, reject) => {
		settleCallback = resolve
		rejectCallback = reject
	})
	const abortPromise = new Promise<never>((_, reject) => {
		rejectAbort = reject
	})
	const abortLogin = () => {
		rejectAbort?.(createLoginCancelledError())
	}
	options.signal?.addEventListener("abort", abortLogin, { once: true })

	const handleCallbackRequest = (
		req: IncomingMessage,
		res: ServerResponse,
	): void => {
		const url = new URL(req.url ?? "/", redirectUri || `http://${redirectHost}`)
		if (url.pathname === "/cancel") {
			res.writeHead(200, textHeaders)
			res.end("Cancelled")
			rejectCallback?.(new Error("OpenAI OAuth login cancelled."))
			return
		}

		if (url.pathname !== "/auth/callback") {
			res.writeHead(404, textHeaders)
			res.end("Not found")
			return
		}

		const error = url.searchParams.get("error")
		if (error) {
			res.writeHead(400, htmlHeaders)
			res.end(
				toCallbackHtml(
					"OpenAI OAuth login failed",
					"You can close this window and return to the terminal.",
				),
			)
			rejectCallback?.(new Error(`OpenAI OAuth login failed: ${error}`))
			return
		}

		const state = url.searchParams.get("state")
		const code = url.searchParams.get("code")
		if (!code || state !== expectedState) {
			res.writeHead(400, htmlHeaders)
			res.end(
				toCallbackHtml(
					"OpenAI OAuth login failed",
					"You can close this window and return to the terminal.",
				),
			)
			rejectCallback?.(new Error("OpenAI OAuth callback was invalid."))
			return
		}

		res.writeHead(200, htmlHeaders)
		res.end(callbackSuccessHtml)
		settleCallback?.({ code })
	}

	if (await isCallbackHostReachable(redirectHost, callbackPort)) {
		throw new Error(toCallbackPortInUseMessage(redirectHost, callbackPort))
	}

	try {
		servers = await listenOnCallbackPort(
			handleCallbackRequest,
			callbackPort,
			listenHost,
		)
		const address = servers[0]?.address() as AddressInfo | null
		if (address?.port !== callbackPort) {
			throw new Error("OpenAI OAuth login callback port could not be resolved.")
		}
	} catch (error) {
		if (isAddressInUseError(error)) {
			throw new Error(toCallbackPortInUseMessage(redirectHost, callbackPort))
		}
		throw error
	}

	try {
		redirectUri = `http://${redirectHost}:${callbackPort}/auth/callback`
		if (options.signal?.aborted) {
			throw createLoginCancelledError()
		}
		const request = await createOpenAIOAuthRequest({
			redirectUri,
			clientId: options.clientId,
		})
		expectedState = request.state

		onMessage(`OpenAI OAuth login URL: ${request.authorizationUrl}`)
		if (options.openBrowser !== false) {
			openUrl(request.authorizationUrl)
		}

		const timeout = new Promise<never>((_, reject) => {
			setTimeout(() => {
				reject(new Error("OpenAI OAuth login timed out."))
			}, timeoutMs).unref()
		})
		const callback = await Promise.race([
			callbackPromise,
			timeout,
			abortPromise,
		])
		const token = await exchangeOpenAIOAuthCode({
			code: callback.code,
			codeVerifier: request.codeVerifier,
			redirectUri,
			clientId: options.clientId,
			tokenUrl: options.tokenUrl,
			fetch: options.fetch,
			signal: options.signal,
		})
		const saved = await saveAuthTokens({
			token,
			authFilePath: options.authFilePath,
		})

		onMessage(`Credentials saved to ${saved.path}`)
		return saved
	} finally {
		options.signal?.removeEventListener("abort", abortLogin)
		await closeServers(servers)
	}
}

const DEFAULT_DEVICE_LOGIN_TIMEOUT_MS = 15 * 60 * 1000
const DEFAULT_DEVICE_POLL_INTERVAL_MS = 5000

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value)

const parseDeviceResponse = async (
	response: Response,
	message: string,
): Promise<Record<string, unknown>> => {
	let payload: unknown
	try {
		payload = await response.json()
	} catch {
		throw new Error(message)
	}
	if (!isRecord(payload)) {
		throw new Error(message)
	}
	return payload
}

const nonEmptyString = (value: unknown): string | undefined =>
	typeof value === "string" && value.trim().length > 0
		? value.trim()
		: undefined

const waitForDevicePoll = (
	timeoutMs: number,
	signal: AbortSignal,
): Promise<void> =>
	new Promise((resolve, reject) => {
		if (signal.aborted) {
			reject(createLoginCancelledError())
			return
		}

		const cleanup = () => signal.removeEventListener("abort", onAbort)
		const timer = setTimeout(() => {
			cleanup()
			resolve()
		}, timeoutMs)
		const onAbort = () => {
			clearTimeout(timer)
			cleanup()
			reject(createLoginCancelledError())
		}
		signal.addEventListener("abort", onAbort, { once: true })
	})

export const runOpenAIOAuthDeviceCodeLogin = async (
	options: OpenAIOAuthLoginOptions = {},
): Promise<SavedAuthTokens> => {
	if (options.signal?.aborted) {
		throw createLoginCancelledError()
	}

	const issuer = DEFAULT_OPENAI_OAUTH_ISSUER.replace(/\/+$/, "")
	const clientId = options.clientId ?? DEFAULT_OPENAI_OAUTH_CLIENT_ID
	// The server-issued device code expires after 15 minutes.
	const timeoutMs = Math.min(
		options.timeoutMs ?? DEFAULT_DEVICE_LOGIN_TIMEOUT_MS,
		DEFAULT_DEVICE_LOGIN_TIMEOUT_MS,
	)
	const fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis)
	const onMessage = options.onMessage ?? console.log
	const controller = new AbortController()
	let timedOut = false
	const onAbort = () => controller.abort()
	options.signal?.addEventListener("abort", onAbort, { once: true })
	const timeout = setTimeout(() => {
		timedOut = true
		controller.abort()
	}, timeoutMs)
	const signal = controller.signal

	try {
		const userCodeResponse = await fetchFn(
			`${issuer}/api/accounts/deviceauth/usercode`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ client_id: clientId }),
				signal,
			},
		)
		if (userCodeResponse.status === 404) {
			throw new Error(
				"OpenAI device-code login is not enabled by the auth server (HTTP 404). Use `openai-oauth login` in a browser-capable environment and mount the resulting auth.json.",
			)
		}
		if (!userCodeResponse.ok) {
			throw new Error(
				`OpenAI device-code request failed with HTTP ${userCodeResponse.status}.`,
			)
		}

		const userCodePayload = await parseDeviceResponse(
			userCodeResponse,
			"OpenAI device-code response was not valid JSON.",
		)
		const deviceAuthId = nonEmptyString(userCodePayload.device_auth_id)
		const userCode =
			nonEmptyString(userCodePayload.user_code) ??
			nonEmptyString(userCodePayload.usercode)
		if (!deviceAuthId || !userCode) {
			throw new Error("OpenAI device-code response was incomplete.")
		}

		const interval = Number(userCodePayload.interval)
		const pollIntervalMs =
			Number.isFinite(interval) && interval > 0
				? interval * 1000
				: DEFAULT_DEVICE_POLL_INTERVAL_MS
		const deadline = Date.now() + timeoutMs
		const verificationUrl = `${issuer}/codex/device`
		onMessage(
			[
				"Open the OpenAI device sign-in page and enter this one-time code:",
				verificationUrl,
				userCode,
				`Continue only if you started this login. The process waits for up to ${Math.ceil(timeoutMs / 60_000)} minutes.`,
			].join("\n"),
		)

		let authorizationCode: string | undefined
		let codeVerifier: string | undefined
		while (!authorizationCode || !codeVerifier) {
			const tokenResponse = await fetchFn(
				`${issuer}/api/accounts/deviceauth/token`,
				{
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({
						device_auth_id: deviceAuthId,
						user_code: userCode,
					}),
					signal,
				},
			)
			if (tokenResponse.status === 403 || tokenResponse.status === 404) {
				const remainingMs = deadline - Date.now()
				if (remainingMs <= 0) {
					throw new Error("OpenAI OAuth device-code login timed out.")
				}
				await waitForDevicePoll(Math.min(pollIntervalMs, remainingMs), signal)
				continue
			}
			if (!tokenResponse.ok) {
				throw new Error(
					`OpenAI device-code polling failed with HTTP ${tokenResponse.status}.`,
				)
			}

			const tokenPayload = await parseDeviceResponse(
				tokenResponse,
				"OpenAI device-code token response was not valid JSON.",
			)
			authorizationCode = nonEmptyString(tokenPayload.authorization_code)
			codeVerifier = nonEmptyString(tokenPayload.code_verifier)
			if (!authorizationCode || !codeVerifier) {
				throw new Error("OpenAI device-code token response was incomplete.")
			}
		}

		const token = await exchangeOpenAIOAuthCode({
			code: authorizationCode,
			codeVerifier,
			redirectUri: `${issuer}/deviceauth/callback`,
			clientId,
			tokenUrl: options.tokenUrl,
			fetch: fetchFn,
			signal,
		})
		if (timedOut) {
			throw new Error("OpenAI OAuth device-code login timed out.")
		}
		const saved = await saveAuthTokens({
			token,
			authFilePath: options.authFilePath,
		})
		onMessage(`Credentials saved to ${saved.path}`)
		return saved
	} catch (error) {
		if (options.signal?.aborted) {
			throw createLoginCancelledError()
		}
		if (timedOut) {
			throw new Error("OpenAI OAuth device-code login timed out.")
		}
		throw error
	} finally {
		clearTimeout(timeout)
		options.signal?.removeEventListener("abort", onAbort)
	}
}
