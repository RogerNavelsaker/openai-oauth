import { createServer } from "node:http"
import type { AddressInfo } from "node:net"
import {
	createOpenAIOAuth,
	type OpenAIOAuthProvider,
} from "@openai-oauth/ai-sdk"
import {
	createOpenAIOAuthTransport,
	type OpenAIOAuthTransport,
} from "@openai-oauth/core"
import { openaiCredentials } from "@openai-oauth/local"
import { startOpenAIOAuthControlServer } from "./auth-control.js"
import { handleChatCompletionsRequest } from "./chat-completions.js"
import {
	handleImageEditRequest,
	handleImageGenerationRequest,
} from "./images.js"
import { createRequestLogger, createTokenRefreshLogger } from "./logging.js"
import type { OpenAIOAuthModel } from "./models.js"
import { createModelResolver } from "./models.js"
import { handleResponsesRequest } from "./responses.js"
import {
	DEFAULT_HOST,
	DEFAULT_PORT,
	resolveAddress,
	toErrorResponse,
	toJsonResponse,
	toWebRequest,
	writeWebResponse,
} from "./shared.js"
import type {
	OpenAIOAuthServerOptions,
	RunningOpenAIOAuthServer,
} from "./types.js"

const handleRoutes = async (
	request: Request,
	provider: OpenAIOAuthProvider,
	client: OpenAIOAuthTransport,
	resolveModels: () => Promise<OpenAIOAuthModel[]>,
	requestLogger: ReturnType<typeof createRequestLogger>,
): Promise<Response> => {
	const url = new URL(request.url)
	if (request.method === "GET" && url.pathname === "/health") {
		return toJsonResponse({
			ok: true,
			replay_state: "stateless",
		})
	}

	if (request.method === "GET" && url.pathname === "/v1/models") {
		try {
			const models = await resolveModels()
			return toJsonResponse({
				object: "list",
				data: models.map((model) => ({
					...model,
					object: model.object ?? "model",
					created: model.created ?? 0,
					owned_by: model.owned_by ?? "codex-oauth",
				})),
			})
		} catch (error) {
			return toErrorResponse(
				error instanceof Error ? error.message : "Failed to load models.",
				502,
				"upstream_error",
			)
		}
	}

	if (request.method === "POST" && url.pathname === "/v1/responses") {
		return handleResponsesRequest(request, client)
	}

	if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
		return handleChatCompletionsRequest(request, provider, requestLogger)
	}

	if (request.method === "POST" && url.pathname === "/v1/images/generations") {
		return handleImageGenerationRequest(request, client)
	}

	if (request.method === "POST" && url.pathname === "/v1/images/edits") {
		return handleImageEditRequest(request, client)
	}

	return toErrorResponse("Route not found.", 404, "not_found_error")
}

const createOpenAIOAuthRuntime = (settings: OpenAIOAuthServerOptions = {}) => {
	const auth = openaiCredentials({
		...settings,
		onTokenRefreshLog: createTokenRefreshLogger(settings),
	})
	const sharedSettings = {
		...settings,
		auth: () => auth.getSession(),
		responsesState: false as const,
	}
	const client = createOpenAIOAuthTransport(sharedSettings)
	const provider = createOpenAIOAuth(client)
	const resolveModels = createModelResolver(client, settings.models)
	const requestLogger = createRequestLogger(settings)

	const handler = async (request: Request): Promise<Response> => {
		try {
			return await handleRoutes(
				request,
				provider,
				client,
				resolveModels,
				requestLogger,
			)
		} catch (error) {
			return toErrorResponse(
				error instanceof Error ? error.message : "Unexpected server error.",
				500,
				"server_error",
			)
		}
	}

	return { handler, resolveModels }
}

export const createOpenAIOAuthFetchHandler = (
	settings: OpenAIOAuthServerOptions = {},
): ((request: Request) => Promise<Response>) =>
	createOpenAIOAuthRuntime(settings).handler

export const startOpenAIOAuthServer = async (
	settings: OpenAIOAuthServerOptions = {},
): Promise<RunningOpenAIOAuthServer> => {
	const host = settings.host ?? DEFAULT_HOST
	const port = settings.port ?? DEFAULT_PORT
	const runtime = createOpenAIOAuthRuntime(settings)
	const controlServer = settings.authControl
		? await startOpenAIOAuthControlServer({
				...settings.authControl,
				authFilePath: settings.authFilePath,
				store: settings.store,
				clientId: settings.clientId,
				tokenUrl: settings.tokenUrl,
				fetch: settings.fetch,
			})
		: undefined

	try {
		let models: string[]
		if (controlServer) {
			try {
				models = (await runtime.resolveModels()).map((model) => model.id)
			} catch {
				// Keep the login control plane available when credentials are absent or rejected.
				models = []
			}
		} else {
			models = (await runtime.resolveModels()).map((model) => model.id)
		}
		const handler = runtime.handler
		const server = createServer(async (req, res) => {
			try {
				const requestPath = new URL(req.url ?? "/", "http://localhost").pathname
				if (settings.store && requestPath.startsWith("/v1/")) {
					const authorization = req.headers.authorization ?? ""
					const apiKey = authorization.toLowerCase().startsWith("bearer ")
						? authorization.slice(7).trim()
						: ""
					if (!apiKey || !settings.store.verifyApiKey(apiKey)) {
						res.setHeader("WWW-Authenticate", 'Bearer realm="openai-oauth"')
						await writeWebResponse(
							res,
							toJsonResponse(
								{
									error: {
										message: "Invalid API key.",
										type: "authentication_error",
										code: "invalid_api_key",
									},
								},
								401,
							),
						)
						return
					}
				}
				const request = await toWebRequest(req, { host, port })
				const response = await handler(request)
				await writeWebResponse(res, response)
			} catch (error) {
				if (res.headersSent || res.writableEnded) {
					res.destroy(error instanceof Error ? error : undefined)
					return
				}

				const message =
					error instanceof Error ? error.message : "Unexpected server error."
				await writeWebResponse(
					res,
					toErrorResponse(message, 500, "server_error"),
				)
			}
		})

		await new Promise<void>((resolve, reject) => {
			server.once("error", reject)
			server.listen(port, host, () => {
				server.off("error", reject)
				resolve()
			})
		})

		const address = resolveAddress(server.address() as AddressInfo, host)
		return {
			server,
			host: address.host,
			port: address.port,
			url: `http://${address.host}:${address.port}/v1`,
			...(controlServer ? { controlUrl: controlServer.url } : {}),
			models,
			close: async () => {
				try {
					await controlServer?.close()
				} finally {
					if (server.listening) {
						await new Promise<void>((resolve, reject) => {
							server.close((error) => (error ? reject(error) : resolve()))
						})
					}
				}
			},
		}
	} catch (error) {
		await controlServer?.close().catch(() => undefined)
		throw error
	}
}
