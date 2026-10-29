import type { LocalOpenAIOAuthOptions } from "@openai-oauth/local"
import type {
	OpenAIOAuthServerLogEvent,
	OpenAIOAuthServerOptions,
} from "./types.js"

type TokenRefreshLogEvent = Parameters<
	NonNullable<LocalOpenAIOAuthOptions["onTokenRefreshLog"]>
>[0]

export const createRequestLogger = (
	settings: OpenAIOAuthServerOptions,
): ((event: OpenAIOAuthServerLogEvent) => void) | undefined => {
	if (typeof settings.requestLogger === "function") {
		return settings.requestLogger
	}

	if (process.env.CODEX_OPENAI_SERVER_LOG_REQUESTS !== "1") {
		return undefined
	}

	return (event) => {
		console.log(
			JSON.stringify({
				source: "openai-oauth",
				timestamp: new Date().toISOString(),
				...event,
			}),
		)
	}
}

export const createTokenRefreshLogger = (
	settings: Pick<LocalOpenAIOAuthOptions, "onTokenRefreshLog">,
): ((event: TokenRefreshLogEvent) => void) | undefined => {
	if (typeof settings.onTokenRefreshLog === "function") {
		return settings.onTokenRefreshLog
	}

	if (process.env.CODEX_OPENAI_SERVER_LOG_TOKEN_REFRESH !== "1") {
		return undefined
	}

	return (event) => {
		console.log(
			JSON.stringify({
				source: "openai-oauth",
				timestamp: new Date().toISOString(),
				...event,
			}),
		)
	}
}

export const emitRequestLog = (
	logger: ((event: OpenAIOAuthServerLogEvent) => void) | undefined,
	event: OpenAIOAuthServerLogEvent,
) => {
	try {
		logger?.(event)
	} catch {}
}
