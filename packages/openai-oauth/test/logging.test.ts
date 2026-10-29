import { afterEach, describe, expect, test, vi } from "vitest"
import { createTokenRefreshLogger } from "../src/logging.js"

afterEach(() => {
	vi.unstubAllEnvs()
	vi.restoreAllMocks()
})

describe("token refresh logging", () => {
	test("is disabled unless explicitly enabled", () => {
		vi.stubEnv("CODEX_OPENAI_SERVER_LOG_TOKEN_REFRESH", "")
		expect(createTokenRefreshLogger({})).toBeUndefined()
	})

	test("writes structured refresh events when enabled", () => {
		vi.stubEnv("CODEX_OPENAI_SERVER_LOG_TOKEN_REFRESH", "1")
		const output = vi.spyOn(console, "log").mockImplementation(() => {})
		const logger = createTokenRefreshLogger({})

		logger?.({
			type: "token_refresh_failed",
			durationMs: 12,
			errorName: "Error",
			status: 401,
			oauthErrorCode: "invalid_grant",
		})

		const entry = JSON.parse(String(output.mock.calls[0]?.[0]))
		expect(entry).toMatchObject({
			source: "openai-oauth",
			type: "token_refresh_failed",
			durationMs: 12,
			status: 401,
			oauthErrorCode: "invalid_grant",
		})
		expect(entry.timestamp).toMatch(/Z$/)
	})
})
