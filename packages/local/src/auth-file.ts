import { promises as fs } from "node:fs"
import os from "node:os"
import path from "node:path"
import {
	deriveAccountId,
	deriveChatGptAccountIsFedRamp,
	type FetchFunction,
	type OpenAIOAuthTokenResponse,
	parseJwtClaims,
	refreshOpenAIOAuthTokens,
} from "@openai-oauth/core"
import lockfile from "proper-lockfile"

const AUTH_FILENAME = "auth.json"
const REFRESH_EXPIRY_MARGIN_MS = 5 * 60 * 1000
const REFRESH_INTERVAL_MS = 55 * 60 * 1000

type StoredTokens = {
	id_token?: string
	access_token?: string
	refresh_token?: string
	account_id?: string
}

type AuthFile = {
	[key: string]: unknown
	OPENAI_API_KEY?: string
	tokens?: StoredTokens
	last_refresh?: string
}

export type EffectiveAuth = {
	accessToken: string
	accountId: string
	isFedRamp?: boolean
	idToken?: string
	refreshToken?: string
	sourcePath?: string
	lastRefresh?: string
}

type RefreshReason =
	| "access_token_missing"
	| "access_token_expiring"
	| "refresh_interval_elapsed"

type RefreshLogContext = {
	refreshReason: RefreshReason
	lastRefreshAgeMs?: number
	accessTokenExpiresAt?: string
	accessTokenSecondsUntilExpiry?: number
}

type TokenRefreshLogEvent =
	| ({ type: "token_refresh_started" } & RefreshLogContext)
	| ({
			type: "token_refresh_succeeded"
			durationMs: number
	  } & RefreshLogContext)
	| ({
			type: "token_refresh_failed"
			durationMs: number
			errorName: string
			status?: number
			oauthErrorCode?: string
			errorDescription?: string
			responseBodyBytes?: number
			responseContentType?: string
			oauthRequestId?: string
	  } & RefreshLogContext)

export type AuthLoaderOptions = {
	clientId?: string
	issuer?: string
	tokenUrl?: string
	authFilePath?: string
	fetch: FetchFunction
	ensureFresh?: boolean
	now?: () => Date
	onTokenRefreshLog?: (event: TokenRefreshLogEvent) => void
}

export type SaveAuthTokensOptions = {
	token: OpenAIOAuthTokenResponse
	authFilePath?: string
	now?: () => Date
}

export type SavedAuthTokens = {
	path: string
	auth: EffectiveAuth
}

type AuthReadResult = {
	path?: string
	data?: AuthFile
}

const refreshes = new Map<string, Promise<EffectiveAuth>>()

const emitTokenRefreshLog = (
	logger: AuthLoaderOptions["onTokenRefreshLog"],
	event: TokenRefreshLogEvent,
): void => {
	try {
		logger?.(event)
	} catch {}
}

type RefreshOutcome = {
	accessToken: string
	idToken?: string
	refreshToken?: string
	accountId?: string
	isFedRamp?: boolean
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value)

const parseIsoDate = (value: string | undefined): Date | undefined => {
	if (typeof value !== "string" || !value) {
		return undefined
	}
	const date = new Date(value)
	return Number.isNaN(date.getTime()) ? undefined : date
}

const getRefreshContext = (
	accessToken: string | undefined,
	lastRefresh: string | undefined,
	now: Date,
): RefreshLogContext | undefined => {
	const refreshedAt = parseIsoDate(lastRefresh)
	const lastRefreshAgeMs = refreshedAt
		? now.getTime() - refreshedAt.getTime()
		: undefined
	const claims = accessToken ? parseJwtClaims(accessToken) : undefined
	const exp = claims && typeof claims.exp === "number" ? claims.exp : undefined
	const expiryMs = exp === undefined ? undefined : exp * 1000
	const expiryDate =
		expiryMs !== undefined &&
		Number.isFinite(expiryMs) &&
		Math.abs(expiryMs) <= 8.64e15
			? new Date(expiryMs).toISOString()
			: undefined
	const context = {
		...(lastRefreshAgeMs === undefined ? {} : { lastRefreshAgeMs }),
		...(expiryDate === undefined ? {} : { accessTokenExpiresAt: expiryDate }),
		...(expiryMs === undefined || !Number.isFinite(expiryMs)
			? {}
			: {
					accessTokenSecondsUntilExpiry: Math.floor(
						(expiryMs - now.getTime()) / 1000,
					),
				}),
	}

	if (!accessToken) {
		return { refreshReason: "access_token_missing", ...context }
	}
	if (
		expiryMs !== undefined &&
		Number.isFinite(expiryMs) &&
		expiryMs <= now.getTime() + REFRESH_EXPIRY_MARGIN_MS
	) {
		return { refreshReason: "access_token_expiring", ...context }
	}
	if (
		expiryMs === undefined &&
		lastRefreshAgeMs !== undefined &&
		lastRefreshAgeMs >= REFRESH_INTERVAL_MS
	) {
		return { refreshReason: "refresh_interval_elapsed", ...context }
	}
	return undefined
}

const uniquePaths = (paths: string[]): string[] => {
	const seen = new Set<string>()
	const result: string[] = []

	for (const candidate of paths) {
		if (!seen.has(candidate)) {
			seen.add(candidate)
			result.push(candidate)
		}
	}

	return result
}

export const resolveAuthFileCandidates = (authFilePath?: string): string[] => {
	if (typeof authFilePath === "string" && authFilePath.length > 0) {
		return [authFilePath]
	}

	const codexHome = process.env.CODEX_HOME

	return uniquePaths(
		[
			authFilePath,
			codexHome ? path.join(codexHome, AUTH_FILENAME) : undefined,
			path.join(os.homedir(), ".codex", AUTH_FILENAME),
		].filter(
			(value): value is string => typeof value === "string" && value.length > 0,
		),
	)
}

const resolveWritePath = (preferred: string | undefined): string => {
	if (preferred) {
		return preferred
	}

	const envHome = process.env.CODEX_HOME
	if (envHome) {
		return path.join(envHome, AUTH_FILENAME)
	}

	return path.join(os.homedir(), ".codex", AUTH_FILENAME)
}

const toAuthFile = (input: Record<string, unknown>): AuthFile => {
	const auth: AuthFile = { ...input }
	const tokensValue = input.tokens

	if (typeof input.OPENAI_API_KEY === "string" && input.OPENAI_API_KEY) {
		auth.OPENAI_API_KEY = input.OPENAI_API_KEY
	} else {
		delete auth.OPENAI_API_KEY
	}

	if (isRecord(tokensValue) && Object.keys(tokensValue).length > 0) {
		auth.tokens = {
			id_token:
				typeof tokensValue.id_token === "string"
					? tokensValue.id_token
					: undefined,
			access_token:
				typeof tokensValue.access_token === "string"
					? tokensValue.access_token
					: undefined,
			refresh_token:
				typeof tokensValue.refresh_token === "string"
					? tokensValue.refresh_token
					: undefined,
			account_id:
				typeof tokensValue.account_id === "string"
					? tokensValue.account_id
					: undefined,
		}
	} else {
		delete auth.tokens
	}

	if (typeof input.last_refresh === "string" && input.last_refresh) {
		auth.last_refresh = input.last_refresh
	} else {
		delete auth.last_refresh
	}

	return auth
}

const readAuthFile = async (candidates: string[]): Promise<AuthReadResult> => {
	for (const candidate of candidates) {
		try {
			const content = await fs.readFile(candidate, "utf-8")
			const parsed = JSON.parse(content)
			if (isRecord(parsed)) {
				return { path: candidate, data: toAuthFile(parsed) }
			}
			throw new Error(`Auth file at ${candidate} must contain a JSON object.`)
		} catch (error) {
			if (
				typeof error === "object" &&
				error !== null &&
				"code" in error &&
				error.code === "ENOENT"
			) {
				continue
			}
			if (error instanceof SyntaxError) {
				throw new Error(`Auth file at ${candidate} is not valid JSON.`, {
					cause: error,
				})
			}
			throw error
		}
	}

	return {}
}

const ensureDirectory = async (filePath: string): Promise<void> => {
	await fs.mkdir(path.dirname(filePath), { recursive: true })
}

const writeAuthFile = async (
	filePath: string,
	data: AuthFile,
): Promise<void> => {
	await ensureDirectory(filePath)
	await fs.writeFile(filePath, JSON.stringify(data, null, 2), {
		encoding: "utf-8",
		mode: 0o600,
	})
}

const withAuthFileLock = async <T>(
	filePath: string,
	action: (assertLock: () => void) => Promise<T>,
): Promise<T> => {
	await ensureDirectory(filePath)
	try {
		await fs.writeFile(filePath, "{}", {
			encoding: "utf-8",
			flag: "wx",
			mode: 0o600,
		})
	} catch (error) {
		if (!isRecord(error) || error.code !== "EEXIST") throw error
	}

	let compromisedError: Error | undefined
	const release = await lockfile.lock(filePath, {
		realpath: false,
		retries: {
			retries: 10,
			factor: 2,
			minTimeout: 100,
			maxTimeout: 1000,
			randomize: true,
		},
		stale: 30_000,
		update: 10_000,
		onCompromised: (error) => {
			compromisedError = error
		},
	})
	const assertLock = (): void => {
		if (compromisedError) throw compromisedError
	}

	let result!: T
	let actionError: unknown
	let actionFailed = false
	try {
		result = await action(assertLock)
		assertLock()
	} catch (error) {
		actionError = error
		actionFailed = true
	}

	let releaseError: unknown
	let releaseFailed = false
	try {
		await release()
	} catch (error) {
		if (!compromisedError) {
			releaseError = error
			releaseFailed = true
		}
	}
	if (actionFailed) throw actionError
	if (releaseFailed) throw releaseError
	assertLock()
	return result
}

export const resolveCodexAuthFilePath = (authFilePath?: string): string => {
	if (authFilePath) {
		return authFilePath
	}

	const codexHome = process.env.CODEX_HOME
	return path.join(
		codexHome ?? path.join(os.homedir(), ".codex"),
		AUTH_FILENAME,
	)
}

export const saveAuthTokens = async (
	options: SaveAuthTokensOptions,
): Promise<SavedAuthTokens> => {
	const filePath = resolveCodexAuthFilePath(options.authFilePath)
	const accountId =
		options.token.accountId ??
		deriveAccountId(options.token.idToken) ??
		deriveAccountId(options.token.accessToken)

	if (!accountId) {
		throw new Error(
			"ChatGPT account id not found in OpenAI OAuth token response.",
		)
	}

	return withAuthFileLock(filePath, async (assertLock) => {
		const existing = (await readAuthFile([filePath])).data ?? {}
		const now = options.now ?? (() => new Date())
		const savedAt = now().toISOString()

		assertLock()
		await writeAuthFile(filePath, {
			...existing,
			auth_mode: "chatgpt",
			tokens: {
				id_token: options.token.idToken,
				access_token: options.token.accessToken,
				refresh_token: options.token.refreshToken,
				account_id: accountId,
			},
			last_refresh: savedAt,
		})

		return {
			path: filePath,
			auth: {
				accessToken: options.token.accessToken,
				accountId,
				isFedRamp: options.token.isFedRamp,
				idToken: options.token.idToken,
				refreshToken: options.token.refreshToken,
				sourcePath: filePath,
				lastRefresh: savedAt,
			},
		}
	})
}

const refreshChatGptTokens = async (
	refreshToken: string,
	clientId: string | undefined,
	issuer: string | undefined,
	tokenUrl: string | undefined,
	fetchFn: FetchFunction,
): Promise<RefreshOutcome> => {
	const refreshed = await refreshOpenAIOAuthTokens({
		refreshToken,
		clientId,
		issuer,
		tokenUrl,
		fetch: fetchFn,
	})

	return {
		accessToken: refreshed.accessToken,
		idToken: refreshed.idToken,
		refreshToken: refreshed.refreshToken ?? refreshToken,
		accountId: refreshed.accountId,
		isFedRamp: refreshed.isFedRamp,
	}
}

const normalizeTokens = (tokens: StoredTokens | undefined): StoredTokens => {
	const maybeString = (value: unknown): string | undefined =>
		typeof value === "string" && value.length > 0 ? value : undefined

	return {
		id_token: maybeString(tokens?.id_token),
		access_token: maybeString(tokens?.access_token),
		refresh_token: maybeString(tokens?.refresh_token),
		account_id: maybeString(tokens?.account_id),
	}
}

export const loadAuthTokens = async (
	options: AuthLoaderOptions,
): Promise<EffectiveAuth> => {
	const {
		clientId,
		issuer,
		tokenUrl,
		authFilePath,
		fetch,
		ensureFresh = true,
		now = () => new Date(),
		onTokenRefreshLog,
	} = options

	if (typeof fetch !== "function") {
		throw new Error(
			"A fetch implementation is required to refresh ChatGPT tokens.",
		)
	}

	const candidates = resolveAuthFileCandidates(authFilePath)
	const readResult = await readAuthFile(candidates)
	const authData = readResult.data ?? {}
	const tokens = normalizeTokens(authData.tokens)

	let accessToken = tokens.access_token
	let idToken = tokens.id_token
	let refreshToken = tokens.refresh_token
	let accountId = tokens.account_id ?? deriveAccountId(idToken)
	let isFedRamp =
		deriveChatGptAccountIsFedRamp(idToken) ||
		deriveChatGptAccountIsFedRamp(accessToken)
	let lastRefresh = authData.last_refresh

	const refreshLogContext =
		ensureFresh && typeof refreshToken === "string"
			? getRefreshContext(accessToken, lastRefresh, now())
			: undefined

	if (refreshLogContext && typeof refreshToken === "string") {
		const lockPath = path.resolve(
			readResult.path ?? resolveWritePath(authFilePath),
		)
		let pending = refreshes.get(lockPath)
		if (!pending) {
			pending = withAuthFileLock(lockPath, async (assertLock) => {
				const latest = await readAuthFile([lockPath])
				const latestAuth = latest.data ?? {}
				const latestTokens = normalizeTokens(latestAuth.tokens)
				const latestAccess = latestTokens.access_token
				const latestRefresh = latestTokens.refresh_token
				const latestRefreshContext = getRefreshContext(
					latestAccess,
					latestAuth.last_refresh,
					now(),
				)
				if (latestAccess && !latestRefreshContext) {
					const latestAccount =
						latestTokens.account_id ??
						deriveAccountId(latestTokens.id_token) ??
						deriveAccountId(latestAccess)
					if (!latestAccount)
						throw new Error(
							"ChatGPT account id not found in auth.json. Run `npx openai-oauth login` to sign in again.",
						)
					return {
						accessToken: latestAccess,
						accountId: latestAccount,
						idToken: latestTokens.id_token,
						refreshToken: latestRefresh,
						isFedRamp:
							deriveChatGptAccountIsFedRamp(latestTokens.id_token) ||
							deriveChatGptAccountIsFedRamp(latestAccess),
						sourcePath: lockPath,
						lastRefresh: latestAuth.last_refresh,
					}
				}
				if (!latestRefreshContext) {
					throw new Error("ChatGPT access token not found in auth.json.")
				}
				if (!latestRefresh) {
					throw new Error(
						"ChatGPT refresh token not found in auth.json. Please run npx openai-oauth login to sign in again.",
					)
				}
				const refreshContext = latestRefreshContext
				const startedAt = Date.now()
				emitTokenRefreshLog(onTokenRefreshLog, {
					type: "token_refresh_started",
					...refreshContext,
				})
				try {
					const refreshed = await refreshChatGptTokens(
						latestRefresh,
						clientId,
						issuer,
						tokenUrl,
						fetch,
					)
					const nextId = refreshed.idToken ?? latestTokens.id_token
					const nextRefresh = refreshed.refreshToken ?? latestRefresh
					const nextAccount =
						refreshed.accountId ??
						latestTokens.account_id ??
						deriveAccountId(nextId) ??
						deriveAccountId(refreshed.accessToken)
					if (!nextAccount)
						throw new Error(
							"ChatGPT account id not found in OpenAI OAuth token response.",
						)
					const refreshedAt = now().toISOString()
					assertLock()
					await writeAuthFile(lockPath, {
						...latestAuth,
						auth_mode: "chatgpt",
						tokens: {
							id_token: nextId,
							access_token: refreshed.accessToken,
							refresh_token: nextRefresh,
							account_id: nextAccount,
						},
						last_refresh: refreshedAt,
					})
					emitTokenRefreshLog(onTokenRefreshLog, {
						type: "token_refresh_succeeded",
						durationMs: Date.now() - startedAt,
						...refreshContext,
					})
					return {
						accessToken: refreshed.accessToken,
						accountId: nextAccount,
						idToken: nextId,
						refreshToken: nextRefresh,
						isFedRamp:
							deriveChatGptAccountIsFedRamp(latestTokens.id_token) ||
							deriveChatGptAccountIsFedRamp(latestAccess) ||
							refreshed.isFedRamp === true ||
							deriveChatGptAccountIsFedRamp(nextId) ||
							deriveChatGptAccountIsFedRamp(refreshed.accessToken),
						sourcePath: lockPath,
						lastRefresh: refreshedAt,
					}
				} catch (error) {
					const details = isRecord(error) ? error : {}
					const status =
						typeof details.status === "number" &&
						details.status >= 100 &&
						details.status <= 599
							? details.status
							: undefined
					const code = details.oauthErrorCode
					const errorDescription = details.oauthErrorDescription
					const responseBodyBytes = details.responseBodyBytes
					const responseContentType = details.responseContentType
					const oauthRequestId = details.oauthRequestId
					emitTokenRefreshLog(onTokenRefreshLog, {
						type: "token_refresh_failed",
						durationMs: Date.now() - startedAt,
						...refreshContext,
						errorName:
							error instanceof Error && error.name
								? error.name
								: "UnknownError",
						...(status === undefined ? {} : { status }),
						...(typeof code === "string" &&
						/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(code)
							? { oauthErrorCode: code }
							: {}),
						...(typeof errorDescription === "string"
							? { errorDescription }
							: {}),
						...(typeof responseBodyBytes === "number"
							? { responseBodyBytes }
							: {}),
						...(typeof responseContentType === "string"
							? { responseContentType }
							: {}),
						...(typeof oauthRequestId === "string" &&
						/^[A-Za-z0-9._:-]{1,128}$/.test(oauthRequestId)
							? { oauthRequestId }
							: {}),
					})
					throw error
				}
			})
			refreshes.set(lockPath, pending)
			void pending
				.finally(() => {
					if (refreshes.get(lockPath) === pending) refreshes.delete(lockPath)
				})
				.catch(() => {})
		}
		const refreshed = await pending
		accessToken = refreshed.accessToken
		idToken = refreshed.idToken ?? idToken
		refreshToken = refreshed.refreshToken ?? refreshToken
		accountId = refreshed.accountId
		isFedRamp = refreshed.isFedRamp ?? isFedRamp
		lastRefresh = refreshed.lastRefresh
	}
	if (typeof accessToken !== "string" || accessToken.length === 0) {
		throw new Error(
			"ChatGPT access token not found. Run `npx openai-oauth login` to sign in.",
		)
	}

	if (typeof accountId !== "string" || accountId.length === 0) {
		throw new Error(
			"ChatGPT account id not found in auth.json. Run `npx openai-oauth login` to sign in again.",
		)
	}

	return {
		accessToken,
		accountId,
		isFedRamp,
		idToken,
		refreshToken,
		sourcePath: readResult.path ?? resolveWritePath(authFilePath),
		lastRefresh,
	}
}
