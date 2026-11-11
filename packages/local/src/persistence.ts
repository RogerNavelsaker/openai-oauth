import { createHash } from "node:crypto"
import { promises as fs } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import type { Database } from "@tursodatabase/database/compat"
import { drizzle, type SqliteRemoteDatabase } from "drizzle-orm/sqlite-proxy"
import lockfile from "proper-lockfile"
import { type EffectiveAuth, readAuthFileCredentials } from "./auth-file.js"
import {
	openEncryptedDatabase,
	validateEncryptionKey,
} from "./encrypted-database.js"
import { applyPersistenceMigrations } from "./persistence-migrations.js"
import { persistenceSchema } from "./persistence-schema.js"

export type PersistentOAuthCredentials = Pick<
	EffectiveAuth,
	| "accessToken"
	| "accountId"
	| "isFedRamp"
	| "idToken"
	| "refreshToken"
	| "lastRefresh"
> & {
	refreshGeneration?: number
}

export type OpenPersistentStoreOptions = {
	databaseUrl: string
	encryptionKey: string
}

export type ImportAuthFileOptions = {
	authFilePath?: string
}

export type ImportAuthFileResult = {
	imported: boolean
}

export type PersistentApiKeyMetadata = {
	id: string
	label: string
	prefix: string
	createdAt: string
	revokedAt?: string
}

export type CreatePersistentApiKey = {
	id: string
	label: string
	prefix: string
	token: string
	createdAt?: Date
}

type StoredOAuthCredentials = {
	access_token: string
	refresh_token: string | null
	id_token: string | null
	account_id: string
	is_fed_ramp: number
	last_refresh: string | null
	refresh_generation: number
}

type StoredApiKey = {
	id: string
	label: string
	prefix: string
	created_at: number
	revoked_at: number | null
}

const verifierForApiKey = (token: string): string =>
	`sha256:${createHash("sha256").update(token).digest("hex")}`

const toApiKeyMetadata = (row: StoredApiKey): PersistentApiKeyMetadata => ({
	id: row.id,
	label: row.label,
	prefix: row.prefix,
	createdAt: new Date(row.created_at).toISOString(),
	...(row.revoked_at === null
		? {}
		: { revokedAt: new Date(row.revoked_at).toISOString() }),
})

export type PersistentStore = {
	database: Database
	drizzle: SqliteRemoteDatabase<typeof persistenceSchema>
	getOAuthCredentials: () => PersistentOAuthCredentials | undefined
	saveOAuthCredentials: (credentials: PersistentOAuthCredentials) => void
	clearOAuthCredentials: () => void
	createApiKey: (input: CreatePersistentApiKey) => PersistentApiKeyMetadata
	listApiKeys: () => PersistentApiKeyMetadata[]
	revokeApiKey: (id: string) => boolean
	verifyApiKey: (token: string) => boolean
	withOAuthRefreshLock: <T>(
		action: (assertLock: () => void) => Promise<T>,
	) => Promise<T>
	importAuthFile: (
		options?: ImportAuthFileOptions,
	) => Promise<ImportAuthFileResult>
	close: () => void
}

const databasePathFromUrl = (databaseUrl: string): string => {
	if (typeof databaseUrl !== "string" || !databaseUrl) {
		throw new Error("AUTH_DATABASE_URL must be a file: URL.")
	}

	let url: URL
	try {
		url = new URL(databaseUrl)
	} catch (error) {
		throw new Error("AUTH_DATABASE_URL must be a valid file: URL.", {
			cause: error,
		})
	}
	if (
		url.protocol !== "file:" ||
		url.host !== "" ||
		url.search !== "" ||
		url.hash !== ""
	) {
		throw new Error(
			"AUTH_DATABASE_URL must use the file: protocol without a host, query, or fragment.",
		)
	}

	try {
		const filePath = fileURLToPath(url)
		if (!path.basename(filePath))
			throw new Error("Database filename is required.")
		return filePath
	} catch (error) {
		throw new Error("AUTH_DATABASE_URL must identify a local database file.", {
			cause: error,
		})
	}
}

const ensurePrivateDatabaseDirectory = async (
	directoryPath: string,
): Promise<void> => {
	await fs.mkdir(directoryPath, { recursive: true, mode: 0o700 })
	const directory = await fs.lstat(directoryPath)
	if (!directory.isDirectory() || directory.isSymbolicLink()) {
		throw new Error("AUTH_DATABASE_URL parent must be a real directory.")
	}
	await fs.chmod(directoryPath, 0o700)
}

const ensurePrivateDatabaseFile = async (
	databasePath: string,
): Promise<void> => {
	try {
		const file = await fs.lstat(databasePath)
		if (!file.isFile() || file.isSymbolicLink()) {
			throw new Error(
				"AUTH_DATABASE_URL must identify a regular database file.",
			)
		}
		await fs.chmod(databasePath, 0o600)
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
		try {
			const handle = await fs.open(databasePath, "wx", 0o600)
			await handle.close()
		} catch (createError) {
			if ((createError as NodeJS.ErrnoException).code !== "EEXIST") {
				throw createError
			}
		}
		const file = await fs.lstat(databasePath)
		if (!file.isFile() || file.isSymbolicLink()) {
			throw new Error(
				"AUTH_DATABASE_URL must identify a regular database file.",
			)
		}
		await fs.chmod(databasePath, 0o600)
	}
}
const toStoredValues = (credentials: PersistentOAuthCredentials) => {
	if (!credentials.accessToken || !credentials.accountId) {
		throw new Error("OAuth access token and account id are required.")
	}
	return {
		accessToken: credentials.accessToken,
		refreshToken: credentials.refreshToken ?? null,
		idToken: credentials.idToken ?? null,
		accountId: credentials.accountId,
		isFedRamp: credentials.isFedRamp === true ? 1 : 0,
		lastRefresh: credentials.lastRefresh ?? null,
		refreshGeneration: credentials.refreshGeneration ?? 0,
	}
}

const fromStoredValues = (
	row: StoredOAuthCredentials | undefined,
): PersistentOAuthCredentials | undefined => {
	if (!row) return undefined
	return {
		accessToken: row.access_token,
		...(row.refresh_token === null ? {} : { refreshToken: row.refresh_token }),
		...(row.id_token === null ? {} : { idToken: row.id_token }),
		accountId: row.account_id,
		isFedRamp: row.is_fed_ramp === 1,
		...(row.last_refresh === null ? {} : { lastRefresh: row.last_refresh }),
		refreshGeneration: row.refresh_generation,
	}
}

const withDatabaseRefreshLock = async <T>(
	databasePath: string,
	action: (assertLock: () => void) => Promise<T>,
): Promise<T> => {
	let compromisedError: Error | undefined
	const release = await lockfile.lock(databasePath, {
		realpath: false,
		retries: {
			retries: 40,
			factor: 1.5,
			minTimeout: 50,
			maxTimeout: 500,
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
		releaseError = error
		releaseFailed = true
	}
	if (actionFailed) throw actionError
	if (releaseFailed && !compromisedError) throw releaseError
	assertLock()
	return result
}

export const openPersistentStore = async ({
	databaseUrl,
	encryptionKey,
}: OpenPersistentStoreOptions): Promise<PersistentStore> => {
	if (typeof encryptionKey !== "string" || encryptionKey.length === 0) {
		throw new Error("AUTH_DATABASE_KEY is required.")
	}
	validateEncryptionKey(encryptionKey)
	const databasePath = databasePathFromUrl(databaseUrl)
	await ensurePrivateDatabaseDirectory(path.dirname(databasePath))
	await ensurePrivateDatabaseFile(databasePath)

	const database = await openEncryptedDatabase({
		path: databasePath,
		hexKey: encryptionKey,
	})
	try {
		await fs.chmod(databasePath, 0o600)
		database.exec("PRAGMA journal_mode=WAL")
		const journalMode = database.prepare("PRAGMA journal_mode").get() as {
			journal_mode?: string
		}
		if (journalMode.journal_mode?.toLowerCase() !== "wal") {
			throw new Error("Encrypted auth database must support WAL mode.")
		}
		database.exec("PRAGMA foreign_keys=ON")
		const foreignKeys = database.prepare("PRAGMA foreign_keys").get() as {
			foreign_keys?: number
		}
		if (foreignKeys.foreign_keys !== 1) {
			throw new Error("Encrypted auth database must enforce foreign keys.")
		}
		applyPersistenceMigrations(database)
		return {
			database,
			drizzle: drizzle(
				async (query, params, method) => {
					const statement = database.prepare(query)
					if (method === "run") {
						statement.run(...params)
						return { rows: [] }
					}
					if (method === "get") {
						const row = statement.get(...params)
						return {
							rows: (row === undefined
								? undefined
								: Object.values(row as object)) as never,
						}
					}
					const rows = statement.all(...params)
					return { rows: rows.map((row) => Object.values(row as object)) }
				},
				{ schema: persistenceSchema },
			),
			getOAuthCredentials: () => {
				const row = database
					.prepare(
						`SELECT access_token, refresh_token, id_token, account_id,
							is_fed_ramp, last_refresh, refresh_generation
						FROM oauth_credentials WHERE id = 1`,
					)
					.get() as StoredOAuthCredentials | undefined
				return fromStoredValues(row)
			},
			saveOAuthCredentials: (credentials) => {
				const current = database
					.prepare(
						"SELECT refresh_generation FROM oauth_credentials WHERE id = 1",
					)
					.get() as { refresh_generation?: number } | undefined
				const values = toStoredValues({
					...credentials,
					refreshGeneration:
						credentials.refreshGeneration ??
						(current?.refresh_generation ?? 0) + 1,
				})
				database
					.prepare(
						`INSERT INTO oauth_credentials (
							id, access_token, refresh_token, id_token, account_id,
							is_fed_ramp, last_refresh, refresh_generation
						) VALUES (1, @accessToken, @refreshToken, @idToken, @accountId,
							@isFedRamp, @lastRefresh, @refreshGeneration)
						ON CONFLICT(id) DO UPDATE SET
							access_token = excluded.access_token,
							refresh_token = excluded.refresh_token,
							id_token = excluded.id_token,
							account_id = excluded.account_id,
							is_fed_ramp = excluded.is_fed_ramp,
							last_refresh = excluded.last_refresh,
							refresh_generation = excluded.refresh_generation,
							updated_at = cast(unixepoch('subsecond') * 1000 as integer)`,
					)
					.run(values)
			},
			clearOAuthCredentials: () => {
				database.prepare("DELETE FROM oauth_credentials WHERE id = 1").run()
			},
			createApiKey: ({ id, label, prefix, token, createdAt }) => {
				const createdAtMs = (createdAt ?? new Date()).getTime()
				database
					.prepare(
						`INSERT INTO api_keys (id, label, prefix, verifier, created_at)
						 VALUES (@id, @label, @prefix, @verifier, @createdAt)`,
					)
					.run({
						id,
						label,
						prefix,
						verifier: verifierForApiKey(token),
						createdAt: createdAtMs,
					})
				return {
					id,
					label,
					prefix,
					createdAt: new Date(createdAtMs).toISOString(),
				}
			},
			listApiKeys: () => {
				const rows = database
					.prepare(
						`SELECT id, label, prefix, created_at, revoked_at
						 FROM api_keys ORDER BY created_at DESC, id DESC`,
					)
					.all() as StoredApiKey[]
				return rows.map(toApiKeyMetadata)
			},
			revokeApiKey: (id) => {
				const result = database
					.prepare(
						`UPDATE api_keys SET revoked_at = cast(unixepoch('subsecond') * 1000 as integer)
						 WHERE id = ? AND revoked_at IS NULL`,
					)
					.run(id)
				return result.changes === 1
			},
			verifyApiKey: (token) => {
				if (typeof token !== "string" || token.length < 32) return false
				const verifier = verifierForApiKey(token)
				return (
					database
						.prepare(
							"SELECT 1 FROM api_keys WHERE verifier = ? AND revoked_at IS NULL LIMIT 1",
						)
						.get(verifier) !== undefined
				)
			},
			withOAuthRefreshLock: (action) =>
				withDatabaseRefreshLock(databasePath, action),
			importAuthFile: async (options = {}) => {
				const credentials = await readAuthFileCredentials(options.authFilePath)
				if (!credentials) return { imported: false }
				const values = toStoredValues(credentials)
				const result = database
					.prepare(
						`INSERT OR IGNORE INTO oauth_credentials (
							id, access_token, refresh_token, id_token, account_id,
							is_fed_ramp, last_refresh
						) VALUES (1, @accessToken, @refreshToken, @idToken, @accountId,
							@isFedRamp, @lastRefresh)`,
					)
					.run(values)
				return { imported: result.changes === 1 }
			},
			close: () => database.close(),
		}
	} catch (error) {
		database.close()
		throw error
	}
}
