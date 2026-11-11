import type { Database } from "@tursodatabase/database/compat"

const MIGRATION_STATEMENTS = [
	`CREATE TABLE IF NOT EXISTS user (
		id TEXT PRIMARY KEY NOT NULL,
		name TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		username TEXT UNIQUE,
		display_username TEXT,
		email_verified INTEGER NOT NULL DEFAULT 0,
		image TEXT,
		created_at INTEGER NOT NULL DEFAULT (cast(unixepoch('subsecond') * 1000 as integer)),
		updated_at INTEGER NOT NULL DEFAULT (cast(unixepoch('subsecond') * 1000 as integer))
	)`,
	`CREATE TABLE IF NOT EXISTS session (
		id TEXT PRIMARY KEY NOT NULL,
		expires_at INTEGER NOT NULL,
		token TEXT NOT NULL UNIQUE,
		created_at INTEGER NOT NULL DEFAULT (cast(unixepoch('subsecond') * 1000 as integer)),
		updated_at INTEGER NOT NULL DEFAULT (cast(unixepoch('subsecond') * 1000 as integer)),
		ip_address TEXT,
		user_agent TEXT,
		user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE
	)`,
	`CREATE INDEX IF NOT EXISTS session_userId_idx ON session(user_id)`,
	`CREATE TABLE IF NOT EXISTS account (
		id TEXT PRIMARY KEY NOT NULL,
		account_id TEXT NOT NULL,
		provider_id TEXT NOT NULL,
		user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
		access_token TEXT,
		refresh_token TEXT,
		id_token TEXT,
		access_token_expires_at INTEGER,
		refresh_token_expires_at INTEGER,
		scope TEXT,
		password TEXT,
		created_at INTEGER NOT NULL DEFAULT (cast(unixepoch('subsecond') * 1000 as integer)),
		updated_at INTEGER NOT NULL DEFAULT (cast(unixepoch('subsecond') * 1000 as integer))
	)`,
	`CREATE INDEX IF NOT EXISTS account_userId_idx ON account(user_id)`,
	`CREATE TABLE IF NOT EXISTS verification (
		id TEXT PRIMARY KEY NOT NULL,
		identifier TEXT NOT NULL,
		value TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		created_at INTEGER NOT NULL DEFAULT (cast(unixepoch('subsecond') * 1000 as integer)),
		updated_at INTEGER NOT NULL DEFAULT (cast(unixepoch('subsecond') * 1000 as integer))
	)`,
	`CREATE INDEX IF NOT EXISTS verification_identifier_idx ON verification(identifier)`,
	`CREATE TABLE IF NOT EXISTS oauth_credentials (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		access_token TEXT NOT NULL,
		refresh_token TEXT,
		id_token TEXT,
		account_id TEXT NOT NULL,
		is_fed_ramp INTEGER NOT NULL DEFAULT 0,
		last_refresh TEXT,
		updated_at INTEGER NOT NULL DEFAULT (cast(unixepoch('subsecond') * 1000 as integer))
	)`,
	`CREATE TABLE IF NOT EXISTS api_keys (
		id TEXT PRIMARY KEY NOT NULL,
		label TEXT NOT NULL,
		prefix TEXT NOT NULL,
		verifier TEXT NOT NULL,
		created_at INTEGER NOT NULL DEFAULT (cast(unixepoch('subsecond') * 1000 as integer)),
		revoked_at INTEGER
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS api_keys_verifier_idx ON api_keys(verifier)`,
	`CREATE TABLE IF NOT EXISTS bootstrap_state (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		admin_user_id TEXT REFERENCES user(id) ON DELETE SET NULL,
		username_changed INTEGER NOT NULL DEFAULT 0,
		password_changed INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL DEFAULT (cast(unixepoch('subsecond') * 1000 as integer)),
		updated_at INTEGER NOT NULL DEFAULT (cast(unixepoch('subsecond') * 1000 as integer))
	)`,
]

const REFRESH_GENERATION_MIGRATION_STATEMENTS = [
	`ALTER TABLE oauth_credentials ADD COLUMN refresh_generation INTEGER NOT NULL DEFAULT 0`,
]

export const applyPersistenceMigrations = (database: Database): void => {
	database.exec("BEGIN IMMEDIATE")
	try {
		database.exec(`
			CREATE TABLE IF NOT EXISTS auth_schema_migrations (
				version INTEGER PRIMARY KEY NOT NULL,
				applied_at INTEGER NOT NULL DEFAULT (cast(unixepoch('subsecond') * 1000 as integer))
			)
		`)
		const current = database
			.prepare("SELECT MAX(version) AS version FROM auth_schema_migrations")
			.get() as { version?: number | null }
		if ((current.version ?? 0) < 1) {
			for (const statement of MIGRATION_STATEMENTS) database.exec(statement)
			database
				.prepare("INSERT INTO auth_schema_migrations(version) VALUES (1)")
				.run()
		}
		if ((current.version ?? 0) < 2) {
			for (const statement of REFRESH_GENERATION_MIGRATION_STATEMENTS) {
				database.exec(statement)
			}
			database
				.prepare("INSERT INTO auth_schema_migrations(version) VALUES (2)")
				.run()
		}
		database.exec("COMMIT")
	} catch (error) {
		database.exec("ROLLBACK")
		throw error
	}
}
