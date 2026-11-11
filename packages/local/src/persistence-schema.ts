import { sql } from "drizzle-orm"
import {
	index,
	integer,
	sqliteTable,
	text,
	uniqueIndex,
} from "drizzle-orm/sqlite-core"

const nowMilliseconds = sql`(cast(unixepoch('subsecond') * 1000 as integer))`

export const user = sqliteTable("user", {
	id: text("id").primaryKey(),
	name: text("name").notNull(),
	email: text("email").notNull().unique(),
	username: text("username").unique(),
	displayUsername: text("display_username"),
	emailVerified: integer("email_verified", { mode: "boolean" })
		.default(false)
		.notNull(),
	image: text("image"),
	createdAt: integer("created_at", { mode: "timestamp_ms" })
		.default(nowMilliseconds)
		.notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp_ms" })
		.default(nowMilliseconds)
		.notNull(),
})

export const session = sqliteTable(
	"session",
	{
		id: text("id").primaryKey(),
		expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
		token: text("token").notNull().unique(),
		createdAt: integer("created_at", { mode: "timestamp_ms" })
			.default(nowMilliseconds)
			.notNull(),
		updatedAt: integer("updated_at", { mode: "timestamp_ms" })
			.default(nowMilliseconds)
			.notNull(),
		ipAddress: text("ip_address"),
		userAgent: text("user_agent"),
		userId: text("user_id")
			.notNull()
			.references(() => user.id, { onDelete: "cascade" }),
	},
	(table) => [index("session_userId_idx").on(table.userId)],
)

export const account = sqliteTable(
	"account",
	{
		id: text("id").primaryKey(),
		accountId: text("account_id").notNull(),
		providerId: text("provider_id").notNull(),
		userId: text("user_id")
			.notNull()
			.references(() => user.id, { onDelete: "cascade" }),
		accessToken: text("access_token"),
		refreshToken: text("refresh_token"),
		idToken: text("id_token"),
		accessTokenExpiresAt: integer("access_token_expires_at", {
			mode: "timestamp_ms",
		}),
		refreshTokenExpiresAt: integer("refresh_token_expires_at", {
			mode: "timestamp_ms",
		}),
		scope: text("scope"),
		password: text("password"),
		createdAt: integer("created_at", { mode: "timestamp_ms" })
			.default(nowMilliseconds)
			.notNull(),
		updatedAt: integer("updated_at", { mode: "timestamp_ms" })
			.default(nowMilliseconds)
			.notNull(),
	},
	(table) => [index("account_userId_idx").on(table.userId)],
)

export const verification = sqliteTable(
	"verification",
	{
		id: text("id").primaryKey(),
		identifier: text("identifier").notNull(),
		value: text("value").notNull(),
		expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
		createdAt: integer("created_at", { mode: "timestamp_ms" })
			.default(nowMilliseconds)
			.notNull(),
		updatedAt: integer("updated_at", { mode: "timestamp_ms" })
			.default(nowMilliseconds)
			.notNull(),
	},
	(table) => [index("verification_identifier_idx").on(table.identifier)],
)

export const oauthCredentials = sqliteTable("oauth_credentials", {
	id: integer("id").primaryKey(),
	accessToken: text("access_token").notNull(),
	refreshToken: text("refresh_token"),
	idToken: text("id_token"),
	accountId: text("account_id").notNull(),
	isFedRamp: integer("is_fed_ramp", { mode: "boolean" })
		.default(false)
		.notNull(),
	lastRefresh: text("last_refresh"),
	refreshGeneration: integer("refresh_generation").notNull().default(0),
	updatedAt: integer("updated_at", { mode: "timestamp_ms" })
		.default(nowMilliseconds)
		.notNull(),
})

export const apiKeys = sqliteTable(
	"api_keys",
	{
		id: text("id").primaryKey(),
		label: text("label").notNull(),
		prefix: text("prefix").notNull(),
		verifier: text("verifier").notNull(),
		createdAt: integer("created_at", { mode: "timestamp_ms" })
			.default(nowMilliseconds)
			.notNull(),
		revokedAt: integer("revoked_at", { mode: "timestamp_ms" }),
	},
	(table) => [uniqueIndex("api_keys_verifier_idx").on(table.verifier)],
)

export const bootstrapState = sqliteTable("bootstrap_state", {
	id: integer("id").primaryKey(),
	adminUserId: text("admin_user_id").references(() => user.id, {
		onDelete: "set null",
	}),
	usernameChanged: integer("username_changed", { mode: "boolean" })
		.default(false)
		.notNull(),
	passwordChanged: integer("password_changed", { mode: "boolean" })
		.default(false)
		.notNull(),
	createdAt: integer("created_at", { mode: "timestamp_ms" })
		.default(nowMilliseconds)
		.notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp_ms" })
		.default(nowMilliseconds)
		.notNull(),
})

export const persistenceSchema = {
	user,
	session,
	account,
	verification,
	oauthCredentials,
	apiKeys,
	bootstrapState,
}
