import {
	type PersistentStore,
	persistenceSchema,
} from "@openai-oauth/local/persistence"
import { betterAuth } from "better-auth"
import { drizzleAdapter } from "better-auth/adapters/drizzle"
import { username } from "better-auth/plugins"
import { eq, like } from "drizzle-orm"

export type AdminAuthOptions = {
	baseURL: string
	secret: string
}

export type BootstrapCredentials = {
	username?: string
	password?: string
}

export type AdminBootstrapState = {
	adminUserId: string | null
	usernameChanged: boolean
	passwordChanged: boolean
}

const BOOTSTRAP_EMAIL_SUFFIX = "@bootstrap.oauth.invalid"

export const readBootstrapState = async (
	store: PersistentStore,
): Promise<AdminBootstrapState | undefined> => {
	const state = await store.drizzle
		.select({
			adminUserId: persistenceSchema.bootstrapState.adminUserId,
			usernameChanged: persistenceSchema.bootstrapState.usernameChanged,
			passwordChanged: persistenceSchema.bootstrapState.passwordChanged,
		})
		.from(persistenceSchema.bootstrapState)
		.where(eq(persistenceSchema.bootstrapState.id, 1))
		.get()
	return state
}

const findOrphanedBootstrapUser = async (
	store: PersistentStore,
): Promise<string | undefined> => {
	const users = await store.drizzle
		.select({ id: persistenceSchema.user.id })
		.from(persistenceSchema.user)
		.where(like(persistenceSchema.user.email, `%${BOOTSTRAP_EMAIL_SUFFIX}`))
		.limit(2)
	if (users.length > 1) {
		throw new Error(
			"Bootstrap state is missing but multiple bootstrap users exist.",
		)
	}
	return users[0]?.id
}

const getBootstrapState = async (
	store: PersistentStore,
): Promise<AdminBootstrapState> => {
	const state = await readBootstrapState(store)
	if (!state)
		throw new Error("Could not persist administrator bootstrap state.")
	return state
}

export const createAdminAuth = (
	store: PersistentStore,
	options: AdminAuthOptions,
) => {
	if (Buffer.byteLength(options.secret, "utf8") < 32) {
		throw new Error("AUTH_SESSION_SECRET must be at least 32 bytes.")
	}
	const baseURL = new URL(options.baseURL)
	if (
		baseURL.origin !== options.baseURL.replace(/\/$/, "") ||
		(baseURL.protocol !== "https:" &&
			!(
				["localhost", "127.0.0.1", "[::1]"].includes(baseURL.hostname) &&
				baseURL.protocol === "http:"
			))
	) {
		throw new Error(
			"LOGIN_UI_PUBLIC_ORIGIN must be an HTTPS origin or loopback HTTP.",
		)
	}
	const secure = baseURL.protocol === "https:"

	return betterAuth({
		baseURL: baseURL.origin,
		secret: options.secret,
		trustedOrigins: [baseURL.origin],
		database: drizzleAdapter(store.drizzle, {
			provider: "sqlite",
			schema: persistenceSchema,
		}),
		emailAndPassword: {
			enabled: true,
			autoSignIn: false,
			requireEmailVerification: false,
			minPasswordLength: 12,
			maxPasswordLength: 128,
		},
		plugins: [username({ minUsernameLength: 3, maxUsernameLength: 64 })],
		session: {
			expiresIn: 60 * 60 * 12,
			updateAge: 60 * 60,
		},
		advanced: {
			useSecureCookies: secure,
			defaultCookieAttributes: {
				httpOnly: true,
				sameSite: "strict",
				secure,
			},
		},
	})
}

export const initializeAdminBootstrap = async (
	auth: ReturnType<typeof createAdminAuth>,
	store: PersistentStore,
	credentials: BootstrapCredentials = {},
): Promise<AdminBootstrapState> => {
	const existing = await readBootstrapState(store)
	if (existing) return existing

	let adminUserId = await findOrphanedBootstrapUser(store)
	if (!adminUserId) {
		const { username: bootstrapUsername, password: bootstrapPassword } =
			credentials
		if (!bootstrapUsername || !bootstrapPassword) {
			throw new Error(
				"AUTH_BOOTSTRAP_USERNAME and AUTH_BOOTSTRAP_PASSWORD are required for first initialization.",
			)
		}
		if (!/^[A-Za-z0-9_.]{3,64}$/.test(bootstrapUsername)) {
			throw new Error(
				"AUTH_BOOTSTRAP_USERNAME must be 3–64 letters, digits, dots, or underscores.",
			)
		}
		if (
			Buffer.byteLength(bootstrapPassword, "utf8") < 12 ||
			bootstrapPassword.length > 128
		) {
			throw new Error("AUTH_BOOTSTRAP_PASSWORD must be 12–128 characters.")
		}

		const normalizedUsername = bootstrapUsername.toLowerCase()
		const response = await auth.api.signUpEmail({
			body: {
				email: `${normalizedUsername}${BOOTSTRAP_EMAIL_SUFFIX}`,
				name: bootstrapUsername,
				password: bootstrapPassword,
				username: bootstrapUsername,
				displayUsername: bootstrapUsername,
			},
			headers: new Headers({ origin: auth.options.baseURL }),
			asResponse: true,
		})
		if (!response.ok) {
			throw new Error("Could not create the bootstrap administrator account.")
		}
		const result: unknown = await response.json()
		if (
			typeof result !== "object" ||
			result === null ||
			!("user" in result) ||
			typeof result.user !== "object" ||
			result.user === null ||
			!("id" in result.user) ||
			typeof result.user.id !== "string"
		) {
			throw new Error("Could not identify the bootstrap administrator account.")
		}
		adminUserId = result.user.id
	}

	await store.drizzle
		.insert(persistenceSchema.bootstrapState)
		.values({
			id: 1,
			adminUserId,
			usernameChanged: false,
			passwordChanged: false,
		})
		.onConflictDoNothing()

	return getBootstrapState(store)
}

const updateBootstrapFlag = (
	store: PersistentStore,
	adminUserId: string,
	flag: "username_changed" | "password_changed",
): void => {
	const result = store.database
		.prepare(
			`UPDATE bootstrap_state
			SET ${flag} = 1,
				updated_at = cast(unixepoch('subsecond') * 1000 as integer)
			WHERE id = 1 AND admin_user_id = ?`,
		)
		.run(adminUserId)
	if (result.changes !== 1) {
		throw new Error("Could not persist bootstrap credential-change state.")
	}
}

export type BootstrapCredentialChange = {
	currentPassword: string
	newPassword: string
	username: string
}

export const changeBootstrapCredentials = async (
	auth: ReturnType<typeof createAdminAuth>,
	store: PersistentStore,
	headers: Headers,
	change: BootstrapCredentialChange,
): Promise<AdminBootstrapState> => {
	const session = await auth.api.getSession({ headers })
	if (!session) throw new Error("Administrator sign-in is required.")
	const state = await readBootstrapState(store)
	if (!state || state.adminUserId !== session.user.id) {
		throw new Error(
			"This session is not authorized to change administrator credentials.",
		)
	}

	if (!state.usernameChanged) {
		if (!/^[A-Za-z0-9_.]{3,64}$/.test(change.username)) {
			throw new Error(
				"Username must be 3–64 letters, digits, dots, or underscores.",
			)
		}
		if (
			change.username.toLowerCase() === session.user.username?.toLowerCase()
		) {
			throw new Error(
				"Choose a username different from the bootstrap username.",
			)
		}
		const response = await auth.api.updateUser({
			body: {
				username: change.username,
				displayUsername: change.username,
			},
			headers,
			asResponse: true,
		})
		if (!response.ok)
			throw new Error("Could not update the administrator username.")
		updateBootstrapFlag(store, session.user.id, "username_changed")
	}

	if (!state.passwordChanged) {
		if (
			typeof change.currentPassword !== "string" ||
			change.currentPassword.length === 0 ||
			typeof change.newPassword !== "string" ||
			Buffer.byteLength(change.newPassword, "utf8") < 12 ||
			change.newPassword.length > 128
		) {
			throw new Error(
				"Provide the current password and a new 12–128 character password.",
			)
		}
		if (change.currentPassword === change.newPassword) {
			throw new Error(
				"Choose a new password different from the bootstrap password.",
			)
		}
		const response = await auth.api.changePassword({
			body: {
				currentPassword: change.currentPassword,
				newPassword: change.newPassword,
				revokeOtherSessions: false,
			},
			headers,
			asResponse: true,
		})
		if (!response.ok)
			throw new Error("Could not update the administrator password.")
		updateBootstrapFlag(store, session.user.id, "password_changed")
	}

	return getBootstrapState(store)
}

export const getAdminSession = (
	auth: ReturnType<typeof createAdminAuth>,
	headers: Headers,
) => auth.api.getSession({ headers })
