import { promises as fs } from "node:fs"
import os from "node:os"
import path from "node:path"
import { pathToFileURL } from "node:url"
import {
	openPersistentStore,
	persistenceSchema,
} from "@openai-oauth/local/persistence"
import { afterEach, describe, expect, it } from "vitest"
import {
	changeBootstrapCredentials,
	createAdminAuth,
	initializeAdminBootstrap,
} from "./admin-auth.js"

const AUTH_SECRET = "test-only-secret-for-admin-authentication-32-bytes"
const BOOTSTRAP_PASSWORD = "test-bootstrap-password-strong-123"
const tempDirs: string[] = []

const createStore = async () => {
	const directory = await fs.mkdtemp(
		path.join(os.tmpdir(), "oauth-admin-auth-"),
	)
	tempDirs.push(directory)
	return openPersistentStore({
		databaseUrl: pathToFileURL(path.join(directory, "auth.db")).href,
		encryptionKey:
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
}

afterEach(async () => {
	await Promise.all(
		tempDirs
			.splice(0)
			.map((directory) => fs.rm(directory, { recursive: true, force: true })),
	)
})

describe("admin authentication bootstrap", () => {
	it("creates the deployment-provisioned admin once and never resets it", async () => {
		const store = await createStore()
		try {
			const auth = createAdminAuth(store, {
				baseURL: "https://oauth.example.test",
				secret: AUTH_SECRET,
			})
			const first = await initializeAdminBootstrap(auth, store, {
				username: "bootstrap_admin",
				password: BOOTSTRAP_PASSWORD,
			})
			expect(first).toMatchObject({
				usernameChanged: false,
				passwordChanged: false,
			})
			expect(
				await store.drizzle.select().from(persistenceSchema.session),
			).toHaveLength(0)

			const secondAuth = createAdminAuth(store, {
				baseURL: "https://oauth.example.test",
				secret: AUTH_SECRET,
			})
			const second = await initializeAdminBootstrap(secondAuth, store, {
				username: "changed-deployment-value",
				password: "different-bootstrap-password-456",
			})
			expect(second).toEqual(first)
			const signedIn = await auth.api.signInUsername({
				body: {
					username: "bootstrap_admin",
					password: BOOTSTRAP_PASSWORD,
				},
				asResponse: true,
			})
			expect(signedIn.ok).toBe(true)
			const sessionCookie = signedIn.headers.get("set-cookie") ?? ""
			expect(sessionCookie).toContain("HttpOnly")
			expect(sessionCookie).toContain("Secure")
			expect(sessionCookie).toMatch(/SameSite=Strict/i)
			const sessionHeaders = new Headers({
				cookie: sessionCookie.split(";", 1)[0] ?? "",
				origin: "https://oauth.example.test",
			})
			const completed = await changeBootstrapCredentials(
				auth,
				store,
				sessionHeaders,
				{
					currentPassword: BOOTSTRAP_PASSWORD,
					newPassword: "new-admin-password-strong-789",
					username: "real_admin",
				},
			)
			expect(completed).toMatchObject({
				usernameChanged: true,
				passwordChanged: true,
			})
			const changedUserLogin = await auth.api.signInUsername({
				body: {
					username: "real_admin",
					password: "new-admin-password-strong-789",
				},
				asResponse: true,
			})
			expect(changedUserLogin.ok).toBe(true)
			const users = await store.drizzle.select().from(persistenceSchema.user)
			expect(users).toHaveLength(1)
			expect(users[0]?.username).toBe("real_admin")
		} finally {
			store.close()
		}
	})

	it("fails closed when first-run bootstrap secrets are missing", async () => {
		const store = await createStore()
		try {
			const auth = createAdminAuth(store, {
				baseURL: "https://oauth.example.test",
				secret: AUTH_SECRET,
			})
			await expect(initializeAdminBootstrap(auth, store)).rejects.toThrow(
				"AUTH_BOOTSTRAP_USERNAME and AUTH_BOOTSTRAP_PASSWORD are required for first initialization",
			)
		} finally {
			store.close()
		}
	})
})
