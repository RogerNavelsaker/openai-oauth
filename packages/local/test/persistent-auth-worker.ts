import { access, appendFile, writeFile } from "node:fs/promises"
import path from "node:path"
import { pathToFileURL } from "node:url"
import { forceRefreshAuthTokens } from "../src/auth-file.js"
import { openPersistentStore } from "../src/persistence.js"

const [databasePath, workerId, readyDirectory, releasePath, refreshCallsPath] =
	process.argv.slice(2)
const encryptionKey = process.env.TEST_DATABASE_KEY
if (
	!databasePath ||
	!workerId ||
	!readyDirectory ||
	!releasePath ||
	!refreshCallsPath ||
	!encryptionKey
) {
	throw new Error("Missing persistent-auth worker configuration")
}

const store = await openPersistentStore({
	databaseUrl: pathToFileURL(databasePath).href,
	encryptionKey,
})
try {
	await writeFile(path.join(readyDirectory, `${workerId}.ready`), "ready")
	for (;;) {
		try {
			await access(releasePath)
			break
		} catch {
			await new Promise((resolve) => setTimeout(resolve, 10))
		}
	}
	await forceRefreshAuthTokens({
		store,
		clientId: "test-client",
		now: () => new Date("2026-11-11T12:00:00.000Z"),
		fetch: async () => {
			await appendFile(refreshCallsPath, `${workerId}\n`)
			await new Promise((resolve) => setTimeout(resolve, 400))
			return Response.json({
				access_token: "rotated-cross-process-access",
				refresh_token: "rotated-cross-process-refresh",
			})
		},
	})
} finally {
	store.close()
}
