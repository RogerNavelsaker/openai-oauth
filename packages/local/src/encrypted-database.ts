import path from "node:path"
import { Database } from "@tursodatabase/database/compat"

export type EncryptedDatabaseOptions = {
	path: string
	hexKey: string
}

export const validateEncryptionKey = (hexKey: string): void => {
	if (!/^[\da-f]{64}$/i.test(hexKey)) {
		throw new Error(
			"AUTH_DATABASE_KEY must be exactly 64 hexadecimal characters (32 bytes).",
		)
	}
}

const MULTIPROCESS_OPEN_RETRIES = 3
const MULTIPROCESS_OPEN_RETRY_DELAY_MS = 500
const LEGACY_OPEN_RACE =
	"Database is already open without experimental multiprocess WAL in another process"

export const openEncryptedDatabase = async ({
	path: databasePath,
	hexKey,
}: EncryptedDatabaseOptions): Promise<Database> => {
	validateEncryptionKey(hexKey)
	if (!databasePath || databasePath === ":memory:") {
		throw new Error(
			"AUTH_DATABASE_PATH must be a filesystem path for encrypted persistence.",
		)
	}

	const resolvedPath = path.resolve(databasePath)

	for (let attempt = 0; ; attempt++) {
		try {
			return new Database(resolvedPath, {
				encryption: { cipher: "aes256gcm", hexkey: hexKey },
				experimental: ["encryption", "multiprocess_wal"],
				timeout: 30_000,
			})
		} catch (error) {
			const isOpenRace =
				error instanceof Error && error.message.includes(LEGACY_OPEN_RACE)
			if (!isOpenRace || attempt >= MULTIPROCESS_OPEN_RETRIES) throw error

			// Turso 0.8.3 has this concurrent-open race (upstream issue #10114).
			await new Promise((resolve) =>
				setTimeout(resolve, MULTIPROCESS_OPEN_RETRY_DELAY_MS),
			)
		}
	}
}
