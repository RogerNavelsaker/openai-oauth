import { existsSync, writeFileSync } from "node:fs"
import { Database } from "@tursodatabase/database/compat"

const [dbPath, readyPath, releasePath] = process.argv.slice(2)
const key = process.env.TEST_DATABASE_KEY
if (!dbPath || !readyPath || !releasePath || !key) {
	throw new Error("Missing legacy database worker configuration")
}

const database = new Database(dbPath, {
	encryption: { cipher: "aes256gcm", hexkey: key },
	experimental: ["encryption"],
	timeout: 30_000,
})
writeFileSync(readyPath, "ready")
while (!existsSync(releasePath)) await Bun.sleep(10)
database.close()
