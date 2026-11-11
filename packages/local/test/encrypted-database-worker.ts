import { openEncryptedDatabase } from "../src/encrypted-database.js"
import { encryptedDatabaseRuntime } from "./encrypted-database-runtime.js"

const [dbPath, workerId] = process.argv.slice(2)
const key = process.env.TEST_DATABASE_KEY
if (!dbPath || !workerId || !key) {
	throw new Error("Missing encrypted database worker configuration")
}

const database = await openEncryptedDatabase({ path: dbPath, hexKey: key })
if (process.env.TEST_PARENT_RUNTIME) {
	console.log(
		JSON.stringify({
			event: "encrypted-db-runtime",
			role: "worker",
			workerId,
			parentRuntime: JSON.parse(process.env.TEST_PARENT_RUNTIME),
			...encryptedDatabaseRuntime(),
		}),
	)
}
const insert = database.prepare(
	"INSERT INTO writes (worker, iteration) VALUES (?, ?)",
)
for (let iteration = 0; iteration < 20; iteration++) {
	insert.run(workerId, iteration)
}
database.close()
