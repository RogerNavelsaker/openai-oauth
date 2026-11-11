import { spawn } from "node:child_process"
import { existsSync, writeFileSync } from "node:fs"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Database } from "@tursodatabase/database/compat"
import { afterEach, describe, expect, it } from "vitest"
import { openEncryptedDatabase } from "../src/encrypted-database.js"
import { encryptedDatabaseRuntime } from "./encrypted-database-runtime.js"

const KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const WRONG_KEY =
	"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
const tempDirs: string[] = []
const options = (hexkey: string) => ({
	encryption: { cipher: "aes256gcm" as const, hexkey },
	experimental: ["encryption", "multiprocess_wal"] as const,
	timeout: 30_000,
})

const createDatabase = async () => {
	const directory = await mkdtemp(
		path.join(os.tmpdir(), "openai-oauth-encrypted-db-"),
	)
	tempDirs.push(directory)
	const dbPath = path.join(directory, "auth.db")
	const database = new Database(dbPath, options(KEY))
	database.exec("PRAGMA journal_mode=WAL")
	database.exec(
		"CREATE TABLE writes (worker TEXT NOT NULL, iteration INTEGER NOT NULL)",
	)
	return { dbPath, database }
}

afterEach(async () => {
	await Promise.all(
		tempDirs
			.splice(0)
			.map((directory) => rm(directory, { recursive: true, force: true })),
	)
})

describe("encrypted local database", () => {
	it("persists encrypted data and rejects an incorrect key", async () => {
		const { dbPath, database } = await createDatabase()
		database
			.prepare("INSERT INTO writes VALUES (?, ?)")
			.run("sensitive-marker", 1)
		database.close()

		const bytes = await readFile(dbPath)
		expect(bytes.subarray(0, 16).toString("ascii")).not.toBe(
			"SQLite format 3\0",
		)
		expect(bytes.includes(Buffer.from("sensitive-marker"))).toBe(false)

		const reopened = new Database(dbPath, options(KEY))
		expect(
			reopened.prepare("SELECT COUNT(*) AS count FROM writes").get(),
		).toEqual({ count: 1 })
		reopened.close()

		expect(() => new Database(dbPath, options(WRONG_KEY))).toThrow()
	})

	it("serializes concurrent writes from four separate processes", async () => {
		const { dbPath, database } = await createDatabase()
		database.close()
		const workerPath = new URL(
			"./encrypted-database-worker.ts",
			import.meta.url,
		).pathname
		const parentRuntime =
			process.env.TEST_DATABASE_DIAGNOSTICS === "1"
				? encryptedDatabaseRuntime()
				: undefined
		if (parentRuntime) {
			console.log(
				JSON.stringify({
					event: "encrypted-db-runtime",
					role: "parent",
					runtime: parentRuntime,
				}),
			)
		}

		const results = await Promise.allSettled(
			Array.from(
				{ length: 4 },
				(_, index) =>
					new Promise<void>((resolve, reject) => {
						const child = spawn(
							"bun",
							["run", workerPath, dbPath, `worker-${index}`],
							{
								stdio: "inherit",
								env: {
									...process.env,
									TEST_DATABASE_KEY: KEY,
									...(parentRuntime
										? { TEST_PARENT_RUNTIME: JSON.stringify(parentRuntime) }
										: {}),
								},
							},
						)
						child.once("error", reject)
						child.once("exit", (code) =>
							code === 0
								? resolve()
								: reject(new Error(`worker exited with ${code}`)),
						)
					}),
			),
		)
		for (const result of results) {
			if (result.status === "rejected") throw result.reason
		}

		const verify = new Database(dbPath, options(KEY))
		try {
			expect(
				verify.prepare("SELECT COUNT(*) AS count FROM writes").get(),
			).toEqual({ count: 80 })
		} finally {
			verify.close()
		}
	})

	it("rejects a persistent mixed-mode opener after bounded retries", async () => {
		const { dbPath, database } = await createDatabase()
		database.close()
		const directory = path.dirname(dbPath)
		const readyPath = path.join(directory, "legacy.ready")
		const releasePath = path.join(directory, "legacy.release")
		const workerPath = new URL(
			"./legacy-encrypted-database-worker.ts",
			import.meta.url,
		).pathname
		const child = spawn(
			"bun",
			["run", workerPath, dbPath, readyPath, releasePath],
			{
				stdio: "inherit",
				env: { ...process.env, TEST_DATABASE_KEY: KEY },
			},
		)
		const childExit = new Promise<void>((resolve, reject) => {
			child.once("error", reject)
			child.once("exit", (code) =>
				code === 0
					? resolve()
					: reject(new Error(`legacy worker exited with ${code}`)),
			)
		})

		try {
			const deadline = Date.now() + 5_000
			while (
				!existsSync(readyPath) &&
				child.exitCode === null &&
				Date.now() < deadline
			) {
				await new Promise((resolve) => setTimeout(resolve, 10))
			}
			expect(existsSync(readyPath)).toBe(true)
			await expect(
				openEncryptedDatabase({ path: dbPath, hexKey: KEY }),
			).rejects.toThrow(
				"Database is already open without experimental multiprocess WAL in another process",
			)
		} finally {
			writeFileSync(releasePath, "release")
			await childExit
		}
	})
})
