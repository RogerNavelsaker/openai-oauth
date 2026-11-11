import { execFileSync } from "node:child_process"
import { createHash } from "node:crypto"
import { readFileSync, realpathSync } from "node:fs"
import { createRequire } from "node:module"

const require = createRequire(import.meta.url)

const resolveBun = (): { bunPath: string; bunVersion: string } => {
	const resolver = process.platform === "win32" ? "where.exe" : "which"
	const output = execFileSync(resolver, ["bun"], { encoding: "utf8" })
	const bunPath = output.trim().split(/\r?\n/)[0]
	if (!bunPath)
		throw new Error("Could not resolve the bun executable from PATH.")
	const version = process.versions.bun
		? `${process.versions.bun}`
		: execFileSync(bunPath, ["--version"], { encoding: "utf8" }).trim()
	return { bunPath: realpathSync(bunPath), bunVersion: version }
}

export const encryptedDatabaseRuntime = () => {
	const addonPath = Object.keys(require.cache ?? {}).find(
		(filePath) =>
			filePath.includes("@tursodatabase/database-") &&
			filePath.endsWith(".node"),
	)
	if (!addonPath) {
		throw new Error("Turso native addon is not present in the module cache.")
	}

	const resolvedAddonPath = realpathSync(addonPath)
	const addonSha256 = createHash("sha256")
		.update(readFileSync(resolvedAddonPath))
		.digest("hex")

	return {
		processExecPath: process.execPath,
		resolvedProcessPath: realpathSync(process.execPath),
		runtimeKind: process.versions.bun ? "bun" : "node",
		runtimeVersion: process.versions.bun ?? process.versions.node,
		...resolveBun(),
		platform: process.platform,
		arch: process.arch,
		addonPath,
		resolvedAddonPath,
		addonSha256,
	}
}
