import { spawnSync } from "node:child_process"
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { afterEach, describe, expect, test } from "vitest"

const entrypoint = resolve(
	dirname(fileURLToPath(import.meta.url)),
	"../../../scripts/oci-entrypoint.sh",
)
const tempDirs: string[] = []

const makeExecutable = (content: string): string => {
	const dir = mkdtempSync(join(tmpdir(), "openai-oauth-entrypoint-"))
	tempDirs.push(dir)
	const path = join(dir, "fake-cli")
	writeFileSync(path, content)
	chmodSync(path, 0o700)
	return path
}

afterEach(() => {
	for (const dir of tempDirs.splice(0))
		rmSync(dir, { recursive: true, force: true })
})

describe("OCI login UI entrypoint", () => {
	test("preserves the CLI-only default and forwards arguments", () => {
		const cli = makeExecutable('#!/bin/sh\nprintf "%s\\n" "$@"\n')
		const result = spawnSync(
			"bash",
			[entrypoint, "--device-auth", "--port", "11531"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					OPENAI_OAUTH_CLI_BIN: cli,
				},
			},
		)

		expect(result.error).toBeUndefined()
		expect(result.status).toBe(0)
		expect(result.stdout).toBe("--device-auth\n--port\n11531\n")
	})

	test("requires the control token before starting the optional UI", () => {
		const cli = makeExecutable("#!/bin/sh\necho should-not-start\n")
		const result = spawnSync("bash", [entrypoint, "--help"], {
			encoding: "utf8",
			env: {
				...process.env,
				OPENAI_OAUTH_CLI_BIN: cli,
				OPENAI_OAUTH_LOGIN_UI: "1",
				OPENAI_OAUTH_CONTROL_TOKEN: "",
				LOGIN_UI_PUBLIC_ORIGIN: "http://127.0.0.1:10533",
			},
		})

		expect(result.error).toBeUndefined()
		expect(result.status).toBe(1)
		expect(result.stderr).toContain("OPENAI_OAUTH_CONTROL_TOKEN")
		expect(result.stdout).not.toContain("should-not-start")
	})

	test("starts the bundled UI with the sidecar's loopback control endpoint", () => {
		const cli = makeExecutable("#!/bin/sh\necho cli-started\n")
		const bun = makeExecutable(
			'#!/bin/sh\nprintf "%s\\n" "$SIDECAR_CONTROL_TOKEN" "$SIDECAR_CONTROL_URL"\n',
		)
		const token = "0123456789abcdef0123456789abcdef"
		const result = spawnSync("bash", [entrypoint, "--device-auth"], {
			encoding: "utf8",
			timeout: 5000,
			env: {
				...process.env,
				OPENAI_OAUTH_CLI_BIN: cli,
				OPENAI_OAUTH_LOGIN_UI: "1",
				OPENAI_OAUTH_CONTROL_TOKEN: token,
				OPENAI_OAUTH_CONTROL_PORT: "11532",
				LOGIN_UI_PUBLIC_ORIGIN: "http://127.0.0.1:11533",
				BUN_BIN: bun,
			},
		})

		expect(result.error).toBeUndefined()
		expect(result.status).toBe(0)
		expect(result.stdout).toContain(token)
		expect(result.stdout).toContain("http://127.0.0.1:11532")
	})

	test("rejects a non-loopback control listener when the UI is enabled", () => {
		const cli = makeExecutable("#!/bin/sh\necho should-not-start\n")
		const result = spawnSync("bash", [entrypoint, "--help"], {
			encoding: "utf8",
			env: {
				...process.env,
				OPENAI_OAUTH_CLI_BIN: cli,
				OPENAI_OAUTH_LOGIN_UI: "1",
				OPENAI_OAUTH_CONTROL_TOKEN: "0123456789abcdef0123456789abcdef",
				OPENAI_OAUTH_CONTROL_HOST: "0.0.0.0",
				LOGIN_UI_PUBLIC_ORIGIN: "http://127.0.0.1:11533",
			},
		})

		expect(result.error).toBeUndefined()
		expect(result.status).toBe(1)
		expect(result.stderr).toContain("must be loopback")
		expect(result.stdout).not.toContain("should-not-start")
	})
})
