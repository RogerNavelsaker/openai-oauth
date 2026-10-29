import { mkdtemp, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { beforeEach, describe, expect, test, vi } from "vitest"

vi.mock("../src/cli-runtime.js", () => ({
	findRunningCliRuntime: vi.fn(),
	followCliLogs: vi.fn(),
	readRecentCliLogs: vi.fn(),
	sendDetachedError: vi.fn(),
	startCliWorker: vi.fn(),
	stopCliRuntime: vi.fn(),
}))
vi.mock("../src/cli-worker.js", () => ({ runCliWorker: vi.fn() }))
vi.mock("../src/cli-logging.js", () => ({
	installCliWarningLogger: vi.fn(),
	toAlreadyRunningMessage: vi.fn(() => "already running"),
	toBackgroundStartupMessage: vi.fn(() => "ready"),
	toDetachedMessage: vi.fn(() => "detached"),
	toForegroundStartupMessage: vi.fn(() => "ready"),
	toRunningMessage: vi.fn(() => "running"),
}))
vi.mock("../src/login.js", () => ({
	runOpenAIOAuthDeviceCodeLogin: vi.fn(),
	runOpenAIOAuthLogin: vi.fn(),
}))
vi.mock("../src/update-check.js", () => ({
	checkForOpenAIOAuthUpdates: vi.fn(async () => undefined),
}))

import { runCli } from "../src/cli-app.js"
import { findRunningCliRuntime, startCliWorker } from "../src/cli-runtime.js"
import { runOpenAIOAuthDeviceCodeLogin } from "../src/login.js"

const mockFindRunningCliRuntime =
	findRunningCliRuntime as unknown as ReturnType<typeof vi.fn>
const mockStartCliWorker = startCliWorker as unknown as ReturnType<typeof vi.fn>
const mockDeviceLogin = runOpenAIOAuthDeviceCodeLogin as unknown as ReturnType<
	typeof vi.fn
>

const worker = {
	url: "http://127.0.0.1:10531/v1",
	models: ["gpt-6-luna"],
	detach: vi.fn(async () => undefined),
} as unknown as Awaited<ReturnType<typeof startCliWorker>>

describe("device-auth server startup", () => {
	beforeEach(() => {
		vi.clearAllMocks()
		mockFindRunningCliRuntime.mockResolvedValue(undefined)
		mockStartCliWorker.mockResolvedValue(worker)
		mockDeviceLogin.mockResolvedValue({
			path: "/tmp/auth.json",
		} as Awaited<ReturnType<typeof runOpenAIOAuthDeviceCodeLogin>>)
	})

	test("waits for device login when credentials are missing before starting the server", async () => {
		const root = await mkdtemp(path.join(os.tmpdir(), "openai-oauth-startup-"))
		const authFilePath = path.join(root, "missing-auth.json")

		try {
			await runCli(["--device-auth", "--oauth-file", authFilePath, "--detach"])

			expect(runOpenAIOAuthDeviceCodeLogin).toHaveBeenCalledWith(
				expect.objectContaining({ authFilePath }),
			)
			expect(startCliWorker).toHaveBeenCalledTimes(1)
		} finally {
			await rm(root, { recursive: true, force: true })
		}
	})

	test("re-authenticates after a rejected refresh and retries startup once", async () => {
		const root = await mkdtemp(path.join(os.tmpdir(), "openai-oauth-startup-"))
		const authFilePath = path.join(root, "auth.json")
		await writeFile(authFilePath, "{}")
		mockStartCliWorker
			.mockRejectedValueOnce(
				new Error("OpenAI OAuth token request failed with HTTP 401."),
			)
			.mockResolvedValueOnce(worker)

		try {
			await runCli(["--device-auth", "--oauth-file", authFilePath, "--detach"])

			expect(runOpenAIOAuthDeviceCodeLogin).toHaveBeenCalledTimes(1)
			expect(startCliWorker).toHaveBeenCalledTimes(2)
		} finally {
			await rm(root, { recursive: true, force: true })
		}
	})

	test("does not start device login for unrelated startup failures", async () => {
		const root = await mkdtemp(path.join(os.tmpdir(), "openai-oauth-startup-"))
		const authFilePath = path.join(root, "auth.json")
		await writeFile(authFilePath, "{}")
		mockStartCliWorker
			.mockRejectedValueOnce(new Error("network unavailable"))
			.mockRejectedValueOnce(
				new Error("OpenAI API request failed with HTTP 401."),
			)

		try {
			await expect(
				runCli(["--device-auth", "--oauth-file", authFilePath, "--detach"]),
			).rejects.toThrow("network unavailable")
			await expect(
				runCli(["--device-auth", "--oauth-file", authFilePath, "--detach"]),
			).rejects.toThrow("OpenAI API request failed with HTTP 401.")
			expect(runOpenAIOAuthDeviceCodeLogin).not.toHaveBeenCalled()
			expect(startCliWorker).toHaveBeenCalledTimes(2)
		} finally {
			await rm(root, { recursive: true, force: true })
		}
	})
})
