import { isAbsolute, resolve } from "node:path"
import { pathToFileURL } from "node:url"
import type { PersistentStore } from "@openai-oauth/local/persistence"
import { openPersistentStore } from "@openai-oauth/local/persistence"
import { cliMessages } from "./cli-logging.js"
import {
	type ActiveCliRuntime,
	acquireCliRuntimeLock,
	activateCliRuntime,
	type CliRuntimeMode,
	sendDetachedAcknowledgement,
	sendDetachedError,
	sendDetachedReady,
	sendRemoteStopping,
} from "./cli-runtime.js"
import { startOpenAIOAuthServer } from "./server.js"
import type {
	OpenAIOAuthServerOptions,
	RunningOpenAIOAuthServer,
} from "./types.js"

type WorkerCommand =
	| { type: "openai-oauth:detach" }
	| { type: "openai-oauth:stop" }

const isWorkerCommand = (value: unknown): value is WorkerCommand => {
	if (typeof value !== "object" || value == null) {
		return false
	}
	const type = (value as { type?: unknown }).type
	return type === "openai-oauth:detach" || type === "openai-oauth:stop"
}

const openPersistentStoreFromEnvironment = async (): Promise<
	PersistentStore | undefined
> => {
	const databasePath = process.env.OPENAI_OAUTH_DATABASE_PATH
	const encryptionKey = process.env.OPENAI_OAUTH_DATABASE_KEY
	if (databasePath === undefined && encryptionKey === undefined)
		return undefined
	if (!databasePath || !encryptionKey) {
		throw new Error(
			"OPENAI_OAUTH_DATABASE_PATH and OPENAI_OAUTH_DATABASE_KEY must both be configured.",
		)
	}
	if (!isAbsolute(databasePath)) {
		throw new Error("OPENAI_OAUTH_DATABASE_PATH must be an absolute path.")
	}
	return openPersistentStore({
		databaseUrl: pathToFileURL(resolve(databasePath)).href,
		encryptionKey,
	})
}

const startCliInstance = async (
	options: OpenAIOAuthServerOptions,
	mode: CliRuntimeMode,
	version: string,
	onRemoteStop: () => void | Promise<void>,
): Promise<{
	server: RunningOpenAIOAuthServer
	runtime: ActiveCliRuntime
	models: string[]
	store?: PersistentStore
}> => {
	const lock = await acquireCliRuntimeLock()
	let server: RunningOpenAIOAuthServer | undefined

	try {
		server = await startOpenAIOAuthServer(options)
		const runtime = await activateCliRuntime(lock, {
			mode,
			url: server.url,
			version,
			onStop: onRemoteStop,
		})
		return { server, runtime, models: server.models, store: options.store }
	} catch (error) {
		await server?.close().catch(() => undefined)
		await lock.release()
		throw error
	}
}

export const runCliWorker = async (
	options: OpenAIOAuthServerOptions,
	initialMode: CliRuntimeMode,
	version: string,
): Promise<void> => {
	if (typeof process.send !== "function") {
		throw new Error("OpenAI OAuth worker requires an IPC channel.")
	}

	let detached = false
	let stopping = false
	let instance: Awaited<ReturnType<typeof startCliInstance>> | undefined

	const shutdown = async (
		source: "parent" | "remote" | "signal" | "disconnect",
	) => {
		if (stopping) {
			return
		}
		stopping = true

		if (source === "remote") {
			await sendRemoteStopping()
		}

		await instance?.server.close().catch(() => undefined)
		await instance?.runtime.close().catch(() => undefined)
		instance?.store?.close()
		if (process.connected) {
			process.disconnect?.()
		}
		process.exit(0)
	}

	const store = options.store ?? (await openPersistentStoreFromEnvironment())
	try {
		instance = await startCliInstance(
			store ? { ...options, store } : options,
			initialMode,
			version,
			() => shutdown("remote"),
		)
	} catch (error) {
		if (!options.store) store?.close()
		throw error
	}

	const onMessage = (value: unknown) => {
		if (!isWorkerCommand(value) || stopping) {
			return
		}

		if (value.type === "openai-oauth:stop") {
			void shutdown("parent")
			return
		}

		void (async () => {
			try {
				await instance?.runtime.setMode("background")
				detached = true
				sendDetachedAcknowledgement()
			} catch (error) {
				await sendDetachedError(
					error instanceof Error ? error.message : cliMessages.couldNotDetach(),
				)
			}
		})()
	}
	const onDisconnect = () => {
		if (!detached) {
			void shutdown("disconnect")
		}
	}
	const onSignal = () => shutdown("signal")

	process.on("message", onMessage)
	process.once("disconnect", onDisconnect)
	process.once("SIGINT", onSignal)
	process.once("SIGTERM", onSignal)

	console.log(cliMessages.workerStarted(instance.server.url))
	sendDetachedReady(instance.server.url, instance.models)
}
