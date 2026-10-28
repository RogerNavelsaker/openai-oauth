import type { OpenAIOAuthTransport } from "@openai-oauth/core"

export type OpenAIOAuthModel = Record<string, unknown> & { id: string }

type ModelResolver = () => Promise<OpenAIOAuthModel[]>

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value)

const uniqueStrings = (values: string[]): string[] => [...new Set(values)]

const modelListError = (bodyText: string): string => {
	try {
		const parsed = JSON.parse(bodyText)
		if (
			isRecord(parsed) &&
			isRecord(parsed.error) &&
			typeof parsed.error.message === "string"
		) {
			return parsed.error.message
		}
	} catch {}

	return bodyText || "Failed to load models from Codex."
}

const readModelList = async (
	client: OpenAIOAuthTransport,
): Promise<OpenAIOAuthModel[]> => {
	const response = await client.request("/models")
	const bodyText = await response.text()

	if (!response.ok) {
		throw new Error(modelListError(bodyText))
	}

	let parsed: unknown
	try {
		parsed = JSON.parse(bodyText)
	} catch {
		throw new Error("Codex returned an invalid models response.")
	}

	if (!isRecord(parsed) || !Array.isArray(parsed.data)) {
		throw new Error("Codex returned a malformed models response.")
	}

	const models = new Map<string, OpenAIOAuthModel>()
	for (const value of parsed.data) {
		if (
			!isRecord(value) ||
			typeof value.id !== "string" ||
			value.id.length === 0
		)
			continue
		models.set(value.id, value as OpenAIOAuthModel)
	}
	if (models.size === 0) {
		throw new Error("Codex returned an empty models list.")
	}

	return [...models.values()]
}

export const resolveOpenAIOAuthModels = async (
	client: OpenAIOAuthTransport,
	configuredModels: string[] | undefined,
): Promise<OpenAIOAuthModel[]> =>
	Array.isArray(configuredModels) && configuredModels.length > 0
		? uniqueStrings(configuredModels).map((id) => ({ id }))
		: readModelList(client)

export const createModelResolver =
	(
		client: OpenAIOAuthTransport,
		configuredModels: string[] | undefined,
	): ModelResolver =>
	() =>
		resolveOpenAIOAuthModels(client, configuredModels)
