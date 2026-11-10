import { createOpenAI } from "@ai-sdk/openai"
import {
	type ImageModelV4,
	type LanguageModelV4,
	type LanguageModelV4Content,
	type LanguageModelV4FinishReason,
	type LanguageModelV4ResponseMetadata,
	type LanguageModelV4Usage,
	NoSuchModelError,
	type ProviderV4,
	type SharedV4ProviderMetadata,
	type SharedV4Warning,
} from "@ai-sdk/provider"
import { withUserAgentSuffix } from "@ai-sdk/provider-utils"
import {
	createOpenAIOAuthTransport,
	type OpenAIOAuth,
	type OpenAIOAuthTransport,
} from "@openai-oauth/core"
import packageMetadata from "../package.json" with { type: "json" }

export type OpenAIOAuthModelId = string
export type OpenAIOAuthImageModelId = string

export type OpenAIOAuthProviderSettings = {
	name?: string
}

export type OpenAIOAuthProviderInput = OpenAIOAuthTransport | OpenAIOAuth

const emptyUsage = (): LanguageModelV4Usage => ({
	inputTokens: {
		total: undefined,
		noCache: undefined,
		cacheRead: undefined,
		cacheWrite: undefined,
	},
	outputTokens: {
		total: undefined,
		text: undefined,
		reasoning: undefined,
	},
})

const mergeProviderMetadata = (
	left: SharedV4ProviderMetadata | undefined,
	right: SharedV4ProviderMetadata | undefined,
): SharedV4ProviderMetadata | undefined => {
	if (left == null) return right
	if (right == null) return left

	const merged: SharedV4ProviderMetadata = { ...left }
	for (const [provider, value] of Object.entries(right)) {
		const existing = merged[provider]
		merged[provider] = existing == null ? value : { ...existing, ...value }
	}

	return merged
}

class CodexResponsesLanguageModel implements LanguageModelV4 {
	readonly specificationVersion = "v4" as const
	readonly provider: string
	readonly modelId: string
	readonly supportedUrls: LanguageModelV4["supportedUrls"]

	constructor(private readonly model: LanguageModelV4) {
		this.provider = model.provider
		this.modelId = model.modelId
		this.supportedUrls = model.supportedUrls
	}

	doStream(
		options: Parameters<LanguageModelV4["doStream"]>[0],
	): ReturnType<LanguageModelV4["doStream"]> {
		return this.model.doStream(options)
	}

	async doGenerate(
		options: Parameters<LanguageModelV4["doGenerate"]>[0],
	): Promise<Awaited<ReturnType<LanguageModelV4["doGenerate"]>>> {
		const streamResult = await this.model.doStream(options)
		const reader = streamResult.stream.getReader()

		const content: Array<LanguageModelV4Content> = []
		const warnings: Array<SharedV4Warning> = []
		const activeTextById = new Map<string, LanguageModelV4Content>()
		const activeReasoningById = new Map<string, LanguageModelV4Content>()

		let finishReason: LanguageModelV4FinishReason = {
			unified: "other",
			raw: undefined,
		}
		let usage: LanguageModelV4Usage = emptyUsage()
		let providerMetadata: SharedV4ProviderMetadata | undefined
		let responseMetadata: LanguageModelV4ResponseMetadata | undefined

		try {
			while (true) {
				const { value: part, done } = await reader.read()
				if (done) {
					break
				}

				switch (part.type) {
					case "stream-start": {
						warnings.push(...part.warnings)
						break
					}

					case "response-metadata": {
						responseMetadata = {
							id: part.id,
							timestamp: part.timestamp,
							modelId: part.modelId,
						}
						break
					}

					case "text-start": {
						const textPart: LanguageModelV4Content = {
							type: "text",
							text: "",
							providerMetadata: part.providerMetadata,
						}

						content.push(textPart)
						activeTextById.set(part.id, textPart)
						break
					}

					case "text-delta": {
						const existing = activeTextById.get(part.id)
						if (existing == null) {
							const textPart: LanguageModelV4Content = {
								type: "text",
								text: part.delta,
								providerMetadata: part.providerMetadata,
							}

							content.push(textPart)
							activeTextById.set(part.id, textPart)
						} else if (existing.type === "text") {
							existing.text += part.delta
							existing.providerMetadata = mergeProviderMetadata(
								existing.providerMetadata,
								part.providerMetadata,
							)
						}
						break
					}

					case "text-end": {
						const existing = activeTextById.get(part.id)
						if (existing?.type === "text") {
							existing.providerMetadata = mergeProviderMetadata(
								existing.providerMetadata,
								part.providerMetadata,
							)
							activeTextById.delete(part.id)
						}
						break
					}

					case "reasoning-start": {
						const reasoningPart: LanguageModelV4Content = {
							type: "reasoning",
							text: "",
							providerMetadata: part.providerMetadata,
						}

						content.push(reasoningPart)
						activeReasoningById.set(part.id, reasoningPart)
						break
					}

					case "reasoning-delta": {
						const existing = activeReasoningById.get(part.id)
						if (existing == null) {
							const reasoningPart: LanguageModelV4Content = {
								type: "reasoning",
								text: part.delta,
								providerMetadata: part.providerMetadata,
							}

							content.push(reasoningPart)
							activeReasoningById.set(part.id, reasoningPart)
						} else if (existing.type === "reasoning") {
							existing.text += part.delta
							existing.providerMetadata = mergeProviderMetadata(
								existing.providerMetadata,
								part.providerMetadata,
							)
						}
						break
					}

					case "reasoning-end": {
						const existing = activeReasoningById.get(part.id)
						if (existing?.type === "reasoning") {
							existing.providerMetadata = mergeProviderMetadata(
								existing.providerMetadata,
								part.providerMetadata,
							)
							activeReasoningById.delete(part.id)
						}
						break
					}

					case "ping":
					case "tool-input-start":
					case "tool-input-delta":
					case "tool-input-end": {
						break
					}

					case "tool-approval-request":
					case "tool-call":
					case "tool-result":
					case "custom":
					case "reasoning-file":
					case "file":
					case "source": {
						content.push(part)
						break
					}

					case "finish": {
						finishReason = part.finishReason
						usage = part.usage
						providerMetadata = part.providerMetadata
						break
					}

					case "raw": {
						break
					}

					case "error": {
						throw part.error instanceof Error
							? part.error
							: new Error("Streaming request failed.", { cause: part.error })
					}

					default: {
						part satisfies never
					}
				}
			}
		} finally {
			reader.releaseLock()
		}

		const responseHeaders = streamResult.response?.headers
		const response =
			responseMetadata == null && responseHeaders == null
				? undefined
				: {
						...(responseMetadata ?? {}),
						...(responseHeaders == null ? {} : { headers: responseHeaders }),
					}

		return {
			content,
			finishReason,
			usage,
			providerMetadata,
			request: streamResult.request,
			response,
			warnings,
		}
	}
}

export interface OpenAIOAuthProvider extends ProviderV4 {
	(modelId: OpenAIOAuthModelId): LanguageModelV4
	languageModel(modelId: OpenAIOAuthModelId): LanguageModelV4
	image(modelId: OpenAIOAuthImageModelId): ImageModelV4
	imageModel(modelId: OpenAIOAuthImageModelId): ImageModelV4
}

const isTransport = (
	input: OpenAIOAuthProviderInput,
): input is OpenAIOAuthTransport => input.kind === "openai-compatible"

const toTransport = (input: OpenAIOAuthProviderInput): OpenAIOAuthTransport => {
	if (isTransport(input)) {
		return input
	}

	return createOpenAIOAuthTransport({
		auth: () => input.getSession(),
		baseURL: input.baseURL,
		fetch: input.fetch,
		headers: input.headers,
		instructions: input.instructions,
		openAIBaseURL: input.openAIBaseURL,
	})
}

export const createOpenAIOAuth = (
	input: OpenAIOAuthProviderInput,
	settings: OpenAIOAuthProviderSettings = {},
): OpenAIOAuthProvider => {
	const transport = toTransport(input)
	const baseURL = transport.baseURL
	const providerName = settings.name ?? "openai"
	const oauthFetch = transport.fetch

	const provider = createOpenAI({
		apiKey: "openai-oauth",
		baseURL,
		fetch: oauthFetch,
		headers: withUserAgentSuffix({}, `openai-oauth/${packageMetadata.version}`),
		name: providerName,
	})

	const createModel = (modelId: OpenAIOAuthModelId) =>
		new CodexResponsesLanguageModel(provider.responses(modelId))
	const createImageModel = (modelId: OpenAIOAuthImageModelId) =>
		provider.image(modelId)

	const providerFn = (modelId: OpenAIOAuthModelId) => createModel(modelId)
	const specificationVersion: ProviderV4["specificationVersion"] = "v4"

	return Object.assign(providerFn, {
		specificationVersion,
		languageModel: createModel,
		image: createImageModel,
		embeddingModel: (modelId: string) => {
			throw new NoSuchModelError({ modelId, modelType: "embeddingModel" })
		},
		imageModel: createImageModel,
	})
}
