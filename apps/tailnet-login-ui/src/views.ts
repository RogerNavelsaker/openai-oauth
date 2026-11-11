export type LoginState =
	| "idle"
	| "starting"
	| "awaiting_user"
	| "awaiting_callback"
	| "complete"
	| "failed"
	| "cancelled"

export type ControlStatus = {
	credentialsConfigured: boolean
	credentialsUpdatedAt?: string
	accessTokenExpiresAt?: string
	accessTokenAppearsValid?: boolean
	isNearExpiry?: boolean
	refreshAvailable?: boolean
	notice?: string
	login: {
		state: LoginState
		id?: string
		verificationUrl?: string
		userCode?: string
		authorizationUrl?: string
		error?: string
	}
}

const escapeHtml = (value: string): string =>
	value.replace(/[&<>"']/g, (character) => {
		const entities: Record<string, string> = {
			"&": "&amp;",
			"<": "&lt;",
			">": "&gt;",
			'"': "&quot;",
			"'": "&#39;",
		}
		return entities[character] ?? character
	})

const formatTimestamp = (value: string): string => {
	const date = new Date(value)
	return Number.isNaN(date.getTime())
		? value
		: new Intl.DateTimeFormat(undefined, {
				dateStyle: "medium",
				timeStyle: "short",
			}).format(date)
}
const isActive = (state: LoginState): boolean =>
	state === "starting" ||
	state === "awaiting_user" ||
	state === "awaiting_callback"

export const renderStatus = (
	csrf: string,
	status?: ControlStatus,
	unavailable = false,
): string => {
	const state = status?.login.state ?? "idle"
	const poll = status !== undefined && isActive(state)
	const login = status?.login
	const metadata = status?.credentialsConfigured
		? `<dl class="mt-5 grid grid-cols-1 gap-y-2 text-sm text-zinc-300 sm:grid-cols-[max-content_minmax(0,1fr)] sm:gap-x-6"><dt class="text-zinc-400">Access token updated:</dt><dd class="min-w-0 break-words">${status.credentialsUpdatedAt ? escapeHtml(formatTimestamp(status.credentialsUpdatedAt)) : "Unavailable"}</dd><dt class="text-zinc-400">Access token expiry:</dt><dd class="min-w-0 break-words">${status.accessTokenExpiresAt ? escapeHtml(formatTimestamp(status.accessTokenExpiresAt)) : "Unavailable"}</dd></dl>`
		: ""
	const message =
		status?.notice ??
		(() => {
			if (unavailable) {
				return "The sidecar login service is unavailable. Check its connection and try again."
			}
			switch (state) {
				case "starting":
					return "Requesting a one-time sign-in code…"
				case "awaiting_user":
					return "Enter this code on OpenAI's device sign-in page."
				case "awaiting_callback":
					return "Complete sign-in in your browser, then paste the full localhost callback URL here."
				case "complete":
					return "Sign-in complete. Your credentials are ready to use."
				case "failed":
					return (
						login?.error ??
						"Sign-in failed. Start a new login or check the sidecar logs."
					)
				case "cancelled":
					return "Sign-in was cancelled."
				default:
					if (!status?.credentialsConfigured) {
						return "No credentials are configured yet. Start either sign-in method when ready."
					}
					if (!status.accessTokenAppearsValid) {
						return "Access token is expired or could not be verified. Refresh it or sign out before signing in again."
					}
					return status.isNearExpiry
						? "Access token expires soon. Refresh it or sign out."
						: "Authenticated. Refresh your access token or sign out."
			}
		})()
	const controls =
		poll && login?.id
			? `<form class="mt-6" hx-post="/_cancel" hx-target="#login-status" hx-swap="outerHTML"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="id" value="${escapeHtml(login.id)}"><button class="rounded-lg bg-red-500 px-4 py-2 text-sm font-bold text-white transition-colors hover:bg-red-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-300" type="submit">Cancel</button></form>`
			: !unavailable && !poll
				? status?.credentialsConfigured
					? `<div class="mt-6 flex flex-wrap gap-3">${status.refreshAvailable ? `<form hx-post="/_refresh" hx-target="#login-status" hx-swap="outerHTML"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button class="rounded-lg bg-emerald-400 px-4 py-2 text-sm font-bold text-zinc-950 transition-colors hover:bg-emerald-300 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300" type="submit">Refresh</button></form>` : `<button class="rounded-lg bg-zinc-700 px-4 py-2 text-sm font-bold text-zinc-400 cursor-not-allowed" type="button" disabled aria-disabled="true">Refresh</button>`}<form hx-post="/_sign-out" hx-target="#login-status" hx-swap="outerHTML"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button class="rounded-lg bg-red-500 px-4 py-2 text-sm font-bold text-white transition-colors hover:bg-red-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-300" type="submit">Sign out</button></form></div>`
					: `<div class="mt-6 flex flex-wrap gap-3"><form hx-post="/_start" hx-target="#login-status" hx-swap="outerHTML"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button class="rounded-lg bg-emerald-400 px-4 py-2 text-sm font-bold text-zinc-950 transition-colors hover:bg-emerald-300 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300" type="submit">Device-code</button></form><form hx-post="/_browser-start" hx-target="#login-status" hx-swap="outerHTML"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button class="rounded-lg bg-emerald-400 px-4 py-2 text-sm font-bold text-zinc-950 transition-colors hover:bg-emerald-300 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300" type="submit">Browser</button></form></div>`
				: ""
	const deviceCode =
		state === "awaiting_user" && login?.userCode
			? `<div class="mt-5 rounded-lg border border-zinc-700 bg-zinc-950 p-4"><p class="text-xs font-semibold uppercase tracking-wide text-zinc-400">One-time code</p><div class="mt-2 flex items-center gap-3"><code id="device-code" class="select-all text-2xl font-bold tracking-widest text-emerald-300">${escapeHtml(login.userCode)}</code><button class="rounded-lg bg-sky-400 px-4 py-2 text-sm font-bold text-zinc-950 transition-colors hover:bg-sky-300 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-300" type="button" data-copy-device-code>Copy</button><span class="sr-only" id="device-code-copy-status" aria-live="polite"></span></div><a class="mt-4 inline-block text-sm font-semibold text-sky-300 underline" href="https://auth.openai.com/codex/device" target="_blank" rel="noopener noreferrer">Open OpenAI device sign-in</a></div>`
			: ""
	const browser =
		state === "awaiting_callback" && login?.authorizationUrl && login.id
			? `<div class="mt-5 rounded-lg border border-zinc-700 bg-zinc-950 p-4"><a class="font-semibold text-sky-300 underline" href="${escapeHtml(login.authorizationUrl)}" target="_blank" rel="noopener noreferrer">Open OpenAI sign-in</a><p class="mt-3 text-sm text-zinc-300">After approval, the localhost page may fail to load. Copy its full URL from the address bar and paste it below. This URL is used once to finish sign-in.</p><form class="mt-4" hx-post="/_browser-callback" hx-target="#login-status" hx-swap="outerHTML"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="id" value="${escapeHtml(login.id)}"><label class="block text-sm" for="callback-url">Localhost callback URL</label><input class="mt-2 w-full rounded border border-zinc-600 bg-zinc-900 px-3 py-2 text-sm text-zinc-300" id="callback-url" name="callbackUrl" type="url" required autocomplete="off"><button class="mt-3 rounded-lg bg-sky-400 px-4 py-2 text-sm font-bold text-zinc-950" type="submit">Submit callback URL</button></form></div>`
			: ""
	const title = (() => {
		switch (state) {
			case "awaiting_callback":
				return "Waiting for browser callback"
			case "awaiting_user":
				return "Waiting for sign-in"
			case "complete":
				return "Signed in"
			case "failed":
				return "Sign-in failed"
			case "cancelled":
				return "Sign-in cancelled"
			case "starting":
				return "Starting sign-in"
			default:
				if (!status?.credentialsConfigured) return "Sign-in required"
				return status.accessTokenAppearsValid
					? "Authenticated"
					: "Authentication required"
		}
	})()
	const statusDotClass = status?.accessTokenAppearsValid
		? status.isNearExpiry
			? "bg-orange-400"
			: "bg-emerald-400"
		: "bg-red-500"
	return `<section id="login-status" class="rounded-xl border border-zinc-800 bg-zinc-900 p-6 shadow-xl"${poll ? ' hx-get="/_status" hx-trigger="every 2s" hx-swap="outerHTML"' : ""}><div class="flex items-center gap-3"><span class="h-2.5 w-2.5 rounded-full ${statusDotClass}" aria-hidden="true"></span><h2 class="text-lg font-semibold text-zinc-100">${unavailable ? "Login service unavailable" : title}</h2></div><p class="mt-3 text-sm leading-6 text-zinc-300">${escapeHtml(message)}</p>${metadata}${deviceCode}${browser}${controls}</section>`
}

export const renderPage = (
	csrf: string,
	status?: ControlStatus,
	unavailable = false,
): string => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>OpenAI OAuth sign-in</title><link rel="stylesheet" href="/assets/styles.css"><script src="/assets/htmx.js" defer></script><script src="/assets/hyperscript.js" defer></script><script src="/assets/copy.js" defer></script></head>
<body class="flex min-h-screen items-center justify-center bg-zinc-950 px-4 py-6 text-zinc-100"><main class="w-full max-w-2xl"><h1 class="text-3xl font-bold tracking-tight">OpenAI OAuth sign-in</h1><p class="mt-2 text-sm text-zinc-400">Choose a sign-in method. Your credentials are never shown here.</p><div class="mt-6">${renderStatus(csrf, status, unavailable)}</div><p class="mt-4 text-xs leading-5 text-zinc-500">Never share callback URLs or sign-in codes.</p></main></body></html>`
