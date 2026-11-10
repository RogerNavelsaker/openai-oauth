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
	const message = unavailable
		? "The sidecar login service is unavailable. Check its connection and try again."
		: state === "starting"
			? "Requesting a one-time sign-in code…"
			: state === "awaiting_user"
				? "Enter this code on OpenAI's device sign-in page."
				: state === "awaiting_callback"
					? "Complete sign-in in your browser, then paste the full localhost callback URL here."
					: state === "complete"
						? "Sign-in complete. Credentials were saved by the sidecar."
						: state === "failed"
							? (login?.error ??
								"Sign-in failed. Start a new login or check the sidecar logs.")
							: state === "cancelled"
								? "Sign-in was cancelled."
								: status?.credentialsConfigured
									? "Credentials are configured. You can sign in again if needed."
									: "No credentials are configured yet. Start either sign-in method when ready."
	const controls =
		poll && login?.id
			? `<form class="mt-6" hx-post="/_cancel" hx-target="#login-status" hx-swap="outerHTML"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="id" value="${escapeHtml(login.id)}"><button class="rounded-lg border border-zinc-600 px-4 py-2 text-sm font-semibold text-zinc-100 hover:bg-zinc-800" type="submit">Cancel sign-in</button></form>`
			: !unavailable
				? `<div class="mt-6 flex flex-wrap gap-3">
			<form hx-post="/_start" hx-target="#login-status" hx-swap="outerHTML"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button class="rounded-lg bg-emerald-400 px-4 py-2 text-sm font-bold text-zinc-950 hover:bg-emerald-300" type="submit">Start device-code sign-in</button></form>
			<form hx-post="/_browser-start" hx-target="#login-status" hx-swap="outerHTML"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button class="rounded-lg border border-sky-400 px-4 py-2 text-sm font-semibold text-sky-200 hover:bg-zinc-800" type="submit">Start browser sign-in</button></form>
		</div>`
				: ""
	const deviceCode =
		state === "awaiting_user" && login?.userCode
			? `<div class="mt-5 rounded-lg border border-zinc-700 bg-zinc-950 p-4"><p class="text-xs font-semibold uppercase tracking-wide text-zinc-400">One-time code</p><div class="mt-2 flex items-center gap-3"><code id="device-code" class="select-all text-2xl font-bold tracking-widest text-emerald-300">${escapeHtml(login.userCode)}</code><button class="rounded border border-zinc-600 px-3 py-2 text-xs text-zinc-100 hover:bg-zinc-800" type="button" data-copy-device-code>Copy code</button><span class="sr-only" id="device-code-copy-status" aria-live="polite"></span></div><a class="mt-4 inline-block text-sm font-semibold text-sky-300 underline" href="https://auth.openai.com/codex/device" target="_blank" rel="noopener noreferrer">Open OpenAI device sign-in</a></div>`
			: ""
	const browser =
		state === "awaiting_callback" && login?.authorizationUrl && login.id
			? `<div class="mt-5 rounded-lg border border-zinc-700 bg-zinc-950 p-4"><a class="font-semibold text-sky-300 underline" href="${escapeHtml(login.authorizationUrl)}" target="_blank" rel="noopener noreferrer">Open OpenAI sign-in</a><p class="mt-3 text-sm text-zinc-300">After approval, the localhost page may fail to load. Copy its full URL from the address bar and paste it below. This URL is used once to finish sign-in.</p><form class="mt-4" hx-post="/_browser-callback" hx-target="#login-status" hx-swap="outerHTML"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="id" value="${escapeHtml(login.id)}"><label class="block text-sm" for="callback-url">Localhost callback URL</label><input class="mt-2 w-full rounded border border-zinc-600 bg-zinc-900 px-3 py-2 text-sm" id="callback-url" name="callbackUrl" type="url" required autocomplete="off"><button class="mt-3 rounded-lg bg-sky-400 px-4 py-2 text-sm font-bold text-zinc-950" type="submit">Submit callback URL</button></form></div>`
			: ""
	const title =
		state === "awaiting_callback"
			? "Waiting for browser callback"
			: state === "awaiting_user"
				? "Waiting for sign-in"
				: state === "complete"
					? "Signed in"
					: state === "failed"
						? "Sign-in failed"
						: state === "cancelled"
							? "Sign-in cancelled"
							: state === "starting"
								? "Starting sign-in"
								: status?.credentialsConfigured
									? "Credentials configured"
									: "Sign-in required"
	return `<section id="login-status" class="rounded-xl border border-zinc-800 bg-zinc-900 p-6 shadow-xl"${poll ? ' hx-get="/_status" hx-trigger="every 2s" hx-swap="outerHTML"' : ""}><div class="flex items-center gap-3"><span class="h-2.5 w-2.5 rounded-full ${poll ? "animate-pulse bg-amber-300" : state === "complete" ? "bg-emerald-400" : "bg-zinc-500"}" aria-hidden="true"></span><h2 class="text-lg font-semibold text-zinc-100">${unavailable ? "Login service unavailable" : title}</h2></div><p class="mt-3 text-sm leading-6 text-zinc-300">${escapeHtml(message)}</p>${deviceCode}${browser}${controls}</section>`
}

export const renderPage = (
	csrf: string,
	status?: ControlStatus,
	unavailable = false,
): string => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>OpenAI OAuth sign-in</title><link rel="stylesheet" href="/assets/styles.css"><script src="/assets/htmx.js" defer></script><script src="/assets/hyperscript.js" defer></script><script src="/assets/copy.js" defer></script></head>
<body class="min-h-screen bg-zinc-950 px-4 py-12 text-zinc-100"><main class="mx-auto max-w-xl"><p class="text-xs font-bold uppercase tracking-[0.2em] text-emerald-300">Private account control</p><h1 class="mt-3 text-3xl font-bold tracking-tight">OpenAI OAuth sign-in</h1><p class="mt-3 text-sm leading-6 text-zinc-400">Choose browser sign-in or device-code sign-in. Login starts only when you press a button. Tokens stay on the sidecar.</p><div class="mt-8">${renderStatus(csrf, status, unavailable)}</div><p class="mt-6 text-xs leading-5 text-zinc-500">Never share callback URLs or sign-in codes. This page does not receive or display credentials.</p></main></body></html>`
