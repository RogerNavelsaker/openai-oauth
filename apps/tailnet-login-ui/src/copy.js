document.addEventListener("click", async (event) => {
	if (!(event.target instanceof Element)) return
	const button = event.target.closest("[data-copy-device-code]")
	if (!(button instanceof HTMLButtonElement)) return

	const code = document.getElementById("device-code")?.textContent?.trim()
	if (!code) return

	const status = document.getElementById("device-code-copy-status")
	try {
		await navigator.clipboard.writeText(code)
		button.textContent = "Copied!"
		if (status) status.textContent = "Code copied to clipboard."
	} catch {
		if (status)
			status.textContent = "Copy failed. Select the code to copy it manually."
	}
})
