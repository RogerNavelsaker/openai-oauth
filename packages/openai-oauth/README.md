# openai-oauth

[Docs](https://github.com/RogerNavelsaker/openai-oauth#dev-proxy) | [GitHub](https://github.com/RogerNavelsaker/openai-oauth) | [npm](https://www.npmjs.com/package/openai-oauth)

Turn your ChatGPT account into an OpenAI-compatible local API.

```bash
> npx openai-oauth

OpenAI-compatible endpoint ready at http://127.0.0.1:10531/v1
Use this as your OpenAI base URL. No API key is required.
Available Models: gpt-5.6-sol, gpt-5.6-terra, gpt-image-2, ...

[d] Run in background  [q] Quit
```

Press `d` to keep it running in the background or `q` to quit. You can also manage it directly:

```bash
npx openai-oauth --detach
npx openai-oauth status
npx openai-oauth logs --follow
npx openai-oauth stop
```

## Package Notes

`openai-oauth` exposes an OpenAI-compatible local endpoint backed by your ChatGPT account.

Supported endpoints:

- `/v1/responses`
- `/v1/chat/completions`
- `/v1/images/generations`
- `/v1/images/edits`
- `/v1/models`

Image generation uses JSON requests. Image editing uses the standard OpenAI multipart request with one or more `image` fields. Both return base64 image data and usage metadata.

```bash
curl http://127.0.0.1:10531/v1/images/generations \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-image-2","prompt":"A tiny house in a forest","quality":"low"}'
```

Common flags:

| Config | Flag | Default |
| --- | --- | --- |
| Host binding | `--host` | `127.0.0.1` |
| Port | `--port` | `10531` |
| Model allowlist | `--models` | Account-specific Codex models discovered from ChatGPT |
| Auth file path | `--oauth-file` | `$CODEX_HOME/auth.json` or `~/.codex/auth.json` |
| Open browser | `--open` / `--no-open` | `--open` |
| Device-code authentication | `--device-auth` | Off for CLI; on in OCI image |
| Login timeout | `--login-timeout-ms` | Browser: `300000`; device-code: `900000` |

Binding `--host` beyond loopback exposes the proxy to your network. Anyone who can reach that port can make requests with your ChatGPT account.

The default browser login listens on loopback and uses `http://localhost:1455/auth/callback`. Use `openai-oauth login --device-auth` on remote or headless hosts; it prints a one-time code and waits for approval without opening a callback port. The OCI image enables this mode automatically when credentials are missing or a startup refresh is rejected with HTTP 401. If the auth server returns HTTP 404, device-code login is disabled; authenticate on a browser-capable host and provide its `auth.json` instead.

The CLI resolves the latest published Codex client version automatically. Advanced flags also exist for overriding it, the upstream Codex base URL, OAuth client id, and OAuth token URL.

## More

[Learn more in the openai-oauth README.](https://github.com/RogerNavelsaker/openai-oauth#readme)
