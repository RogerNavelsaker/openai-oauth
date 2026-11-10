#!/usr/bin/env bash
set -euo pipefail

cli_bin=${OPENAI_OAUTH_CLI_BIN:-openai-oauth}
if [[ ${OPENAI_OAUTH_LOGIN_UI:-0} != 1 ]]; then
	exec "$cli_bin" "$@"
fi

control_token=${OPENAI_OAUTH_CONTROL_TOKEN:-}
if [[ ${#control_token} -lt 32 ]]; then
	printf '%s\n' 'OPENAI_OAUTH_CONTROL_TOKEN must be at least 32 bytes when the login UI is enabled.' >&2
	exit 1
fi
if [[ -z ${LOGIN_UI_PUBLIC_ORIGIN:-} ]]; then
	printf '%s\n' 'LOGIN_UI_PUBLIC_ORIGIN is required when the login UI is enabled.' >&2
	exit 1
fi

control_host=${OPENAI_OAUTH_CONTROL_HOST:-127.0.0.1}
case "$control_host" in
	127.0.0.1) control_url_host=127.0.0.1 ;;
	::1) control_url_host='[::1]' ;;
	*)
		printf '%s\n' 'OPENAI_OAUTH_CONTROL_HOST must be loopback when the login UI is enabled.' >&2
		exit 1
		;;
esac
control_port=${OPENAI_OAUTH_CONTROL_PORT:-10532}
if [[ ! $control_port =~ ^[0-9]{1,5}$ ]] ||
	(( 10#$control_port < 1 || 10#$control_port > 65535 )); then
	printf '%s\n' 'OPENAI_OAUTH_CONTROL_PORT must be between 1 and 65535 when the login UI is enabled.' >&2
	exit 1
fi

script_path=${BASH_SOURCE[0]}
script_dir=${script_path%/*}
if [[ $script_dir == "$script_path" ]]; then
	script_dir=.
fi
ui_server=${LOGIN_UI_SERVER_PATH:-"$script_dir/../apps/tailnet-login-ui/src/server.ts"}
bun_bin=${BUN_BIN:-bun}
if [[ ! -f $ui_server ]]; then
	printf '%s\n' "Tailnet login UI server was not found: $ui_server" >&2
	exit 1
fi

export SIDECAR_CONTROL_TOKEN=$control_token
export SIDECAR_CONTROL_URL="http://${control_url_host}:${control_port}"

sidecar_pid=
ui_pid=
stop_children() {
	for pid in "$sidecar_pid" "$ui_pid"; do
		if [[ -n $pid ]]; then
			kill -TERM "$pid" 2>/dev/null || true
		fi
	done
}
shutdown_requested=0
on_signal() {
	shutdown_requested=1
	stop_children
}
trap on_signal INT TERM HUP

"$cli_bin" "$@" &
sidecar_pid=$!
"$bun_bin" "$ui_server" &
ui_pid=$!

set +e
wait -n "$sidecar_pid" "$ui_pid"
status=$?
set -e
stop_children
wait "$sidecar_pid" 2>/dev/null || true
wait "$ui_pid" 2>/dev/null || true

if (( shutdown_requested )); then
	exit 0
fi
exit "$status"
