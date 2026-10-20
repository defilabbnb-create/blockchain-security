#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# On macOS Node does not inherit the Network Settings HTTP proxy automatically.
# Honor explicit environment settings and allow opting out with USE_SYSTEM_PROXY=0.
if [[ "$(uname -s)" == Darwin && "${USE_SYSTEM_PROXY:-1}" != 0 && -z "${HTTPS_PROXY:-${https_proxy:-}}" && -z "${HTTP_PROXY:-${http_proxy:-}}" && -z "${ALL_PROXY:-${all_proxy:-}}" ]]; then
  proxy_settings="$(scutil --proxy)"
  proxy_enabled="$(awk '$1 == "HTTPSEnable" {print $3}' <<< "$proxy_settings")"
  proxy_host="$(awk '$1 == "HTTPSProxy" {print $3}' <<< "$proxy_settings")"
  proxy_port="$(awk '$1 == "HTTPSPort" {print $3}' <<< "$proxy_settings")"
  if [[ "$proxy_enabled" == 1 && -n "$proxy_host" && "$proxy_port" =~ ^[0-9]+$ ]]; then
    export HTTPS_PROXY="http://${proxy_host}:${proxy_port}"
  fi
fi
if [[ -n "${HTTPS_PROXY:-${https_proxy:-${HTTP_PROXY:-${http_proxy:-}}}}" ]]; then
  export NODE_USE_ENV_PROXY="${NODE_USE_ENV_PROXY:-1}"
fi
if [[ -f "$ROOT/.env" ]]; then
  exec node --env-file="$ROOT/.env" "$@"
else
  exec node "$@"
fi
