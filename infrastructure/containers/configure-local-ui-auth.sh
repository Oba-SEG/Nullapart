#!/bin/sh
set -eu

env_file="${1:-.env.local}"
if [ ! -f "$env_file" ]; then
  echo "local environment file does not exist: $env_file" >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to generate the local UI credential" >&2
  exit 1
fi

umask 077
if ! grep -q '^NULLAPART_LOCAL_UI_USER=' "$env_file"; then
  printf '\nNULLAPART_LOCAL_UI_USER=ob1\n' >>"$env_file"
fi
if ! grep -q '^NULLAPART_LOCAL_UI_PASSWORD=' "$env_file"; then
  password="$(openssl rand -base64 24 | tr -d '\n')"
  printf 'NULLAPART_LOCAL_UI_PASSWORD=%s\n' "$password" >>"$env_file"
fi
chmod 0600 "$env_file"
echo "local UI authentication is configured in $env_file"

