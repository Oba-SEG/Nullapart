#!/usr/bin/env bash
#
# provision-local-zitadel.sh
#
# Seeds the local-only ZITADEL identity provider started by `compose.local.yml`
# with the Control Plane OIDC relying party (project + confidential web app +
# redirect-URI allow-list) and records the resulting relying-party settings in
# `.env.local` for Mail Core.
#
# Trust notes:
#   * This script is local development provisioning, not a production
#     installer. It runs on the operator's host with the local PAT that
#     `zitadel start-from-init` wrote to the gitignored bootstrap directory.
#   * ZITADEL is only a login/assertion source: nothing here grants Nullapart
#     permissions. Product RBAC, sessions, RLS and audit stay in Mail Core
#     (`docs/03-IDENTITY-RBAC-IMPERSONATION.md`).
#   * Client secret and PAT never reach stdout, logs or `.env.local` keys
#     other than `NULLAPART_OIDC_CLIENT_SECRET`; the script prints identifiers
#     only.
#
# Requirements: bash, curl, python3.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

env_file="$repo_root/.env.local"
bootstrap_dir="$repo_root/infrastructure/containers/.zitadel-bootstrap"
state_file="$bootstrap_dir/provision.json"
pat_file="$bootstrap_dir/nullapart-bootstrap.pat"

project_name="Nullapart Control Plane"
app_name="nullapart-control-plane"

fail() {
  printf 'provision-local-zitadel: %s\n' "$*" >&2
  exit 1
}

[[ -f "$env_file" ]] || fail ".env.local not found in $repo_root"
[[ -f "$pat_file" ]] || fail "bootstrap PAT not found in $bootstrap_dir (start the zitadel service first)"

command -v curl >/dev/null || fail "curl is required"
command -v python3 >/dev/null || fail "python3 is required"

env_get() {
  grep -m1 "^$1=" "$env_file" | cut -d= -f2- || true
}

set_env() {
  local key="$1" value="$2"
  SPROVISION_KEY="$key" SPROVISION_VALUE="$value" SPROVISION_FILE="$env_file" python3 <<'PY'
import os

key = os.environ["SPROVISION_KEY"]
value = os.environ["SPROVISION_VALUE"]
path = os.environ["SPROVISION_FILE"]
lines = open(path).read().splitlines(True)
out = []
seen = False
for line in lines:
    if line.startswith(key + "="):
        out.append(f"{key}={value}\n")
        seen = True
    else:
        out.append(line)
if not seen:
    out.append(f"{key}={value}\n")
open(path, "w").write("".join(out))
PY
}

bind="${NULLAPART_BIND_ADDRESS:-$(env_get NULLAPART_BIND_ADDRESS)}"
bind="${bind:-127.0.0.1}"
zport="${NULLAPART_ZITADEL_PORT:-$(env_get NULLAPART_ZITADEL_PORT)}"
zport="${zport:-53090}"
app_port="${NULLAPART_FRONTEND_PORT:-$(env_get NULLAPART_FRONTEND_PORT)}"
app_port="${app_port:-53080}"

issuer="http://${bind}:${zport}"
redirect_uri="http://${bind}:${app_port}/api/v1/auth/oidc/callback"
post_logout_uri="http://${bind}:${app_port}/"

# Already provisioned and configured: keep the run idempotent.
existing_id="$(env_get NULLAPART_OIDC_CLIENT_ID)"
existing_secret="$(env_get NULLAPART_OIDC_CLIENT_SECRET)"
if [[ -n "$existing_id" && -n "$existing_secret" ]]; then
  set_env NULLAPART_OIDC_ISSUER "$issuer"
  set_env NULLAPART_OIDC_REDIRECT_URI "$redirect_uri"
  printf 'provision-local-zitadel: already provisioned (client id present in .env.local)\n'
  exit 0
fi

pat="$(tr -d '\r\n' < "$pat_file")"
[[ -n "$pat" ]] || fail "bootstrap PAT file is empty"

api_status=""
api_body=""
api() {
  local method="$1" path="$2" body="${3-}"
  local out code
  out="$(mktemp)"
  if [[ -n "$body" ]]; then
    code="$(curl -sS -o "$out" -w '%{http_code}' -X "$method" "${issuer}${path}" \
      -H "Authorization: Bearer ${pat}" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      --data "$body")" || true
  else
    code="$(curl -sS -o "$out" -w '%{http_code}' -X "$method" "${issuer}${path}" \
      -H "Authorization: Bearer ${pat}" \
      -H "Accept: application/json")" || true
  fi
  api_status="$code"
  api_body="$(cat "$out")"
  rm -f "$out"
  case "$api_status" in
    2*) return 0 ;;
    *)
      printf 'provision-local-zitadel: %s %s -> HTTP %s\n' "$method" "$path" "$api_status" >&2
      python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    print("  " + str(d.get("message") or d.get("code") or d), file=sys.stderr)
except Exception:
    print("  (unreadable response body)", file=sys.stderr)' <<<"$api_body" || true
      return 1 ;;
  esac
}

json_get() {
  python3 -c 'import json,sys
value = json.load(sys.stdin)
for part in sys.argv[1].split("."):
    value = value[part] if isinstance(value, dict) else ""
print(value)' "$1" <<<"$api_body"
}

state_project=""
state_app=""
state_client=""
if [[ -f "$state_file" ]]; then
  state="$(cat "$state_file")"
  state_project="$(python3 -c 'import json,sys;print(json.load(sys.stdin).get("projectId",""))' <<<"$state")"
  state_app="$(python3 -c 'import json,sys;print(json.load(sys.stdin).get("appId",""))' <<<"$state")"
  state_client="$(python3 -c 'import json,sys;print(json.load(sys.stdin).get("clientId",""))' <<<"$state")"
fi

project_id="$state_project"
app_id="$state_app"
client_id="$state_client"

if [[ -n "$project_id" && -n "$app_id" ]]; then
  # The relying party still exists: re-issue the secret (the previous one was
  # never written, otherwise this script would have exited above).
  if api POST "/management/v1/projects/${project_id}/apps/${app_id}/oidc_config/_generate_client_secret" '{}'; then
    client_secret="$(json_get clientSecret)"
    printf 'provision-local-zitadel: regenerated client secret for app %s\n' "$app_id"
  else
    printf 'provision-local-zitadel: stored app is gone, recreating\n'
    project_id=""
    app_id=""
    client_id=""
    client_secret=""
  fi
fi

if [[ -z "$project_id" ]]; then
  payload="$(python3 -c 'import json,sys;print(json.dumps({"name": sys.argv[1]}))' "$project_name")"
  api POST /management/v1/projects "$payload" || fail "project creation failed"
  project_id="$(json_get id)"
  [[ -n "$project_id" ]] || fail "project creation returned no id"
  printf 'provision-local-zitadel: created project %s\n' "$project_id"
fi

if [[ -z "$app_id" ]]; then
  payload="$(python3 - "$redirect_uri" "$post_logout_uri" <<'PY'
import json
import sys

redirect_uri, post_logout_uri = sys.argv[1], sys.argv[2]
print(json.dumps({
    "name": "nullapart-control-plane",
    "redirectUris": [redirect_uri],
    "postLogoutRedirectUris": [post_logout_uri],
    "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
    "grantTypes": [
        "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
        "OIDC_GRANT_TYPE_REFRESH_TOKEN",
    ],
    "appType": "OIDC_APP_TYPE_WEB",
    "authMethodType": "OIDC_AUTH_METHOD_TYPE_BASIC",
    "version": "OIDC_VERSION_1_0",
    # Local HTTP redirect URIs are only accepted for applications in dev mode.
    "devMode": True,
    "accessTokenType": "OIDC_TOKEN_TYPE_BEARER",
}))
PY
)"
  api POST "/management/v1/projects/${project_id}/apps/oidc" "$payload" || fail "OIDC app creation failed"
  app_id="$(json_get appId)"
  client_id="$(json_get clientId)"
  client_secret="$(json_get clientSecret)"
  [[ -n "$app_id" && -n "$client_id" && -n "$client_secret" ]] || fail "OIDC app creation returned an incomplete response"
  printf 'provision-local-zitadel: created app %s in project %s\n' "$app_id" "$project_id"
fi

mkdir -p "$bootstrap_dir"
cat >"$state_file" <<EOF
{"projectId": "$project_id", "appId": "$app_id", "clientId": "$client_id"}
EOF
chmod 600 "$state_file"

set_env NULLAPART_OIDC_ISSUER "$issuer"
set_env NULLAPART_OIDC_REDIRECT_URI "$redirect_uri"
set_env NULLAPART_OIDC_CLIENT_ID "$client_id"
set_env NULLAPART_OIDC_CLIENT_SECRET "$client_secret"
unset client_secret

# Provider reachability and issuer identity (mix-up defense in Mail Core
# requires the discovered issuer to equal the configured one).
discovery="$(curl -sS "${issuer}/.well-known/openid-configuration" -H 'Accept: application/json')" \
  || fail "discovery document is unreachable from this host"
discovered="$(python3 -c 'import json,sys;print(json.load(sys.stdin).get("issuer",""))' <<<"$discovery")"
[[ "$discovered" == "$issuer" ]] || fail "discovered issuer '$discovered' does not equal configured issuer '$issuer'"
end_session="$(python3 -c 'import json,sys;print("yes" if json.load(sys.stdin).get("end_session_endpoint") else "no")' <<<"$discovery")"

printf 'provision-local-zitadel: ok\n'
printf '  issuer:                %s\n' "$issuer"
printf '  redirect uri:          %s\n' "$redirect_uri"
printf '  post logout redirect:  %s\n' "$post_logout_uri"
printf '  project/app:           %s / %s\n' "$project_id" "$app_id"
printf '  end session endpoint:  %s\n' "$end_session"
printf '  wrote NULLAPART_OIDC_* to .env.local (values not printed)\n'
printf 'next: set NULLAPART_IDENTITY_PROVIDER=oidc in .env.local and run\n'
printf '  docker compose --env-file .env.local -f compose.local.yml up -d --build mailcore\n'
