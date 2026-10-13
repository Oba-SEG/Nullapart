#!/usr/bin/env bash
# Repeatable Phase 9 verification against the required local/dev host.
#
# Required:
#   SSHPASS=1234 scripts/phase9_remote_verify.sh

set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-192.168.8.4}"
REMOTE_USER="${REMOTE_USER:-ob1}"
REMOTE_PATH="${REMOTE_PATH:-/home/ob1/Nullapart}"
LOCAL_TUNNEL_PORT="${LOCAL_TUNNEL_PORT:-15536}"
API_LOGIN="${API_LOGIN:-}"
REMOTE_COMPOSE_FILE="${REMOTE_COMPOSE_FILE:-compose.local.yml}"
REMOTE_COMPOSE_ENV="${REMOTE_COMPOSE_ENV:-.env.local}"
REMOTE_DEPLOYMENT_ID="${REMOTE_DEPLOYMENT_ID:-LOCAL-TEST}"

if [[ -z "${SSHPASS:-}" ]]; then
  echo "SSHPASS must be set for ${REMOTE_USER}@${REMOTE_HOST}" >&2
  exit 2
fi

for binary in sshpass ssh rsync cargo nc; do
  if ! command -v "${binary}" >/dev/null 2>&1; then
    echo "missing required command: ${binary}" >&2
    exit 2
  fi
done

SSH_OPTIONS=(
  -o ConnectTimeout=10
  -o ConnectionAttempts=1
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
)

remote() {
  SSHPASS="${SSHPASS}" sshpass -e ssh "${SSH_OPTIONS[@]}" "${REMOTE_USER}@${REMOTE_HOST}" "$@"
}

REMOTE_COMPOSE="docker compose --env-file '${REMOTE_COMPOSE_ENV}' -f '${REMOTE_COMPOSE_FILE}'"

echo "Checking SSH reachability for ${REMOTE_USER}@${REMOTE_HOST}..."
remote "cd '${REMOTE_PATH}' && ${REMOTE_COMPOSE} config -q"

echo "Syncing Phase 9 source, UI, docs, tests and migration files..."
PHASE9_FILES=(
  crates/mail-core/src/bin/mailcore-server.rs
  crates/mail-core/src/lib.rs
  crates/mail-core/src/operations_api.rs
  crates/mail-core/tests/postgres_operations_hardening.rs
  docs/phases/PHASE-9-LOCAL-IMPLEMENTATION-PLAN.md
  docs/runbooks/PHASE9-OPERATIONS-HARDENING.md
  frontend/.npmrc
  frontend/src/pages/Operations.css
  frontend/src/pages/Operations.test.tsx
  frontend/src/pages/Operations.tsx
  migrations/032_operations_hardening.sql
  migrations/033_operations_automation_categories.sql
  scripts/phase9_remote_verify.sh
)
SSHPASS="${SSHPASS}" sshpass -e rsync -avR \
  -e "ssh ${SSH_OPTIONS[*]}" \
  "${PHASE9_FILES[@]}" \
  "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}/"

echo "Rebuilding the remote Mail Core and frontend images with the synced Phase 9 source..."
remote "cd '${REMOTE_PATH}' && ${REMOTE_COMPOSE} build mailcore frontend"

echo "Applying Phase 9 migrations on the remote PostgreSQL container..."
remote "cd '${REMOTE_PATH}' && \
  ${REMOTE_COMPOSE} up -d postgres && \
  pg_container=\$(${REMOTE_COMPOSE} ps -q postgres) && \
  test -n \"\${pg_container}\" && \
  for _ in \$(seq 1 60); do \
    if docker exec \"\${pg_container}\" pg_isready -U nullapart -d nullapart >/dev/null 2>&1; then \
      break; \
    fi; \
    sleep 1; \
  done && \
  docker exec \"\${pg_container}\" pg_isready -U nullapart -d nullapart >/dev/null && \
  if docker exec \"\${pg_container}\" psql -U nullapart -d nullapart -Atc \"\
      SELECT to_regclass('public.operations_tier3_capabilities') IS NOT NULL\
    \" | grep -q '^t$'; then \
    echo 'migration 032 already applied'; \
  else \
    docker exec -i \"\${pg_container}\" psql -U nullapart -d nullapart < migrations/032_operations_hardening.sql; \
  fi && \
  if docker exec \"\${pg_container}\" psql -U nullapart -d nullapart -Atc \"\
      SELECT to_regclass('public.operations_automation_categories') IS NOT NULL\
    \" | grep -q '^t$'; then \
    echo 'migration 033 already applied'; \
  else \
    docker exec -i \"\${pg_container}\" psql -U nullapart -d nullapart < migrations/033_operations_automation_categories.sql; \
  fi"

REMOTE_DB_PORT="$(
  remote "cd '${REMOTE_PATH}' && ${REMOTE_COMPOSE} port postgres 5432 | sed -E 's/.*:([0-9]+)$/\\1/' | tail -n 1"
)"
REMOTE_DB_PORT="${REMOTE_DB_PORT:-5432}"
REMOTE_DB_PASSWORD="$(
  remote "cd '${REMOTE_PATH}' && sed -n 's/^NULLAPART_POSTGRES_PASSWORD=//p' .env.local 2>/dev/null | head -n 1"
)"
REMOTE_DB_PASSWORD="${REMOTE_DB_PASSWORD:-nullapart_dev}"

echo "Opening PostgreSQL tunnel on 127.0.0.1:${LOCAL_TUNNEL_PORT}..."
if nc -z 127.0.0.1 "${LOCAL_TUNNEL_PORT}" >/dev/null 2>&1; then
  echo "local tunnel port ${LOCAL_TUNNEL_PORT} is already in use; reusing it"
  tunnel_pid=""
else
  SSHPASS="${SSHPASS}" sshpass -e ssh "${SSH_OPTIONS[@]}" \
    -N -L "127.0.0.1:${LOCAL_TUNNEL_PORT}:127.0.0.1:${REMOTE_DB_PORT}" \
    "${REMOTE_USER}@${REMOTE_HOST}" &
  tunnel_pid="$!"
  trap 'if [[ -n "${tunnel_pid:-}" ]]; then kill "${tunnel_pid}" >/dev/null 2>&1 || true; fi' EXIT
  for _ in {1..20}; do
    if nc -z 127.0.0.1 "${LOCAL_TUNNEL_PORT}" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done
fi

echo "Running ignored Phase 9 PostgreSQL suite against the remote DB..."
NULLAPART_TEST_DATABASE_URL="postgres://nullapart:${REMOTE_DB_PASSWORD}@127.0.0.1:${LOCAL_TUNNEL_PORT}/nullapart" \
  cargo test --test postgres_operations_hardening -- --ignored --test-threads=1

echo "Checking authenticated operations-hardening API and UI on the remote host..."
remote "cd '${REMOTE_PATH}' && \
  ${REMOTE_COMPOSE} up -d --force-recreate mailcore frontend && \
  api_authority=\$(${REMOTE_COMPOSE} port mailcore 8081 | tail -n 1) && \
  test -n \"\${api_authority}\" && \
  case \"\${api_authority}\" in \
    0.0.0.0:*) api_authority=\"127.0.0.1:\${api_authority##*:}\" ;; \
  esac && \
  api_url=\"http://\${api_authority}\" && \
  for _ in \$(seq 1 60); do \
    if curl -sS \"\${api_url}/api/v1/auth/session\" >/dev/null 2>&1; then \
      break; \
    fi; \
    sleep 1; \
  done && \
  api_login='${API_LOGIN}' && \
  pg_container=\$(${REMOTE_COMPOSE} ps -q postgres) && \
  if [[ -z \"\${api_login}\" ]]; then \
    api_login=\$(docker exec \"\${pg_container}\" psql -U nullapart -d nullapart -Atc \"\
      SELECT u.login \
      FROM admin_users u \
      JOIN admin_user_roles ur ON ur.user_id = u.id \
      JOIN admin_role_permissions rp ON rp.role_id = ur.role_id \
      WHERE u.deployment_id = '${REMOTE_DEPLOYMENT_ID}' \
        AND u.lifecycle = 'active' \
        AND rp.permission = 'operations:view' \
      ORDER BY u.created_at \
      LIMIT 1\
    \"); \
  fi && \
  test -n \"\${api_login}\" && \
  set -a && . ./.env.local 2>/dev/null || true && set +a && \
  test -n \"\${NULLAPART_LOCAL_CONTROL_TOKEN:-}\" && \
  cookie_file=\$(mktemp) && \
  curl -fsS -c \"\${cookie_file}\" \
    -H \"Authorization: Bearer \${NULLAPART_LOCAL_CONTROL_TOKEN}\" \
    -H \"X-Nullapart-Local-User: \${api_login}\" \
    -X POST \"\${api_url}/api/v1/auth/login\" >/dev/null && \
  curl -fsS -b \"\${cookie_file}\" \
    -H \"Authorization: Bearer \${NULLAPART_LOCAL_CONTROL_TOKEN}\" \
    -H \"X-Nullapart-Local-User: \${api_login}\" \
    \"\${api_url}/api/v1/operations/hardening\" | grep -q '\"tier3_capabilities\"' && \
  curl -fsS -b \"\${cookie_file}\" \
    -H \"Authorization: Bearer \${NULLAPART_LOCAL_CONTROL_TOKEN}\" \
    -H \"X-Nullapart-Local-User: \${api_login}\" \
    \"\${api_url}/api/v1/operations/hardening\" | grep -q '\"alert_rules\"' && \
  curl -fsS -b \"\${cookie_file}\" \
    -H \"Authorization: Bearer \${NULLAPART_LOCAL_CONTROL_TOKEN}\" \
    -H \"X-Nullapart-Local-User: \${api_login}\" \
    \"\${api_url}/api/v1/operations/hardening\" | grep -q '\"automation_categories\"' && \
  frontend_authority=\$(${REMOTE_COMPOSE} port frontend 80 | tail -n 1) && \
  test -n \"\${frontend_authority}\" && \
  case \"\${frontend_authority}\" in \
    0.0.0.0:*) frontend_authority=\"127.0.0.1:\${frontend_authority##*:}\" ;; \
  esac && \
  curl -fsS \
    -u \"\${NULLAPART_LOCAL_UI_USER}:\${NULLAPART_LOCAL_UI_PASSWORD}\" \
    \"http://\${frontend_authority}/operations\" | grep -q '<div id=\"root\"' && \
  rm -f \"\${cookie_file}\""

echo "Phase 9 remote verification passed."
