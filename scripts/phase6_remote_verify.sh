#!/usr/bin/env bash
# Repeatable Phase 6 verification against the required local/dev host.
#
# Required:
#   SSHPASS=1234 scripts/phase6_remote_verify.sh
#
# Optional environment:
#   REMOTE_HOST=192.168.8.4
#   REMOTE_USER=ob1
#   REMOTE_PATH=/home/ob1/Nullapart
#   LOCAL_TUNNEL_PORT=15533
#   API_LOGIN=admin@example.test
#   REMOTE_COMPOSE_FILE=compose.local.yml
#   REMOTE_COMPOSE_ENV=.env.local
#   REMOTE_DEPLOYMENT_ID=LOCAL-TEST

set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-192.168.8.4}"
REMOTE_USER="${REMOTE_USER:-ob1}"
REMOTE_PATH="${REMOTE_PATH:-/home/ob1/Nullapart}"
LOCAL_TUNNEL_PORT="${LOCAL_TUNNEL_PORT:-15533}"
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

echo "Syncing Phase 6 source and migration files..."
PHASE6_FILES=(
  crates/mail-core/src/admin_rbac.rs
  crates/mail-core/src/bin/mailcore-server.rs
  crates/mail-core/src/lib.rs
  crates/mail-core/src/outbound.rs
  crates/mail-core/src/outbound_intelligence.rs
  crates/mail-core/src/outbound_intelligence_api.rs
  crates/mail-core/src/policy_admin.rs
  crates/mail-core/tests/postgres_outbound_intelligence.rs
  docs/phases/PHASE-6-LOCAL-IMPLEMENTATION-PLAN.md
  frontend/src/components/Layout.tsx
  frontend/src/lib/router.tsx
  frontend/src/pages/OutboundIntelligence.css
  frontend/src/pages/OutboundIntelligence.test.tsx
  frontend/src/pages/OutboundIntelligence.tsx
  migrations/029_outbound_intelligence_control_plane.sql
)
SSHPASS="${SSHPASS}" sshpass -e rsync -avR \
  -e "ssh ${SSH_OPTIONS[*]}" \
  "${PHASE6_FILES[@]}" \
  "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}/"

echo "Rebuilding the remote Mail Core image with the synced Phase 6 source..."
remote "cd '${REMOTE_PATH}' && ${REMOTE_COMPOSE} build mailcore"

echo "Applying migration 029 on the remote PostgreSQL container..."
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
  docker exec -i \"\${pg_container}\" psql -U nullapart -d nullapart < migrations/029_outbound_intelligence_control_plane.sql"

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

echo "Running ignored Phase 6 PostgreSQL suite against the remote DB..."
NULLAPART_TEST_DATABASE_URL="postgres://nullapart:${REMOTE_DB_PASSWORD}@127.0.0.1:${LOCAL_TUNNEL_PORT}/nullapart" \
  cargo test --test postgres_outbound_intelligence -- --ignored --test-threads=1

echo "Checking authenticated outbound-intelligence API on the remote host..."
remote "cd '${REMOTE_PATH}' && \
  ${REMOTE_COMPOSE} up -d --force-recreate mailcore && \
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
  if [[ -z \"\${api_login}\" ]]; then \
    pg_container=\$(${REMOTE_COMPOSE} ps -q postgres) && \
    api_login=\$(docker exec \"\${pg_container}\" psql -U nullapart -d nullapart -Atc \"\
      SELECT u.login \
      FROM admin_users u \
      JOIN admin_user_roles ur ON ur.user_id = u.id \
      JOIN admin_role_permissions rp ON rp.role_id = ur.role_id \
      WHERE u.deployment_id = '${REMOTE_DEPLOYMENT_ID}' \
        AND u.lifecycle = 'active' \
        AND rp.permission = 'outbound-intelligence:view' \
      ORDER BY CASE \
          WHEN EXISTS (\
            SELECT 1 \
            FROM admin_user_roles ur2 \
            JOIN admin_roles r2 ON r2.id = ur2.role_id \
            WHERE ur2.user_id = u.id AND r2.role_key = 'system_admin'\
          ) THEN 0 ELSE 1 END, \
        u.created_at \
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
    \"\${api_url}/api/v1/outbound-intelligence\" | grep -q '\"deployment_id\"' && \
  rm -f \"\${cookie_file}\""

echo "Phase 6 remote verification passed."
