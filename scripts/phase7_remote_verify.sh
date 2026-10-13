#!/usr/bin/env bash
# Repeatable Phase 7 verification against the required local/dev host.
#
# Required:
#   SSHPASS=1234 scripts/phase7_remote_verify.sh
#
# Optional environment:
#   REMOTE_HOST=192.168.8.4
#   REMOTE_USER=ob1
#   REMOTE_PATH=/home/ob1/Nullapart
#   LOCAL_TUNNEL_PORT=15534
#   API_LOGIN=admin@example.test
#   REMOTE_COMPOSE_FILE=compose.local.yml
#   REMOTE_COMPOSE_ENV=.env.local
#   REMOTE_DEPLOYMENT_ID=LOCAL-TEST

set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-192.168.8.4}"
REMOTE_USER="${REMOTE_USER:-ob1}"
REMOTE_PATH="${REMOTE_PATH:-/home/ob1/Nullapart}"
LOCAL_TUNNEL_PORT="${LOCAL_TUNNEL_PORT:-15534}"
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

echo "Syncing Phase 7 source, UI, docs and migration files..."
PHASE7_FILES=(
  compose.local.yml
  crates/mail-core/src/admin_rbac.rs
  crates/mail-core/src/bin/mailcore-server.rs
  crates/mail-core/src/deep_ai.rs
  crates/mail-core/src/lib.rs
  crates/mail-core/tests/postgres_deep_ai.rs
  docs/phases/PHASE-7-LOCAL-IMPLEMENTATION-PLAN.md
  frontend/src/components/Layout.tsx
  frontend/src/lib/router.tsx
  frontend/src/pages/DeepAi.css
  frontend/src/pages/DeepAi.test.tsx
  frontend/src/pages/DeepAi.tsx
  migrations/030_deep_ai.sql
  scripts/phase7_remote_verify.sh
)
SSHPASS="${SSHPASS}" sshpass -e rsync -avR \
  -e "ssh ${SSH_OPTIONS[*]}" \
  "${PHASE7_FILES[@]}" \
  "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}/"

echo "Rebuilding the remote Mail Core image with the synced Phase 7 source..."
remote "cd '${REMOTE_PATH}' && ${REMOTE_COMPOSE} build mailcore"

echo "Applying migration 030 on the remote PostgreSQL container..."
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
      SELECT to_regclass('public.deep_ai_skills') IS NOT NULL\
    \" | grep -q '^t$'; then \
    echo 'migration 030 already applied'; \
  else \
    docker exec -i \"\${pg_container}\" psql -U nullapart -d nullapart < migrations/030_deep_ai.sql; \
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

echo "Running ignored Phase 7 PostgreSQL suite against the remote DB..."
NULLAPART_TEST_DATABASE_URL="postgres://nullapart:${REMOTE_DB_PASSWORD}@127.0.0.1:${LOCAL_TUNNEL_PORT}/nullapart" \
  cargo test --test postgres_deep_ai -- --ignored --test-threads=1

echo "Preparing repeatable Deep AI rollback fixtures on the remote DB..."
remote "cd '${REMOTE_PATH}' && \
  pg_container=\$(${REMOTE_COMPOSE} ps -q postgres) && \
  test -n \"\${pg_container}\" && \
  docker exec \"\${pg_container}\" psql -U nullapart -d nullapart -v ON_ERROR_STOP=1 -c \"\
    INSERT INTO deep_ai_skills (\
      deployment_id, skill_id, skill_version, owner, purpose, allowed_data_classes,\
      allowed_tools, max_input_tokens, max_output_tokens, max_artifacts, timeout_ms,\
      concurrency_limit, model_requirement, prompt_template_version, input_schema_version,\
      output_schema_version, evaluation_suite_version, release_state, rollback_skill_version,\
      created_by\
    )\
    SELECT id, 'security.message.deep_analysis', 'v2', 'security-platform',\
      'Remote Phase 7 rollback fixture for message analysis skill verification.',\
      ARRAY['quarantined','blocked','reported_phishing'],\
      ARRAY['artifact.retrieve','scanner.findings']::TEXT[],\
      32768, 2048, 8, 120000, 4,\
      'OpenAI-compatible regional Deep AI backend',\
      'prompt-v2', 'input-v1', 'output-v1', 'eval-v1',\
      'released', NULL, 'phase7-remote-verify'\
    FROM deployments\
    WHERE id = '${REMOTE_DEPLOYMENT_ID}'\
    ON CONFLICT (deployment_id, skill_id, skill_version)\
    DO UPDATE SET release_state = 'released', rollback_skill_version = NULL, updated_at = now();\
    INSERT INTO deep_ai_model_releases (\
      deployment_id, region, model_release, backend, serving_base_url, quantization,\
      context_window, approval_state, approved_by, approved_at, rollback_to_model_release\
    )\
    SELECT id, region, 'local-qwen3.5-9b-phase7-v2', 'ollama',\
      'http://127.0.0.1:11434/v1', 'q4_local_dev', 32768,\
      'approved', 'phase7-remote-verify', now(), NULL\
    FROM deployments\
    WHERE id = '${REMOTE_DEPLOYMENT_ID}'\
    ON CONFLICT (deployment_id, region, model_release)\
    DO UPDATE SET approval_state = 'approved', approved_by = 'phase7-remote-verify',\
      approved_at = now(), rollback_to_model_release = NULL, updated_at = now();\
  \""

echo "Checking authenticated Deep AI API on the remote host..."
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
        AND rp.permission = 'deep-ai:manage' \
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
  login_json=\$(curl -fsS -c \"\${cookie_file}\" \
    -H \"Authorization: Bearer \${NULLAPART_LOCAL_CONTROL_TOKEN}\" \
    -H \"X-Nullapart-Local-User: \${api_login}\" \
    -X POST \"\${api_url}/api/v1/auth/login\") && \
  csrf_token=\$(printf '%s' \"\${login_json}\" | sed -n 's/.*\"csrfToken\":\"\([^\"]*\)\".*/\1/p') && \
  test -n \"\${csrf_token}\" && \
  curl -fsS -b \"\${cookie_file}\" \
    -H \"Authorization: Bearer \${NULLAPART_LOCAL_CONTROL_TOKEN}\" \
    -H \"X-Nullapart-Local-User: \${api_login}\" \
    \"\${api_url}/api/v1/deep-ai\" | grep -q '\"released_skills\"' && \
  curl -fsS -b \"\${cookie_file}\" \
    -H \"Authorization: Bearer \${NULLAPART_LOCAL_CONTROL_TOKEN}\" \
    -H \"X-Nullapart-Local-User: \${api_login}\" \
    -H \"X-CSRF-Token: \${csrf_token}\" \
    -H \"X-Idempotency-Key: phase7-rollback-probe-\$(date +%s)\" \
    -H 'Content-Type: application/json' \
    -d '{\"skill_id\":\"security.message.deep_analysis\",\"current_skill_version\":\"v2\",\"rollback_skill_version\":\"v1\",\"model_release\":\"local-qwen3.5-9b-phase7-v2\",\"rollback_to_model_release\":\"local-qwen3.5-9b-phase7\",\"reason\":\"Remote Phase 7 verifier exercises audited rollback control.\"}' \
    \"\${api_url}/api/v1/deep-ai/rollback\" | grep -q '\"changed\":true' && \
  curl -fsS \
    -H \"Authorization: Bearer \${NULLAPART_DEEP_AI_WORKLOAD_TOKEN:-local-deep-ai-workload-token}\" \
    \"\${api_url}/internal/deep-ai/v1/models\" | grep -q 'local-qwen3.5-9b-phase7' && \
  curl -fsS \
    -H \"Authorization: Bearer \${NULLAPART_DEEP_AI_WORKLOAD_TOKEN:-local-deep-ai-workload-token}\" \
    -H 'Content-Type: application/json' \
    -d '{\"model\":\"local-qwen3.5-9b-phase7\",\"messages\":[{\"role\":\"user\",\"content\":\"local phase 7 serving probe\"}]}' \
    \"\${api_url}/internal/deep-ai/v1/chat/completions\" | grep -q 'chat.completion' && \
  rm -f \"\${cookie_file}\""

echo "Phase 7 remote verification passed."
