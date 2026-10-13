#!/usr/bin/env bash
# Repeatable Phase 8 verification against the required local/dev host.
#
# Required:
#   SSHPASS=1234 scripts/phase8_remote_verify.sh
#
# Optional environment:
#   REMOTE_HOST=192.168.8.4
#   REMOTE_USER=ob1
#   REMOTE_PATH=/home/ob1/Nullapart
#   LOCAL_TUNNEL_PORT=15535
#   API_LOGIN=admin@example.test
#   REMOTE_COMPOSE_FILE=compose.local.yml
#   REMOTE_COMPOSE_ENV=.env.local
#   REMOTE_DEPLOYMENT_ID=LOCAL-TEST

set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-192.168.8.4}"
REMOTE_USER="${REMOTE_USER:-ob1}"
REMOTE_PATH="${REMOTE_PATH:-/home/ob1/Nullapart}"
LOCAL_TUNNEL_PORT="${LOCAL_TUNNEL_PORT:-15535}"
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

echo "Syncing Phase 8 source, UI, docs, tests and migration files..."
PHASE8_FILES=(
  crates/mail-core/src/bin/mailcore-server.rs
  crates/mail-core/src/connectors_remediation_api.rs
  crates/mail-core/src/lib.rs
  crates/mail-core/tests/postgres_connectors_remediation.rs
  docs/phases/PHASE-8-LOCAL-IMPLEMENTATION-PLAN.md
  frontend/.npmrc
  frontend/src/components/Layout.tsx
  frontend/src/lib/router.tsx
  frontend/src/pages/ConnectorsRemediation.css
  frontend/src/pages/ConnectorsRemediation.test.tsx
  frontend/src/pages/ConnectorsRemediation.tsx
  migrations/031_connectors_remediation.sql
  scripts/phase8_remote_verify.sh
)
SSHPASS="${SSHPASS}" sshpass -e rsync -avR \
  -e "ssh ${SSH_OPTIONS[*]}" \
  "${PHASE8_FILES[@]}" \
  "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}/"

echo "Rebuilding the remote Mail Core and frontend images with the synced Phase 8 source..."
remote "cd '${REMOTE_PATH}' && ${REMOTE_COMPOSE} build mailcore frontend"

echo "Applying migration 031 on the remote PostgreSQL container..."
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
      SELECT to_regclass('public.connector_integrations') IS NOT NULL\
    \" | grep -q '^t$'; then \
    echo 'migration 031 already applied'; \
  else \
    docker exec -i \"\${pg_container}\" psql -U nullapart -d nullapart < migrations/031_connectors_remediation.sql; \
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

echo "Running ignored Phase 8 PostgreSQL suite against the remote DB..."
NULLAPART_TEST_DATABASE_URL="postgres://nullapart:${REMOTE_DB_PASSWORD}@127.0.0.1:${LOCAL_TUNNEL_PORT}/nullapart" \
  cargo test --test postgres_connectors_remediation -- --ignored --test-threads=1

echo "Preparing a repeatable delivered-message fixture on the remote DB..."
REMOTE_TENANT_MESSAGE_ID="$(
  remote "cd '${REMOTE_PATH}' && \
    set -a && . ./.env.local 2>/dev/null || true && set +a && \
    pg_container=\$(${REMOTE_COMPOSE} ps -q postgres) && \
    test -n \"\${pg_container}\" && \
    customer_id=\"\${NULLAPART_LOCAL_CONTROL_CUSTOMER_ID:-}\" && \
    if [[ -z \"\${customer_id}\" ]]; then \
      customer_id=\$(docker exec \"\${pg_container}\" psql -U nullapart -d nullapart -Atc \"\
        SELECT id FROM customers WHERE deployment_id = '${REMOTE_DEPLOYMENT_ID}' AND lifecycle = 'active' ORDER BY created_at LIMIT 1\
      \"); \
    fi && \
    test -n \"\${customer_id}\" && \
    docker exec \"\${pg_container}\" psql -U nullapart -d nullapart -v ON_ERROR_STOP=1 -At \
      -c \"\
        WITH ids AS (\
          SELECT uuid_generate_v4() AS tx_id, uuid_generate_v4() AS message_id\
        ), inserted_tx AS (\
          INSERT INTO smtp_transactions (\
            id, deployment_id, direction, envelope_sender, message_id, content_hash,\
            mime_artifact_id, spf_result, dkim_result, dmarc_result, arc_result, received_at\
          )\
          SELECT tx_id, '${REMOTE_DEPLOYMENT_ID}', 'inbound', 'phase8-fixture@example.test',\
            '<phase8-remote-fixture@example.test>', 'phase8-content-hash',\
            'phase8-mime-artifact', '{\\\"result\\\":\\\"pass\\\"}'::jsonb,\
            '{\\\"result\\\":\\\"pass\\\"}'::jsonb, '{\\\"result\\\":\\\"pass\\\"}'::jsonb,\
            '{\\\"result\\\":\\\"none\\\"}'::jsonb, now()\
          FROM ids\
          RETURNING id\
        ), inserted_message AS (\
          INSERT INTO tenant_message_instances (id, transaction_id, customer_id, disposition)\
          SELECT ids.message_id, inserted_tx.id, '\${customer_id}', 'allow'\
          FROM ids, inserted_tx\
          RETURNING id\
        )\
        SELECT id FROM inserted_message\
      \""
)"
REMOTE_TENANT_MESSAGE_ID="${REMOTE_TENANT_MESSAGE_ID//$'\r'/}"
test -n "${REMOTE_TENANT_MESSAGE_ID}"
echo "Delivered-message fixture: ${REMOTE_TENANT_MESSAGE_ID}"

echo "Checking authenticated connectors/remediation API on the remote host..."
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
        AND rp.permission = 'connectors:manage' \
      ORDER BY u.created_at \
      LIMIT 1\
    \"); \
  fi && \
  test -n \"\${api_login}\" && \
  set -a && . ./.env.local 2>/dev/null || true && set +a && \
  test -n \"\${NULLAPART_LOCAL_CONTROL_TOKEN:-}\" && \
  customer_id=\"\${NULLAPART_LOCAL_CONTROL_CUSTOMER_ID:-}\" && \
  if [[ -z \"\${customer_id}\" ]]; then \
    customer_id=\$(docker exec \"\${pg_container}\" psql -U nullapart -d nullapart -Atc \"\
      SELECT id FROM customers WHERE deployment_id = '${REMOTE_DEPLOYMENT_ID}' AND lifecycle = 'active' ORDER BY created_at LIMIT 1\
    \"); \
  fi && \
  test -n \"\${customer_id}\" && \
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
    \"\${api_url}/api/v1/connectors-remediation\" | grep -q '\"connectors\"' && \
  curl -fsS -b \"\${cookie_file}\" \
    -H \"Authorization: Bearer \${NULLAPART_LOCAL_CONTROL_TOKEN}\" \
    -H \"X-Nullapart-Local-User: \${api_login}\" \
    -H \"X-CSRF-Token: \${csrf_token}\" \
    -H \"X-Idempotency-Key: phase8-connector-upsert-\$(date +%s)\" \
    -H 'Content-Type: application/json' \
    -d '{\"provider\":\"microsoft_365\",\"display_name\":\"Phase 8 Microsoft 365 Remote\",\"external_tenant_id_hash\":\"phase8remoteexternalhash\",\"credential_reference_hash\":\"phase8remotecredentialhash\",\"status\":\"active\",\"auth_state\":\"healthy\",\"token_expires_at\":null,\"capabilities\":[{\"capability\":\"directory_sync\",\"enabled\":true,\"granted_scopes\":[\"User.Read.All\",\"Group.Read.All\"],\"reason\":\"Remote verifier directory sync least privilege.\"},{\"capability\":\"mailbox_search\",\"enabled\":true,\"granted_scopes\":[\"Mail.Read\"],\"reason\":\"Remote verifier mailbox search only after security case.\"},{\"capability\":\"retro_remediation\",\"enabled\":true,\"granted_scopes\":[\"Mail.ReadWrite\"],\"reason\":\"Remote verifier post delivery remediation request.\"}]}' \
    \"\${api_url}/api/v1/connectors-remediation/connectors\" | grep -q '\"provider\":\"microsoft_365\"' && \
  connector_id=\$(docker exec \"\${pg_container}\" psql -U nullapart -d nullapart -Atc \"\
    SELECT id FROM connector_integrations \
    WHERE deployment_id = '${REMOTE_DEPLOYMENT_ID}' \
      AND customer_id = '\${customer_id}' \
      AND external_tenant_id_hash = 'phase8remoteexternalhash' \
    ORDER BY updated_at DESC LIMIT 1\
  \") && \
  test -n \"\${connector_id}\" && \
  remediation_payload=\$(printf '{\"connector_id\":\"%s\",\"tenant_message_id\":\"%s\",\"mailbox_address_hash\":\"phase8mailboxaddresshash\",\"provider_message_id_hash\":\"phase8providermessagehash\",\"purpose\":\"post_delivery_threat\",\"action_type\":\"move_to_quarantine\",\"reason\":\"Remote verifier records pending provider remediation intent.\"}' \"\${connector_id}\" '${REMOTE_TENANT_MESSAGE_ID}') && \
  curl -fsS -b \"\${cookie_file}\" \
    -H \"Authorization: Bearer \${NULLAPART_LOCAL_CONTROL_TOKEN}\" \
    -H \"X-Nullapart-Local-User: \${api_login}\" \
    -H \"X-CSRF-Token: \${csrf_token}\" \
    -H \"X-Idempotency-Key: phase8-remediation-\$(date +%s)\" \
    -H 'Content-Type: application/json' \
    -d \"\${remediation_payload}\" \
    \"\${api_url}/api/v1/connectors-remediation/remediations\" | grep -q '\"provider_side_effect\":\"not_executed_in_control_plane\"' && \
  curl -fsS -b \"\${cookie_file}\" \
    -H \"Authorization: Bearer \${NULLAPART_LOCAL_CONTROL_TOKEN}\" \
    -H \"X-Nullapart-Local-User: \${api_login}\" \
    \"\${api_url}/api/v1/connectors-remediation\" | grep -q '\"remediation_actions\"' && \
  frontend_authority=\$(${REMOTE_COMPOSE} port frontend 80 | tail -n 1) && \
  test -n \"\${frontend_authority}\" && \
  case \"\${frontend_authority}\" in \
    0.0.0.0:*) frontend_authority=\"127.0.0.1:\${frontend_authority##*:}\" ;; \
  esac && \
  curl -fsS \
    -u \"\${NULLAPART_LOCAL_UI_USER}:\${NULLAPART_LOCAL_UI_PASSWORD}\" \
    \"http://\${frontend_authority}/connectors-remediation\" | grep -q '<div id=\"root\"' && \
  rm -f \"\${cookie_file}\""

echo "Phase 8 remote verification passed."
