# Local Development Dependencies

`compose.local.yml` starts only stateful local dependencies. It does not model
the production ECS or dedicated mail-node topology, and it does not expose
Redis outside the Compose network.

## Start

```text
cp .env.local.example .env.local
# replace NULLAPART_POSTGRES_PASSWORD and every replace-with-… value with
# local-only secrets (the identity block is required only once you switch to
# OIDC login)
docker compose --env-file .env.local -f compose.local.yml up -d
docker compose --env-file .env.local -f compose.local.yml ps
```

PostgreSQL runs on `127.0.0.1:${NULLAPART_POSTGRES_PORT}` and applies every
tracked migration in `migrations/` only when its volume is first created.
For an existing local-only volume, apply each newly added reviewed migration
explicitly before exercising its feature. For example:

```text
docker compose --env-file .env.local -f compose.local.yml exec -T postgres \
  psql -U nullapart -d nullapart -v ON_ERROR_STOP=1 \
  -f /docker-entrypoint-initdb.d/003_quarantine.sql
docker compose --env-file .env.local -f compose.local.yml exec -T postgres \
  psql -U nullapart -d nullapart -v ON_ERROR_STOP=1 \
  -f /docker-entrypoint-initdb.d/004_scanner_evidence.sql
```

Resetting the volume is destructive and should be used only for local data:

```text
docker compose --env-file .env.local -f compose.local.yml down -v
```

Run the durable handoff integration test after the services are healthy:

```text
NULLAPART_TEST_DATABASE_URL='postgres://nullapart:YOUR_LOCAL_PASSWORD@127.0.0.1:5433/nullapart' \
  cargo test -p nullapart-mail-core --test postgres_handoff_idempotency -- --ignored
```

Run the Phase 2 release transaction test after migration `003` is applied:

```text
NULLAPART_TEST_DATABASE_URL='postgres://nullapart:YOUR_LOCAL_PASSWORD@127.0.0.1:5433/nullapart' \
  cargo test -p nullapart-mail-core --test postgres_quarantine_release -- --ignored
```

Run the artifact-to-scanner-evidence-to-quarantine integration test after
migration `004` is applied:

```text
NULLAPART_TEST_DATABASE_URL='postgres://nullapart:YOUR_LOCAL_PASSWORD@127.0.0.1:5433/nullapart' \
  cargo test -p nullapart-mail-core --test postgres_scanner_pipeline -- --ignored
```

## Identity provider (ZITADEL, OIDC)

Local Control Plane login can run against the bundled `zitadel` service
(`ghcr.io/zitadel/zitadel:v4.19.2`). It is an authentication source only:
roles, permissions, sessions, impersonation, row-level security and audit stay
in Nullapart, and the browser keeps holding only the opaque HttpOnly session
cookie — no token is ever written to browser storage.

First run writes the instance machine key and the two personal access tokens
into `infrastructure/containers/.zitadel-bootstrap/` (git-ignored, mode
`0700`) instead of container stdout, so no credential lands in the logs. The
management PAT in that directory is the only credential the provisioning
script uses.

Provision the control-plane OAuth client (idempotent; writes
`NULLAPART_OIDC_ISSUER`, `NULLAPART_OIDC_REDIRECT_URI`, `NULLAPART_OIDC_CLIENT_ID`
and `NULLAPART_OIDC_CLIENT_SECRET` into `.env.local`, and the project/app ids
into `.zitadel-bootstrap/provision.json`):

```text
infrastructure/containers/provision-local-zitadel.sh
```

Two notes about the seeded instance:

- MFA is forced (`ZITADEL_DEFAULTINSTANCE_LOGINPOLICY_FORCEMFA`), so the first
  login for a human admin enrolls an OTP authenticator; self-registration is
  disabled, so users are created by an administrator.
- Set `NULLAPART_ZITADEL_ADMIN_USERNAME` so its local part matches an existing
  `admin_users.login` (the local stack uses `ob1`). The first OIDC login then
  *links* to that user through `admin_users.auth_subject` instead of being
  refused as an unprovisioned identity.

To bring an existing volume up to the OIDC path:

```text
# 1. migration (local volumes only; fresh volumes apply it at creation)
docker compose --env-file .env.local -f compose.local.yml exec -T postgres \
  psql -U nullapart -d nullapart -v ON_ERROR_STOP=1 \
  -f /docker-entrypoint-initdb.d/012_oidc_identity_integration.sql
infrastructure/containers/provision-local-runtime-role.sh
# 2. provision the client, then flip the server-authoritative mode
infrastructure/containers/provision-local-zitadel.sh
#    set NULLAPART_IDENTITY_PROVIDER=oidc in .env.local
docker compose --env-file .env.local -f compose.local.yml up -d mailcore
```

Verification (HTTP level, through the reverse proxy at
`${NULLAPART_BIND_ADDRESS:-127.0.0.1}:${NULLAPART_FRONTEND_PORT:-53080}`, which
adds its own HTTP basic auth):

- `POST /api/v1/auth/login` → `303` to `GET /api/v1/auth/login` → `303` to the
  IdP authorize URL (PKCE S256, `state`, `nonce`) plus the short-lived
  `nullapart_oidc_flow` cookie;
- after the IdP login and MFA, `/api/v1/auth/oidc/callback` returns `303` and
  sets `nullapart_session`; `GET /api/v1/auth/session` → `200` for the linked
  admin;
- `GET /api/v1/auth/reauth` → `303` with `prompt=login`, and its callback
  writes a `session_step_up` audit row;
- `POST /api/v1/auth/logout` → `200` carrying `idpLogoutUrl`, then
  `GET /api/v1/auth/session` → `401`;
- an IdP user with no local row gets `403 Account is not provisioned`, an
  audited `session_login` `denied` row, and no bootstrap.

`NULLAPART_IDENTITY_PROVIDER=proxy_header` (the default) restores the header
exchange, where `POST /api/v1/auth/login` answers `200` with a session. The
mode is configuration, never authorization: `oidc` only becomes usable when
the `NULLAPART_OIDC_*` family is complete.

## Scope

`compose.local.yml` is the complete local stack. It does not model the
production ECS or dedicated mail-node topology.

| Service | Purpose |
| --- | --- |
| `postgres` | authoritative local data and every tracked migration |
| `redis` | runtime cache and counters |
| `mailcore` | Mail Core: artifact store, scanner fabric, quarantine, handoff, reinjection worker |
| `clamav` | malware scanner backend used by the ClamAV adapter |
| `rspamd` | SMTP-time milter scoring in the Postfix path |
| `postfix` | SMTP entry point, after-queue `mailcore-filter` handoff, reinjection listener |
| `frontend` | static Control Plane build and local reverse proxy, which injects the workload token before proxying `/api/v1/...` to `mailcore` |
| `zitadel` | local OIDC identity provider for Control Plane login (authentication source only, never an authorization source) |
| `zitadel-db` | private PostgreSQL for `zitadel`; no published port, never shared with `postgres` |

Only `postgres`, `mailcore`, `postfix`, `frontend` and `zitadel` publish
loopback (or `NULLAPART_BIND_ADDRESS`) ports; Redis, Rspamd, ClamAV and
`zitadel-db` stay inside the Compose network.

Exercise the mail path locally with:

```text
docker compose --env-file .env.local -f compose.local.yml up -d --build
docker compose --env-file .env.local -f compose.local.yml ps
```

Send a message through the after-queue filter on
`127.0.0.1:${NULLAPART_SMTP_PORT:-2525}`, then inspect the resulting
quarantine case through the Control Plane UI on
`127.0.0.1:${NULLAPART_FRONTEND_PORT:-53080}`.

Postfix and Rspamd are part of this stack; a service that merely starts the
daemons is not sufficient evidence, so the after-queue handoff, quarantine,
authorized release and reinjection contracts must be exercised end to end
before a Phase 2 completion claim.
