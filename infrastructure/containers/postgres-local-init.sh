#!/bin/sh
set -eu

for migration in /opt/nullapart/migrations/*.sql; do
  psql --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --file "$migration"
done

psql --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --file /opt/nullapart/phase2-local-seed.sql

sh /opt/nullapart/provision-local-runtime-role.sh
