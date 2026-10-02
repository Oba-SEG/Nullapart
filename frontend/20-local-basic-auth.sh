#!/bin/sh
set -eu

user="${NULLAPART_LOCAL_UI_USER:?set NULLAPART_LOCAL_UI_USER}"
password="${NULLAPART_LOCAL_UI_PASSWORD:?set NULLAPART_LOCAL_UI_PASSWORD}"

case "$user" in
  *:*|*"
"*)
    echo "invalid local UI user" >&2
    exit 1
    ;;
esac

if [ "${#password}" -lt 16 ]; then
  echo "local UI password must contain at least 16 characters" >&2
  exit 1
fi
case "$password" in
  *"
"*)
    echo "invalid local UI password" >&2
    exit 1
    ;;
esac

umask 077
htpasswd -bcB /etc/nginx/.htpasswd "$user" "$password" >/dev/null
chown root:nginx /etc/nginx/.htpasswd
chmod 0640 /etc/nginx/.htpasswd
