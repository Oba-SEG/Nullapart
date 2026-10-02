#!/bin/sh
set -eu

fail() {
  printf '%s\n' "mailcore-filter-wrapper: $1" >&2
  exit 75
}

queue_id=
client_address=
client_hostname=
client_helo=
sasl_username=
sender=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --)
      shift
      break
      ;;
    --queue-id)
      shift
      [ "$#" -gt 0 ] || fail "missing --queue-id value"
      queue_id="$1"
      shift
      ;;
    --client-address)
      shift
      [ "$#" -gt 0 ] || fail "missing --client-address value"
      client_address="$1"
      shift
      ;;
    --client-hostname)
      shift
      [ "$#" -gt 0 ] || fail "missing --client-hostname value"
      client_hostname="$1"
      shift
      ;;
    --client-helo)
      shift
      [ "$#" -gt 0 ] || fail "missing --client-helo value"
      client_helo="$1"
      shift
      ;;
    --sasl-username)
      shift
      [ "$#" -gt 0 ] || fail "missing --sasl-username value"
      sasl_username="$1"
      shift
      ;;
    --sender)
      shift
      [ "$#" -gt 0 ] || fail "missing --sender value"
      sender="$1"
      shift
      ;;
    *)
      fail "unexpected argument $1"
      ;;
  esac
done

[ -n "$queue_id" ] || fail "missing --queue-id"
[ -n "$client_address" ] || fail "missing --client-address"
[ -n "$sender" ] || fail "missing --sender"
[ "$#" -gt 0 ] || fail "no recipients supplied"

if [ "$sender" = '"<>"' ]; then
  sender="<>"
fi

exec /usr/libexec/nullapart/mailcore-filter \
  --queue-id "$queue_id" \
  --client-address "$client_address" \
  --client-hostname "$client_hostname" \
  --client-helo "$client_helo" \
  --sasl-username "$sasl_username" \
  --sender "$sender" \
  -- "$@"
