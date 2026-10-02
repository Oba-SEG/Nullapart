#!/bin/bash
set -e

postconf -e "smtpd_milters=${NULLAPART_RSPAMD_MILTER:-inet:localhost:11332}"
postconf -e "non_smtpd_milters=${NULLAPART_RSPAMD_MILTER:-inet:localhost:11332}"

if [ -n "${NULLAPART_RELAY_DOMAIN:-}" ]; then
  printf '%s OK\n' "$NULLAPART_RELAY_DOMAIN" > /etc/postfix/relay_domains
  postmap /etc/postfix/relay_domains
fi
if [ "${NULLAPART_LOCAL_ACCEPT_ALL_RELAY_RECIPIENTS:-false}" = "true" ]; then
  postconf -e 'relay_recipient_maps='
fi
if [ "${NULLAPART_LOCAL_DISABLE_SMTP_TLS:-false}" = "true" ]; then
  postconf -e 'smtpd_tls_security_level=none'
fi
if [ -n "${NULLAPART_LOCAL_DISCARD_DOMAIN:-}" ]; then
  printf '%s discard:\n' "$NULLAPART_LOCAL_DISCARD_DOMAIN" > /etc/postfix/transport
  postmap /etc/postfix/transport
  postconf -e 'transport_maps=hash:/etc/postfix/transport'
fi

# Fail startup if Postfix ignored or rejected any effective setting.
postfix check
# Start syslog for mail logging
syslog-ng &
# Start Postfix
postfix start
# Keep container alive
tail -f /var/log/mail.log 2>/dev/null || sleep infinity
