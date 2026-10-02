#!/bin/bash
# Nullapart Mail Node Bootstrap — Amazon Linux 2023
# Sets up Postfix + Rspamd + Mail Core for the SEG pipeline.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "[nullapart] Starting mail node bootstrap (node=${node_index}, env=${environment})"

# System updates
dnf update -y
dnf install -y postfix postfix-pgsql rspamd clamav clamav-update clamd \
  rust cargo openssl-devel gcc systemd-resolved

# Create mailcore user
useradd -r -s /sbin/nologin -d /var/lib/nullapart mailcore || true

# Directories
mkdir -p /etc/nullapart /var/lib/nullapart/spool /var/log/mailcore
chown mailcore:mailcore /var/lib/nullapart /var/lib/nullapart/spool /var/log/mailcore

# Copy configs from S3 or inline
cat > /etc/nullapart/node.env <<EOF
NULLAPART_DEPLOYMENT_ID=${deployment_id}
NULLAPART_NODE_ID=mxin-${environment}-$(printf '%02d' ${node_index})
NULLAPART_ENVIRONMENT=${environment}
NULLAPART_HANDOFF_HMAC_SECRET=CHANGE_ME_BEFORE_PRODUCTION
NULLAPART_HANDOFF_HMAC_KEY_ID=mail-handoff-v1
NULLAPART_MAILCORE_HANDOFF_URL=http://127.0.0.1:8081/internal/handoff
NULLAPART_HANDOFF_MAX_BYTES=52428800
EOF
chmod 600 /etc/nullapart/node.env

# Enable and start services
systemctl enable postfix rspamd clamd@scan
systemctl start postfix rspamd clamd@scan

echo "[nullapart] Mail node bootstrap complete"
