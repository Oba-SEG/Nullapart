#!/bin/sh
set -eu

artifact_root="${NULLAPART_ARTIFACT_ROOT:-/var/lib/nullapart/artifacts}"

install -d -o mailcore -g mailcore -m 0700 "$artifact_root"
chown mailcore:mailcore "$artifact_root"
chmod 0700 "$artifact_root"

exec setpriv --reuid=mailcore --regid=mailcore --init-groups mailcore-server
