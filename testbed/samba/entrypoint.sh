#!/bin/sh
# SPDX-License-Identifier: MIT
# Provision the domain once (TLS with the testbed's certificate, the dataset from seed.sh),
# then run Samba in the foreground.
set -eu
: "${CARNELIAN_REALM:?}" "${CARNELIAN_DOMAIN:?}" "${CARNELIAN_ADMIN_PASSWORD:?}"
tls=/var/lib/samba/private/tls
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  samba-tool domain provision --realm="$CARNELIAN_REALM" --domain="$CARNELIAN_DOMAIN" --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --adminpass="$CARNELIAN_ADMIN_PASSWORD" \
    --option="tls enabled = yes" --option="tls keyfile = $tls/server.key" \
    --option="tls certfile = $tls/server.crt" --option="tls cafile = $tls/ca.crt" >/dev/null
  mkdir -p "$tls"
  cp /certificates/server.key /certificates/server.crt /certificates/ca.crt "$tls/"
  chmod 600 "$tls/server.key"
  sh /seed/seed.sh
  echo "provisioned $CARNELIAN_REALM"
fi
exec samba --foreground --no-process-group
