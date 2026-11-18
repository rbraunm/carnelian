#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
mkdir -p /etc/ldap/slapd.d /var/lib/ldap /run/slapd /etc/ldap/tls
cp /certificates/server.crt /certificates/server.key /certificates/ca.crt /etc/ldap/tls/
chown -R openldap:openldap /etc/ldap/tls /etc/ldap/slapd.d /var/lib/ldap /run/slapd
chmod 600 /etc/ldap/tls/server.key
if [ ! -e /etc/ldap/slapd.d/cn=config.ldif ]; then
  su -s /bin/sh openldap -c "slapadd -n 0 -F /etc/ldap/slapd.d -l /seed/config.ldif"
  su -s /bin/sh openldap -c "slapadd -n 1 -F /etc/ldap/slapd.d -l /seed/data.ldif"
fi
exec slapd -h "ldap:/// ldaps:///" -F /etc/ldap/slapd.d -u openldap -g openldap -d stats
