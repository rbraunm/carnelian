# SPDX-License-Identifier: MIT
# An OpenLDAP server from Debian's own packages; the entry script loads the configuration and
# the dataset prepare.py wrote, then serves LDAP (StartTLS) and LDAPS.
FROM debian:trixie-slim
RUN apt-get update -qq \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends slapd ldap-utils \
  && rm -rf /var/lib/apt/lists/* /etc/ldap/slapd.d /var/lib/ldap/*
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["sh", "/entrypoint.sh"]
