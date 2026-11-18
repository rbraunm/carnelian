# SPDX-License-Identifier: MIT
# An Active Directory domain controller from Debian's own Samba packages; the entry script
# provisions the domain on first start and loads the testbed dataset.
FROM debian:trixie-slim
RUN apt-get update -qq \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends samba samba-ad-dc winbind ldb-tools \
  && rm -rf /var/lib/apt/lists/* /etc/samba/smb.conf
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["sh", "/entrypoint.sh"]
