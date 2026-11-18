# SPDX-License-Identifier: MIT
"""Prepare the testbed's files for one host: certificates, the Keycloak realm, and testbed.json.

  python testbed/prepare.py --host <name the tests reach the testbed by>

Every password and the client secret are derived from CARNELIAN_TESTBED_SECRET, so the
same secret always gives the same files and nothing secret is committed. Output goes to
testbed/generated (git-ignored): certificates/ (a test CA and the server's certificate for
the host, localhost and 127.0.0.1), realm/carnelian.json for Keycloak to import, keycloak.env
for compose, and testbed.json, which the tests read through `pytest --testbed`. Run with the
test extras installed (it uses `cryptography` to make the certificates).

  python testbed/prepare.py --host <name> --wait   waits until Keycloak serves the realm.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import shlex
import socket
import hashlib
import hmac
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

here = Path(__file__).parent
generated = here / "generated"
realmName = "carnelian"
clientID = "carnelian-oidc"
redirectURI = "http://127.0.0.1:53682/callback"
samlConsumerURL = "https://sp.carnelian.test/acs"
samlEntities = {"response": "https://sp.carnelian.test/signs-response", "assertion": "https://sp.carnelian.test/signs-assertion"}
keycloakPort = 8443
mdqPort = 8444
casPort = 8445
casServiceURL = "https://sp.carnelian.test/cas"
openLDAPBase = "dc=carnelian,dc=test"
openLDAPService = f"cn=service,ou=services,{openLDAPBase}"
openLDAPPorts = (1389, 1636)
federationScope = "carnelian.test"
federationAuthority = "https://federation.carnelian.test"
directoryRealm = "CARNELIAN.TEST"
directoryDomain = "CARNELIAN"
directoryBase = "DC=carnelian,DC=test"
serviceAccount = "svc-carnelian"


def derived(secret: str, label: str) -> str:
  return hmac.new(secret.encode(), label.encode(), hashlib.sha256).hexdigest()[:32]


def makeCertificates(host: str) -> None:
  from cryptography import x509
  from cryptography.hazmat.primitives import hashes, serialization
  from cryptography.hazmat.primitives.asymmetric import ec
  from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

  folder = generated / "certificates"
  folder.mkdir(parents=True, exist_ok=True)
  start = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
  caKey = ec.generate_private_key(ec.SECP256R1())
  caName = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Carnelian testbed CA")])
  ca = (x509.CertificateBuilder().subject_name(caName).issuer_name(caName).public_key(caKey.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(start + datetime.timedelta(days=400))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(caKey.public_key()), critical=False)
        .sign(caKey, hashes.SHA256()))
  serverKey = ec.generate_private_key(ec.SECP256R1())
  names = [x509.DNSName(host), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
  server = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(caName).public_key(serverKey.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(start + datetime.timedelta(days=397))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(serverKey.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(caKey.public_key()), critical=False)
            .sign(caKey, hashes.SHA256()))
  (folder / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
  (folder / "server.crt").write_bytes(server.public_bytes(serialization.Encoding.PEM))
  (folder / "server.key").write_bytes(serverKey.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
  os.chmod(folder / "server.key", 0o644)


def signingKey(name: str) -> tuple[str, str]:
  """An RSA key and its self-signed certificate, both PEM: the realm's SAML key, the federation's metadata key."""
  from cryptography import x509
  from cryptography.hazmat.primitives import hashes, serialization
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.x509.oid import NameOID

  key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
  start = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
  certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                 .serial_number(x509.random_serial_number()).not_valid_before(start)
                 .not_valid_after(start + datetime.timedelta(days=400)).sign(key, hashes.SHA256()))
  return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode("ascii"),
          certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"))


def userProfile() -> str:
  """Keycloak's user profile with unmanaged attributes on, so each user can carry its subjectID."""
  def attribute(name, validations):
    return {"name": name, "displayName": f"${{{name}}}", "validations": validations, "multivalued": False,
            "permissions": {"view": ["admin", "user"], "edit": ["admin"]}}
  return json.dumps({
    "attributes": [attribute("username", {"length": {"min": 1, "max": 255}}),
                   attribute("email", {"email": {}, "length": {"max": 255}}),
                   attribute("firstName", {"length": {"max": 255}}), attribute("lastName", {"length": {"max": 255}})],
    "unmanagedAttributePolicy": "ENABLED",
  })


def realm(secret: str, host: str, realmKey: tuple[str, str]) -> tuple[dict, list[dict]]:
  dataset = json.loads((here / "dataset.json").read_text(encoding="utf-8"))
  many = [f"/{dataset['manyGroupsPrefix']}{index:02d}" for index in range(dataset["manyGroupsCount"])]
  groups = dataset["groups"] + [{"name": path[1:]} for path in many]
  users, accounts = [], []
  for user in dataset["users"]:
    password = derived(secret, f"user:{user['userName']}")
    subject = f"{derived(secret, 'subject:' + user['userName'])[:16]}@{federationScope}"
    memberOf = many if user["groups"] == "many" else user["groups"]
    users.append({
      "username": user["userName"], "enabled": user["enabled"], "email": user["email"], "emailVerified": True,
      "firstName": user["firstName"], "lastName": user["lastName"], "groups": memberOf,
      "attributes": {"subjectID": [subject]},
      "credentials": [{"type": "password", "value": password, "temporary": False}],
    })
    accounts.append({**user, "groups": memberOf, "password": password, "subjectID": subject})
  privateKey, certificate = realmKey
  document = {
    "realm": realmName, "enabled": True, "sslRequired": "all", "groups": groups, "users": users,
    "components": {
      "org.keycloak.keys.KeyProvider": [{
        "name": "testbed-rsa", "providerId": "rsa", "subComponents": {},
        "config": {"priority": ["500"], "enabled": ["true"], "active": ["true"], "algorithm": ["RS256"],
                   "privateKey": [privateKey], "certificate": [certificate]},
      }],
      "org.keycloak.userprofile.UserProfileProvider": [{
        "providerId": "declarative-user-profile", "subComponents": {}, "config": {"kc.user.profile.config": [userProfile()]},
      }],
    },
    "clients": [samlClient(entity, signs) for signs, entity in samlEntities.items()] + [{
      "clientId": clientID, "enabled": True, "protocol": "openid-connect", "publicClient": False,
      "secret": derived(secret, "client:oidc"), "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
      "redirectUris": [redirectURI], "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "+"},
      "protocolMappers": [{
        "name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
        "config": {"full.path": "true", "id.token.claim": "true", "access.token.claim": "false",
                   "userinfo.token.claim": "true", "claim.name": "groups"},
      }],
    }],
  }
  return document, accounts


def samlClient(entityID: str, signs: str) -> dict:
  """A SAML client that signs its responses, or only its assertions; never encrypts or wants signed requests."""
  def mapper(name, kind, config):
    return {"name": name, "protocol": "saml", "protocolMapper": kind, "config": config}
  return {
    "clientId": entityID, "enabled": True, "protocol": "saml", "redirectUris": [samlConsumerURL],
    "attributes": {
      "saml.server.signature": "true" if signs == "response" else "false",
      "saml.assertion.signature": "true" if signs == "assertion" else "false",
      "saml.client.signature": "false", "saml.encrypt": "false", "saml.authnstatement": "true",
      "saml.signature.algorithm": "RSA_SHA256", "saml_signature_canonicalization_method": "http://www.w3.org/2001/10/xml-exc-c14n#",
      "saml_name_id_format": "username", "saml.force.name.id.format": "true",
      "saml_assertion_consumer_url_post": samlConsumerURL,
    },
    "protocolMappers": [
      mapper("groups", "saml-group-membership-mapper", {"full.path": "true", "attribute.name": "groups", "single": "true"}),
      mapper("email", "saml-user-property-mapper", {"user.attribute": "email", "attribute.name": "email"}),
      mapper("givenName", "saml-user-property-mapper", {"user.attribute": "firstName", "attribute.name": "givenName"}),
      mapper("subject-id", "saml-user-attribute-mapper", {
        "user.attribute": "subjectID", "attribute.name": "urn:oasis:names:tc:SAML:attribute:subject-id",
        "attribute.nameformat": "URI Reference", "friendly.name": "subject-id"}),
    ],
  }


def federationEntity(issuer: str, realmCertificate: str, federationKey: tuple[str, str]) -> bytes:
  """Keycloak as an institution of the testbed federation: its metadata with scope and names, signed by the federation."""
  from lxml import etree
  from signxml import XMLSigner

  body = "".join(line for line in realmCertificate.splitlines() if "CERTIFICATE" not in line)
  until = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
  entity = etree.fromstring(
    f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
    f'xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" '
    f'xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" ID="_testbed" entityID="{issuer}" validUntil="{until}">'
    f'<md:Extensions><mdrpi:RegistrationInfo registrationAuthority="{federationAuthority}"/></md:Extensions>'
    '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:Extensions>'
    f'<shibmd:Scope regexp="false">{federationScope}</shibmd:Scope><mdui:UIInfo>'
    '<mdui:DisplayName xml:lang="en">Carnelian Testbed University</mdui:DisplayName>'
    '<mdui:DisplayName xml:lang="ar">\u062c\u0627\u0645\u0639\u0629 \u0643\u0627\u0631\u0646\u064a\u0644\u064a\u0627\u0646</mdui:DisplayName>'
    '</mdui:UIInfo></md:Extensions><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>'
    f'<ds:X509Certificate>{body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
    '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
    f'Location="{issuer}/protocol/saml"/></md:IDPSSODescriptor></md:EntityDescriptor>')
  signed = XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256",
                     c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(
    entity, key=federationKey[0].encode("ascii"), reference_uri="#_testbed", always_add_key_value=False)
  return etree.tostring(signed, xml_declaration=True, encoding="UTF-8")


def casFiles(secret: str, host: str, accounts: list[dict]) -> None:
  """Apereo CAS: its TLS keystore, its properties, the one service it serves, and the users with their attributes."""
  from cryptography import x509
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.serialization import pkcs12

  folder = generated / "cas"
  (folder / "services").mkdir(parents=True, exist_ok=True)
  certificates = generated / "certificates"
  key = serialization.load_pem_private_key((certificates / "server.key").read_bytes(), password=None)
  certificate = x509.load_pem_x509_certificate((certificates / "server.crt").read_bytes())
  storePassword = derived(secret, "cas:keystore")
  (folder / "keystore.p12").write_bytes(pkcs12.serialize_key_and_certificates(
    b"cas", key, certificate, None, serialization.BestAvailableEncryption(storePassword.encode("ascii"))))
  os.chmod(folder / "keystore.p12", 0o644)
  users = ",".join(f"{account['userName']}::{account['password']}" for account in accounts if account["enabled"])
  # Java may read a .properties file as Latin-1; \uXXXX escapes mean the same under either reading.
  (folder / "cas.properties").write_text("\n".join([
    f"server.port={casPort}", "server.ssl.enabled=true", "server.ssl.key-store=file:/etc/cas/keystore.p12",
    f"server.ssl.key-store-password={storePassword}", f"server.ssl.key-password={storePassword}", "server.ssl.key-store-type=PKCS12", "server.ssl.key-alias=cas",
    f"cas.server.name=https://{host}:{casPort}", "cas.server.prefix=${cas.server.name}/cas",
    "cas.authn.accept.enabled=true", "cas.logout.follow-service-redirects=true", f"cas.authn.accept.users={users}", "cas.authn.accept.name=Testbed",
    "cas.service-registry.core.init-from-json=true", "cas.service-registry.json.location=file:/etc/cas/services",
    "cas.authn.attribute-repository.json[0].location=file:/etc/cas/config/attributes.json",
    "cas.authn.attribute-repository.json[0].id=testbed",
  ]).encode("ascii", "backslashreplace").decode("ascii") + "\n", encoding="ascii")
  (folder / "services" / "carnelian-1.json").write_text(json.dumps({
    "@class": "org.apereo.cas.services.CasRegisteredService", "serviceId": f"^{re.escape(casServiceURL)}(\\?.*)?$",
    "name": "carnelian", "id": 1, "evaluationOrder": 1,
    "attributeReleasePolicy": {"@class": "org.apereo.cas.services.ReturnAllAttributeReleasePolicy"},
  }, indent=2), encoding="utf-8")
  (folder / "attributes.json").write_text(json.dumps({
    account["userName"]: {"mail": [account["email"]], "displayName": [f"{account['firstName']} {account['lastName']}"],
                          "memberOf": account["groups"]}
    for account in accounts if account["enabled"]
  }, indent=2, ensure_ascii=False), encoding="utf-8")


def ldif(name: str, value: str) -> str:
  """One LDIF line; a value that is not plain ASCII, or starts with a space, colon or '<', goes in base64."""
  plain = value.isascii() and value.isprintable() and not value.startswith((" ", ":", "<"))
  return f"{name}: {value}" if plain else f"{name}:: {base64.b64encode(value.encode('utf-8')).decode('ascii')}"


def openLDAPFiles(secret: str, accounts: list[dict]) -> None:
  """OpenLDAP's configuration and the dataset: people, nested groupOfNames in one container, a locked account."""
  dataset = json.loads((here / "dataset.json").read_text(encoding="utf-8"))
  folder = generated / "openldap"
  folder.mkdir(parents=True, exist_ok=True)
  (folder / "config.ldif").write_text("\n".join([
    "dn: cn=config", "objectClass: olcGlobal", "cn: config",
    "olcTLSCertificateFile: /etc/ldap/tls/server.crt", "olcTLSCertificateKeyFile: /etc/ldap/tls/server.key",
    "olcTLSCACertificateFile: /etc/ldap/tls/ca.crt", "",
    "dn: cn=module{0},cn=config", "objectClass: olcModuleList", "cn: module{0}", "olcModulePath: /usr/lib/ldap",
    "olcModuleLoad: back_mdb", "olcModuleLoad: ppolicy", "",
    "dn: cn=schema,cn=config", "objectClass: olcSchemaConfig", "cn: schema", "",
    "include: file:///etc/ldap/schema/core.ldif", "",
    "include: file:///etc/ldap/schema/cosine.ldif", "",
    "include: file:///etc/ldap/schema/inetorgperson.ldif", "",
    "dn: olcDatabase={-1}frontend,cn=config", "objectClass: olcDatabaseConfig", "objectClass: olcFrontendConfig",
    "olcDatabase: {-1}frontend", "",
    "dn: olcDatabase={0}config,cn=config", "objectClass: olcDatabaseConfig", "olcDatabase: {0}config",
    "olcAccess: {0}to * by * none", "",
    "dn: olcDatabase={1}mdb,cn=config", "objectClass: olcDatabaseConfig", "objectClass: olcMdbConfig",
    "olcDatabase: {1}mdb", "olcDbDirectory: /var/lib/ldap", f"olcSuffix: {openLDAPBase}",
    "olcDbIndex: objectClass eq", "olcDbIndex: uid,member eq",
    "olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none",
    f'olcAccess: {{1}}to * by dn.exact="{openLDAPService}" read by self read by * none', "",
    "dn: olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config", "objectClass: olcOverlayConfig",
    "objectClass: olcPPolicyConfig", "olcOverlay: {0}ppolicy", f"olcPPolicyDefault: cn=default,ou=policies,{openLDAPBase}",
  ]) + "\n", encoding="ascii", newline="\n")

  members: dict[str, list[str]] = {}

  def groupDN(name: str) -> str:
    return f"cn={name},ou=groups,{openLDAPBase}"

  def walk(tree: list[dict]) -> None:
    for group in tree:
      members.setdefault(group["name"], [])
      for child in group.get("subGroups", []):
        members[group["name"]].append(groupDN(child["name"]))
      walk(group.get("subGroups", []))

  walk(dataset["groups"])
  for index in range(dataset["manyGroupsCount"]):
    members[f"{dataset['manyGroupsPrefix']}{index:02d}"] = []
  entries = [
    [f"dn: {openLDAPBase}", "objectClass: dcObject", "objectClass: organization", "dc: carnelian", "o: Carnelian testbed"],
    *[[f"dn: ou={unit},{openLDAPBase}", "objectClass: organizationalUnit", f"ou: {unit}"]
      for unit in ("people", "groups", "services", "policies")],
    [f"dn: cn=default,ou=policies,{openLDAPBase}", "objectClass: device", "objectClass: pwdPolicy", "cn: default",
     "pwdAttribute: userPassword", "pwdLockout: TRUE"],
    [f"dn: {openLDAPService}", "objectClass: organizationalRole", "objectClass: simpleSecurityObject", "cn: service",
     f"userPassword: {derived(secret, 'openldap:service')}"],
  ]
  for account in accounts:
    dn = f"uid={account['userName']},ou=people,{openLDAPBase}"
    entry = [ldif("dn", dn), "objectClass: inetOrgPerson", ldif("uid", account["userName"]),
             ldif("cn", f"{account['firstName']} {account['lastName']}"), ldif("sn", account["lastName"]),
             ldif("givenName", account["firstName"]), ldif("displayName", f"{account['firstName']} {account['lastName']}"),
             ldif("mail", account["email"]), ldif("userPassword", account["password"])]
    if not account["enabled"]:
      entry.append("pwdAccountLockedTime: 000001010000Z")
    entries.append(entry)
    for path in account["groups"]:
      members[path.rsplit("/", 1)[1]].append(dn)
  for name, memberDNs in members.items():
    entries.append([ldif("dn", groupDN(name)), "objectClass: groupOfNames", ldif("cn", name),
                    *(ldif("member", member) for member in memberDNs)])
  (folder / "data.ldif").write_text("\n\n".join("\n".join(entry) for entry in entries) + "\n", encoding="ascii", newline="\n")


def sambaSeed(secret: str, accounts: list[dict]) -> str:
  """samba-tool commands that load the dataset: nested groups, accounts, memberships, the service account."""
  dataset = json.loads((here / "dataset.json").read_text(encoding="utf-8"))
  lines = ["set -eu", "samba-tool domain passwordsettings set --complexity=off --min-pwd-length=12 >/dev/null"]

  def groups(tree, parent=None):
    for group in tree:
      lines.append(f"samba-tool group add {shlex.quote(group['name'])} >/dev/null")
      if parent:
        lines.append(f"samba-tool group addmembers {shlex.quote(parent)} {shlex.quote(group['name'])} >/dev/null")
      groups(group.get("subGroups", []), group["name"])

  groups(dataset["groups"])
  for index in range(dataset["manyGroupsCount"]):
    lines.append(f"samba-tool group add {dataset['manyGroupsPrefix']}{index:02d} >/dev/null")
  lines.append(f"samba-tool user create {serviceAccount} {shlex.quote(derived(secret, 'directory:service'))} "
               f"--given-name=Carnelian --surname=Service >/dev/null")
  for account in accounts:
    lines.append(
      f"samba-tool user create {shlex.quote(account['userName'])} {shlex.quote(account['password'])} "
      f"--given-name={shlex.quote(account['firstName'])} --surname={shlex.quote(account['lastName'])} "
      f"--mail-address={shlex.quote(account['email'])} >/dev/null")
    for group in account["groups"]:
      lines.append(f"samba-tool group addmembers {shlex.quote(group.rsplit('/', 1)[1])} {shlex.quote(account['userName'])} >/dev/null")
    if not account["enabled"]:
      lines.append(f"samba-tool user disable {shlex.quote(account['userName'])} >/dev/null")
  return "\n".join(lines) + "\n"


def prepare(host: str, secret: str) -> None:
  makeCertificates(host)
  realmKey, federationKey = signingKey("Carnelian testbed realm"), signingKey("Carnelian testbed federation")
  document, accounts = realm(secret, host, realmKey)
  issuer = f"https://{host}:{keycloakPort}/realms/{realmName}"
  (generated / "mdq").mkdir(parents=True, exist_ok=True)
  for stale in (generated / "mdq").glob("*.xml"):
    stale.unlink()
  (generated / "mdq" / f"{hashlib.sha256(issuer.encode('utf-8')).hexdigest()}.xml").write_bytes(
    federationEntity(issuer, realmKey[1], federationKey))
  (generated / "certificates" / "federation.crt").write_text(federationKey[1], encoding="ascii")
  casFiles(secret, host, accounts)
  openLDAPFiles(secret, accounts)
  (generated / "realm").mkdir(parents=True, exist_ok=True)
  (generated / "realm" / "carnelian.json").write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
  (generated / "samba").mkdir(parents=True, exist_ok=True)
  (generated / "samba" / "seed.sh").write_text(sambaSeed(secret, accounts), encoding="utf-8", newline="\n")
  (generated / "samba.env").write_text(
    f"CARNELIAN_REALM={directoryRealm}\nCARNELIAN_DOMAIN={directoryDomain}\n"
    f"CARNELIAN_ADMIN_PASSWORD=Adm-{derived(secret, 'directory:administrator')}\n", encoding="ascii")
  (generated / "keycloak.env").write_text(
    f"KC_BOOTSTRAP_ADMIN_PASSWORD={derived(secret, 'keycloak:admin')}\nCARNELIAN_TESTBED_HOST={host}\n", encoding="ascii")
  (generated / "testbed.json").write_text(json.dumps({
    "certificateAuthority": str((generated / "certificates" / "ca.crt").resolve()),
    "openIDConnect": {"issuer": issuer, "clientID": clientID, "clientSecret": derived(secret, "client:oidc"),
                      "redirectURI": redirectURI},
    "saml": {"metadataURL": f"https://{host}:{keycloakPort}/realms/{realmName}/protocol/saml/descriptor",
             "identityProviderEntityID": issuer, "consumerURL": samlConsumerURL, "entities": samlEntities},
    "openLDAP": {"host": host, "ldapPort": openLDAPPorts[0], "ldapsPort": openLDAPPorts[1], "baseDN": openLDAPBase,
                 "groupsBaseDN": f"ou=groups,{openLDAPBase}", "serviceDN": openLDAPService,
                 "servicePassword": derived(secret, "openldap:service")},
    "cas": {"serverURL": f"https://{host}:{casPort}/cas", "serviceURL": casServiceURL},
    "federation": {"mdqURL": f"https://{host}:{mdqPort}", "institution": issuer, "scope": federationScope,
                   "registrationAuthority": federationAuthority,
                   "signingCertificate": str((generated / "certificates" / "federation.crt").resolve())},
    "directory": {"host": host, "ldapsPort": 636, "ldapPort": 389, "baseDN": directoryBase,
                  "serviceDN": f"{serviceAccount}@{directoryRealm.lower()}",
                  "servicePassword": derived(secret, "directory:service")},
    "accounts": accounts,
  }, indent=2, ensure_ascii=False), encoding="utf-8")
  print(f"prepared the testbed for {host} in {generated}")


def waitForKeycloak(host: str, timeoutSeconds: int) -> None:
  context = ssl.create_default_context(cafile=str(generated / "certificates" / "ca.crt"))
  address = f"https://{host}:{keycloakPort}/realms/{realmName}/.well-known/openid-configuration"
  deadline = time.monotonic() + timeoutSeconds
  while True:
    try:
      with urllib.request.urlopen(address, context=context, timeout=5) as response:
        if json.load(response)["issuer"].endswith(f"/realms/{realmName}"):
          print(f"Keycloak serves {address}")
          return
    except OSError as error:
      if time.monotonic() > deadline:
        raise SystemExit(f"Keycloak did not answer at {address} within {timeoutSeconds} s: {error}")
    time.sleep(3)


def waitForTLS(host: str, port: int, what: str, timeoutSeconds: int) -> None:
  context = ssl.create_default_context(cafile=str(generated / "certificates" / "ca.crt"))
  deadline = time.monotonic() + timeoutSeconds
  while True:
    try:
      with socket.create_connection((host, port), timeout=5) as raw, context.wrap_socket(raw, server_hostname=host):
        print(f"{what} answers TLS at {host}:{port}")
        return
    except OSError as error:
      if time.monotonic() > deadline:
        raise SystemExit(f"{what} did not answer TLS at {host}:{port} within {timeoutSeconds} s: {error}")
    time.sleep(3)


def waitForDirectory(host: str, timeoutSeconds: int) -> None:
  context = ssl.create_default_context(cafile=str(generated / "certificates" / "ca.crt"))
  deadline = time.monotonic() + timeoutSeconds
  while True:
    try:
      with socket.create_connection((host, 636), timeout=5) as raw, context.wrap_socket(raw, server_hostname=host):
        print(f"the directory answers LDAPS at {host}:636")
        return
    except OSError as error:
      if time.monotonic() > deadline:
        raise SystemExit(f"the directory did not answer LDAPS at {host}:636 within {timeoutSeconds} s: {error}")
    time.sleep(3)


def waitForFederation(host: str, timeoutSeconds: int) -> None:
  context = ssl.create_default_context(cafile=str(generated / "certificates" / "ca.crt"))
  issuer = urllib.parse.quote(f"https://{host}:{keycloakPort}/realms/{realmName}", safe="")
  address = f"https://{host}:{mdqPort}/entities/{issuer}"
  deadline = time.monotonic() + timeoutSeconds
  while True:
    try:
      with urllib.request.urlopen(address, context=context, timeout=5) as response:
        if b"EntityDescriptor" in response.read():
          print(f"the federation's MDQ service answers at {address}")
          return
    except OSError as error:
      if time.monotonic() > deadline:
        raise SystemExit(f"the federation's MDQ service did not answer at {address} within {timeoutSeconds} s: {error}")
    time.sleep(3)


def waitForCAS(host: str, timeoutSeconds: int) -> None:
  context = ssl.create_default_context(cafile=str(generated / "certificates" / "ca.crt"))
  address = f"https://{host}:{casPort}/cas/login"
  deadline = time.monotonic() + timeoutSeconds
  while True:
    try:
      with urllib.request.urlopen(address, context=context, timeout=5) as response:
        if response.status == 200:
          print(f"CAS serves {address}")
          return
    except OSError as error:
      if time.monotonic() > deadline:
        raise SystemExit(f"CAS did not answer at {address} within {timeoutSeconds} s: {error}")
    time.sleep(5)


def main() -> None:
  parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument("--host", required=True)
  parser.add_argument("--wait", action="store_true", help="wait for Keycloak instead of preparing")
  parser.add_argument("--timeout", type=int, default=300)
  parser.add_argument("--directory", action="store_true", help="with --wait, also wait for the directory")
  arguments = parser.parse_args()
  if arguments.wait:
    waitForKeycloak(arguments.host, arguments.timeout)
    waitForFederation(arguments.host, arguments.timeout)
    waitForCAS(arguments.host, arguments.timeout)
    waitForTLS(arguments.host, openLDAPPorts[1], "OpenLDAP", arguments.timeout)
    if arguments.directory:
      waitForDirectory(arguments.host, arguments.timeout)
    return
  secret = os.environ.get("CARNELIAN_TESTBED_SECRET")
  if not secret:
    sys.exit("set CARNELIAN_TESTBED_SECRET; every testbed password is derived from it")
  prepare(arguments.host, secret)


if __name__ == "__main__":
  main()
