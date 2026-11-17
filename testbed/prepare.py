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
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import ssl
import sys
import time
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


def realm(secret: str, host: str) -> tuple[dict, list[dict]]:
  dataset = json.loads((here / "dataset.json").read_text(encoding="utf-8"))
  many = [f"/{dataset['manyGroupsPrefix']}{index:02d}" for index in range(dataset["manyGroupsCount"])]
  groups = dataset["groups"] + [{"name": path[1:]} for path in many]
  users, accounts = [], []
  for user in dataset["users"]:
    password = derived(secret, f"user:{user['userName']}")
    memberOf = many if user["groups"] == "many" else user["groups"]
    users.append({
      "username": user["userName"], "enabled": user["enabled"], "email": user["email"], "emailVerified": True,
      "firstName": user["firstName"], "lastName": user["lastName"], "groups": memberOf,
      "credentials": [{"type": "password", "value": password, "temporary": False}],
    })
    accounts.append({**user, "groups": memberOf, "password": password})
  document = {
    "realm": realmName, "enabled": True, "sslRequired": "all", "groups": groups, "users": users,
    "clients": [samlClient(entity, signs) for signs, entity in samlEntities.items()] + [{
      "clientId": clientID, "enabled": True, "protocol": "openid-connect", "publicClient": False,
      "secret": derived(secret, "client:oidc"), "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
      "redirectUris": [redirectURI], "attributes": {"pkce.code.challenge.method": "S256"},
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
    ],
  }


def prepare(host: str, secret: str) -> None:
  makeCertificates(host)
  document, accounts = realm(secret, host)
  (generated / "realm").mkdir(parents=True, exist_ok=True)
  (generated / "realm" / "carnelian.json").write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
  (generated / "keycloak.env").write_text(
    f"KC_BOOTSTRAP_ADMIN_PASSWORD={derived(secret, 'keycloak:admin')}\nCARNELIAN_TESTBED_HOST={host}\n", encoding="ascii")
  issuer = f"https://{host}:{keycloakPort}/realms/{realmName}"
  (generated / "testbed.json").write_text(json.dumps({
    "certificateAuthority": str((generated / "certificates" / "ca.crt").resolve()),
    "openIDConnect": {"issuer": issuer, "clientID": clientID, "clientSecret": derived(secret, "client:oidc"),
                      "redirectURI": redirectURI},
    "saml": {"metadataURL": f"https://{host}:{keycloakPort}/realms/{realmName}/protocol/saml/descriptor",
             "identityProviderEntityID": issuer, "consumerURL": samlConsumerURL, "entities": samlEntities},
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


def main() -> None:
  parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument("--host", required=True)
  parser.add_argument("--wait", action="store_true", help="wait for Keycloak instead of preparing")
  parser.add_argument("--timeout", type=int, default=300)
  arguments = parser.parse_args()
  if arguments.wait:
    waitForKeycloak(arguments.host, arguments.timeout)
    return
  secret = os.environ.get("CARNELIAN_TESTBED_SECRET")
  if not secret:
    sys.exit("set CARNELIAN_TESTBED_SECRET; every testbed password is derived from it")
  prepare(arguments.host, secret)


if __name__ == "__main__":
  main()
