# SPDX-License-Identifier: MIT
"""Research and education federations: signed metadata (signxml as the oracle), institutions and their
scopes, scoped identifiers, the service provider's metadata, and InCommon's real MDQ service."""

import base64
import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner

from carnelian.federation import (Federation, eduPersonPrincipalName, pairwiseID, researchAndScholarship, scopedIdentifier,
                                  serviceProviderMetadata, subjectID)
from carnelian.fetching import Fetcher, HTTPFailure, secureContext
from carnelian.saml import SAMLIdentity, SAMLRefused, ServiceProvider

from testOIDC import account, signInAtKeycloak
from testSAML import _Posted

vectors = Path(__file__).parent / "vectors"
now = 1_800_000_000
entity = "https://idp.example.edu/idp/shibboleth"
mdq = "https://mdq.example.org"


def certificate(key, name):
  subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
  start = datetime.datetime.fromtimestamp(now - 86400, datetime.UTC)
  built = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
           .serial_number(1).not_valid_before(start).not_valid_after(start + datetime.timedelta(days=30))
           .sign(key, hashes.SHA256()))
  return built.public_bytes(serialization.Encoding.PEM)


federationKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
federationCertificate = certificate(federationKey, "federation signing").decode("ascii")
idpKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
idpCertificate = base64.b64encode(x509.load_pem_x509_certificate(certificate(idpKey, "idp")).public_bytes(
  serialization.Encoding.DER)).decode()


def instant(offset):
  return datetime.datetime.fromtimestamp(now + offset, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def metadata(entityID=entity, validUntil=86400, scopes='<shibmd:Scope regexp="false">example.edu</shibmd:Scope>'):
  until = f' validUntil="{instant(validUntil)}"' if validUntil is not None else ""
  return etree.fromstring(f"""<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" ID="_m1" entityID="{entityID}"{until}><md:Extensions><mdrpi:RegistrationInfo registrationAuthority="https://incommon.org"/><mdattr:EntityAttributes><saml:Attribute Name="http://macedir.org/entity-category-support"><saml:AttributeValue>{researchAndScholarship}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://macedir.org/entity-category"><saml:AttributeValue>http://refeds.org/category/hide-from-discovery</saml:AttributeValue></saml:Attribute></mdattr:EntityAttributes></md:Extensions><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:Extensions>{scopes}<mdui:UIInfo><mdui:DisplayName xml:lang="en">Example University</mdui:DisplayName><mdui:DisplayName xml:lang="es">Universidad de Ejemplo</mdui:DisplayName></mdui:UIInfo></md:Extensions><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{idpCertificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.edu/idp/profile/SAML2/Redirect/SSO"/></md:IDPSSODescriptor></md:EntityDescriptor>""")


def signed(element, signingKey=federationKey):
  return etree.tostring(XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256",
                                  c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(
    element, key=signingKey, reference_uri="#_m1", always_add_key_value=False))


class Recorded:
  """The network, as far as the federation is concerned: what was asked for, and the answer."""

  def __init__(self, answer):
    self.answer, self.asked = answer, []

  def getBytes(self, address, accept):
    self.asked.append((address, accept))
    return self.answer


def federation(answer=b"", clock=lambda: now):
  return Federation("Example", mdq, federationCertificate, Recorded(answer), clock=clock)


def testSignedMetadataGivesTheInstitution():
  institution = federation().read(signed(metadata()), entity)
  assert institution.entityID == entity and institution.scopes == ("example.edu",)
  assert institution.registrationAuthority == "https://incommon.org"
  assert institution.entityCategories == ("http://refeds.org/category/hide-from-discovery",)
  assert institution.hiddenFromDiscovery
  assert (institution.displayName("es-MX"), institution.displayName("fr"), institution.displayName("en-GB")) == (
    "Universidad de Ejemplo", "Example University", "Example University")
  assert institution.identityProvider.singleSignOnURL == "https://idp.example.edu/idp/profile/SAML2/Redirect/SSO"
  assert institution.identityProvider.signingKeys[0].modulus == idpKey.public_key().public_numbers().n


def testInstitutionsAreAskedForByMDQAndKeptUntilValidUntil():
  ticks = [now]
  source = federation(signed(metadata(validUntil=3600)), clock=lambda: ticks[0])
  source.institution(entity)
  ticks[0] = now + 3500
  source.institution(entity)
  assert source.fetcher.asked == [(f"{mdq}/entities/https%3A%2F%2Fidp.example.edu%2Fidp%2Fshibboleth",
                                   "application/samlmetadata+xml")]
  ticks[0] = now + 3600
  with pytest.raises(SAMLRefused, match="expired"):
    source.institution(entity)


class Unknown:
  """An MDQ service that knows no entity: every lookup fails as the fetcher reports a 404."""

  def __init__(self):
    self.asked = []

  def getBytes(self, address, accept):
    self.asked.append(address)
    raise HTTPFailure(f"{address} answered 404, not 200")


def testAFailedLookupIsRefusedByNameAndRememberedForAWhile():
  ticks = [now]
  unknown = "https://unknown.example.edu/idp"
  source = Federation("Example", mdq, federationCertificate, Unknown(), refusalCacheSeconds=60, clock=lambda: ticks[0])
  why = (f"Example's metadata for {unknown} could not be fetched: "
         f"{mdq}/entities/https%3A%2F%2Funknown.example.edu%2Fidp answered 404, not 200")
  for tick in (now, now + 59):
    ticks[0] = tick
    with pytest.raises(SAMLRefused) as refused:
      source.institution(unknown)
    assert str(refused.value) == why
  assert len(source.fetcher.asked) == 1
  ticks[0] = now + 60
  with pytest.raises(SAMLRefused):
    source.institution(unknown)
  assert len(source.fetcher.asked) == 2


def testMetadataThatIsRefusedIsNotFetchedAgainAtOnce():
  source = federation(signed(metadata()).replace(b"Example University", b"Evil University"))
  for _ in range(3):
    with pytest.raises(SAMLRefused, match="digest"):
      source.institution(entity)
  assert len(source.fetcher.asked) == 1


@pytest.mark.parametrize("entityID", ["", "https://idp.example.edu/" + "a" * 1001])
def testAnEntityIDOutsideSAMLsLengthIsRefusedWithoutAFetch(entityID):
  source = federation()
  with pytest.raises(SAMLRefused, match="an entity ID is 1 to 1024 characters"):
    source.institution(entityID)
  assert source.fetcher.asked == []


def tampered():
  document = signed(metadata()).replace(b"Example University", b"Evil University")
  return document


@pytest.mark.parametrize("document, why", [
  (lambda: etree.tostring(metadata()), "not signed|no signature|Signature"),
  (lambda: signed(metadata(), rsa.generate_private_key(public_exponent=65537, key_size=2048)), "signature"),
  (tampered, "digest"),
  (lambda: signed(metadata(validUntil=-1)), "expired"),
  (lambda: signed(metadata(validUntil=None)), "validUntil"),
  (lambda: signed(metadata(entityID="https://other.example.edu/idp")), "answered for 'https://other.example.edu/idp'"),
  (lambda: signed(metadata(scopes='<shibmd:Scope regexp="true">^.*$</shibmd:Scope>')), "regular expression"),
  (lambda: signed(metadata(scopes="")), "has no scope"),
])
def testMetadataThatCannotBeTrustedIsRefused(document, why):
  with pytest.raises(SAMLRefused, match=why):
    federation().read(document(), entity)


def categoryWithChild():
  root = metadata()
  value = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute[@Name='http://macedir.org/entity-category']/"
                    "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
  value.text = "http://refeds.org/category/"
  etree.SubElement(value, "{urn:x}b").tail = "hide-from-discovery"
  return signed(root)


@pytest.mark.parametrize("document, why", [
  (lambda: signed(metadata(scopes='<shibmd:Scope regexp="false">example<x:b xmlns:x="urn:x"/>.edu</shibmd:Scope>')),
   "<Scope> must hold text only"),
  (categoryWithChild, "<AttributeValue> must hold text only"),
])
def testSignedMetadataTextFieldsMustBeTextOnly(document, why):
  with pytest.raises(SAMLRefused, match=why):
    federation().read(document(), entity)


def identity(value, attribute=subjectID, issuer=entity, count=1):
  return SAMLIdentity(issuer=issuer, nameID="transient", nameIDFormat=None, sessionIndex=None,
                      attributes={attribute: (value,) * count})


@pytest.mark.parametrize("attribute, value, expected", [
  (subjectID, "Ana.Lima-1@Example.EDU", None),
  (subjectID, "3NHC2ZKBG2OVZWYP@example.edu", "3nhc2zkbg2ovzwyp@example.edu"),
  (pairwiseID, "HTTSOCNAZDW4AMUOA7XKTMPLQ5DUULE2@example.edu", "httsocnazdw4amuoa7xktmplq5duule2@example.edu"),
  (eduPersonPrincipalName, "Ana.Lima@example.edu", "Ana.Lima@example.edu"),
])
def testScopedIdentifiersInTheInstitutionsScope(attribute, value, expected):
  institution = federation().read(signed(metadata()), entity)
  if expected is None:
    with pytest.raises(SAMLRefused, match="not a scoped identifier"):
      scopedIdentifier(identity(value, attribute), institution, attribute)
  else:
    assert scopedIdentifier(identity(value, attribute), institution, attribute) == expected


@pytest.mark.parametrize("given, why", [
  (identity("ana@other.edu"), "may vouch for example.edu, not other.edu"),
  (identity("ana@example.edu.evil.org"), "not example.edu.evil.org"),
  (identity("ana@example.edu", count=2), "2 values"),
  (identity("ana@example.edu", attribute=eduPersonPrincipalName), "0 values"),
  (identity("ana@example.edu", issuer="https://other.example.edu/idp"), "issued by"),
])
def testAnInstitutionCannotVouchOutsideItsScope(given, why):
  institution = federation().read(signed(metadata()), entity)
  with pytest.raises(SAMLRefused, match=why):
    scopedIdentifier(given, institution, subjectID)


def testTheServiceProvidersMetadataIsWhatAFederationRegisters():
  document = etree.fromstring(serviceProviderMetadata(
    "https://openfurrow.example.org/saml", "https://openfurrow.example.org/signin/with/incommon/return",
    {"en": "OpenFurrow", "es": "OpenFurrow (ensayos)"}, "https://openfurrow.example.org/about",
    "https://openfurrow.example.org/privacy", "Example Station", "it@example.org", "security@example.org"))
  names = {"md": "urn:oasis:names:tc:SAML:2.0:metadata", "mdui": "urn:oasis:names:tc:SAML:metadata:ui",
           "saml": "urn:oasis:names:tc:SAML:2.0:assertion"}
  assert document.get("entityID") == "https://openfurrow.example.org/saml"
  consumer = document.find("md:SPSSODescriptor/md:AssertionConsumerService", names)
  assert (consumer.get("Binding"), consumer.get("Location")) == (
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "https://openfurrow.example.org/signin/with/incommon/return")
  assert [name.text for name in document.findall(".//mdui:DisplayName", names)] == ["OpenFurrow", "OpenFurrow (ensayos)"]
  assert [value.text for value in document.findall(".//saml:AttributeValue", names)] == [researchAndScholarship]
  assert [email.text for email in document.findall("md:ContactPerson/md:EmailAddress", names)] == [
    "mailto:it@example.org", "mailto:security@example.org"]
  assert document.find("md:SPSSODescriptor", names).get("WantAssertionsSigned") == "true"
  with pytest.raises(ValueError, match="https"):
    serviceProviderMetadata("x", "http://openfurrow.example.org/back", {}, "https://a", "https://b", "o", "a@b")


def testFederationMetadataCarriesTheServiceProvidersKeysAndLogout():
  certificate = x509.load_pem_x509_certificate(federationCertificate.encode("ascii")).public_bytes(serialization.Encoding.DER)
  document = etree.fromstring(serviceProviderMetadata(
    "https://openfurrow.example.org/saml", "https://openfurrow.example.org/signin/with/incommon/return", {"en": "OpenFurrow"},
    "https://openfurrow.example.org/about", "https://openfurrow.example.org/privacy", "Example Station", "it@example.org",
    signingCertificate=certificate, encryptionCertificates=(certificate,),
    singleLogoutURL="https://openfurrow.example.org/signout/saml"))
  names = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
  assert [key.get("use") for key in document.findall("md:SPSSODescriptor/md:KeyDescriptor", names)] == ["signing", "encryption"]
  assert {service.get("Location") for service in document.findall("md:SPSSODescriptor/md:SingleLogoutService", names)} == {
    "https://openfurrow.example.org/signout/saml"}
  assert document.find("md:SPSSODescriptor", names).get("AuthnRequestsSigned") == "true"

# ---- InCommon's real MDQ service, which also serves eduGAIN's institutions ----

@pytest.mark.parametrize("entityID, scope, authority", [
  ("urn:mace:incommon:arizona.edu", "arizona.edu", "https://incommon.org"),
  ("https://idp.rsu.edu.ng/idp/shibboleth", "rsu.edu.ng", "http://ukfederation.org.uk"),
  ("https://040cafe602.up.edu.br/idp/shibboleth", "up.edu.br", "http://cafe.rnp.br"),
])
def testInCommonsRealMetadataIsVerified(request, entityID, scope, authority):
  if not request.config.getoption("--live"):
    pytest.skip("live test: run with --live to check InCommon's published metadata")
  source = Federation("InCommon", "https://mdq.incommon.org", (vectors / "incommonMDQ.pem").read_text(encoding="ascii"),
                      Fetcher(secureContext()))
  institution = source.institution(entityID)
  assert scope in institution.scopes and institution.registrationAuthority == authority
  assert institution.identityProvider.singleSignOnURL.startswith("https://")
  assert institution.identityProvider.signingKeys


# ---- the testbed's own federation, vouching for its Keycloak --------------------

@pytest.mark.parametrize("userName", ["ana", "\u0645\u0631\u064a\u0645"])
def testSigningInThroughTheTestbedFederation(testbed, userName):
  settings = testbed["federation"]
  fetcher = Fetcher(secureContext(testbed["certificateAuthority"]))
  source = Federation("testbed", settings["mdqURL"], Path(settings["signingCertificate"]).read_text(encoding="ascii"), fetcher)
  institution = source.institution(settings["institution"])
  assert institution.scopes == (settings["scope"],) and institution.registrationAuthority == settings["registrationAuthority"]
  assert institution.displayName("ar-EG") == "\u062c\u0627\u0645\u0639\u0629 \u0643\u0627\u0631\u0646\u064a\u0644\u064a\u0627\u0646"
  serviceProvider = ServiceProvider(testbed["saml"]["entities"]["response"], testbed["saml"]["consumerURL"],
                                    institution.identityProvider)
  address, started = serviceProvider.beginSignIn()
  expected = account(testbed, userName)
  _, page = signInAtKeycloak(address, userName, expected["password"], fetcher.context)
  form = _Posted()
  form.feed(page)
  identity = serviceProvider.finishSignIn(started, form.fields["SAMLResponse"])
  assert scopedIdentifier(identity, institution, subjectID) == expected["subjectID"]
