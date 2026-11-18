# SPDX-License-Identifier: MIT
"""The SAML service provider: crafted responses signed by signxml, the classic attacks, then a real Keycloak."""

import base64
import copy
import datetime
import html.parser
import urllib.parse
import zlib

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree
from signxml import XMLSigner

from carnelian.fetching import Fetcher, secureContext
from carnelian.saml import IdentityProvider, Pending, ReplayCache, SAMLRefused, ServiceProvider, identityProviderFromMetadata
from carnelian.signatures import RSAPublicKey
from carnelian.xmlTree import parse

from testOIDC import account, signInAtKeycloak

saml = "urn:oasis:names:tc:SAML:2.0:assertion"
samlp = "urn:oasis:names:tc:SAML:2.0:protocol"
dsigNS = "http://www.w3.org/2000/09/xmldsig#"
idp = "https://idp.example.org/realms/test"
sp = "https://sp.example.org/meta"
acs = "https://sp.example.org/acs"
now = 1_800_000_000
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public = RSAPublicKey(key.public_key().public_numbers().n, key.public_key().public_numbers().e)


def instant(offset):
  return datetime.datetime.fromtimestamp(now + offset, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def response(requestID="_req", assertionID="a1", nameID="ana", audience=sp, recipient=acs, destination=acs,
             notOnOrAfter=300, confirmationTo=None, status="urn:oasis:names:tc:SAML:2.0:status:Success"):
  return etree.fromstring(f"""<samlp:Response xmlns:samlp="{samlp}" xmlns:saml="{saml}" ID="r1" Version="2.0" IssueInstant="{instant(0)}" Destination="{destination}" InResponseTo="{requestID}"><saml:Issuer>{idp}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status><saml:Assertion ID="{assertionID}" Version="2.0" IssueInstant="{instant(0)}"><saml:Issuer>{idp}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{nameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="{recipient}" InResponseTo="{confirmationTo or requestID}" NotOnOrAfter="{instant(notOnOrAfter)}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{instant(-5)}" NotOnOrAfter="{instant(notOnOrAfter)}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{instant(0)}" SessionIndex="s-1"/><saml:AttributeStatement><saml:Attribute Name="groups"><saml:AttributeValue>/field/team-a</saml:AttributeValue><saml:AttributeValue>/analysts</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>""")


def signed(element, signingKey=key):
  return XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256",
                   c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(
    element, key=signingKey, reference_uri=f"#{element.get('ID')}", always_add_key_value=False)


def signAssertion(root, signingKey=key):
  assertion = root.find(f"{{{saml}}}Assertion")
  root.replace(assertion, signed(assertion, signingKey))
  return root


def posted(root):
  return base64.b64encode(etree.tostring(root)).decode()


def provider(cache=None):
  return ServiceProvider(sp, acs, IdentityProvider(idp, f"{idp}/sso", (public,)), replayCache=cache, clock=lambda: now)


pending = Pending(requestID="_req", startedAt=now - 10)


@pytest.mark.parametrize("signWhat", ["assertion", "response"])
def testASignedResponseGivesTheIdentity(signWhat):
  root = response()
  root = signAssertion(root) if signWhat == "assertion" else signed(root)
  identity = provider().finishSignIn(pending, posted(root))
  assert (identity.nameID, identity.sessionIndex, identity.issuer) == ("ana", "s-1", idp)
  assert identity.attributes == {"groups": ("/field/team-a", "/analysts")}


@pytest.mark.parametrize("changes, message", [
  ({"audience": "https://other.example.org"}, "not for 'https://sp.example.org/meta'"),
  ({"recipient": "https://evil.example.org/acs"}, "no subject confirmation is for this sign-in"),
  ({"confirmationTo": "_other"}, "no subject confirmation is for this sign-in"),
  ({"requestID": "_other"}, "does not answer this sign-in's request"),
  ({"destination": "https://evil.example.org/acs"}, "the response is for 'https://evil.example.org/acs'"),
  ({"notOnOrAfter": -61}, "has expired"),
  ({"status": "urn:oasis:names:tc:SAML:2.0:status:Responder"}, "answered urn:oasis:names:tc:SAML:2.0:status:Responder"),
])
def testEachProtocolCheckRefuses(changes, message):
  with pytest.raises(SAMLRefused, match=message):
    provider().finishSignIn(pending, posted(signAssertion(response(**changes))))


def testAnUnsignedResponseIsRefused():
  with pytest.raises(SAMLRefused, match="neither the response nor its assertion is signed"):
    provider().finishSignIn(pending, posted(response()))


def testAnAssertionIsUsedOnce():
  cache = ReplayCache()
  provider(cache).finishSignIn(pending, posted(signAssertion(response())))
  with pytest.raises(SAMLRefused, match="assertion 'a1' was already used"):
    provider(cache).finishSignIn(pending, posted(signAssertion(response())))


def testAnEncryptedAssertionIsRefusedByName():
  root = response()
  assertion = root.find(f"{{{saml}}}Assertion")
  encrypted = etree.Element(f"{{{saml}}}EncryptedAssertion")
  root.replace(assertion, encrypted)
  with pytest.raises(SAMLRefused, match="encrypted assertions are refused"):
    provider().finishSignIn(pending, posted(root))


def testAnAssertionSignedByAnotherKeyIsRefused():
  other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  with pytest.raises(SAMLRefused, match="does not verify with any trusted key"):
    provider().finishSignIn(pending, posted(signAssertion(response(), other)))


def testCommentInjectionInTheNameIDDoesNotShortenIt():
  root = signAssertion(response(nameID="admin@example.org.evil.example"))
  text = etree.tostring(root).replace(b"admin@example.org.evil", b"admin@example.org<!---->.evil")
  identity = provider().finishSignIn(pending, base64.b64encode(text).decode())
  assert identity.nameID == "admin@example.org.evil.example"


def testWrappingAForgedAssertionAroundTheSignedOneIsRefused():
  # XSW: the genuine signed assertion is hidden inside a forged one carrying another name.
  root = signAssertion(response())
  genuine = root.find(f"{{{saml}}}Assertion")
  forged = copy.deepcopy(genuine)
  forged.remove(forged.find(f"{{{dsigNS}}}Signature"))
  forged.set("ID", "forged")
  forged.find(f".//{{{saml}}}NameID").text = "admin"
  root.replace(genuine, forged)
  forged.append(genuine)
  with pytest.raises(SAMLRefused, match="neither the response nor its assertion is signed"):
    provider().finishSignIn(pending, posted(root))


def testASecondUnsignedAssertionBesideTheSignedOneIsRefused():
  root = signAssertion(response())
  forged = copy.deepcopy(root.find(f"{{{saml}}}Assertion"))
  forged.remove(forged.find(f"{{{dsigNS}}}Signature"))
  forged.set("ID", "forged")
  forged.find(f".//{{{saml}}}NameID").text = "admin"
  root.insert(2, forged)
  with pytest.raises(SAMLRefused, match="has 2 <Assertion> children; it needs exactly one"):
    provider().finishSignIn(pending, posted(root))


def testMovingTheSignedResponseIntoAWrapperIsRefused():
  # XSW on a signed response: a forged response wraps the genuine one, whose signature still verifies.
  genuine = signed(response())
  forged = response(nameID="admin")
  extensions = etree.SubElement(forged, f"{{{samlp}}}Extensions")
  extensions.append(genuine)
  with pytest.raises(SAMLRefused, match="neither the response nor its assertion is signed"):
    provider().finishSignIn(pending, posted(forged))


def testTheRedirectCarriesADeflatedRequestForThisProvider():
  address, started = provider().beginSignIn("state-1")
  query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(address).query))
  request = parse(zlib.decompress(base64.b64decode(query["SAMLRequest"]), -15))
  assert (request.localName, request.attribute("ID"), request.attribute("AssertionConsumerServiceURL")) == (
    "AuthnRequest", started.requestID, acs)
  assert query["RelayState"] == "state-1"


# ---- against the testbed's Keycloak ----------------------------------------

class _Posted(html.parser.HTMLParser):
  def __init__(self):
    super().__init__()
    self.fields = {}

  def handle_starttag(self, tag, attributes):
    attributes = dict(attributes)
    if tag == "input" and attributes.get("name"):
      self.fields[attributes["name"]] = attributes.get("value", "")


@pytest.fixture(scope="module")
def keycloakIdentityProvider(testbed):
  settings = testbed["saml"]
  fetcher = Fetcher(secureContext(testbed["certificateAuthority"]))
  metadata = fetcher.getBytes(settings["metadataURL"], "application/samlmetadata+xml, application/xml;q=0.9")
  return identityProviderFromMetadata(metadata, settings["identityProviderEntityID"]), fetcher


@pytest.mark.parametrize("signs", ["response", "assertion"])
@pytest.mark.parametrize("userName", ["ana", "jose", "layla", "\u0645\u0631\u064a\u0645", "manygroups"])
def testEveryoneSignsInThroughKeycloak(testbed, keycloakIdentityProvider, signs, userName):
  identityProvider, fetcher = keycloakIdentityProvider
  settings = testbed["saml"]
  serviceProvider = ServiceProvider(settings["entities"][signs], settings["consumerURL"], identityProvider)
  address, started = serviceProvider.beginSignIn()
  expected = account(testbed, userName)
  _, page = signInAtKeycloak(address, userName, expected["password"], fetcher.context)
  form = _Posted()
  form.feed(page)
  assert "SAMLResponse" in form.fields, page[:500]
  identity = serviceProvider.finishSignIn(started, form.fields["SAMLResponse"])
  assert identity.nameID == userName
  assert sorted(identity.attributes["groups"]) == sorted(expected["groups"])
  assert identity.attributes["email"] == (expected["email"],)
  assert identity.attributes["givenName"] == (expected["firstName"],)
  with pytest.raises(SAMLRefused, match="was already used"):
    serviceProvider.finishSignIn(started, form.fields["SAMLResponse"])
