# SPDX-License-Identifier: MIT
"""Every parser an attacker can reach, fed arbitrary input: the only way it may fail is its own refusal,
by name -- never another exception, a hang, or a recursion error. Signed documents with one byte changed
are refused or read exactly as before."""

import base64
import json
import os
import time

from hypothesis import HealthCheck, given, settings, strategies as strategies

from carnelian.cas import CASRefused, CASServer, Pending as CASPending
from carnelian.der import DERError, publicKeyFromCertificate, readOne
from carnelian.oidc import Pending as OpenIDConnectPending, SignInRefused
from carnelian.jose import JOSEError, KeySet, readHeader, verifyCompact
from carnelian.ldap import DirectoryRefused, readAll, readTLV
from carnelian.saml import SAMLRefused
from carnelian.scim import SCIMRefused, SCIMService, parseFilter
from carnelian.signatures import SignatureError
from carnelian.xmldsig import SignatureRefused, verifyEnveloped
from carnelian.xmlTree import XMLRefused, parse

from testOIDC import good, idToken, jwks, now, party
from testSAML import pending, posted, provider, response, signAssertion
from testSCIM import MemoryStore

# CARNELIAN_FUZZ=deep runs each property 20,000 times instead of the 300 every test run makes.
settings.register_profile("quick", max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
settings.register_profile("deep", max_examples=20_000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
settings.load_profile(os.environ.get("CARNELIAN_FUZZ", "quick"))
fuzzed = settings()
xmlish = strategies.text(alphabet=strategies.sampled_from(list("<>/=\"' :!?-[]&;#xmlnsabcdeSAMLAssertion\n")), max_size=300)


@fuzzed
@given(strategies.binary(max_size=400))
def testDERRefusesByName(data):
  try:
    readOne(data)
  except DERError:
    pass
  try:
    publicKeyFromCertificate(data)
  except (DERError, SignatureError):
    pass


@fuzzed
@given(strategies.binary(max_size=400) | xmlish.map(lambda text: text.encode("utf-8")))
def testXMLRefusesByName(data):
  try:
    root = parse(data)
  except XMLRefused:
    return
  try:
    verifyEnveloped(root, [])
  except (SignatureRefused, XMLRefused):
    pass


def testDeepXMLIsRefusedByName():
  for depth in (2000, 100_000):
    try:
      parse(b"<a>" * depth + b"</a>" * depth)
    except XMLRefused:
      pass


@fuzzed
@given(strategies.binary(max_size=200))
def testBERRefusesByName(data):
  try:
    readTLV(data)
    readAll(data)
  except DirectoryRefused:
    pass


@fuzzed
@given(strategies.text(max_size=200) | strategies.text(alphabet="()[]\"'.andornotpreqcoswgtl $:\\", max_size=200))
def testSCIMFiltersRefuseByName(text):
  try:
    parseFilter(text)
  except SCIMRefused:
    pass


def testDeeplyNestedFiltersAreRefusedByName():
  for text in ("(" * 5000 + 'a eq "b"' + ")" * 5000, "not (" * 3000 + 'a pr' + ")" * 3000):
    try:
      parseFilter(text)
    except SCIMRefused:
      pass


@fuzzed
@given(strategies.text(alphabet="ABCDEFabcdef0123456789-_.=", max_size=300))
def testJOSERefusesByName(token):
  keys = KeySet(jwks)
  try:
    header = readHeader(token)
    verifyCompact(token, keys.keyFor(header))
  except JOSEError:
    pass


@fuzzed
@given(strategies.integers(min_value=0, max_value=10_000), strategies.integers(min_value=0, max_value=255))
def testAnIDTokenWithOneByteChangedIsRefused(position, value):
  token = idToken(good)
  data = bytearray(token.encode("ascii"))
  index = position % len(data)
  if data[index] == value:
    return
  data[index] = value
  keys = KeySet(jwks)
  try:
    changed = data.decode("ascii")
    verifyCompact(changed, keys.keyFor(readHeader(changed)))
  except (JOSEError, UnicodeDecodeError):
    return
  raise AssertionError(f"a token changed at {index} was accepted")


service = SCIMService(MemoryStore(), "https://app.example.org/scim/v2", lambda token: token == "t")
json7 = strategies.recursive(strategies.none() | strategies.booleans() | strategies.integers() | strategies.text(max_size=20),
                             lambda children: strategies.lists(children, max_size=4)
                             | strategies.dictionaries(strategies.text(max_size=12), children, max_size=4), max_leaves=20)


@fuzzed
@given(strategies.sampled_from(["GET", "POST", "PUT", "PATCH", "DELETE"]),
       strategies.sampled_from(["/Users", "/Groups", "/Users/x", "/Groups/x", "/Schemas", "/x/y/z", "/"]),
       strategies.text(max_size=60), json7 | strategies.binary(max_size=80))
def testSCIMAlwaysAnswers(method, path, query, body):
  data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
  answer = service.handle(method, path, query, {"Authorization": "Bearer t", "Content-Type": "application/scim+json"}, data)
  assert 200 <= answer.status < 600


@fuzzed
@given(strategies.binary(max_size=300) | xmlish.map(lambda text: text.encode("utf-8")))
def testCASAnswersRefuseByName(data):
  try:
    CASServer("https://cas.example.org/cas", "https://app.example.org/cas", None).read(data)
  except CASRefused:
    pass


@fuzzed
@given(strategies.binary(max_size=400))
def testSAMLResponsesRefuseByName(data):
  try:
    provider().finishSignIn(pending, base64.b64encode(data).decode("ascii"))
  except SAMLRefused:
    pass


signedResponse = None


@fuzzed
@given(strategies.integers(min_value=0, max_value=100_000), strategies.integers(min_value=0, max_value=255))
def testASignedResponseWithOneByteChangedIsRefusedOrReadTheSame(position, value):
  global signedResponse
  if signedResponse is None:
    signedResponse = base64.b64decode(posted(signAssertion(response())))
  expected = provider().finishSignIn(pending, base64.b64encode(signedResponse).decode("ascii"))
  data = bytearray(signedResponse)
  index = position % len(data)
  data[index] = value
  try:
    identity = provider().finishSignIn(pending, base64.b64encode(bytes(data)).decode("ascii"))
  except SAMLRefused:
    return
  assert (identity.issuer, identity.nameID, identity.attributes) == (expected.issuer, expected.nameID, expected.attributes)


# The pending state is one no generated query can hold, so no case reaches the provider's token or validation endpoint.
unguessable = "0123456789abcdef" * 4
callbackQuery = strategies.dictionaries(strategies.sampled_from(["state", "code", "ticket", "iss", "error", "error_description"]),
                                        strategies.text(max_size=40), max_size=6)


@fuzzed
@given(callbackQuery)
def testOpenIDConnectCallbacksRefuseByName(query):
  relyingParty = party()
  pending = OpenIDConnectPending(issuer=relyingParty.provider.issuer, clientID="app", state=unguessable, nonce="n-1",
                                 codeVerifier="v", startedAt=now)
  try:
    relyingParty.finishSignIn(pending, query)
  except SignInRefused:
    pass


@fuzzed
@given(callbackQuery)
def testCASCallbacksRefuseByName(query):
  cas = CASServer("https://cas.example.org/cas", "https://app.example.org/cas", None)
  try:
    cas.finishSignIn(CASPending(state=unguessable, startedAt=time.time()), query)
  except CASRefused:
    pass
