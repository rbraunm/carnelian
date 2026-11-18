# SPDX-License-Identifier: MIT
"""The OpenID Connect relying party: ID token checks with a stand-in network, then a real Keycloak."""

import html.parser
import http.cookiejar
import json
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from carnelian.fetching import Fetcher, HTTPFailure, secureContext
from carnelian.jose import base64urlEncode
from carnelian.oidc import Pending, Provider, RelyingParty, SignInRefused, discover

issuer = "https://id.example.org/realms/test"
signingKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
numbers = signingKey.public_key().public_numbers()
jwks = {"keys": [{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
                  "n": base64urlEncode(numbers.n.to_bytes(256, "big")), "e": base64urlEncode(numbers.e.to_bytes(3, "big"))}]}


class StandInNetwork(Fetcher):
  """The provider's JWK set, served without a network: a double for the network boundary only."""

  def __init__(self):
    super().__init__(secureContext())
    self.fetched = 0

  def getJSON(self, url, headers=None):
    assert url == f"{issuer}/keys"
    self.fetched += 1
    return jwks


def idToken(claims, header=None):
  header = header or {"alg": "RS256", "kid": "k1"}
  signingInput = f"{base64urlEncode(json.dumps(header).encode())}.{base64urlEncode(json.dumps(claims).encode())}"
  signature = signingKey.sign(signingInput.encode(), padding.PKCS1v15(), hashes.SHA256())
  return f"{signingInput}.{base64urlEncode(signature)}"


now = 1_800_000_000


def party():
  provider = Provider(issuer=issuer, authorizationEndpoint=f"{issuer}/auth", tokenEndpoint=f"{issuer}/token",
                      jwksURI=f"{issuer}/keys", userinfoEndpoint=None, signingAlgorithms=frozenset({"RS256"}))
  return RelyingParty(provider, "app", "secret", "https://app.example.org/callback", StandInNetwork(), clock=lambda: now)


good = {"iss": issuer, "aud": "app", "sub": "s-1", "exp": now + 300, "iat": now - 5, "nonce": "n-1"}


def testAGoodIDTokenPassesAndKeysAreFetchedOnce():
  relyingParty = party()
  assert relyingParty.checkIDToken(idToken(good), "n-1")["sub"] == "s-1"
  relyingParty.checkIDToken(idToken(good), "n-1")
  assert relyingParty.fetcher.fetched == 1


@pytest.mark.parametrize("change, message", [
  ({"iss": "https://evil.example.org"}, "issuer 'https://evil.example.org' is not"),
  ({"aud": "other"}, "not for client 'app'"),
  ({"aud": ["app", "other"]}, "authorized party is None"),
  ({"azp": "other"}, "authorized party is 'other'"),
  ({"exp": now - 61}, "has expired"),
  ({"iat": now + 61}, "issued in the future"),
  ({"nonce": "n-2"}, "nonce does not match"),
  ({"sub": ""}, "names no subject"),
  ({"exp": "soon"}, "no numeric 'exp'"),
])
def testEachIDTokenCheckRefuses(change, message):
  with pytest.raises(SignInRefused, match=message):
    party().checkIDToken(idToken(good | change), "n-1")


def testALeewayOfAMinuteIsAllowed():
  assert party().checkIDToken(idToken(good | {"exp": now - 59, "iat": now + 59}), "n-1")


@pytest.mark.parametrize("header, message", [
  ({"alg": "none", "kid": "k1"}, "algorithm 'none' is refused"),
  ({"alg": "RS256", "kid": "k9"}, "0 signing keys with kid 'k9'"),
  ({"alg": "PS256", "kid": "k1"}, r"algorithm 'PS256' is not one of \['RS256'\]"),
])
def testATokenSignedWrongIsRefused(header, message):
  with pytest.raises(SignInRefused, match=message):
    party().checkIDToken(idToken(good, header), "n-1")


def testTheReturnMustMatchThePendingSignIn():
  relyingParty = party()
  pending = Pending(state="s", nonce="n-1", codeVerifier="v", startedAt=now)
  with pytest.raises(SignInRefused, match="state does not match"):
    relyingParty.finishSignIn(pending, {"state": "t", "code": "c"})
  with pytest.raises(SignInRefused, match="the provider refused: no consent"):
    relyingParty.finishSignIn(pending, {"state": "s", "error": "access_denied", "error_description": "no consent"})
  stale = Pending(state="s", nonce="n-1", codeVerifier="v", startedAt=now - 601)
  with pytest.raises(SignInRefused, match="took too long"):
    relyingParty.finishSignIn(stale, {"state": "s", "code": "c"})


def testTheSignInAddressCarriesPKCEAndTheNonce():
  address, pending = party().beginSignIn()
  query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(address).query))
  assert query["code_challenge_method"] == "S256" and query["state"] == pending.state and query["nonce"] == pending.nonce
  import base64
  import hashlib
  assert query["code_challenge"] == base64.urlsafe_b64encode(hashlib.sha256(pending.codeVerifier.encode()).digest()).rstrip(b"=").decode()


# ---- against the testbed's Keycloak ----------------------------------------

class StandInProvider(StandInNetwork):
  """A provider's discovery document and token endpoint, served without a network."""

  def __init__(self, document=None, claims=None):
    super().__init__()
    self.document, self.claims = document, claims

  def getJSON(self, url, headers=None):
    if url.endswith("/.well-known/openid-configuration"):
      return self.document
    return super().getJSON(url, headers)

  def postForm(self, url, fields, headers=None):
    assert url == f"{issuer}/token" and fields["code"] == "c"
    return {"id_token": idToken(self.claims)}


discovery = {"issuer": issuer, "authorization_endpoint": f"{issuer}/auth", "token_endpoint": f"{issuer}/token",
             "jwks_uri": f"{issuer}/keys", "id_token_signing_alg_values_supported": ["RS256"]}


@pytest.mark.parametrize("change, message", [
  ({"id_token_signing_alg_values_supported": None}, "is not a list of names"),
  ({"id_token_signing_alg_values_supported": "RS256"}, "is not a list of names"),
  ({"code_challenge_methods_supported": "S256"}, "is not a list of names"),
  ({"code_challenge_methods_supported": ["plain"]}, "does not offer PKCE"),
  ({"token_endpoint": "http://id.example.org/token"}, "not an https URL"),
])
def testADiscoveryDocumentThatIsNotWhatTheStandardSaysIsRefused(change, message):
  document = {key: value for key, value in (discovery | change).items() if value is not None}
  with pytest.raises(SignInRefused, match=message):
    discover(issuer, StandInProvider(document))


def testADiscoveryDocumentWithoutPKCEMethodsStillGetsPKCE():
  provider = discover(issuer, StandInProvider(discovery))
  assert provider.signingAlgorithms == frozenset({"RS256"}) and provider.userinfoEndpoint is None


def finishedWith(claims):
  provider = Provider(issuer=issuer, authorizationEndpoint=f"{issuer}/auth", tokenEndpoint=f"{issuer}/token",
                      jwksURI=f"{issuer}/keys", userinfoEndpoint=None, signingAlgorithms=frozenset({"RS256"}))
  relyingParty = RelyingParty(provider, "app", "secret", "https://app.example.org/callback", StandInProvider(claims=claims),
                              clock=lambda: now)
  return relyingParty.finishSignIn(Pending(state="s", nonce="n-1", codeVerifier="v", startedAt=now), {"state": "s", "code": "c"})


def testTheIdentityCarriesTheClaims():
  identity = finishedWith(good | {"preferred_username": "ana", "email": "ana@example.org", "name": "Ana", "groups": ["/a"]})
  assert (identity.subject, identity.userName, identity.email, identity.displayName, identity.groups) == (
    "s-1", "ana", "ana@example.org", "Ana", ("/a",))


@pytest.mark.parametrize("change, message", [
  ({"_claim_names": {"groups": "src1"}, "_claim_sources": {"src1": {"endpoint": "https://graph.example.org"}}},
   "left the groups out"),
  ({"name": 5}, "'name' is not text"),
  ({"preferred_username": ["ana"]}, "'preferred_username' is not text"),
  ({"groups": "/a"}, "not a list of names"),
])
def testAGroupsOverageOrClaimsOfTheWrongKindAreRefused(change, message):
  with pytest.raises(SignInRefused, match=message):
    finishedWith(good | change)

class _Form(html.parser.HTMLParser):
  def __init__(self):
    super().__init__()
    self.action = None

  def handle_starttag(self, tag, attributes):
    attributes = dict(attributes)
    if tag == "form" and attributes.get("id") == "kc-form-login":
      self.action = attributes["action"]


class _Stop(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, request, fp, code, message, headers, newURL):
    raise urllib.error.HTTPError(newURL, code, message, headers, fp)


def signInAtKeycloak(address, userName, password, context):
  """What a person does in the browser: open the address, fill in the form; returns the query sent back."""
  opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                       urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), _Stop())
  form = _Form()
  with opener.open(address, timeout=20) as response:
    form.feed(response.read().decode("utf-8"))
  assert form.action, "Keycloak's login form was not found"
  data = urllib.parse.urlencode({"username": userName, "password": password, "credentialId": ""}).encode()
  try:
    with opener.open(urllib.request.Request(form.action, data=data, method="POST"), timeout=20) as response:
      return None, response.read().decode("utf-8")
  except urllib.error.HTTPError as redirect:
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(redirect.url).query)), None


@pytest.fixture(scope="module")
def keycloak(testbed):
  fetcher = Fetcher(secureContext(testbed["certificateAuthority"]))
  settings = testbed["openIDConnect"]
  provider = discover(settings["issuer"], fetcher)
  return RelyingParty(provider, settings["clientID"], settings["clientSecret"], settings["redirectURI"], fetcher), fetcher


def account(testbed, userName):
  return next(account for account in testbed["accounts"] if account["userName"] == userName)


@pytest.mark.parametrize("userName", ["ana", "jose", "layla", "wei", "\u0645\u0631\u064a\u0645", "manygroups"])
def testEveryoneInTheDatasetSignsIn(testbed, keycloak, userName):
  relyingParty, fetcher = keycloak
  expected = account(testbed, userName)
  address, pending = relyingParty.beginSignIn()
  query, page = signInAtKeycloak(address, userName, expected["password"], fetcher.context)
  assert query is not None, page[:500]
  identity = relyingParty.finishSignIn(pending, query)
  assert identity.userName == userName
  assert identity.displayName == f"{expected['firstName']} {expected['lastName']}"
  assert identity.email == expected["email"]
  assert sorted(identity.groups) == sorted(expected["groups"])
  with pytest.raises((SignInRefused, HTTPFailure)):
    relyingParty.finishSignIn(pending, query)


def testADisabledAccountDoesNotSignIn(testbed, keycloak):
  relyingParty, fetcher = keycloak
  address, _ = relyingParty.beginSignIn()
  query, page = signInAtKeycloak(address, "disabled", account(testbed, "disabled")["password"], fetcher.context)
  assert query is None and "disabled" in page.lower()


def testAWrongPasswordDoesNotSignIn(testbed, keycloak):
  relyingParty, fetcher = keycloak
  address, _ = relyingParty.beginSignIn()
  query, _ = signInAtKeycloak(address, "ana", "not the password", fetcher.context)
  assert query is None


def testTheDiscoveryDocumentIsTheProvidersOwn(testbed, keycloak):
  relyingParty, fetcher = keycloak
  assert relyingParty.provider.issuer == testbed["openIDConnect"]["issuer"]
  with pytest.raises(SignInRefused, match="discovery document names issuer"):
    discover(testbed["openIDConnect"]["issuer"] + "/", fetcher)
